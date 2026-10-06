//
//  FileStore.swift
//  ACE SDK
//
//  A directory-backed ACEStore. Identical lock protocol in all ACE SDKs; the files at
//  rest are portable, but concurrent mixed-language access to one root is unsupported.
//

import Foundation
import Darwin

/// `ACEStore` over a directory: `<root>/<key>`, directories 0700, files 0600.
///
/// - Reads refuse symlinks and files larger than 64 MiB.
/// - Writes go to `<dir>/.tmp-<16 hex>` (`O_CREAT|O_EXCL|O_NOFOLLOW`), are fsynced, renamed
///   over the key and the directory is fsynced.
/// - Locks are `<root>/locks/<name>.lock` files created with `O_EXCL` containing
///   `{"createdAt":N,"host":"…","pid":N}`. A lock left by a dead process on the same host,
///   or an unparseable lock file older than 60 s, is broken; otherwise the caller polls
///   every 50 ms until the timeout. An in-process mutex keyed by (realpath(root), name)
///   serializes callers within this process.
public final class FileStore: ACEStore, @unchecked Sendable {
    public let directory: URL
    private let root: String
    private static let maxReadBytes = 64 << 20
    private static let processMutexes = NamedMutexes()

    /// Opens (creating if needed, mode 0700) the store directory.
    public init(directory: URL) throws {
        let path = directory.standardizedFileURL.path
        if mkdir(path, 0o700) != 0 && errno != EEXIST {
            // Create intermediate directories as well.
            do {
                try FileManager.default.createDirectory(atPath: path, withIntermediateDirectories: true,
                                                        attributes: [.posixPermissions: 0o700])
            } catch {
                throw ACEError(.storageFailed, "cannot create store directory: \(error.localizedDescription)")
            }
        }
        var st = stat()
        guard lstat(path, &st) == 0, (st.st_mode & S_IFMT) == S_IFDIR else {
            throw ACEError(.storageFailed, "store root is not a directory")
        }
        guard let real = realpath(path, nil) else { throw ACEError(.storageFailed, "cannot resolve store root") }
        defer { free(real) }
        self.root = String(cString: real)
        self.directory = URL(fileURLWithPath: self.root, isDirectory: true)
    }

    private func path(_ key: String) -> String { root + "/" + key }

    private func posixError(_ op: String, _ key: String) -> ACEError {
        ACEError(.storageFailed, "\(op) \(key): \(String(cString: strerror(errno)))")
    }

    // MARK: ACEStore

    public func read(_ key: String) throws -> Data? {
        try validateStoreKey(key)
        let p = path(key)
        var st = stat()
        if lstat(p, &st) != 0 {
            if errno == ENOENT || errno == ENOTDIR { return nil }
            throw posixError("stat", key)
        }
        guard (st.st_mode & S_IFMT) == S_IFREG else { throw ACEError(.storageFailed, "\(key) is not a regular file") }
        guard st.st_size <= Self.maxReadBytes else { throw ACEError(.storageFailed, "\(key) exceeds 64 MiB") }
        let fd = open(p, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else {
            if errno == ENOENT { return nil }
            throw posixError("open", key)
        }
        defer { close(fd) }
        var out = Data()
        var buf = [UInt8](repeating: 0, count: 65536)
        while true {
            let n = Darwin.read(fd, &buf, buf.count)
            if n < 0 {
                if errno == EINTR { continue }
                throw posixError("read", key)
            }
            if n == 0 { break }
            out.append(buf, count: n)
            guard out.count <= Self.maxReadBytes else { throw ACEError(.storageFailed, "\(key) exceeds 64 MiB") }
        }
        return out
    }

    public func write(_ key: String, _ value: Data) throws {
        try validateStoreKey(key)
        let p = path(key)
        let dir = (p as NSString).deletingLastPathComponent
        try makeDirectories(dir)
        let tmp = dir + "/.tmp-" + randomHex(8)
        let fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard fd >= 0 else { throw posixError("create", key) }
        var ok = false
        defer {
            if !ok { unlink(tmp) }
        }
        do {
            defer { close(fd) }
            try writeAll(fd, value, key: key)
            guard fsync(fd) == 0 else { throw posixError("fsync", key) }
        }
        guard rename(tmp, p) == 0 else { throw posixError("rename", key) }
        ok = true
        try fsyncDirectory(dir)
    }

    public func delete(_ key: String) throws {
        try validateStoreKey(key)
        if unlink(path(key)) != 0 && errno != ENOENT && errno != ENOTDIR {
            throw posixError("unlink", key)
        }
    }

    public func list(prefix: String) throws -> [String] {
        var out: [String] = []
        // Walk only the directory that can contain the prefix.
        let slash = prefix.lastIndex(of: "/")
        let base = slash.map { String(prefix[..<$0]) } ?? ""
        try walk(base.isEmpty ? root : root + "/" + base, relative: base, into: &out)
        return out.filter { $0.hasPrefix(prefix) && isValidStoreKey($0) }.sorted()
    }

    private func walk(_ dir: String, relative: String, into out: inout [String]) throws {
        guard let d = opendir(dir) else {
            if errno == ENOENT || errno == ENOTDIR { return }
            throw posixError("opendir", relative)
        }
        defer { closedir(d) }
        while let entry = readdir(d) {
            let name = withUnsafeBytes(of: entry.pointee.d_name) { raw in
                String(decoding: raw.prefix(Int(entry.pointee.d_namlen)), as: UTF8.self)
            }
            if name.hasPrefix(".") { continue }
            let rel = relative.isEmpty ? name : relative + "/" + name
            if relative.isEmpty && name == "locks" { continue }
            let full = dir + "/" + name
            var st = stat()
            guard lstat(full, &st) == 0 else { continue }
            switch st.st_mode & S_IFMT {
            case S_IFDIR: try walk(full, relative: rel, into: &out)
            case S_IFREG: out.append(rel)
            default: continue
            }
        }
    }

    // MARK: Locks

    private struct LockContent: Equatable {
        let createdAt: Int
        let host: String
        let pid: Int32
        var data: Data {
            JSONWriter.serialize(.object([
                "createdAt": num(createdAt), "host": .string(host), "pid": num(Int(pid)),
            ]))
        }
    }

    public func lock(_ name: String, timeout: TimeInterval) throws -> any ACEStoreLock {
        try validateStoreKey(name)
        let mutexKey = root + "\u{0}" + name
        let deadline = Date(timeIntervalSinceNow: max(0, timeout))
        guard Self.processMutexes.acquire(mutexKey, timeout: timeout) else { throw lockTimeoutError(name) }
        do {
            let content = try acquireFileLock(name, deadline: deadline)
            let lockKey = "locks/\(name).lock"
            return makeStoreLock {
                if let current = (try? self.read(lockKey)) ?? nil, current == content.data {
                    unlink(self.root + "/" + lockKey)
                }
                Self.processMutexes.release(mutexKey)
            }
        } catch {
            Self.processMutexes.release(mutexKey)
            throw error
        }
    }

    private func acquireFileLock(_ name: String, deadline: Date) throws -> LockContent {
        let dir = root + "/locks"
        try makeDirectories(dir)
        let lockPath = dir + "/" + name + ".lock"
        let content = LockContent(createdAt: systemClock(), host: Self.hostname(), pid: getpid())
        while true {
            let fd = open(lockPath, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
            if fd >= 0 {
                defer { close(fd) }
                do {
                    try writeAll(fd, content.data, key: "locks/\(name).lock")
                    guard fsync(fd) == 0 else { throw posixError("fsync", "locks/\(name).lock") }
                } catch {
                    unlink(lockPath)
                    throw error
                }
                return content
            }
            guard errno == EEXIST else { throw posixError("create", "locks/\(name).lock") }
            if isStale("locks/\(name).lock") {
                unlink(lockPath)
                continue
            }
            if Date() >= deadline { throw lockTimeoutError(name) }
            usleep(50_000)
        }
    }

    private func isStale(_ lockKey: String) -> Bool {
        var st = stat()
        guard lstat(root + "/" + lockKey, &st) == 0 else { return false }
        let raw = ((try? read(lockKey)) ?? nil) ?? Data()
        if let v = try? JSONParser.parse(raw), let host = v["host"]?.stringValue,
           let pidValue = v["pid"]?.wireInt, v["createdAt"]?.wireInt != nil {
            guard host == Self.hostname(), pidValue <= Int(Int32.max) else { return false }
            return kill(Int32(pidValue), 0) != 0 && errno == ESRCH
        }
        let age = systemClock() - Int(st.st_mtimespec.tv_sec)
        return age > 60
    }

    private static func hostname() -> String {
        var buf = [CChar](repeating: 0, count: 256)
        guard gethostname(&buf, buf.count) == 0 else { return "unknown" }
        return String(decoding: buf.prefix(while: { $0 != 0 }).map { UInt8(bitPattern: $0) }, as: UTF8.self)
    }

    // MARK: Helpers

    private func makeDirectories(_ dir: String) throws {
        guard dir.hasPrefix(root) else { throw ACEError(.storageFailed, "path escapes the store root") }
        var current = root
        let rest = dir.dropFirst(root.count).split(separator: "/")
        for part in rest {
            current += "/" + part
            if mkdir(current, 0o700) != 0 {
                guard errno == EEXIST else { throw posixError("mkdir", String(part)) }
                var st = stat()
                guard lstat(current, &st) == 0, (st.st_mode & S_IFMT) == S_IFDIR else {
                    throw ACEError(.storageFailed, "\(part) is not a directory")
                }
            }
        }
    }

    private func writeAll(_ fd: Int32, _ data: Data, key: String) throws {
        try data.withUnsafeBytes { (raw: UnsafeRawBufferPointer) in
            var offset = 0
            while offset < raw.count {
                let n = Darwin.write(fd, raw.baseAddress! + offset, raw.count - offset)
                if n < 0 {
                    if errno == EINTR { continue }
                    throw posixError("write", key)
                }
                offset += n
            }
        }
    }

    private func fsyncDirectory(_ dir: String) throws {
        let fd = open(dir, O_RDONLY | O_CLOEXEC)
        guard fd >= 0 else { throw posixError("open", dir) }
        defer { close(fd) }
        guard fsync(fd) == 0 else { throw posixError("fsync", dir) }
    }

    private func randomHex(_ bytes: Int) -> String {
        var rng = SystemRandomNumberGenerator()
        return hexEncode((0..<bytes).map { _ in UInt8.random(in: .min ... .max, using: &rng) })
    }
}
