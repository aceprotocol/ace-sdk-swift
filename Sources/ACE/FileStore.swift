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
/// - Locks use POSIX flock over permanent files on a local filesystem. The kernel releases
///   them on process exit. Never unlink or replace lock files; network mounts are unsupported.
public final class FileStore: ACEStore, @unchecked Sendable {
    public let directory: URL
    private let root: String
    private static let maxReadBytes = ACELimits.maxStoreValueBytes
    private static let processMutexes = NamedMutexes()

    /// Opens (creating if needed, mode 0700) the store directory.
    public init(directory: URL) throws {
        let path = directory.standardizedFileURL.path
        var parentDirectories: [String] = [], cursor = path, before = stat()
        while lstat(cursor, &before) != 0 && errno == ENOENT {
            cursor = (cursor as NSString).deletingLastPathComponent
            parentDirectories.append(cursor)
        }
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
        for parent in parentDirectories { try fsyncDirectory(parent) }
    }

    private func path(_ key: String) -> String { root + "/" + key }
    private func validateDataKey(_ key: String) throws {
        try validateStoreKey(key)
        guard key != "locks", !key.hasPrefix("locks/") else { throw ACEError(.invalidArgument, "locks/ is reserved by FileStore") }
    }

    private func posixError(_ op: String, _ key: String) -> ACEError {
        ACEError(.storageFailed, "\(op) \(key): \(String(cString: strerror(errno)))")
    }

    // MARK: ACEStore

    public func read(_ key: String) throws -> Data? {
        try validateDataKey(key)
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
        try validateDataKey(key)
        try validateStoreValue(value)
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
        try validateDataKey(key)
        if unlink(path(key)) == 0 {
            try fsyncDirectory((path(key) as NSString).deletingLastPathComponent)
        } else if errno != ENOENT && errno != ENOTDIR {
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

    public func lock(_ name: String, timeout: TimeInterval) throws -> any ACEStoreLock {
        try validateLockName(name)
        let mutexKey = root + "\u{0}" + name
        let deadline = ProcessInfo.processInfo.systemUptime + max(0, timeout)
        guard Self.processMutexes.acquire(mutexKey, timeout: timeout) else { throw lockTimeoutError(name) }
        do {
            let fd = try acquireFileLock(name, deadline: deadline)
            return makeStoreLock {
                close(fd)
                Self.processMutexes.release(mutexKey)
            }
        } catch {
            Self.processMutexes.release(mutexKey)
            throw error
        }
    }

    private func acquireFileLock(_ name: String, deadline: TimeInterval) throws -> Int32 {
        let dir = root + "/locks"
        try makeDirectories(dir)
        let fd = open(dir + "/" + name + ".lock", O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK, 0o600)
        guard fd >= 0 else { throw posixError("open lock", name) }
        do {
            var st = stat()
            guard fstat(fd, &st) == 0, (st.st_mode & S_IFMT) == S_IFREG else { throw ACEError(.storageFailed, "lock is not a regular file") }
            while flock(fd, LOCK_EX | LOCK_NB) != 0 {
                guard errno == EWOULDBLOCK || errno == EAGAIN || errno == EINTR else { throw posixError("flock", name) }
                if ProcessInfo.processInfo.systemUptime >= deadline { throw lockTimeoutError(name) }
                usleep(50_000)
            }
            return fd
        } catch { close(fd); throw error }
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
            } else {
                try fsyncDirectory((current as NSString).deletingLastPathComponent)
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
}
