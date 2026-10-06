//
//  Store.swift
//  ACE SDK
//
//  The key-value store behind the pipeline (PeerStore, ThreadStore, Inbox, Outbox).
//

import Foundation

/// An exclusive lock acquired from an `ACEStore`. Release exactly once.
public protocol ACEStoreLock: Sendable {
    func release()
}

/// Durable key-value storage for pipeline state. Implementations are synchronous.
///
/// - Keys match `^[a-z0-9][a-z0-9._-]*(/[a-z0-9][a-z0-9._-]*)*$` and are ≤ 200 characters.
/// - `write` is an atomic replace, durable when it returns. `delete` of a missing key is fine.
/// - `list(prefix:)` returns the keys with that prefix, sorted ascending.
/// - `lock(_:timeout:)` is exclusive and non-reentrant. The SDK uses the names `receive`,
///   `threads` and `peers`. A timeout is `receiver_busy` for `receive` and
///   `storage_failed` otherwise; every I/O error is `storage_failed`.
public protocol ACEStore: Sendable {
    func read(_ key: String) throws -> Data?
    func write(_ key: String, _ value: Data) throws
    func delete(_ key: String) throws
    func list(prefix: String) throws -> [String]
    func lock(_ name: String, timeout: TimeInterval) throws -> any ACEStoreLock
}

/// Key grammar check (`invalid_argument`).
func validateStoreKey(_ key: String) throws {
    guard isValidStoreKey(key) else { throw ACEError(.invalidArgument, "invalid store key '\(String(key.prefix(64)))'") }
}

func isValidStoreKey(_ key: String) -> Bool {
    let u = Array(key.utf8)
    guard !u.isEmpty, u.count <= 200 else { return false }
    var segmentStart = true
    for b in u {
        let alnum = (b >= 0x61 && b <= 0x7A) || (b >= 0x30 && b <= 0x39)
        if b == UInt8(ascii: "/") {
            if segmentStart { return false }
            segmentStart = true
            continue
        }
        if segmentStart {
            guard alnum else { return false }
            segmentStart = false
        } else {
            guard alnum || b == UInt8(ascii: ".") || b == UInt8(ascii: "_") || b == UInt8(ascii: "-") else { return false }
        }
    }
    return !segmentStart
}

func lockTimeoutError(_ name: String) -> ACEError {
    name == "receive"
        ? ACEError(.receiverBusy, "another receiver holds the '\(name)' lock")
        : ACEError(.storageFailed, "timed out waiting for the '\(name)' lock")
}

/// A process-local mutex per name that can be acquired with a timeout.
final class NamedMutexes: @unchecked Sendable {
    private let cond = NSCondition()
    private var held: Set<String> = []

    func acquire(_ name: String, timeout: TimeInterval) -> Bool {
        let deadline = Date(timeIntervalSinceNow: max(0, timeout))
        cond.lock()
        defer { cond.unlock() }
        while held.contains(name) {
            if timeout <= 0 || !cond.wait(until: deadline) {
                if held.contains(name) { return false }
            }
        }
        held.insert(name)
        return true
    }

    func release(_ name: String) {
        cond.lock()
        held.remove(name)
        cond.broadcast()
        cond.unlock()
    }
}

private final class OnceLock: ACEStoreLock, @unchecked Sendable {
    private let lock = NSLock()
    private var done = false
    private let action: @Sendable () -> Void

    init(_ action: @escaping @Sendable () -> Void) { self.action = action }

    func release() {
        lock.lock()
        let run = !done
        done = true
        lock.unlock()
        if run { action() }
    }
}

func makeStoreLock(_ release: @escaping @Sendable () -> Void) -> any ACEStoreLock { OnceLock(release) }

/// In-memory `ACEStore`: a dictionary plus an in-process mutex per lock name.
public final class MemoryStore: ACEStore, @unchecked Sendable {
    private let lock = NSLock()
    private var data: [String: Data] = [:]
    private let mutexes = NamedMutexes()

    public init() {}

    public func read(_ key: String) throws -> Data? {
        try validateStoreKey(key)
        lock.lock()
        defer { lock.unlock() }
        return data[key]
    }

    public func write(_ key: String, _ value: Data) throws {
        try validateStoreKey(key)
        lock.lock()
        data[key] = value
        lock.unlock()
    }

    public func delete(_ key: String) throws {
        try validateStoreKey(key)
        lock.lock()
        data[key] = nil
        lock.unlock()
    }

    public func list(prefix: String) throws -> [String] {
        lock.lock()
        defer { lock.unlock() }
        return data.keys.filter { $0.hasPrefix(prefix) }.sorted()
    }

    public func lock(_ name: String, timeout: TimeInterval) throws -> any ACEStoreLock {
        try validateStoreKey(name)
        guard mutexes.acquire(name, timeout: timeout) else { throw lockTimeoutError(name) }
        let mutexes = self.mutexes
        return makeStoreLock { mutexes.release(name) }
    }
}

// MARK: - Helpers used by the pipeline

extension ACEStore {
    /// Read and parse a JSON record; `storage_failed` on any error.
    func readJSON(_ key: String) throws -> JValue? {
        let raw: Data?
        do { raw = try read(key) } catch let e as ACEError where e.code == .storageFailed {
            throw e
        } catch {
            throw ACEError(.storageFailed, "read \(key) failed: \(error)")
        }
        guard let raw else { return nil }
        do { return try JSONParser.parse(raw) } catch {
            throw ACEError(.storageFailed, "\(key) is not valid JSON")
        }
    }

    func checkedWrite(_ key: String, _ value: Data) throws {
        do { try write(key, value) } catch let e as ACEError where e.code == .storageFailed {
            throw e
        } catch {
            throw ACEError(.storageFailed, "write \(key) failed: \(error)")
        }
    }

    func checkedDelete(_ key: String) throws {
        do { try delete(key) } catch let e as ACEError where e.code == .storageFailed {
            throw e
        } catch {
            throw ACEError(.storageFailed, "delete \(key) failed: \(error)")
        }
    }

    func checkedList(_ prefix: String) throws -> [String] {
        do { return try list(prefix: prefix) } catch let e as ACEError where e.code == .storageFailed {
            throw e
        } catch {
            throw ACEError(.storageFailed, "list \(prefix) failed: \(error)")
        }
    }

    func checkedLock(_ name: String, timeout: TimeInterval) throws -> any ACEStoreLock {
        do { return try lock(name, timeout: timeout) } catch let e as ACEError where e.code == .storageFailed || e.code == .receiverBusy {
            throw e
        } catch {
            throw ACEError(.storageFailed, "lock \(name) failed: \(error)")
        }
    }

    /// Run `body` holding lock `name`.
    func withLock<T>(_ name: String, timeout: TimeInterval = 10, _ body: () throws -> T) throws -> T {
        let l = try checkedLock(name, timeout: timeout)
        defer { l.release() }
        return try body()
    }
}
