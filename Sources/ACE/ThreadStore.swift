//
//  ThreadStore.swift
//  ACE SDK
//
//  Persistent thread records shared by Inbox and Outbox (lock `threads`).
//

import Foundation

struct StoredThread {
    var snapshot: ThreadSnapshot
    var pending: PendingSend?
}

/// Persistent economic thread state. Every load replays the history through
/// `ThreadStateMachine`; a record that fails to replay is `storage_failed` and is never
/// reset. Terminal threads without a pending send are deleted 30 days after their last entry.
public final class ThreadStore: Sendable {
    /// 30 days (04 retention, > OFFLINE_WINDOW_SECONDS).
    static let retentionSeconds = 2_592_000
    /// Minimum interval between retention sweeps.
    static let pruneIntervalSeconds = 3600

    public let localAceId: String
    private let store: any ACEStore
    private let clock: @Sendable () -> Int
    private let pruneState = PruneState()

    private final class PruneState: @unchecked Sendable {
        let lock = NSLock()
        var last: Int?
    }

    public init(store: any ACEStore, localAceId: String, clock: @escaping @Sendable () -> Int = systemClock) throws {
        guard isACEId(localAceId) else { throw ACEError(.invalidArgument, "localAceId must be an ACE ID") }
        self.store = store
        self.localAceId = localAceId
        self.clock = clock
    }

    static func key(conversationId: String, threadId: String) -> String {
        "threads/" + sha256Hex(conversationId, threadId) + ".json"
    }

    // MARK: Public

    public func get(conversationId: String, threadId: String) throws -> ThreadSnapshot? {
        try load(conversationId: conversationId, threadId: threadId)?.snapshot
    }

    /// Every stored thread, sorted by (conversationId, threadId).
    public func list() throws -> [ThreadSnapshot] {
        try store.checkedList("threads/").compactMap { try load(key: $0)?.snapshot }
            .sorted { ($0.conversationId, $0.threadId) < ($1.conversationId, $1.threadId) }
    }

    public func remove(conversationId: String, threadId: String) throws {
        try store.withLock("threads") {
            try store.checkedDelete(Self.key(conversationId: conversationId, threadId: threadId))
        }
    }

    /// Economic types `senderAceId` may send next (`[.rfq]` for an unknown thread).
    public func allowedTypes(conversationId: String, threadId: String, senderAceId: String) throws -> [MessageType] {
        try machine(for: load(conversationId: conversationId, threadId: threadId))
            .allowedTypes(conversationId: conversationId, threadId: threadId, senderAceId: senderAceId)
    }

    // MARK: Internal

    func load(conversationId: String, threadId: String) throws -> StoredThread? {
        let key = Self.key(conversationId: conversationId, threadId: threadId)
        guard let record = try load(key: key) else { return nil }
        guard record.snapshot.conversationId == conversationId, record.snapshot.threadId == threadId else {
            throw storageError(key, "thread record does not match its key")
        }
        return record
    }

    func load(key: String) throws -> StoredThread? {
        guard let v = try store.readJSON(key) else { return nil }
        guard let o = v.objectValue else { throw storageError(key, "thread record must be an object") }
        try checkVersion(o, key)
        let snapshot = try ThreadSnapshot.parse(v, key: key)
        guard snapshot.localAceId == localAceId else { throw storageError(key, "thread record belongs to another identity") }
        do {
            _ = try ThreadStateMachine(state: [snapshot], localAceId: localAceId)
        } catch let e as ACEError {
            throw storageError(key, "thread history does not replay: \(e.message)")
        }
        var pending: PendingSend?
        if let p = o["pending"], !p.isNull { pending = try PendingSend.parse(p, key: key, versioned: false) }
        return StoredThread(snapshot: snapshot, pending: pending)
    }

    /// A machine restored from `record` (empty when nil).
    func machine(for record: StoredThread?) throws -> ThreadStateMachine {
        do {
            return try ThreadStateMachine(state: record.map { [$0.snapshot] } ?? [], localAceId: localAceId)
        } catch let e as ACEError {
            throw ACEError(.storageFailed, "thread history does not replay: \(e.message)")
        }
    }

    func write(_ record: StoredThread) throws {
        var fields = record.snapshot.jfields()
        fields["pending"] = record.pending?.jvalue(version: false) ?? .null
        fields["version"] = .number("1")
        let key = Self.key(conversationId: record.snapshot.conversationId, threadId: record.snapshot.threadId)
        try store.checkedWrite(key, JSONWriter.serialize(.object(fields)))
        try pruneIfDue(except: key)
    }

    /// Re-derive the state of `history` (no reference checks: bodies are not stored).
    /// Nil for an empty history; an invalid history is `storage_failed`.
    func rebuild(_ base: ThreadSnapshot, history: [ThreadHistoryEntry]) throws -> ThreadSnapshot? {
        guard !history.isEmpty else { return nil }
        let sm = try machine(for: nil)
        do {
            for h in history {
                let to = h.from == localAceId ? base.peerAceId : localAceId
                try sm.applyWithoutReferences(ThreadEvent(conversationId: base.conversationId, threadId: base.threadId, type: h.type,
                                                          messageId: h.messageId, timestamp: h.timestamp, from: h.from, to: to))
            }
        } catch let e as ACEError {
            throw ACEError(.storageFailed, "thread history does not replay: \(e.message)")
        }
        return sm.getSnapshot(conversationId: base.conversationId, threadId: base.threadId)
    }

    func delete(conversationId: String, threadId: String) throws {
        try store.checkedDelete(Self.key(conversationId: conversationId, threadId: threadId))
    }

    func records() throws -> [StoredThread] {
        try store.checkedList("threads/").compactMap { try load(key: $0) }
    }

    /// The stored pending send, or nil when `snap` proves its delivery (it is followed by
    /// an entry from the peer).
    static func clearProvenPending(_ rec: StoredThread?, _ snap: ThreadSnapshot) -> PendingSend? {
        guard let rec, let pending = rec.pending else { return nil }
        guard let idx = snap.history.firstIndex(where: { $0.messageId == pending.message.messageId }) else { return pending }
        return snap.history[(idx + 1)...].contains { $0.from != snap.localAceId } ? nil : pending
    }

    /// Write `snap` (from a delivery record) if it strictly extends the stored history;
    /// a diverging history is `storage_failed`. Caller holds `threads`.
    func repair(from snap: ThreadSnapshot, recordKey: String) throws {
        let stored = try load(conversationId: snap.conversationId, threadId: snap.threadId)
        let old = stored?.snapshot.history ?? []
        let new = snap.history
        if new.count > old.count && Array(new.prefix(old.count)) == old {
            try write(StoredThread(snapshot: snap, pending: Self.clearProvenPending(stored, snap)))
        } else if Array(old.prefix(new.count)) != new {
            throw storageError(recordKey, "thread history diverges from the delivery record")
        }
    }

    /// Delivery records (`deliveries/`) sorted by (timestamp, key).
    func deliveryRecords() throws -> [(key: String, record: DeliveryRecord)] {
        var out: [(key: String, record: DeliveryRecord)] = []
        for key in try store.checkedList("deliveries/") {
            guard let v = try store.readJSON(key) else { continue }
            let rec = try DeliveryRecord.parse(v, key: key)
            guard key == DeliveryRecord.key(from: rec.message.from, messageId: rec.message.messageId) else {
                throw storageError(key, "delivery record does not match its key")
            }
            if let t = rec.thread, t.localAceId != localAceId { throw storageError(key, "delivery thread belongs to another identity") }
            out.append((key, rec))
        }
        return out.sorted { ($0.record.message.timestamp, $0.key) < ($1.record.message.timestamp, $1.key) }
    }

    /// Pending sends held in thread records.
    func pendingSends() throws -> [PendingSend] {
        try store.checkedList("threads/").compactMap { try load(key: $0)?.pending }
    }

    private func pruneIfDue(except current: String) throws {
        let now = clock()
        pruneState.lock.lock()
        let due = pruneState.last.map { now - $0 >= Self.pruneIntervalSeconds } ?? true
        if due { pruneState.last = now }
        pruneState.lock.unlock()
        guard due else { return }
        for key in try store.checkedList("threads/") where key != current {
            guard let record = try? load(key: key) else { continue }
            guard record.pending == nil, record.snapshot.state.isTerminal,
                  let last = record.snapshot.history.last, last.timestamp < now - Self.retentionSeconds else { continue }
            try store.checkedDelete(key)
        }
    }
}
