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
/// reset.
///
/// Retention (at most hourly): terminal threads without a pending send, and non-terminal
/// threads with no entry from `localAceId`, are deleted 30 days after their last entry.
///
/// A per-peer index of non-terminal threads (`threads/index/<sha256hex(peerAceId)>.json`,
/// `{"open":["threads/<64 hex>"…sorted],"version":1}`, record keys without `.json`) bounds how many threads one peer
/// can hold open: `ACELimits.maxOpenThreadsPerPeer`.
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
        self.clock = wireClock(clock)
    }

    static func key(conversationId: String, threadId: String) -> String {
        "threads/" + sha256Hex(conversationId, threadId) + ".json"
    }

    static func indexKey(peerAceId: String) -> String {
        "threads/index/" + sha256Hex(Data(peerAceId.utf8)) + ".json"
    }

    /// Thread record keys (`threads/<hex>.json`), excluding the peer index.
    private func recordKeys() throws -> [String] {
        try store.checkedList("threads/").filter { !$0.dropFirst("threads/".count).contains("/") }
    }

    // MARK: Public

    public func get(conversationId: String, threadId: String) throws -> ThreadSnapshot? {
        try load(conversationId: conversationId, threadId: threadId)?.snapshot
    }

    /// Every stored thread, sorted by (conversationId, threadId).
    public func list() throws -> [ThreadSnapshot] {
        try recordKeys().compactMap { try load(key: $0)?.snapshot }
            .sorted { ($0.conversationId, $0.threadId) < ($1.conversationId, $1.threadId) }
    }

    public func remove(conversationId: String, threadId: String) throws {
        try store.withLock("threads") { try delete(conversationId: conversationId, threadId: threadId) }
    }

    /// Economic types `senderAceId` may send next (`[.rfq]` for an unknown thread).
    public func allowedTypes(conversationId: String, threadId: String, senderAceId: String) throws -> [MessageType] {
        try loadWithMachine(conversationId: conversationId, threadId: threadId).machine
            .allowedTypes(conversationId: conversationId, threadId: threadId, senderAceId: senderAceId)
    }

    // MARK: Internal

    func load(conversationId: String, threadId: String) throws -> StoredThread? {
        try loadWithMachine(conversationId: conversationId, threadId: threadId).record
    }

    /// The stored record and a machine restored from it (empty when there is none).
    func loadWithMachine(conversationId: String, threadId: String) throws -> (record: StoredThread?, machine: ThreadStateMachine) {
        let key = Self.key(conversationId: conversationId, threadId: threadId)
        guard let (record, machine) = try loadReplayed(key: key) else {
            return (nil, try ThreadStateMachine(localAceId: localAceId))
        }
        guard record.snapshot.conversationId == conversationId, record.snapshot.threadId == threadId else {
            throw storageError(key, "thread record does not match its key")
        }
        return (record, machine)
    }

    func load(key: String) throws -> StoredThread? {
        try loadReplayed(key: key)?.0
    }

    private func loadReplayed(key: String) throws -> (StoredThread, ThreadStateMachine)? {
        guard let v = try store.readJSON(key) else { return nil }
        guard let o = v.objectValue else { throw storageError(key, "thread record must be an object") }
        try checkVersion(o, key)
        let snapshot = try ThreadSnapshot.parse(v, key: key)
        guard snapshot.localAceId == localAceId else { throw storageError(key, "thread record belongs to another identity") }
        let machine: ThreadStateMachine
        do {
            machine = try ThreadStateMachine(state: [snapshot], localAceId: localAceId)
        } catch let e as ACEError {
            throw storageError(key, "thread history does not replay: \(e.message)")
        }
        var pending: PendingSend?
        if let p = o["pending"], !p.isNull { pending = try PendingSend.parse(p, key: key, versioned: false) }
        return (StoredThread(snapshot: snapshot, pending: pending), machine)
    }

    func write(_ record: StoredThread) throws {
        var fields = record.snapshot.jfields()
        fields["pending"] = record.pending?.jvalue(version: false) ?? .null
        fields["version"] = num(1)
        let key = Self.key(conversationId: record.snapshot.conversationId, threadId: record.snapshot.threadId)
        let open = !record.snapshot.state.isTerminal
        // Crash-safe order: index an open thread before its record exists; unindex a
        // terminal one only after its record says so. A stale entry is reconciled at the bound.
        if open { try updateIndex(peer: record.snapshot.peerAceId, key: key, open: true) }
        try store.checkedWrite(key, JSONWriter.serialize(.object(fields)))
        if !open { try updateIndex(peer: record.snapshot.peerAceId, key: key, open: false) }
        try pruneIfDue(except: key)
    }

    // MARK: Per-peer open-thread index (caller holds `threads`)

    private func readIndex(_ peer: String) throws -> Set<String> {
        let key = Self.indexKey(peerAceId: peer)
        guard let v = try store.readJSON(key) else { return [] }
        guard let o = v.objectValue, let open = o["open"]?.arrayValue else { throw storageError(key, "malformed thread index") }
        try checkVersion(o, key)
        var out = Set<String>()
        for e in open {
            guard let s = e.stringValue else { throw storageError(key, "malformed thread index") }
            out.insert(s)
        }
        return out
    }

    private func writeIndex(_ peer: String, _ open: Set<String>) throws {
        let key = Self.indexKey(peerAceId: peer)
        if open.isEmpty { try store.checkedDelete(key); return }
        try store.checkedWrite(key, JSONWriter.serialize(.object([
            "open": .array(open.sorted().map { .string($0) }), "version": num(1),
        ])))
    }

    /// Index entry of a record key: the key without `.json` (`threads/<64 hex>`).
    private static func indexEntry(_ key: String) -> String { String(key.dropLast(".json".count)) }

    private func updateIndex(peer: String, key: String, open: Bool) throws {
        var index = try readIndex(peer)
        let entry = Self.indexEntry(key)
        let changed = open ? index.insert(entry).inserted : index.remove(entry) != nil
        if changed { try writeIndex(peer, index) }
    }

    /// `limit_exceeded` when `peer` already holds `ACELimits.maxOpenThreadsPerPeer`
    /// non-terminal threads. A full index is re-verified against the records first, so a
    /// stale entry (crash between record and index writes) never blocks a peer.
    func checkCanOpenThread(peer: String) throws {
        var index = try readIndex(peer)
        guard index.count >= ACELimits.maxOpenThreadsPerPeer else { return }
        let verified = try index.filter { entry in
            guard let rec = try load(key: entry + ".json") else { return false }
            return rec.snapshot.peerAceId == peer && !rec.snapshot.state.isTerminal
        }
        if verified != index {
            index = verified
            try writeIndex(peer, index)
        }
        guard index.count >= ACELimits.maxOpenThreadsPerPeer else { return }
        throw ACEError(.limitExceeded, "peer has \(ACELimits.maxOpenThreadsPerPeer) open threads")
    }

    /// Re-derive the state of `history` (no reference checks: bodies are not stored).
    /// Nil for an empty history; an invalid history is `storage_failed`.
    func rebuild(_ base: ThreadSnapshot, history: [ThreadHistoryEntry]) throws -> ThreadSnapshot? {
        guard !history.isEmpty else { return nil }
        let sm = try ThreadStateMachine(localAceId: localAceId)
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
        let key = Self.key(conversationId: conversationId, threadId: threadId)
        let existing: StoredThread? = try? load(key: key)
        let peer = existing?.snapshot.peerAceId
        try store.checkedDelete(key)
        if let peer { try updateIndex(peer: peer, key: key, open: false) }
    }

    func records() throws -> [StoredThread] {
        try recordKeys().compactMap { try load(key: $0) }
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
        try store.checkedList("deliveries/").compactMap { key in try loadDelivery(key).map { (key, $0) } }
            .sorted { ($0.record.message.timestamp, $0.key) < ($1.record.message.timestamp, $1.key) }
    }

    /// The delivery record at `key`, checked against its key and the local identity.
    func loadDelivery(_ key: String) throws -> DeliveryRecord? {
        guard let v = try store.readJSON(key) else { return nil }
        let rec = try DeliveryRecord.parse(v, key: key)
        guard key == DeliveryRecord.key(from: rec.message.from, messageId: rec.message.messageId) else {
            throw storageError(key, "delivery record does not match its key")
        }
        if let t = rec.thread, t.localAceId != localAceId { throw storageError(key, "delivery thread belongs to another identity") }
        return rec
    }

    private func pruneIfDue(except current: String) throws {
        let now = clock()
        pruneState.lock.lock()
        let due = pruneState.last.map { now - $0 >= Self.pruneIntervalSeconds } ?? true
        if due { pruneState.last = now }
        pruneState.lock.unlock()
        guard due else { return }
        for key in try recordKeys() where key != current {
            guard let record = try? load(key: key), record.pending == nil,
                  let last = record.snapshot.history.last, last.timestamp < now - Self.retentionSeconds else { continue }
            let snap = record.snapshot
            guard snap.state.isTerminal || !snap.history.contains(where: { $0.from == localAceId }) else { continue }
            try store.checkedDelete(key)
            if !snap.state.isTerminal { try updateIndex(peer: snap.peerAceId, key: key, open: false) }
        }
    }
}
