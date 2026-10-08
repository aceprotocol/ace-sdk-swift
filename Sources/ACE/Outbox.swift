//
//  Outbox.swift
//  ACE SDK
//
//  Sender durability (06-security "Durable Delivery", Sender).
//

import Foundation

/// Stage signed envelopes durably before sending them.
///
/// - `stage` signs the message and persists it with its resulting thread state in one
///   write (economic: in the thread record; otherwise `outbox/<sha256(requestId)>.json`).
///   Staging an existing `requestId` returns the pending send unchanged.
/// - `deliver(_:transport:)` calls the transport (e.g. `relay.send` or
///   `deliverDirectOrRelay`); success records a principal `request` in `requests/` (lock
///   `requests`; a write failure leaves the send pending) and then clears the pending send, `envelope_expired` marks it
///   `expired`, any other error leaves it unchanged. An `expired` send is refused with
///   `envelope_expired` before any transport call. A pending send is never abandoned
///   automatically.
/// - `resign` re-signs an `expired` send with the same `messageId` and a fresh timestamp.
///   The ciphertext is kept (the plaintext is not stored; the AEAD binds only the
///   conversation ID) and the thread head entry is rebuilt with the new timestamp.
/// - `abandon` drops a pending send (economic: and its thread head entry); unknown IDs are a no-op.
public actor Outbox {
    private let identity: any ACEIdentity
    private let store: any ACEStore
    private let clock: @Sendable () -> Int
    private let threads: ThreadStore
    /// Thread of each economic pending send staged or found by this instance. Only a hint:
    /// `find` checks the record and falls back to scanning every thread.
    private var threadHints: [String: (conversationId: String, threadId: String)] = [:]

    /// Open the outbox. Under lock `threads`, thread records are repaired from `deliveries/`
    /// records whose snapshot strictly extends the stored history (divergence is
    /// `storage_failed`); records already `acked` and covered by the replay horizon are
    /// skipped (their threads may have been pruned). Nothing is handed over and replay state
    /// is not written.
    public static func open(identity: any ACEIdentity, store: any ACEStore,
                            clock: @escaping @Sendable () -> Int = systemClock) async throws -> Outbox {
        let clock = wireClock(clock)
        let threads = try ThreadStore(store: store, localAceId: identity.getACEId(), clock: clock)
        var replay: ReplayDetector?
        if let raw = try store.checkedRead("replay.json") {
            do {
                let state = try ReplayState(json: raw)
                // Capacity never below the stored entry count, so loading cannot raise the horizon.
                replay = try ReplayDetector(state: state, capacity: max(ACELimits.defaultReplayCapacity, state.entries.count), clock: clock)
            } catch let e as ACEError {
                throw ACEError(.storageFailed, "replay.json is invalid: \(e.message)")
            }
        }
        try store.withLock("threads") {
            for (key, rec) in try threads.deliveryRecords() {
                if rec.status == .acked, replay?.covers(sender: rec.message.from, timestamp: rec.message.timestamp) == true {
                    continue
                }
                if let snap = rec.thread { try threads.repair(from: snap, recordKey: key) }
            }
        }
        return Outbox(identity: identity, store: store, clock: clock, threads: threads)
    }

    private init(identity: any ACEIdentity, store: any ACEStore, clock: @escaping @Sendable () -> Int, threads: ThreadStore) {
        self.identity = identity
        self.store = store
        self.clock = clock
        self.threads = threads
    }

    private static func outboxKey(_ requestId: String) -> String {
        "outbox/" + sha256Hex(Data(requestId.utf8)) + ".json"
    }

    private static func checkRequestId(_ id: String) throws -> String {
        let n = id.unicodeScalars.count
        guard n >= 1, n <= 256, !hasControlCharacter(id) else {
            throw ACEError(.invalidArgument, "requestId must be 1-256 characters without control characters")
        }
        return id
    }

    /// Caller holds the `threads` lock.
    private func find(_ requestId: String) throws -> (PendingSend, StoredThread?)? {
        let key = Self.outboxKey(requestId)
        if let v = try store.readJSON(key) {
            let p = try PendingSend.parse(v, key: key, versioned: true)
            guard p.requestId == requestId else { throw storageError(key, "outbox record does not match its requestId") }
            return (p, nil)
        }
        if let hint = threadHints[requestId],
           let rec = try threads.load(conversationId: hint.conversationId, threadId: hint.threadId),
           let p = rec.pending, p.requestId == requestId {
            return (p, rec)
        }
        threadHints[requestId] = nil
        for rec in try threads.records() {
            if let p = rec.pending, p.requestId == requestId {
                threadHints[requestId] = (rec.snapshot.conversationId, rec.snapshot.threadId)
                return (p, rec)
            }
        }
        return nil
    }

    private func writeOutbox(_ p: PendingSend) throws {
        try store.checkedWrite(Self.outboxKey(p.requestId), JSONWriter.serialize(p.jvalue(version: true)))
    }

    // MARK: API

    /// Sign and persist an outbound message. `requestId` defaults to a random UUID.
    public func stage(
        recipient: VerifiedPeer,
        type: MessageType,
        body: [String: JSONValue],
        threadId: String? = nil,
        requestId: String? = nil
    ) throws -> PendingSend {
        let rid = try requestId.map(Self.checkRequestId) ?? UUID().uuidString.lowercased()
        let local = identity.getACEId()
        return try store.withLock("threads") {
            // A generated requestId is fresh, so only a caller-supplied one can already exist.
            if requestId != nil, let found = try find(rid) { return found.0 }
            let now = clock()
            if type.isEconomic, let threadId {
                let conversationId = try ACEEncryption.computeConversationId(
                    pubA: identity.getEncryptionPublicKey(), pubB: recipient.encryptionPublicKey)
                let (rec, machine) = try threads.loadWithMachine(conversationId: conversationId, threadId: threadId)
                if rec?.pending != nil {
                    throw ACEError(.pendingSendConflict, "the thread already has a pending send")
                }
                // Only a message that opens a thread counts against the peer's open threads.
                if rec == nil, machine.allowedTypes(conversationId: conversationId, threadId: threadId, senderAceId: local).contains(type) {
                    try threads.checkCanOpenThread(peer: recipient.aceId)
                }
                let env = try createMessage(sender: identity, recipient: recipient, type: type, body: body,
                                            threads: machine, threadId: threadId, timestamp: now)
                let pending = PendingSend(requestId: rid, status: .pending, stagedAt: now, message: env)
                guard let snap = machine.getSnapshot(conversationId: conversationId, threadId: threadId) else {
                    throw ACEError(.storageFailed, "thread snapshot missing after createMessage")
                }
                try threads.write(StoredThread(snapshot: snap, pending: pending))
                threadHints[rid] = (conversationId, threadId)
                return pending
            }
            let env = try createMessage(sender: identity, recipient: recipient, type: type, body: body,
                                        threads: try ThreadStateMachine(localAceId: local), threadId: threadId, timestamp: now)
            let pending = PendingSend(requestId: rid, status: .pending, stagedAt: now, message: env,
                                      requestTtl: type == .request ? body["ttl"]?.wireInt : nil)
            try writeOutbox(pending)
            return pending
        }
    }

    /// Hand the staged envelope to `transport` (e.g. `{ try await relay.send($0) }` or
    /// `deliverDirectOrRelay(relay:endpoint:)`) and return its result. Unknown `requestId`
    /// is `invalid_argument`; an `expired` send is `envelope_expired` (re-sign it first).
    @discardableResult
    public func deliver<T: Sendable>(_ requestId: String, transport: @Sendable (ACEMessage) async throws -> T) async throws -> T {
        let rid = try Self.checkRequestId(requestId)
        guard let found = try store.withLock("threads", { try find(rid) }) else {
            throw ACEError(.invalidArgument, "no pending send with this requestId")
        }
        guard found.0.status != .expired else {
            throw ACEError(.envelopeExpired, "the pending send expired; resign it first")
        }
        let message = found.0.message
        let result: T
        do {
            result = try await transport(message)
        } catch let e as ACEError where e.code == .envelopeExpired {
            try update(rid, messageId: message.messageId) { $0.with(status: .expired) }
            throw e
        }
        if message.type == .request {
            // 06 § Durable Delivery, Sender: recorded before the pending send is cleared; a failure
            // here leaves it pending and the retry writes it.
            try store.withLock("requests") {
                try recordRequest(store, message: message, sentAt: clock(), ttl: found.0.requestTtl)
            }
        }
        try update(rid, messageId: message.messageId) { _ in nil }
        return result
    }

    /// Replace the pending send (nil clears it).
    private func update(_ rid: String, messageId: String, _ change: (PendingSend) -> PendingSend?) throws {
        try store.withLock("threads") {
            guard let (p, rec) = try find(rid), p.message.messageId == messageId else { return }
            let new = change(p)
            if new == nil { threadHints[rid] = nil }
            if let rec {
                try threads.write(StoredThread(snapshot: rec.snapshot, pending: new))
            } else if let new {
                try writeOutbox(new)
            } else {
                try store.checkedDelete(Self.outboxKey(rid))
            }
        }
    }

    /// Re-sign an `expired` pending send (same `messageId`, `timestamp = now`).
    @discardableResult
    public func resign(_ requestId: String) throws -> PendingSend {
        let rid = try Self.checkRequestId(requestId)
        return try store.withLock("threads") {
            guard let (p, rec) = try find(rid) else { throw ACEError(.invalidArgument, "no pending send with this requestId") }
            guard p.status == .expired else { throw ACEError(.invalidArgument, "only an expired pending send can be re-signed") }
            let now = clock()
            let env = try ACE.resign(p.message, sender: identity, timestamp: now)
            let new = p.with(status: .pending, message: env)
            guard let rec else {
                try writeOutbox(new)
                return new
            }
            var history = rec.snapshot.history
            guard let head = history.last, head.messageId == p.message.messageId else {
                throw ACEError(.storageFailed, "the pending send is not the thread head")
            }
            history[history.count - 1] = ThreadHistoryEntry(type: head.type, messageId: head.messageId, timestamp: now, from: head.from)
            guard let snap = try threads.rebuild(rec.snapshot, history: history) else {
                throw ACEError(.storageFailed, "empty thread history")
            }
            try threads.write(StoredThread(snapshot: snap, pending: new))
            return new
        }
    }

    /// Drop a pending send; an unknown `requestId` is a no-op.
    public func abandon(_ requestId: String) throws {
        let rid = try Self.checkRequestId(requestId)
        try store.withLock("threads") {
            guard let (p, rec) = try find(rid) else { return }
            threadHints[rid] = nil
            guard let rec else {
                try store.checkedDelete(Self.outboxKey(rid))
                return
            }
            var history = rec.snapshot.history
            if history.last?.messageId == p.message.messageId { history.removeLast() }
            if let snap = try threads.rebuild(rec.snapshot, history: history) {
                try threads.write(StoredThread(snapshot: snap, pending: nil))
            } else {
                try threads.delete(conversationId: rec.snapshot.conversationId, threadId: rec.snapshot.threadId)
            }
        }
    }

    /// Every pending send, sorted by (stagedAt, requestId).
    public func pending() throws -> [PendingSend] {
        var out = try threads.records().compactMap(\.pending)
        for key in try store.checkedList("outbox/") {
            if let v = try store.readJSON(key) { out.append(try PendingSend.parse(v, key: key, versioned: true)) }
        }
        return out.sorted { ($0.stagedAt, $0.requestId) < ($1.stagedAt, $1.requestId) }
    }
}
