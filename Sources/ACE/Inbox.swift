//
//  Inbox.swift
//  ACE SDK
//
//  Receive engine (06-security "Durable Delivery", Receiver).
//

import Foundation

/// Where an envelope came from.
public enum ReceiveSource: Sendable, Equatable {
    /// Fetched from a relay. `streamId` advances the durable cursor for `url`.
    case relay(url: String, streamId: String?)
    /// Delivered directly (unauthenticated until verified; rejections are not persisted).
    case direct
}

/// The result of `Inbox.receive`.
public enum ReceiveOutcome: Sendable {
    /// Verified, committed and handed to `onMessage`.
    case delivered(ParsedMessage)
    /// Already delivered (or a replay); nothing was written.
    case duplicate(from: String, messageId: String)
    /// Permanently rejected. `fingerprint` is nil when the envelope did not decode.
    case quarantined(ACEError, fingerprint: String?)
    /// A transient or local failure; retry later. The relay cursor did not advance.
    case retryable(ACEError)

    public var error: ACEError? {
        switch self {
        case .quarantined(let e, _), .retryable(let e): return e
        default: return nil
        }
    }
}

/// Totals of `Inbox.pull`. `blocked` is the error that stopped it, if any.
public struct PullResult: Sendable {
    public let delivered: Int
    public let duplicates: Int
    public let quarantined: Int
    public let blocked: ACEError?
}

/// Durable, exactly-once-to-the-host receive engine.
///
/// `onMessage` must persist the host effect durably and idempotently, keyed by
/// `(from, messageId)`, then return; throwing means "retry later". Commit order per message:
/// delivery record, thread state, replay state, `onMessage`, ack, cursor. The instance holds
/// the store's `receive` lock until `close()`.
public actor Inbox {
    public typealias MessageHandler = @Sendable (ParsedMessage) async throws -> Void

    static let quarantineCap = 1000
    static let quarantineKeep = 900
    static let sweepEvery = 1024

    nonisolated let identity: any ACEIdentity
    private let localAceId: String
    private let store: any ACEStore
    private let peers: PeerStore
    private let onMessage: MessageHandler
    private let offlineWindow: Int
    private let clock: @Sendable () -> Int
    private let threads: ThreadStore
    private let receiveLock: any ACEStoreLock
    private var replay: ReplayDetector
    private var cursors: [String: String]
    private var failed = false
    private var closed = false
    private var deliveredSinceSweep = 0
    private var heldThreadsLock: (any ACEStoreLock)?

    /// Open the inbox: take the `receive` lock (`receiver_busy` if held), load or create
    /// `replay.json`, load cursors and run recovery from delivery records.
    public static func open(
        identity: any ACEIdentity,
        store: any ACEStore,
        peers: PeerStore,
        onMessage: @escaping MessageHandler,
        capacity: Int = ACELimits.defaultReplayCapacity,
        offlineWindowSeconds: Int = ACELimits.offlineWindowSeconds,
        clock: @escaping @Sendable () -> Int = systemClock
    ) async throws -> Inbox {
        guard offlineWindowSeconds >= ACELimits.timestampWindowSeconds else {
            throw ACEError(.invalidArgument, "offlineWindowSeconds must be >= \(ACELimits.timestampWindowSeconds)")
        }
        guard capacity >= 1 else { throw ACEError(.invalidArgument, "capacity must be an integer >= 1") }
        let threads = try ThreadStore(store: store, localAceId: identity.getACEId(), clock: clock)
        let lock = try store.checkedLock("receive", timeout: 0)
        let inbox: Inbox
        do {
            let replay = try loadReplay(store: store, threads: threads, local: identity.getACEId(), capacity: capacity,
                                        offlineWindow: offlineWindowSeconds, clock: clock)
            let cursors = try loadCursors(store)
            inbox = Inbox(identity: identity, store: store, peers: peers, onMessage: onMessage, offlineWindow: offlineWindowSeconds,
                          clock: clock, threads: threads, lock: lock, replay: replay, cursors: cursors)
        } catch {
            lock.release()
            throw error
        }
        do {
            try await inbox.recover()
        } catch {
            await inbox.close()
            throw error
        }
        return inbox
    }

    private init(identity: any ACEIdentity, store: any ACEStore, peers: PeerStore, onMessage: @escaping MessageHandler,
                 offlineWindow: Int, clock: @escaping @Sendable () -> Int, threads: ThreadStore, lock: any ACEStoreLock,
                 replay: ReplayDetector, cursors: [String: String]) {
        self.identity = identity
        self.localAceId = identity.getACEId()
        self.store = store
        self.peers = peers
        self.onMessage = onMessage
        self.offlineWindow = offlineWindow
        self.clock = clock
        self.threads = threads
        self.receiveLock = lock
        self.replay = replay
        self.cursors = cursors
    }

    deinit {
        heldThreadsLock?.release()
        if !closed { receiveLock.release() }
    }

    /// Release the `receive` lock. Idempotent.
    public func close() {
        guard !closed else { return }
        closed = true
        heldThreadsLock?.release()
        heldThreadsLock = nil
        receiveLock.release()
    }

    /// The durable cursor for a relay URL (normalized), or nil.
    public func cursor(_ relayURL: String) -> String? {
        normalizeRelayURL(relayURL).flatMap { cursors[$0] }
    }

    // MARK: Open

    private static func loadReplay(store: any ACEStore, threads: ThreadStore, local: String, capacity: Int,
                                   offlineWindow: Int, clock: @escaping @Sendable () -> Int) throws -> ReplayDetector {
        let raw: Data?
        do { raw = try store.read("replay.json") } catch {
            throw ACEError(.storageFailed, "read replay.json failed: \(error)")
        }
        guard let raw else {
            // Outbox-only threads (no inbound entry) may legitimately predate the first open.
            let inbound = try threads.records().contains { $0.snapshot.history.contains { $0.from != local } }
            if try !store.checkedList("deliveries/").isEmpty || inbound {
                throw ACEError(.storageFailed, "replay state missing beside history")
            }
            let replay = try ReplayDetector(capacity: capacity, horizon: max(0, clock() - offlineWindow - 1), clock: clock)
            try store.checkedWrite("replay.json", replay.exportState().jsonData())
            return replay
        }
        do {
            return try ReplayDetector(state: try ReplayState(json: raw), capacity: capacity, clock: clock)
        } catch let e as ACEError {
            throw ACEError(.storageFailed, "replay.json is invalid: \(e.message)")
        }
    }

    private static func loadCursors(_ store: any ACEStore) throws -> [String: String] {
        guard let v = try store.readJSON("cursors.json") else { return [:] }
        guard let o = v.objectValue else { throw ACEError(.storageFailed, "cursors.json is invalid") }
        try checkVersion(o, "cursors.json")
        guard let c = o["cursors"]?.objectValue else { throw ACEError(.storageFailed, "cursors.json is invalid") }
        var out: [String: String] = [:]
        for (k, v) in c {
            guard let s = v.stringValue, isStreamCursor(s) else { throw ACEError(.storageFailed, "cursors.json is invalid") }
            out[k] = s
        }
        return out
    }

    private var floor: Int { max(0, clock() - offlineWindow) }

    private func covered(_ m: ParsedMessage) -> Bool {
        replay.covers(sender: m.from, timestamp: m.timestamp)
    }

    private func writeReplay(_ r: ReplayDetector) throws {
        try store.checkedWrite("replay.json", r.exportState().jsonData())
    }

    private func loadDelivery(_ key: String) throws -> DeliveryRecord? {
        guard let v = try store.readJSON(key) else { return nil }
        let rec = try DeliveryRecord.parse(v, key: key)
        guard key == DeliveryRecord.key(from: rec.message.from, messageId: rec.message.messageId) else {
            throw storageError(key, "delivery record does not match its key")
        }
        if let t = rec.thread, t.localAceId != localAceId { throw storageError(key, "delivery thread belongs to another identity") }
        return rec
    }

    /// Repair thread / replay state from delivery records (by timestamp, key), then hand
    /// over pending records; the first handler failure throws `handler_failed`.
    private func recover() async throws {
        var pending: [(String, DeliveryRecord)] = []
        var replayChanged = false
        for (key, rec) in try threads.deliveryRecords() {
            let m = rec.message
            if rec.status == .acked && covered(m) {
                try store.checkedDelete(key)
                continue
            }
            if let snap = rec.thread {
                try store.withLock("threads") { try threads.repair(from: snap, recordKey: key) }
            }
            if try replay.accepts(m.messageId, from: m.from, timestamp: m.timestamp) {
                try replay.commit(m.messageId, from: m.from, timestamp: m.timestamp, floor: floor)
                replayChanged = true
            }
            if rec.status == .pending { pending.append((key, rec)) } else if covered(m) { try store.checkedDelete(key) }
        }
        if replayChanged { try writeReplay(replay) }
        for (key, var rec) in pending {
            do {
                try await onMessage(rec.message)
            } catch {
                throw ACEError(.handlerFailed, "onMessage failed during recovery: \(error)")
            }
            if covered(rec.message) {
                try store.checkedDelete(key)
            } else {
                rec.status = .acked
                try store.checkedWrite(key, try rec.data())
            }
        }
    }

    // MARK: Receive

    /// Verify, commit and hand over one envelope. Never throws: failures are outcomes.
    public func receive(_ envelope: Data, source: ReceiveSource) async -> ReceiveOutcome {
        var normalizedSource = source
        if case .relay(let url, let streamId) = source {
            guard let n = normalizeRelayURL(url) else {
                return .retryable(ACEError(.invalidArgument, "relay URL must be http(s)://host[:port][/path]"))
            }
            if let streamId, !isStreamCursor(streamId) {
                return .retryable(ACEError(.invalidArgument, "streamId must be '<ms>-<seq>'"))
            }
            normalizedSource = .relay(url: n, streamId: streamId)
        }
        if closed { return .retryable(ACEError(.storageFailed, "the inbox is closed")) }
        if failed { return .retryable(ACEError(.storageFailed, "inbox is in a failed state; reopen it")) }
        let outcome = await receiveOne(envelope, normalizedSource)
        switch outcome {
        case .delivered, .duplicate, .quarantined:
            do {
                try advanceCursor(normalizedSource)
            } catch let e as ACEError {
                failed = true
                return .retryable(e)
            } catch {
                failed = true
                return .retryable(ACEError(.storageFailed, "\(error)"))
            }
        case .retryable:
            break
        }
        return outcome
    }

    private func advanceCursor(_ source: ReceiveSource) throws {
        guard case .relay(let url, let streamId?) = source else { return }
        if let current = cursors[url], compareStreamIds(streamId, current) <= 0 { return }
        var next = cursors
        next[url] = streamId
        let data = JSONWriter.serialize(.object([
            "cursors": .object(next.mapValues { .string($0) }), "version": .number("1"),
        ]))
        try store.checkedWrite("cursors.json", data)
        cursors = next
    }

    private func quarantine(_ error: ACEError, _ env: ACEMessage, _ source: ReceiveSource) throws -> ReceiveOutcome {
        let fp = envelopeFingerprint(env)
        if case .relay = source { try writeQuarantine(error, env, fp) }
        return .quarantined(error, fingerprint: fp)
    }

    private func writeQuarantine(_ error: ACEError, _ env: ACEMessage, _ fp: String) throws {
        let key = "quarantine/\(fp).json"
        let existed = ((try? store.read(key)) ?? nil) != nil
        try store.checkedWrite(key, quarantineData(env, error: error, fingerprint: fp, at: clock()))
        if existed { return }
        let keys = try store.checkedList("quarantine/")
        guard keys.count > Self.quarantineCap else { return }
        var aged: [(Int, String, String)] = []
        for k in keys {
            let at = (try? store.readJSON(k))??["quarantinedAt"]?.wireInt ?? -1
            aged.append((at, String(k.dropFirst("quarantine/".count).dropLast(".json".count)), k))
        }
        aged.sort { ($0.0, $0.1) < ($1.0, $1.1) }
        for entry in aged.prefix(aged.count - Self.quarantineKeep) { try store.checkedDelete(entry.2) }
    }

    /// Steps 4–5 for a stored pending delivery.
    private func handOver(_ rec: DeliveryRecord, key: String) async -> ReceiveOutcome {
        let m = rec.message
        do {
            try await onMessage(m)
        } catch {
            return .retryable(ACEError(.handlerFailed, "onMessage failed: \(error)"))
        }
        do {
            if covered(m) {
                try store.checkedDelete(key)
            } else {
                var acked = rec
                acked.status = .acked
                try store.checkedWrite(key, try acked.data())
            }
        } catch {
            failed = true
            return .retryable(error as? ACEError ?? ACEError(.storageFailed, "\(error)"))
        }
        return .delivered(m)
    }

    private func receiveOne(_ data: Data, _ source: ReceiveSource) async -> ReceiveOutcome {
        let now = clock()
        // 1. decode
        let env: ACEMessage
        do { env = try decodeEnvelope(data) } catch {
            return .quarantined(error as? ACEError ?? ACEError(.invalidEnvelope), fingerprint: nil)
        }
        // 2. direct freshness
        if source == .direct, abs(now - env.timestamp) > ACELimits.timestampWindowSeconds {
            return .quarantined(ACEError(.staleTimestamp, "direct delivery outside the timestamp window"),
                                fingerprint: envelopeFingerprint(env))
        }
        // 3. peer (before taking `threads`)
        let peer: VerifiedPeer
        do {
            var p = try await peers.resolve(env.from)
            let mine = identity.getEncryptionPublicKey()
            if try ACEEncryption.computeConversationId(pubA: p.encryptionPublicKey, pubB: mine) != env.conversationId {
                p = try await peers.resolve(env.from, maxAgeSeconds: 0)
            }
            peer = p
        } catch let e as ACEError {
            if e.isTransient { return .retryable(e) }
            do { return try quarantine(e, env, source) } catch { return .retryable(error as? ACEError ?? ACEError(.storageFailed)) }
        } catch {
            return .retryable(ACEError(.storageFailed, "\(error)"))
        }
        // 4. stored delivery
        let key = DeliveryRecord.key(from: env.from, messageId: env.messageId)
        let stored: DeliveryRecord?
        do { stored = try loadDelivery(key) } catch {
            return .retryable(error as? ACEError ?? ACEError(.storageFailed))
        }
        if let stored {
            if stored.status == .pending { return await handOver(stored, key: key) }
            return .duplicate(from: env.from, messageId: env.messageId)
        }
        // 5–7
        let lock: (any ACEStoreLock)?
        do { lock = env.type.isEconomic ? try store.checkedLock("threads", timeout: 10) : nil } catch {
            return .retryable(error as? ACEError ?? ACEError(.storageFailed))
        }
        let committed = parseAndCommit(env, peer: peer, key: key, source: source, now: now)
        if failed, let lock {
            // Keep `threads` until close so concurrent writers cannot diverge from the
            // unrepaired history.
            heldThreadsLock = lock
        } else {
            lock?.release()
        }
        switch committed {
        case .done(let outcome):
            return outcome
        case .handOver(let rec):
            let outcome = await handOver(rec, key: key)
            if case .delivered = outcome {
                deliveredSinceSweep += 1
                if deliveredSinceSweep >= Self.sweepEvery {
                    deliveredSinceSweep = 0
                    _ = try? sweep()
                }
            }
            return outcome
        }
    }

    private enum Committed {
        case done(ReceiveOutcome)
        case handOver(DeliveryRecord)
    }

    /// Steps 5–7.3 (caller holds `threads` for economic types).
    private func parseAndCommit(_ env: ACEMessage, peer: VerifiedPeer, key: String, source: ReceiveSource, now: Int) -> Committed {
        let machine: ThreadStateMachine
        let rec: StoredThread?
        do {
            if env.type.isEconomic, let threadId = env.threadId {
                rec = try threads.load(conversationId: env.conversationId, threadId: threadId)
                machine = try threads.machine(for: rec)
            } else {
                rec = nil
                machine = try ThreadStateMachine(localAceId: localAceId)
            }
        } catch {
            return .done(.retryable(error as? ACEError ?? ACEError(.storageFailed)))
        }
        let tr = replay.clone()
        let parsed: ParsedMessage
        do {
            parsed = try parseMessage(env, receiver: identity, sender: peer, threads: machine, replay: tr, floor: floor, clock: clock)
        } catch let e as ACEError {
            if e.code == .replay { return .done(.duplicate(from: env.from, messageId: env.messageId)) }
            if e.category != .permanent { return .done(.retryable(e)) }
            do {
                let outcome = try quarantine(e, env, source)
                if (try? tr.accepts(env.messageId, from: env.from, timestamp: env.timestamp)) == false {
                    try writeReplay(tr) // a verified message stays one-shot
                    replay = tr
                }
                return .done(outcome)
            } catch {
                return .done(.retryable(error as? ACEError ?? ACEError(.storageFailed)))
            }
        } catch {
            return .done(.retryable(ACEError(.identityUnavailable, "\(error)")))
        }
        let snap = env.type.isEconomic ? env.threadId.flatMap { machine.getSnapshot(conversationId: env.conversationId, threadId: $0) } : nil
        let delivery = DeliveryRecord(fingerprint: envelopeFingerprint(env), message: parsed, receivedAt: now,
                                      source: source == .direct ? "direct" : "relay", status: .pending, thread: snap)
        do {
            try store.checkedWrite(key, try delivery.data()) // 7.1 commit point
        } catch {
            return .done(.retryable(error as? ACEError ?? ACEError(.storageFailed)))
        }
        do {
            if let snap { try threads.write(StoredThread(snapshot: snap, pending: ThreadStore.clearProvenPending(rec, snap))) } // 7.2
            try writeReplay(tr) // 7.3
            replay = tr
        } catch {
            failed = true
            return .done(.retryable(error as? ACEError ?? ACEError(.storageFailed)))
        }
        return .handOver(delivery)
    }

    /// Delete `acked` delivery records covered by a replay horizon; returns the count.
    @discardableResult
    public func sweep() throws -> Int {
        var removed = 0
        for key in try store.checkedList("deliveries/") {
            guard let rec = try loadDelivery(key) else { continue }
            if rec.status == .acked && covered(rec.message) {
                try store.checkedDelete(key)
                removed += 1
            }
        }
        return removed
    }

    // MARK: Relay drivers

    /// Fetch and receive queued messages from the cursor; stops at the first retryable outcome.
    public func pull(_ relay: RelayClient, limit: Int = ACELimits.maxInboxPage) async -> PullResult {
        let url = relay.baseURLString
        var delivered = 0, duplicates = 0, quarantined = 0
        var since = cursors[url]
        while true {
            let page: RelayClient.InboxPage
            do {
                page = try await relay.fetchInbox(identity, since: since, limit: limit)
            } catch {
                return PullResult(delivered: delivered, duplicates: duplicates, quarantined: quarantined,
                                  blocked: error as? ACEError ?? ACEError(.relayUnavailable, "\(error)"))
            }
            for entry in page.entries {
                switch await receive(entry.envelope, source: .relay(url: url, streamId: entry.streamId)) {
                case .delivered: delivered += 1
                case .duplicate: duplicates += 1
                case .quarantined: quarantined += 1
                case .retryable(let e):
                    return PullResult(delivered: delivered, duplicates: duplicates, quarantined: quarantined, blocked: e)
                }
            }
            if page.entries.count < limit {
                return PullResult(delivered: delivered, duplicates: duplicates, quarantined: quarantined, blocked: nil)
            }
            since = page.entries.last?.streamId
        }
    }

    /// `pull`, then receive live SSE events and yield each outcome. Throws the blocking
    /// error of the initial pull, or a `retryable` outcome's error right after yielding it.
    public nonisolated func follow(_ relay: RelayClient) -> AsyncThrowingStream<ReceiveOutcome, Error> {
        AsyncThrowingStream { continuation in
            let task = Task {
                do {
                    let result = await self.pull(relay)
                    if let blocked = result.blocked { throw blocked }
                    let url = relay.baseURLString
                    for try await event in relay.listen(self.identity, since: await self.cursor(url)) {
                        let outcome = await self.receive(event.envelope, source: .relay(url: url, streamId: event.streamId))
                        continuation.yield(outcome)
                        if case .retryable(let e) = outcome { throw e }
                    }
                    continuation.finish()
                } catch {
                    continuation.finish(throwing: error is CancellationError ? nil : error)
                }
            }
            continuation.onTermination = { _ in task.cancel() }
        }
    }
}

/// Compare `<ms>-<seq>` stream IDs as integer pairs.
func compareStreamIds(_ a: String, _ b: String) -> Int {
    func parts(_ s: String) -> [String] {
        s.split(separator: "-").map { p in
            let t = p.drop(while: { $0 == "0" })
            return t.isEmpty ? "0" : String(t)
        }
    }
    let pa = parts(a), pb = parts(b)
    for (x, y) in zip(pa, pb) where x != y {
        if x.count != y.count { return x.count < y.count ? -1 : 1 }
        return x < y ? -1 : 1
    }
    return 0
}
