//
//  Inbox.swift
//  ACE SDK
//
//  Receive engine (06-security "Durable Delivery", Receiver).
//

import Foundation

/// Where an envelope came from.
public enum ReceiveSource: Sendable, Equatable {
    /// Fetched from a relay. `streamId` advances the durable cursor keyed by `url`
    /// normalized (08 § Client Rules, Relay URL). Pass `relayClient.baseURLString` — the
    /// key `pull`, `follow` and `cursor(for:)` use.
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

    /// The message of a `delivered` outcome.
    public var message: ParsedMessage? {
        if case .delivered(let m) = self { return m }
        return nil
    }
}

/// The HTTP reply for one direct-delivery request (08 § Direct Delivery, Receiver).
/// The application serves it: status `status`, `Content-Type: application/json`, body
/// `bodyData`.
public struct DirectReply: Sendable {
    /// 200, 400, 413 or 503.
    public let status: Int
    /// `{"ok":true,"messageId":…}` or `{"ok":false,"error":<code>}`.
    public let body: [String: JSONValue]
    /// The receive outcome, when the `message` member reached the pipeline.
    public let outcome: ReceiveOutcome?

    /// `body` serialized as compact JSON.
    public var bodyData: Data { JSONWriter.serialize(JSONValue.object(body).jvalue ?? .object([:])) }

    static func ok(_ messageId: String, _ outcome: ReceiveOutcome) -> DirectReply {
        DirectReply(status: 200, body: ["ok": true, "messageId": .string(messageId)], outcome: outcome)
    }

    static func fail(_ status: Int, _ error: String, _ outcome: ReceiveOutcome? = nil) -> DirectReply {
        DirectReply(status: status, body: ["ok": false, "error": .string(error)], outcome: outcome)
    }
}

/// The result of `Inbox.pull`.
public struct PullResult: Sendable {
    /// Every `delivered`, `duplicate` and `quarantined` outcome, in relay order. The
    /// cursor has passed all of them. Never contains `retryable`: that stops the pull
    /// and is reported in `blocked`.
    public let outcomes: [ReceiveOutcome]
    /// The error that stopped the pull before the inbox was drained (a fetch failure or a
    /// `retryable` outcome); nil when drained or stopped by `maxPages`. The cursor stops
    /// before the blocking entry, so the next pull retries it.
    public let blocked: ACEError?
    /// `maxPages` (or task cancellation) stopped the pull early; more entries may be waiting.
    public let hasMore: Bool

    public init(outcomes: [ReceiveOutcome], blocked: ACEError?, hasMore: Bool = false) {
        self.outcomes = outcomes
        self.blocked = blocked
        self.hasMore = hasMore
    }

    /// The delivered messages, in relay order.
    public var messages: [ParsedMessage] { outcomes.compactMap(\.message) }
    public var delivered: Int { outcomes.count(where: { if case .delivered = $0 { true } else { false } }) }
    public var duplicates: Int { outcomes.count(where: { if case .duplicate = $0 { true } else { false } }) }
    public var quarantined: Int { outcomes.count(where: { if case .quarantined = $0 { true } else { false } }) }
}

/// Durable, exactly-once-to-the-host receive engine.
///
/// `onMessage` must persist the host effect durably and idempotently, keyed by
/// `(from, messageId)`, then return; throwing means "retry later". Commit order per message:
/// delivery record, `requests/` decision fill (`decision` only), thread state, replay state,
/// `onMessage`, ack, cursor. The instance holds the store's `receive` lock until `close()`.
///
/// `principal` (09) is the receiver's own principal account and its step-4 authorities. With
/// neither `selfSigner` nor `trustedSigners`, only an `eip155` account whose address is the
/// signer's passes; without `principal` every principal-type message is `wrong_principal`.
public actor Inbox {
    public typealias MessageHandler = @Sendable (ParsedMessage) async throws -> Void

    static let quarantineCap = 1000
    static let followBuffer = 64
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
    private let principal: InboxPrincipal?
    private let receiveLock: any ACEStoreLock
    private var replay: ReplayDetector
    private var cursors: [String: String]
    private var failed = false
    private var closed = false
    private var deliveredSinceSweep = 0
    /// `quarantine/` record count, listed once and then maintained (this instance holds
    /// the `receive` lock, so it is the only writer).
    private var quarantineCount: Int?
    /// `threads` / `requests` locks kept after a failure; only appended to, all released at
    /// `close()` (never overwritten, so none leaks).
    private var heldLocks: [any ACEStoreLock] = []

    /// Open the inbox: take the `receive` lock (`receiver_busy` if held), load or create
    /// `replay.json`, load cursors and run recovery from delivery records. An invalid
    /// `principal` (non-CAIP-10 account, malformed signer key) is `invalid_argument`.
    public static func open(
        identity: any ACEIdentity,
        store: any ACEStore,
        peers: PeerStore,
        onMessage: @escaping MessageHandler,
        capacity: Int = ACELimits.defaultReplayCapacity,
        offlineWindowSeconds: Int = ACELimits.offlineWindowSeconds,
        clock: @escaping @Sendable () -> Int = systemClock,
        principal: InboxPrincipal? = nil
    ) async throws -> Inbox {
        try principal?.validate()
        guard offlineWindowSeconds >= ACELimits.timestampWindowSeconds, isWireInt(offlineWindowSeconds) else {
            throw ACEError(.invalidArgument, "offlineWindowSeconds must be an integer in [\(ACELimits.timestampWindowSeconds), 2^53-1]")
        }
        let clock = wireClock(clock)
        guard capacity >= 1 else { throw ACEError(.invalidArgument, "capacity must be an integer >= 1") }
        let threads = try ThreadStore(store: store, localAceId: identity.getACEId(), clock: clock)
        let lock = try store.checkedLock("receive", timeout: 0)
        let inbox: Inbox
        do {
            let replay = try loadReplay(store: store, threads: threads, local: identity.getACEId(), capacity: capacity,
                                        offlineWindow: offlineWindowSeconds, clock: clock)
            let cursors = try loadCursors(store)
            inbox = Inbox(identity: identity, store: store, peers: peers, onMessage: onMessage, offlineWindow: offlineWindowSeconds,
                          clock: clock, threads: threads, principal: principal, lock: lock, replay: replay, cursors: cursors)
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
                 offlineWindow: Int, clock: @escaping @Sendable () -> Int, threads: ThreadStore, principal: InboxPrincipal?,
                 lock: any ACEStoreLock,
                 replay: ReplayDetector, cursors: [String: String]) {
        self.identity = identity
        self.localAceId = identity.getACEId()
        self.store = store
        self.peers = peers
        self.onMessage = onMessage
        self.offlineWindow = offlineWindow
        self.clock = clock
        self.threads = threads
        self.principal = principal
        self.receiveLock = lock
        self.replay = replay
        self.cursors = cursors
    }

    deinit {
        for l in heldLocks { l.release() }
        if !closed { receiveLock.release() }
    }

    /// Release the `receive` lock. Idempotent.
    public func close() {
        guard !closed else { return }
        closed = true
        let held = heldLocks
        heldLocks = []
        for l in held { l.release() }
        receiveLock.release()
    }

    /// The durable cursor (last passed stream ID) for `relay`, or nil before the first entry.
    public func cursor(for relay: RelayClient) -> String? {
        cursors[relay.baseURLString]
    }

    // MARK: Open

    private static func loadReplay(store: any ACEStore, threads: ThreadStore, local: String, capacity: Int,
                                   offlineWindow: Int, clock: @escaping @Sendable () -> Int) throws -> ReplayDetector {
        guard let raw = try store.checkedRead("replay.json") else {
            // Outbox-only threads (no inbound entry) may legitimately predate the first open.
            let inbound = try threads.records().contains { $0.snapshot.history.contains { $0.from != local } }
            if try !store.checkedList("deliveries/").isEmpty || inbound {
                throw ACEError(.storageFailed, "replay state missing beside history")
            }
            let replay = try ReplayDetector(capacity: capacity, horizon: windowFloor(now: clock(), window: offlineWindow + 1), clock: clock)
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

    private var floor: Int { windowFloor(now: clock(), window: offlineWindow) }

    private func covered(_ m: ParsedMessage) -> Bool {
        replay.covers(sender: m.from, timestamp: m.timestamp)
    }

    private func writeReplay(_ r: ReplayDetector) throws {
        try store.checkedWrite("replay.json", r.exportState().jsonData())
    }

    /// After the handler returns: drop the record once a horizon covers it, else mark it `acked`.
    private func finishDelivery(_ rec: DeliveryRecord, key: String) throws {
        if covered(rec.message) {
            try store.checkedDelete(key)
        } else {
            var acked = rec
            acked.status = .acked
            try store.checkedWrite(key, try acked.data())
        }
    }

    /// Repair thread state, `requests/` decision fills (1a) and replay state from delivery
    /// records (by timestamp, key), then hand over pending records; the first handler failure
    /// throws `handler_failed`. A fill that is `bad_reference` / `wrong_principal` (only with a
    /// corrupted store: step 7 and the fill run under one `requests` lock) fails `open`.
    private func recover() async throws {
        var pending: [(String, DeliveryRecord)] = []
        var decisions: [ParsedMessage] = []
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
            if m.type == .decision { decisions.append(m) }
            if try replay.accepts(m.messageId, from: m.from, timestamp: m.timestamp) {
                try replay.commit(m.messageId, from: m.from, timestamp: m.timestamp, floor: floor)
                replayChanged = true
            }
            if rec.status == .pending { pending.append((key, rec)) } else if covered(m) { try store.checkedDelete(key) }
        }
        if !decisions.isEmpty {  // 1a: no-op when already filled
            try store.withLock("requests") { for m in decisions { try fillDecision(store, m) } }
        }
        if replayChanged { try writeReplay(replay) }
        for (key, rec) in pending {
            do {
                try await onMessage(rec.message)
            } catch {
                throw ACEError(.handlerFailed, "onMessage failed during recovery: \(error)")
            }
            try finishDelivery(rec, key: key)
        }
    }

    // MARK: Receive

    /// Verify, commit and hand over one message given as its raw JSON bytes. Message
    /// failures are outcomes (bytes that are not an envelope are `quarantined`); only a
    /// misuse throws `invalid_argument`: an invalid `source` (relay URL or `streamId`) or a
    /// closed inbox.
    public func receive(_ message: Data, source: ReceiveSource) async throws -> ReceiveOutcome {
        var normalizedSource = source
        if case .relay(let url, let streamId) = source {
            let n = try normalizeRelayURL(url)
            if let streamId, !isStreamCursor(streamId) {
                throw ACEError(.invalidArgument, "streamId must be '<ms>-<seq>'")
            }
            normalizedSource = .relay(url: n, streamId: streamId)
        }
        if closed { throw ACEError(.invalidArgument, "the inbox is closed") }
        if failed { return .retryable(ACEError(.storageFailed, "inbox is in a failed state; reopen it")) }
        let outcome = await receiveOne(message, normalizedSource)
        switch outcome {
        case .delivered, .duplicate, .quarantined:
            do {
                try advanceCursor(normalizedSource)
            } catch {
                failed = true
                return .retryable(.wrap(error))
            }
        case .retryable:
            break
        }
        return outcome
    }

    /// Handle one direct-delivery request body (08 § Direct Delivery, Receiver): the first
    /// matching row of
    ///
    /// - a closed inbox (not accepting; not a fault of the request, so the sender falls back
    ///   to the relay) → 503 `internal_error`;
    /// - body larger than `ACELimits.maxDirectBodyBytes` → 413 `payload_too_large`;
    /// - not UTF-8 JSON whose top level is an object with a `message` member → 400
    ///   `invalid_argument`;
    /// - `delivered` or `duplicate` → 200 `{"ok":true,"messageId"}`;
    /// - `quarantined` (a `message` that is not an envelope included) → 400 with its code;
    /// - `retryable` or a thrown transient / local `ACEError` → 503 with its code;
    /// - any other thrown `ACEError` → 400 with its code; anything else → 503 `internal_error`.
    ///
    /// The `message` member is received with source `.direct`. HTTP serving, routing and
    /// rate limiting belong to the application.
    public func receiveDirect(_ body: Data) async -> DirectReply {
        guard !closed else { return .fail(503, "internal_error") }
        guard body.count <= ACELimits.maxDirectBodyBytes else { return .fail(413, "payload_too_large") }
        guard String(validating: body, as: UTF8.self) != nil,
              let request = try? JSONParser.parse(body), let message = request.objectValue?["message"] else {
            return .fail(400, ACEError.Code.invalidArgument.rawValue)
        }
        let outcome: ReceiveOutcome
        do {
            outcome = try await receive(JSONWriter.serialize(message), source: .direct)
        } catch let e as ACEError {
            if closed { return .fail(503, "internal_error") }  // closed meanwhile
            return .fail(e.isTransient ? 503 : 400, e.code.rawValue)
        } catch {
            return .fail(503, "internal_error")
        }
        switch outcome {
        case .delivered(let m): return .ok(m.messageId, outcome)
        case .duplicate(_, let messageId): return .ok(messageId, outcome)
        case .quarantined(let e, _): return .fail(400, e.code.rawValue, outcome)
        case .retryable(let e): return .fail(503, e.code.rawValue, outcome)
        }
    }

    private func advanceCursor(_ source: ReceiveSource) throws {
        guard case .relay(let url, let streamId?) = source else { return }
        if let current = cursors[url], compareStreamIds(streamId, current) <= 0 { return }
        var next = cursors
        next[url] = streamId
        let data = JSONWriter.serialize(.object([
            "cursors": .object(next.mapValues { .string($0) }), "version": num(1),
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
        // O(1) per insert; the listing and the read of every record happen only when the
        // cap is crossed, which then trims to `quarantineKeep` (once per 100 inserts).
        let count = try quarantineCount.map { $0 + 1 } ?? store.checkedList("quarantine/").count
        quarantineCount = count
        guard count > Self.quarantineCap else { return }
        let keys = try store.checkedList("quarantine/")
        var aged: [(Int, String, String)] = []
        for k in keys {
            let at = (try? store.readJSON(k))??["quarantinedAt"]?.wireInt ?? -1
            aged.append((at, String(k.dropFirst("quarantine/".count).dropLast(".json".count)), k))
        }
        aged.sort { ($0.0, $0.1) < ($1.0, $1.1) }
        for entry in aged.prefix(aged.count - Self.quarantineKeep) { try store.checkedDelete(entry.2) }
        quarantineCount = min(keys.count, Self.quarantineKeep)
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
            try finishDelivery(rec, key: key)
        } catch {
            failed = true
            return .retryable(.wrap(error))
        }
        return .delivered(m)
    }

    private func receiveOne(_ data: Data, _ source: ReceiveSource) async -> ReceiveOutcome {
        let now = clock()
        // 1. decode
        let env: ACEMessage
        do { env = try decodeEnvelope(data) } catch {
            return .quarantined(.wrap(error, .invalidEnvelope), fingerprint: nil)
        }
        // 2. direct freshness
        if source == .direct, !isWithinWindow(now: now, ts: env.timestamp, window: ACELimits.timestampWindowSeconds) {
            return .quarantined(ACEError(.staleTimestamp, "direct delivery outside the timestamp window"),
                                fingerprint: envelopeFingerprint(env))
        }
        // 3. peer (before taking `threads`)
        var peer: VerifiedPeer
        do {
            var p = try await peers.resolve(env.from)
            let mine = identity.getEncryptionPublicKey()
            if try ACEEncryption.computeConversationId(pubA: p.encryptionPublicKey, pubB: mine) != env.conversationId {
                p = try await peers.resolve(env.from, maxAgeSeconds: 0)
            }
            peer = p
        } catch let e as ACEError {
            if e.isTransient { return .retryable(e) }
            do { return try quarantine(e, env, source) } catch { return .retryable(.wrap(error)) }
        } catch {
            return .retryable(ACEError(.relayUnavailable, "peer resolution failed: \(error)"))
        }
        // 4. stored delivery
        let key = DeliveryRecord.key(from: env.from, messageId: env.messageId)
        let stored: DeliveryRecord?
        do { stored = try threads.loadDelivery(key) } catch {
            return .retryable(.wrap(error))
        }
        if let stored {
            if stored.status == .pending { return await handOver(stored, key: key) }
            return .duplicate(from: env.from, messageId: env.messageId)
        }
        // 5 (principal types): one refresh of a sender whose pinned principal fails 09 steps
        // 2-5 (R-P20), before any store lock. Transient → retryable (cursor stays); permanent →
        // quarantined.
        if env.type.isPrincipal {
            do {
                peer = try await refreshPrincipalSender(env, peer: peer, now: now)
            } catch let e as ACEError {
                if e.isTransient { return .retryable(e) }
                do { return try quarantine(e, env, source) } catch { return .retryable(.wrap(error)) }
            } catch {
                return .retryable(ACEError(.relayUnavailable, "peer refresh failed: \(error)"))
            }
        }
        // Actor reentrancy: another receive may have failed while this one was suspended at
        // step 3 or the refresh. Re-check after the last await, before taking any store lock.
        if failed { return .retryable(ACEError(.storageFailed, "inbox is in a failed state; reopen it")) }
        // 5–7: economic types under `threads`; a decision under `requests` from the
        // open-request check through the requests/ fill (R-P25)
        let lockName: String? = env.type.isEconomic ? "threads" : env.type == .decision ? "requests" : nil
        let lock: (any ACEStoreLock)?
        do { lock = try lockName.map { try store.checkedLock($0, timeout: ACELimits.defaultLockTimeoutSeconds) } } catch {
            return .retryable(.wrap(error))
        }
        let committed = parseAndCommit(env, peer: peer, key: key, source: source, now: now)
        if failed, let lock {
            // Keep the lock until close so concurrent writers cannot diverge from the
            // unrepaired history / ledger.
            heldLocks.append(lock)
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
                    try? sweep()
                }
            }
            return outcome
        }
    }

    private enum Committed {
        case done(ReceiveOutcome)
        case handOver(DeliveryRecord)
    }

    /// Steps 5–7.3 (caller holds `threads` for economic types, `requests` for a decision).
    private func parseAndCommit(_ env: ACEMessage, peer: VerifiedPeer, key: String, source: ReceiveSource, now: Int) -> Committed {
        let machine: ThreadStateMachine
        let rec: StoredThread?
        do {
            if env.type.isEconomic, let threadId = env.threadId {
                (rec, machine) = try threads.loadWithMachine(conversationId: env.conversationId, threadId: threadId)
            } else {
                rec = nil
                machine = try ThreadStateMachine(localAceId: localAceId)
            }
        } catch {
            return .done(.retryable(.wrap(error)))
        }
        let tr = replay.clone()
        let parsed: ParsedMessage
        do {
            parsed = try parseMessage(env, receiver: identity, sender: peer, threads: machine, replay: tr, floor: floor, clock: clock,
                                      principal: principalContext())
            // A verified message that opens a thread counts against the peer's open threads.
            if env.type.isEconomic && rec == nil { try threads.checkCanOpenThread(peer: env.from) }
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
                return .done(.retryable(.wrap(error)))
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
            return .done(.retryable(.wrap(error)))
        }
        do {
            if parsed.type == .decision { try fillDecision(store, parsed) } // 7.1a: mark the request decided
            if let snap { try threads.write(StoredThread(snapshot: snap, pending: ThreadStore.clearProvenPending(rec, snap))) } // 7.2
            try writeReplay(tr) // 7.3
            replay = tr
        } catch {
            failed = true
            return .done(.retryable(.wrap(error)))
        }
        return .handOver(delivery)
    }

    /// Step-7 context. No `refreshSender`: `receiveOne` refreshes the sender before parsing,
    /// outside the `requests` lock.
    private func principalContext() -> PrincipalContext? {
        guard let principal else { return nil }
        let store = self.store
        return PrincipalContext(account: principal.account,
                                openRequestTo: { c, r, now in try openRequestTo(store, conversationId: c, messageId: r, now: now) },
                                selfSigner: principal.selfSigner, trustedSigners: principal.trustedSigners)
    }

    /// R-P20 / R-P29 / R-P30 (09 § Same-Account Rules, SDK note): when the pinned sender
    /// principal fails steps 2-5 and the envelope verifies under the pinned key and scheme,
    /// refresh the sender from the relay once (rollback barrier) and return the binding the
    /// rules run on. A transient error propagates (retryable); a permanent error from the relay
    /// or adopt, no relay, or a refresh that changes the binding leaves the pinned binding to
    /// decide. A forged envelope triggers no relay call; the pipeline rejects it later.
    private func refreshPrincipalSender(_ env: ACEMessage, peer: VerifiedPeer, now: Int) async throws -> VerifiedPeer {
        guard let principal,
              !senderPrincipalUsable(peer.principal, senderSigningPublicKey: peer.signingPublicKey, principal: principal, now: now),
              wouldPassPreSignatureChecks(env, now: now),
              Self.authenticated(env, by: peer) else { return peer }
        let fresh: VerifiedPeer?
        do {
            fresh = try await peers.refresh(peer.aceId)
        } catch let e as ACEError {
            if e.isTransient { throw e }
            return peer
        } catch {
            throw ACEError(.relayUnavailable, "peer refresh failed: \(error)")
        }
        guard let fresh, fresh.aceId == peer.aceId, fresh.signingPublicKey == peer.signingPublicKey else { return peer }
        return fresh
    }

    /// R-P38: the cheap pipeline checks that precede the signature (recipient, timestamp window
    /// and floor, replay — a pure read, nothing committed), so a misaddressed, stale or replayed
    /// envelope never costs a relay call; the pipeline rejects it afterwards.
    private func wouldPassPreSignatureChecks(_ env: ACEMessage, now: Int) -> Bool {
        guard env.to == localAceId, env.timestamp >= floor, env.timestamp <= now + ACELimits.timestampWindowSeconds else {
            return false
        }
        return (try? replay.accepts(env.messageId, from: env.from, timestamp: env.timestamp)) == true
    }

    /// The envelope signature verifies under `peer`'s pinned key and scheme (as parse steps
    /// 2-4 and 8); malformed signatures are false.
    private static func authenticated(_ env: ACEMessage, by peer: VerifiedPeer) -> Bool {
        guard env.from == peer.aceId, env.signature.scheme == peer.scheme,
              let sig = try? decodeSignature(env.signature.value, scheme: env.signature.scheme, code: .invalidEnvelope),
              let data = try? messageSignData(env) else { return false }
        return ACESigning.verify(signData: data, signature: sig, scheme: peer.scheme, publicKey: peer.signingPublicKey)
    }

    /// Delete `acked` delivery records covered by a replay horizon (every
    /// `sweepEvery` deliveries).
    private func sweep() throws {
        for key in try store.checkedList("deliveries/") {
            guard let rec = try threads.loadDelivery(key) else { continue }
            if rec.status == .acked && covered(rec.message) { try store.checkedDelete(key) }
        }
    }

    // MARK: Relay drivers

    /// Fetch and receive queued entries from the durable cursor, page by page, until the
    /// relay inbox is drained, a `retryable` outcome or fetch failure blocks it, or
    /// `maxPages` full pages were fetched (`hasMore`). Never throws: argument errors
    /// (`limit` outside 1…100, `maxPages` < 1) are reported in `blocked`.
    ///
    /// `outcomes` holds every entry fetched, so memory grows with the backlog; pass
    /// `maxPages` to bound it (or use `follow`, which streams with backpressure).
    public func pull(_ relay: RelayClient, limit: Int = ACELimits.maxInboxPage, maxPages: Int? = nil) async -> PullResult {
        await pull(relay, limit: limit, maxPages: maxPages, yield: nil)
    }

    private func pull(_ relay: RelayClient, limit: Int, maxPages: Int?,
                      yield: (@Sendable (ReceiveOutcome) async -> Void)?) async -> PullResult {
        if let maxPages, maxPages < 1 {
            return PullResult(outcomes: [], blocked: ACEError(.invalidArgument, "maxPages must be >= 1"))
        }
        var outcomes: [ReceiveOutcome] = []
        var pages = 0
        while true {
            if let maxPages, pages >= maxPages { return PullResult(outcomes: outcomes, blocked: nil, hasMore: true) }
            pages += 1
            let page: RelayClient.InboxPage
            do {
                page = try await relay.fetchInbox(identity, since: cursors[relay.baseURLString], limit: limit)
            } catch {
                return PullResult(outcomes: outcomes, blocked: .wrap(error, .relayUnavailable))
            }
            for entry in page.entries {
                // A cancelled caller stops before the next entry; the cursor marks the spot.
                if Task.isCancelled { return PullResult(outcomes: outcomes, blocked: nil, hasMore: true) }
                let outcome: ReceiveOutcome
                do {
                    outcome = try await receive(entry.message, source: .relay(url: relay.baseURLString, streamId: entry.streamId))
                } catch {
                    return PullResult(outcomes: outcomes, blocked: .wrap(error, .invalidArgument))
                }
                if case .retryable(let e) = outcome {
                    await yield?(outcome)  // follow yields it, then throws `blocked`
                    return PullResult(outcomes: outcomes, blocked: e)
                }
                if let yield { await yield(outcome) } else { outcomes.append(outcome) }
            }
            if page.entries.count < limit { return PullResult(outcomes: outcomes, blocked: nil) }
        }
    }

    /// Receive everything queued, then live events, as one stream of outcomes:
    ///
    /// 1. A full `pull`, yielding each of its outcomes as it happens. A `retryable`
    ///    outcome is yielded and then thrown; a failed fetch is thrown (and `onLive` is
    ///    never called).
    /// 2. `relay.listen` from the durable cursor; each event is received and its outcome
    ///    yielded. After yielding a `retryable` outcome the stream throws its error.
    ///
    /// `onLive` is called once the initial pull has finished and the SSE connection is
    /// open, and again after every reconnect — use it for a "live" indicator. It runs on
    /// the stream's task and must not block. Outcomes may still be buffered in the stream
    /// when it is called. Cancelling the consuming task or dropping the stream closes the
    /// connection promptly.
    ///
    /// Backpressure: at most `followBuffer` (64) outcomes wait in the stream; while it is
    /// full, receiving pauses (and so does reading the relay), so a slow consumer never
    /// grows memory.
    public nonisolated func follow(_ relay: RelayClient, onLive: (@Sendable () -> Void)? = nil) -> AsyncThrowingStream<ReceiveOutcome, Error> {
        AsyncThrowingStream(bufferingPolicy: .bufferingOldest(Self.followBuffer)) { continuation in
            let task = Task {
                do {
                    let result = await self.pull(relay, limit: ACELimits.maxInboxPage, maxPages: nil,
                                                 yield: { try? await continuation.yieldWaiting($0) })
                    if let blocked = result.blocked { throw blocked }
                    try Task.checkCancellation()
                    let events = relay.listen(self.identity, since: await self.cursor(for: relay), onOpen: onLive)
                    for try await event in events {
                        let outcome = try await self.receive(event.message, source: .relay(url: relay.baseURLString, streamId: event.streamId))
                        try await continuation.yieldWaiting(outcome)
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

extension AsyncThrowingStream.Continuation where Element: Sendable {
    /// Yield on a `.bufferingOldest` stream, waiting while its buffer is full instead of
    /// dropping. Throws `CancellationError` when the stream terminated or the task is
    /// cancelled.
    func yieldWaiting(_ value: Element) async throws {
        var delay: UInt64 = 1_000_000
        while true {
            switch yield(value) {
            case .enqueued: return
            case .terminated: throw CancellationError()
            case .dropped:
                try await Task.sleep(nanoseconds: delay)
                delay = min(delay * 2, 50_000_000)
            @unknown default: return
            }
        }
    }
}
