//
//  Inbox.swift
//  ACE SDK
//
//  Receive engine (06-security "Durable Delivery", Receiver).
//

import Foundation

/// The result of `Inbox.receive`.
public enum ReceiveOutcome: Sendable {
    /// Verified, committed and handed to `onMessage`.
    case delivered(ParsedMessage)
    /// Already delivered (or a replay); nothing was written.
    case duplicate(from: String, messageId: String)
    /// Permanently rejected. `fingerprint` is nil when the envelope did not decode.
    case quarantined(ACEError, fingerprint: String?)
    /// A transient or local failure; retry later (`SecureMailbox` does not advance its cursor).
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

/// Durable, exactly-once-to-the-host receive engine. It is fed authenticated plaintext by
/// `SecureMailbox` (the only network boundary) or directly by in-process code; it knows
/// nothing about relays, cursors or HTTP.
///
/// `onMessage` must persist the host effect durably and idempotently, keyed by
/// `(from, messageId)`, then return; throwing means "retry later". Commit order per message:
/// delivery record, `requests/` decision fill (`decision` only), thread state, `onMessage`, ack.
/// The delivery record journals the seen-store commit: `replay.json` is rewritten every
/// `replaySnapshotEvery` commits and at `close()`, `open` re-commits the records written since,
/// and a record is deleted only once a written `replay.json` covers it. The instance holds the
/// store's `receive` lock until `close()`.
///
/// `principal` (09) is the receiver's own principal account and its step-4 authorities. With
/// neither `selfSigner` nor `trustedSigners`, only an `eip155` account whose address is the
/// signer's passes; without `principal` principal-type messages are received as data only
/// (no account rules, no `requests/` decision fill).
public actor Inbox {
    public typealias MessageHandler = @Sendable (ParsedMessage) async throws -> Void

    static let quarantineCap = 1000
    static let quarantineKeep = 900
    static let replaySnapshotEvery = 1024

    nonisolated let identity: any ACEIdentity
    private let localAceId: String
    private let store: any ACEStore
    private let peers: PeerStore
    private let onMessage: MessageHandler
    private let offlineWindow: Int
    private let clock: @Sendable () -> Int
    private let threads: ThreadStore
    private let commerce: Bool
    private let principal: InboxPrincipal?
    private let schemas: [String: SchemaValidator]
    private let receiveLock: any ACEStoreLock
    private var replay: ReplayDetector
    /// Commits since `replay.json` was last written (journaled by their delivery records).
    private var replayDirty = 0
    /// `acked` delivery records the written `replay.json` does not cover yet, by key.
    private var acked: [String: (from: String, timestamp: Int)] = [:]
    private var failed = false
    private var closed = false
    /// `quarantine/` record count, listed once and then maintained (this instance holds
    /// the `receive` lock, so it is the only writer).
    private var quarantineCount: Int?
    /// `threads` / `requests` locks kept after a failure; only appended to, all released at
    /// `close()` (never overwritten, so none leaks).
    private var heldLocks: [any ACEStoreLock] = []

    /// Open the inbox: take the `receive` lock (`receiver_busy` if held), load or create
    /// `replay.json` and run recovery from delivery records. An invalid
    /// `principal` (non-CAIP-10 account, malformed signer key) is `invalid_argument`.
    /// `schemas` installs deterministic validators by `schemaDigest` (64 lowercase hex, else
    /// `invalid_argument`); one runs at the body-validation step, before thread/principal
    /// checks, and its failure quarantines the message. Bundled types keep their built-in rules.
    public static func open(
        identity: any ACEIdentity,
        store: any ACEStore,
        peers: PeerStore,
        onMessage: @escaping MessageHandler,
        capacity: Int = ACELimits.defaultReplayCapacity,
        offlineWindowSeconds: Int = ACELimits.offlineWindowSeconds,
        clock: @escaping @Sendable () -> Int = systemClock,
        principal: InboxPrincipal? = nil,
        commerce: Bool = false,
        schemas: [String: SchemaValidator] = [:]
    ) async throws -> Inbox {
        try principal?.validate()
        try checkSchemas(schemas)
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
            inbox = Inbox(identity: identity, store: store, peers: peers, onMessage: onMessage, offlineWindow: offlineWindowSeconds,
                          clock: clock, threads: threads, principal: principal, commerce: commerce, schemas: schemas, lock: lock, replay: replay)
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
                 offlineWindow: Int, clock: @escaping @Sendable () -> Int, threads: ThreadStore, principal: InboxPrincipal?, commerce: Bool,
                 schemas: [String: SchemaValidator], lock: any ACEStoreLock,
                 replay: ReplayDetector) {
        self.identity = identity
        self.localAceId = identity.getACEId()
        self.store = store
        self.peers = peers
        self.onMessage = onMessage
        self.offlineWindow = offlineWindow
        self.clock = clock
        self.threads = threads
        self.principal = principal
        self.commerce = commerce
        self.schemas = schemas
        self.receiveLock = lock
        self.replay = replay
    }

    deinit {
        for l in heldLocks { l.release() }
        if !closed { receiveLock.release() }
    }

    /// Write pending seen-store commits (best effort: the delivery records journal them) and
    /// release the `receive` lock. Idempotent.
    public func close() {
        guard !closed else { return }
        if !failed && replayDirty > 0 { try? persistReplay() }
        closed = true
        let held = heldLocks
        heldLocks = []
        for l in held { l.release() }
        receiveLock.release()
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

    private var floor: Int { windowFloor(now: clock(), window: offlineWindow) }

    /// Economic types run the thread state machine (under `threads`) only with `commerce`.
    private func tracksThread(_ type: MessageType) -> Bool { commerce && type.isEconomic }
    /// A decision fills its `requests/` entry (under `requests`) only with a `principal`.
    private func fillsDecision(_ type: MessageType) -> Bool { principal != nil && type == .decision }

    private func covered(_ m: ParsedMessage) -> Bool {
        replay.covers(sender: m.from, timestamp: m.timestamp)
    }

    private func writeReplay(_ r: ReplayDetector) throws {
        try store.checkedWrite("replay.json", r.exportState().jsonData())
    }

    /// Write the seen store, then delete the acked records it now covers.
    private func persistReplay() throws {
        try writeReplay(replay)
        replayDirty = 0
        try pruneAcked()
    }

    /// Delete the acked records covered by `replay`; call only while it equals `replay.json`.
    private func pruneAcked() throws {
        for (key, m) in acked where replay.covers(sender: m.from, timestamp: m.timestamp) {
            try store.checkedDelete(key)
            acked[key] = nil
        }
    }

    /// After the handler returns: drop the record once the written replay state covers it,
    /// else mark it `acked` (pruned after a later write of `replay.json`).
    private func finishDelivery(_ rec: DeliveryRecord, key: String) throws {
        if replayDirty == 0 && covered(rec.message) {
            try store.checkedDelete(key)
            return
        }
        var done = rec
        done.status = .acked
        try store.checkedWrite(key, try done.data())
        acked[key] = (rec.message.from, rec.message.timestamp)
    }

    /// Repair thread state, `requests/` decision fills (1a) and replay state from delivery
    /// records (by timestamp, key), then hand over pending records; the first handler failure
    /// throws `handler_failed`. A decision's fill is a replayed processing (09 § Requests Ledger):
    /// the Same-Account Rules run again on the pinned sender, and a record that fails them with
    /// `wrong_principal` / `bad_reference` (delivered as data while no principal was installed, or
    /// the request is already decided) changes nothing. Other errors fail `open`.
    private func recover() async throws {
        var pending: [(String, DeliveryRecord)] = []
        var decisions: [ParsedMessage] = []
        var replayChanged = false
        var live: [(String, DeliveryRecord)] = []
        // Covered by `replay.json` as written: deletable before any re-commit raises a horizon.
        for (key, rec) in try threads.deliveryRecords() {
            if rec.status == .acked && covered(rec.message) { try store.checkedDelete(key) } else { live.append((key, rec)) }
        }
        for (key, rec) in live {
            let m = rec.message
            if let snap = rec.thread {
                try store.withLock("threads") { try threads.repair(from: snap, recordKey: key) }
            }
            if fillsDecision(m.type) { decisions.append(m) }
            if try replay.accepts(m.messageId, from: m.from, timestamp: m.timestamp) {
                try replay.commit(m.messageId, from: m.from, timestamp: m.timestamp, floor: floor)
                replayChanged = true
            }
            if rec.status == .pending { pending.append((key, rec)) } else { acked[key] = (m.from, m.timestamp) }
        }
        if !decisions.isEmpty, let context = principalContext() {  // 1a: no-op when already filled
            // Pinned senders only (no network); read before the lock, as `PeerStore` is an actor.
            var senders: [String: VerifiedPeer] = [:]
            for from in Set(decisions.map(\.from)) { senders[from] = try await peers.get(from) }
            let now = clock()
            try store.withLock("requests") {
                for m in decisions {
                    guard let sender = senders[m.from] else { continue }
                    do {
                        try applyMessageRules(m, threads: nil, principal: context, sender: sender, now: now)
                    } catch let e as ACEError where e.code == .wrongPrincipal || e.code == .badReference {
                        continue
                    }
                    try fillDecision(store, m)
                }
            }
        }
        if replayChanged { try persistReplay() }
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
    /// closed inbox throws `invalid_argument`.
    public func receive(_ message: Data) async throws -> ReceiveOutcome {
        if closed { throw ACEError(.invalidArgument, "the inbox is closed") }
        if failed { return .retryable(ACEError(.storageFailed, "inbox is in a failed state; reopen it")) }
        return await receiveOne(message)
    }

    private func quarantine(_ error: ACEError, _ env: ACEMessage) throws -> ReceiveOutcome {
        let fp = envelopeFingerprint(env)
        try writeQuarantine(error, env, fp)
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

    private func receiveOne(_ data: Data) async -> ReceiveOutcome {
        let now = clock()
        // 1. decode
        let env: ACEMessage
        do { env = try decodeEnvelope(data) } catch {
            return .quarantined(.wrap(error, .invalidEnvelope), fingerprint: nil)
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
            do { return try quarantine(e, env) } catch { return .retryable(.wrap(error)) }
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
        let parsed: ParsedMessage
        let gate = PeekReplay(replay)
        do {
            parsed = try parseMessage(env, receiver: identity, sender: peer, gate: gate, floor: floor, clock: clock)
            // Step 6, installed schema: after decoding, before thread/principal checks.
            try validateInstalledSchema(schemas, SchemaMessage(type: parsed.type, schemaDigest: parsed.schemaDigest, threadId: parsed.threadId, body: parsed.body))
        }
        catch let e as ACEError { return rejected(e, env: env, verified: gate.verified) }
        catch { return .retryable(.wrap(error)) }
        if principal != nil && parsed.type.isPrincipal {
            do { peer = try await refreshPrincipalSender(env, peer: peer, now: now) }
            catch { return .retryable(.wrap(error)) }
        }
        // Actor reentrancy: another receive may have failed while this one was suspended at
        // step 3 or the refresh. Re-check after the last await, before taking any store lock.
        if failed { return .retryable(ACEError(.storageFailed, "inbox is in a failed state; reopen it")) }
        if closed { return .retryable(ACEError(.storageFailed, "inbox is closed")) }
        // 5–7: economic types under `threads`; a decision under `requests` from the
        // open-request check through the requests/ fill (R-P25)
        let economic = tracksThread(parsed.type)
        let lockName: String? = economic ? "threads" : fillsDecision(parsed.type) ? "requests" : nil
        let lock: (any ACEStoreLock)?
        do { lock = try lockName.map { try store.checkedLock($0, timeout: ACELimits.defaultLockTimeoutSeconds) } } catch {
            return .retryable(.wrap(error))
        }
        let committed = parseAndCommit(env, parsed: parsed, peer: peer, key: key, now: now, economic: economic)
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
            return await handOver(rec, key: key)
        }
    }

    private enum Committed {
        case done(ReceiveOutcome)
        case handOver(DeliveryRecord)
    }

    /// `verified`: the signature checked out (pipeline step 9 reached).
    private func rejected(_ e: ACEError, env: ACEMessage, verified: Bool) -> ReceiveOutcome {
        if e.code == .replay { return .duplicate(from: env.from, messageId: env.messageId) }
        if e.category != .permanent { return .retryable(e) }
        do {
            let outcome = try quarantine(e, env)
            // An authenticated message stays one-shot. No delivery record journals it, so its
            // commit is written now, on a copy swapped in only once written.
            if verified {
                let tr = replay.clone()
                if try tr.commit(env.messageId, from: env.from, timestamp: env.timestamp, floor: floor) {
                    try writeReplay(tr)
                    replay = tr
                    replayDirty = 0
                    try? pruneAcked()
                }
            }
            return outcome
        } catch { return .retryable(.wrap(error)) }
    }

    private func parseAndCommit(_ env: ACEMessage, parsed: ParsedMessage, peer: VerifiedPeer, key: String,
                                now: Int, economic: Bool) -> Committed {
        let machine: ThreadStateMachine
        let rec: StoredThread?
        do {
            if economic, let threadId = parsed.threadId {
                (rec, machine) = try threads.loadWithMachine(conversationId: env.conversationId, threadId: threadId)
            } else {
                rec = nil
                machine = try ThreadStateMachine(localAceId: localAceId)
            }
        } catch { return .done(.retryable(.wrap(error))) }
        do {
            // After the final await: actor reentrancy may have committed this message meanwhile.
            guard try replay.accepts(env.messageId, from: env.from, timestamp: env.timestamp) else {
                return .done(.duplicate(from: env.from, messageId: env.messageId))
            }
            try applyMessageRules(parsed, threads: economic ? machine : nil, principal: principalContext(), sender: peer, now: now)
            if economic && rec == nil { try threads.checkCanOpenThread(peer: env.from) }
        } catch let e as ACEError { return .done(rejected(e, env: env, verified: true)) }
        catch { return .done(.retryable(.wrap(error))) }
        let snap = economic ? parsed.threadId.flatMap { machine.getSnapshot(conversationId: env.conversationId, threadId: $0) } : nil
        let delivery = DeliveryRecord(fingerprint: envelopeFingerprint(env), message: parsed, receivedAt: now,
                                      status: .pending, thread: snap)
        do {
            try store.checkedWrite(key, try delivery.data()) // 7.1 commit point
        } catch {
            return .done(.retryable(.wrap(error)))
        }
        do {
            // 7.3 in memory; the record just written journals it until the next replay.json.
            try replay.commit(env.messageId, from: env.from, timestamp: env.timestamp, floor: floor)
            replayDirty += 1
            if fillsDecision(parsed.type) { try fillDecision(store, parsed) } // 7.1a: mark the request decided
            if let snap { try threads.write(StoredThread(snapshot: snap, pending: ThreadStore.clearProvenPending(rec, snap))) } // 7.2
        } catch {
            failed = true
            return .done(.retryable(.wrap(error)))
        }
        // A failed snapshot only delays pruning: the records still journal every commit.
        if replayDirty >= Self.replaySnapshotEvery { try? persistReplay() }
        return .handOver(delivery)
    }

    /// Step-7 context. `receiveOne` refreshes the sender before parsing, outside the
    /// `requests` lock.
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
    /// rules run on. Only a transient error propagates (retryable); a permanent error from the
    /// relay or adopt, or no relay, leaves the pinned binding to decide. The refreshed binding is
    /// adopted as is, including an encryption-key rotation; its signing key cannot differ (the
    /// ACE ID is the hash of the signing key). A forged envelope triggers no relay call; the
    /// pipeline rejects it later.
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
        guard let fresh, fresh.aceId == peer.aceId else { return peer }
        assert(fresh.signingPublicKey == peer.signingPublicKey, "ACE ID binds the signing key")
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

}

/// Pipeline steps 7 and 9 against the live seen store without writing it: the Inbox commits
/// only at its commit point. `verified` records that step 9 (after the signature) was reached.
private final class PeekReplay: ReplayGate {
    let replay: ReplayDetector
    private(set) var verified = false
    init(_ replay: ReplayDetector) { self.replay = replay }
    func accepts(_ messageId: String, from sender: String, timestamp: Int) throws -> Bool {
        try replay.accepts(messageId, from: sender, timestamp: timestamp)
    }
    func commit(_ messageId: String, from sender: String, timestamp: Int, floor: Int?) throws -> Bool {
        verified = true
        return try replay.accepts(messageId, from: sender, timestamp: timestamp)
    }
}

/// The `principal` option for a host's own saved principal record (09, R-B12a). The record is
/// P_self only while it validates for `identity`'s signing key at `now` (default: the wall
/// clock). No record is `(nil, nil)`; an invalid or expired one never throws but is
/// `(nil, "<code>: <detail>")` so the host decides how to surface it; a valid one binds its
/// `account` with the record's `signer` as `selfSigner` and the given `trustedSigners`.
public func inboxPrincipalFromOwnRecord(_ record: PrincipalRecord?, identity: any ACEIdentity, now: Int? = nil,
                                        trustedSigners: [PrincipalKey] = []) -> (principal: InboxPrincipal?, warning: String?) {
    guard let record else { return (nil, nil) }
    let own: PrincipalRecord
    do {
        own = try validatePrincipalRecord(record, subjectSigningPublicKey: identity.getSigningPublicKey(), now: now ?? systemClock())
    } catch let error as ACEError {
        return (nil, error.description)   // already `<code>: <detail>`
    } catch {
        return (nil, "invalid_principal: \(error)")
    }
    return (InboxPrincipal(account: own.account, selfSigner: own.signer, trustedSigners: Set(trustedSigners)), nil)
}
