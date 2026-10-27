//
//  Inbox.swift
//  ACE SDK
//
//  The receive pipeline (06 § Receive pipeline), exactly in its order, with admission (05), receipts, the core rules for
//  receipts and contacts, profile rules and the seen store (06 § Deduplication). Holds the store's `receive` lock.
//  An application message is journaled before any state changes: journal (pending, full message) → rules commit → seen →
//  host → journal removed. Every path that finds a pending entry commits its rules again (idempotent per messageId) and
//  finishes the hand-over.
//

import Foundation

/// An authenticated, decrypted and validated message handed to the host.
public struct ReceivedMessage: Sendable, Equatable {
    public let from: String
    public let to: String
    public let messageId: String
    public let timestamp: Int
    public let content: PrivateContent

    public var type: String { content.type }
    public var threadId: String? { content.threadId }
    public var body: [String: JSONValue] { content.body }
}

/// The disposition of one packet.
public enum ReceiveOutcome: Sendable, Equatable {
    /// New: committed, handed to the host (or applied as a receipt / contact) and receipted.
    case delivered(ReceivedMessage)
    /// Already in the seen store; `delivered` was receipted again.
    case duplicate
    /// Answered with a `rejected` receipt carrying `code` (or dropped for receipts and contacts).
    case rejected(String)
    /// Discarded silently (and acknowledged).
    case dropped(ACEError.Code)
    /// Not acknowledged; processed again on the next fetch.
    case retry(ACEError.Code)
    /// The host had no capacity: stop consuming; not acknowledged.
    case hold

    /// True when the relay entry may be acknowledged.
    public var isFinal: Bool {
        switch self {
        case .retry, .hold: return false
        default: return true
        }
    }
}

private struct Reject: Error {
    let code: String
}

/// The `delivered` receipt of a packet already processed (delivered or a duplicate) failed transiently: a retry.
/// `outcome` is the processed packet's own (`delivered`/`duplicate`), returned once the fetch budget is spent.
private struct ReceiptUnsent: Error {
    let error: ACEError
    let outcome: ReceiveOutcome
}


/// The Inbox of one identity, owned by its `NetworkClient`. Every pass through the pipeline (`receive`, a `pull` page,
/// a `follow` entry) runs alone, in arrival order: the actor would otherwise interleave two passes at their suspension
/// points and hand one message over twice. `onMessage` must persist the host effect durably and idempotently, keyed by
/// `(from, messageId)`; throwing `receiver_capacity` holds the inbox, any other throw retries.
package actor Inbox {
    private static let snapshotKey = "inbox/seen.json"
    private static let journalPrefix = "inbox/journal/"
    private static let pendingPrefix = "inbox/pending/"
    private static let attemptsPrefix = "inbox/attempts/"
    private static let compactEvery = 256

    private unowned let network: NetworkClient
    private let identity: any ACEIdentity
    private let store: any ACEStore
    private let onMessage: (@Sendable (ReceivedMessage) async throws -> Void)?
    private let clock: @Sendable () -> Int
    private var lock: (any ACEStoreLock)?
    private var seen: ReplayDetector
    private var journal: Int
    private var lastRefresh: [String: Int] = [:]
    /// The serial section: one pass at a time; a waiting pass is resumed by the one before it.
    private var busy = false
    private var waiters: [CheckedContinuation<Void, Never>] = []

    private init(network: NetworkClient, store: any ACEStore, lock: any ACEStoreLock, seen: ReplayDetector, journal: Int,
                 onMessage: (@Sendable (ReceivedMessage) async throws -> Void)?, clock: @escaping @Sendable () -> Int) {
        self.network = network
        self.identity = network.identity
        self.store = store
        self.lock = lock
        self.seen = seen
        self.journal = journal
        self.onMessage = onMessage
        self.clock = clock
    }

    /// Take the `receive` lock (`lock_busy` when held) and load the seen store (snapshot plus journal).
    package static func open(network: NetworkClient, onMessage: (@Sendable (ReceivedMessage) async throws -> Void)?,
                             capacity: Int = ACELimits.defaultReplayCapacity, clock: @escaping @Sendable () -> Int = systemClock) async throws -> Inbox {
        let store = network.store
        let held = try store.checkedLock("receive", timeout: 0)
        do {
            let journalKeys = try store.checkedList(journalPrefix)
            let seen: ReplayDetector
            if let raw = try store.checkedRead(snapshotKey) {
                do { seen = try ReplayDetector(state: try ReplayState(json: raw), capacity: capacity, clock: clock) } catch {
                    throw ACEError(.storageFailed, "\(snapshotKey) is corrupt")
                }
            } else {
                guard journalKeys.isEmpty else { throw ACEError(.storageFailed, "seen store snapshot missing beside its journal") }
                seen = try ReplayDetector(capacity: capacity, clock: clock)
                try store.checkedWrite(snapshotKey, seen.exportState().jsonData())
            }
            var last = 0
            for key in journalKeys {
                guard let raw = try store.checkedRead(key), let v = JSONValue(stored: raw), let id = v["messageId"]?.stringValue,
                      let from = v["from"]?.stringValue, let ts = v["timestamp"]?.wireInt,
                      let n = Int(key.dropFirst(journalPrefix.count).dropLast(5)) else { throw ACEError(.storageFailed, "\(key) is corrupt") }
                _ = try seen.commit(id, from: from, timestamp: ts)
                last = max(last, n)
            }
            let inbox = Inbox(network: network, store: store, lock: held, seen: seen, journal: last, onMessage: onMessage, clock: clock)
            // A failed recovery leaves the entry pending: the redelivered packet (never acknowledged) finishes it.
            for key in try store.checkedList(pendingPrefix) { _ = try? await inbox.recover(key) }
            return inbox
        } catch {
            held.release()
            throw error
        }
    }

    private func enter() async {
        if busy { await withCheckedContinuation { waiters.append($0) } } else { busy = true }
    }

    private func leave() {
        if waiters.isEmpty { busy = false } else { waiters.removeFirst().resume() }
    }

    private func serialized<T>(_ body: () async throws -> T) async rethrows -> T {
        await enter()
        defer { leave() }
        return try await body()
    }

    /// Persist the seen store and release the `receive` lock, after the pass in progress. Idempotent.
    package func close() async {
        await serialized {
            guard let held = lock else { return }
            try? compact()
            held.release()
            lock = nil
        }
    }

    private func compact() throws {
        try store.checkedWrite(Self.snapshotKey, seen.exportState().jsonData())
        for key in try store.checkedList(Self.journalPrefix) { try store.checkedDelete(key) }
    }

    /// The journal key of entry `n`: 20 zero-padded digits, so key order is numeric order.
    static func journalKey(_ n: Int) -> String {
        let digits = String(n)
        return journalPrefix + String(repeating: "0", count: max(0, 20 - digits.count)) + digits + ".json"
    }

    private func record(_ messageId: String, from: String, timestamp: Int) throws {
        journal += 1
        let key = Self.journalKey(journal)
        let v: JSONValue = ["messageId": .string(messageId), "from": .string(from), "timestamp": .number(Double(timestamp))]
        try store.checkedWrite(key, try v.jsonData())
    }

    // MARK: Fetching

    /// One pass over the relay inbox: process entries in stream order, stop at the first entry without a final
    /// disposition, and acknowledge through the last entry with one. Repeats while pages are full, at most `maxPages`.
    package func pull(limit: Int, maxPages: Int? = nil) async throws -> [ReceiveOutcome] {
        if let maxPages, maxPages < 1 { throw ACEError(.invalidArgument, "maxPages must be at least 1") }
        return try await serialized {
            guard lock != nil else { throw ACEError(.invalidArgument, "the inbox is closed") }
            var outcomes: [ReceiveOutcome] = []
            for _ in 1...(maxPages ?? .max) {
                let page = try await network.relay.fetchInbox(identity, since: nil, limit: limit)
                var through: String?
                var stopped = false
                for entry in page.entries {
                    let outcome = await fetched(entry.packet)
                    outcomes.append(outcome)
                    guard outcome.isFinal else { stopped = true; break }
                    through = entry.streamId
                }
                if let through { try await network.relay.ackInbox(identity, through: through) }
                if stopped || page.entries.count < limit || through == nil { break }
            }
            return outcomes
        }
    }

    /// One entry delivered by `listen`: processed, and acknowledged when its disposition is final.
    package func followed(_ event: RelayClient.Event) async throws -> ReceiveOutcome {
        try await serialized {
            guard lock != nil else { throw ACEError(.invalidArgument, "the inbox is closed") }
            let outcome = await fetched(event.packet)
            if outcome.isFinal { try await network.relay.ackInbox(identity, through: event.streamId) }
            return outcome
        }
    }

    /// `evaluate` plus the poison counter (06 § Acknowledgement): the fetches of a packet that ended in `retry` are
    /// counted in `inbox/attempts/<fingerprint>.json` (a suppressed pin refresh included: a forged packet naming a newer
    /// delegation must not block the inbox); at `MAX_FETCH_ATTEMPTS` the packet is quarantined and dropped. `hold` (the
    /// host has no capacity) is not a failure of the packet and does not count. Any final outcome removes the counter.
    /// The quarantine keeps the failure and the packet header only (`quarantine`). A packet already processed whose
    /// `delivered` receipt kept failing is acknowledged without a quarantine record and returns its own outcome
    /// (`delivered`/`duplicate`): the message was handled, and the sender's retry is deduplicated and receipted.
    private func fetched(_ packet: Data) async -> ReceiveOutcome {
        let (outcome, reason, processed) = await evaluated(packet)
        let fp = sha256Hex(packet), key = Self.attemptsPrefix + fp + ".json"
        if outcome.isFinal {
            try? store.checkedDelete(key)
            return outcome
        }
        guard case .retry(let code) = outcome else { return outcome }
        let attempts = (((try? store.readJSON(key)) ?? nil)?["attempts"]?.wireInt ?? 0) + 1
        guard attempts >= ACELimits.maxFetchAttempts else {
            try? store.checkedWrite(key, try! JSONValue.object(["attempts": .number(Double(attempts))]).jsonData())
            return outcome
        }
        try? store.checkedDelete(key)
        if let processed { return processed }
        try? quarantine(packet, fingerprint: fp, code: code, reason: reason)
        return .dropped(code)
    }

    static let quarantinePrefix = "inbox/quarantine/"
    /// Past `quarantineCap` records the oldest are deleted down to `quarantineKeep` (sdk-py, sdk-ts).
    static let quarantineCap = 1000
    static let quarantineKeep = 900

    /// Record `{fingerprint, code, reason, quarantinedAt, packet}`: the failure (its message cut to 1000 characters) and
    /// the packet's header (`quarantineHeader`), never its ciphertext or signature, so a record is a few hundred bytes and
    /// the cap bounds the quarantine's disk use. Past the cap the oldest by `quarantinedAt` go first (unreadable ones
    /// count as oldest).
    private func quarantine(_ packet: Data, fingerprint: String, code: ACEError.Code, reason: String) throws {
        let record: JSONValue = ["fingerprint": .string(fingerprint), "code": .string(code.rawValue),
                                 "reason": .string(Self.prefix(reason, 1000)), "quarantinedAt": .number(Double(try now())),
                                 "packet": Self.quarantineHeader(packet)]
        try store.checkedWrite(Self.quarantinePrefix + fingerprint + ".json", try record.jsonData())
        let keys = try store.checkedList(Self.quarantinePrefix)
        guard keys.count > Self.quarantineCap else { return }
        let aged = keys.map { k in ((((try? store.readJSON(k)) ?? nil)?["quarantinedAt"]?.wireInt ?? 0), k) }
        for (_, k) in aged.sorted(by: { ($0.0, $0.1) < ($1.0, $1.1) }).prefix(keys.count - Self.quarantineKeep) {
            try store.checkedDelete(k)
        }
    }

    /// The scalar header fields of a (possibly malformed) packet: `ace`, `from`, `to`, `messageId`, `timestamp` and
    /// `prekey` (`encryption.prekey`), each kept only as a string (cut to 256 characters) or a wire integer; null when the
    /// packet is not a JSON object.
    static func quarantineHeader(_ packet: Data) -> JSONValue {
        guard let o = (try? JSONParser.parse(packet))?.objectValue else { return .null }
        var fields = o
        fields["prekey"] = o["encryption"]?["prekey"]
        var out: [String: JSONValue] = [:]
        for k in ["ace", "from", "to", "messageId", "timestamp", "prekey"] {
            if let s = fields[k]?.stringValue {
                out[k] = .string(prefix(s, 256))
            } else if let n = fields[k]?.wireInt {
                out[k] = .number(Double(n))
            }
        }
        return .object(out)
    }

    /// The first `n` Unicode scalars of `s`.
    private static func prefix(_ s: String, _ n: Int) -> String { String(String.UnicodeScalarView(s.unicodeScalars.prefix(n))) }

    // MARK: Pipeline

    /// Process one packet (its JSON bytes) through the receive pipeline.
    package func receive(_ data: Data) async -> ReceiveOutcome {
        await serialized { await evaluate(data) }
    }

    private func evaluate(_ data: Data) async -> ReceiveOutcome { await evaluated(data).outcome }

    /// The outcome and, for a failure, its error message; `processed`: the packet's own outcome when the retry is only
    /// because the `delivered` receipt of a packet already processed was not sent.
    private func evaluated(_ data: Data) async -> (outcome: ReceiveOutcome, reason: String, processed: ReceiveOutcome?) {
        do {
            return (try await pipeline(data), "", nil)
        } catch let r as Reject {
            return (.rejected(r.code), "\(r)", nil)
        } catch let u as ReceiptUnsent {
            return (.retry(u.error.code), u.error.message, u.outcome)
        } catch let e as ACEError {
            return (e.category == .permanent ? .dropped(e.code) : .retry(e.code), e.message, nil)
        } catch {
            return (.retry(.storageFailed), "\(error)", nil)
        }
    }

    private func now() throws -> Int { try unixNow(clock) }

    private func pipeline(_ data: Data) async throws -> ReceiveOutcome {
        // 1. decode; `to` is the local identity
        let packet = try Packet(json: data)
        let me = identity.getACEId()
        guard packet.to == me else { throw ACEError(.wrongRecipient) }
        // 2. admission
        let record = try network.admission.get(packet.from)
        guard record?.state != .blocked else { throw ACEError(.notPermitted, "sender is blocked") }
        // 3. the sender's pin, refreshed once when the packet names a newer delegation. A stranger, or a peer in the table
        // without a pin (e.g. pending), is authenticated only by an admission proof or a contact packet's `source`.
        guard let record, var state = try await network.peers.pinned(packet.from) else {
            return try await unauthenticated(packet, record: record, recoverable: true)
        }
        if packet.signature.seq > (state.signing?.seq ?? -1) {
            let t = try now()
            // A suppressed refresh is a retry, never a drop; like any retry it counts toward the quarantine.
            if let last = lastRefresh[packet.from], t - last < ACELimits.pinRefreshIntervalSeconds {
                throw ACEError(.relayUnavailable, "pin refresh suppressed")
            }
            lastRefresh = lastRefresh.filter { t - $0.value < ACELimits.pinRefreshIntervalSeconds }
            lastRefresh[packet.from] = t  // every attempt counts, a failed one too (06 step 3: at most once per interval)
            do {
                state = try await network.agent(packet.from, refresh: true).state
            } catch let e as ACEError where e.category != .permanent {
                throw e
            } catch {
                // A permanent failure (e.g. a peer after a signing-key change that has not republished its descriptor
                // yet): the packet continues only as a contact candidate checked against the pin.
                return try await unauthenticated(packet, record: record, recoverable: false)
            }
            if packet.signature.seq > (state.signing?.seq ?? -1) { return try await unauthenticated(packet, record: record, recoverable: false) }
        }
        // 4. signature (01 § Operational signatures: the sender usable now), 5. time window
        let now = try now()
        try verifyPacketSignature(packet, sender: state, now: now)
        try checkPacketTime(packet, now: now)
        // 6. decrypt (an unknown prekey or an unparsable plaintext is rejected; the type is not known yet). A storage
        // failure of the vault is a retry.
        let content: PrivateContent
        do {
            content = try PrivateContent(json: try decrypt(packet, now: now))
        } catch let e as ACEError where e.code == .unknownPrekey || e.code == .invalidBody {
            // L1: an unknown_prekey rejection names the prekey it could not open (06 § Receipts).
            try await sendReceipt(to: packet.from, messageId: packet.messageId, outcome: "rejected", code: e.outcomeCode,
                                  prekey: e.code == .unknownPrekey ? packet.encryption.prekey : nil)
            return .rejected(e.outcomeCode)
        }
        return try await authenticated(packet, content: content, state: state, record: record, now: now)
    }

    /// Step 6 (`unknown_prekey`, `decryption_failed`, `invalid_body` for bad padding), then the issuer rule (04 § Peer
    /// prekeys): a packet that opened under the key we offered `from` makes it the in-use key, whatever its disposition from
    /// step 7 on. The content bytes, not yet decoded.
    private func decrypt(_ packet: Packet, now: Int) throws -> Data {
        guard let seed = try network.prekeys.open(packet.encryption.prekey, sender: packet.from, now: now) else { throw ACEError(.unknownPrekey) }
        let plaintext = try decryptPlaintext(packet, seed: seed)
        try network.prekeys.used(peer: packet.from, prekeyId: packet.encryption.prekey, now: now)
        return plaintext
    }

    /// Steps 7–11 for an authenticated, decrypted packet (`state`: the sender's pin, from step 3 or the recovery path). The
    /// holder rule first (04 § Peer prekeys): the key the content offers is held for the sender under that pin when the
    /// packet is newer than the one that carried the held key (a duplicate records too); contact packets record nothing.
    /// A message's `admission` (never on a core packet: decoding refuses it, 03 § Private content) has its reply permit
    /// held like a receipt renewal (05 § Admission recovery) and never reaches the host; neither does `prekey`.
    private func authenticated(_ packet: Packet, content carried: PrivateContent, state: KelState, record: AdmissionRecord?,
                               now: Int) async throws -> ReceiveOutcome {
        let me = identity.getACEId()
        let core = carried.type == CoreTypes.receipt || carried.type == CoreTypes.contact
        if carried.type != CoreTypes.contact, let offered = carried.prekey {
            try network.prekeys.hold(peer: packet.from, prekey: try Prekey(publicKey: offered), timestamp: packet.timestamp, pin: state.lastHash)
        }
        var content = carried.with(admission: nil)
        content.prekey = nil  // the offered peer prekey never reaches the host
        do {
            if let admission = carried.admission {
                try await network.holdTheirPermit(admission.permit, from: packet.from) { $0.map { $0.state != .blocked } ?? false }
            }
            // 7–8. installed schema, body
            try network.profiles.validate(content)
            // 9. dedupe before any rule runs: a retried message is never judged against state it already changed; an
            // interrupted hand-over is finished first
            let pending = Self.pendingKey(packet.from, packet.messageId)
            if !core, try store.checkedRead(pending) != nil {
                guard try await recover(pending) else { return .hold }
                try await receiptDelivered(to: packet.from, messageId: packet.messageId, outcome: .duplicate)
                return .duplicate
            }
            if seen.contains(packet.messageId, from: packet.from) {
                if !core { try await receiptDelivered(to: packet.from, messageId: packet.messageId, outcome: .duplicate) }
                return .duplicate
            }
            // beyond the horizon: dropped, never receipted; the sender's next retry carries a fresh timestamp (06 § Deduplication)
            if seen.covers(sender: packet.from, timestamp: packet.timestamp) { return .dropped(.replayHorizon) }
            // 10. core rules, profile rules, then commit
            let event = ProfileEvent(direction: .receive, from: packet.from, to: me, messageId: packet.messageId, timestamp: packet.timestamp,
                                     type: content.type, threadId: content.threadId)
            var source: VerifiedAgent?
            if content.type == CoreTypes.receipt { try checkReceipt(content.body, state: state, now: now) }
            if content.type == CoreTypes.contact {
                // verified against the pin; the pin itself moves only once the rules below pass (06 step 10)
                let s = try await verifiedSource(content.body["source"] ?? .null, from: packet.from, pinned: state, now: now)
                source = try checkContact(content.body, record: record, source: s, now: now)
            }
            // 10. busy-thread check, then the profile rules (08 § Sender state and busy threads)
            if let threadId = content.threadId, network.outbox.governs(content.type),
               try await network.outbox.busy(to: packet.from, threadId: threadId) != nil {
                throw Reject(code: ACEError.Code.threadBusy.rawValue)  // rejected with a receipt, not retried
            }
            try network.configuration.rules.check(event, body: content.body)
            // an admitted peer's newer KEL may be pinned; an older source falls back to the held descriptor (04 § Caching)
            if let source { try await network.peers.adoptOrUsable(source) }
            let message = ReceivedMessage(from: packet.from, to: me, messageId: packet.messageId, timestamp: packet.timestamp, content: content)
            switch content.type {
            case CoreTypes.receipt, CoreTypes.contact:
                try network.configuration.rules.commit(event, body: content.body)
                if content.type == CoreTypes.receipt { try await applyReceipt(from: packet.from, content.body) }
                else { try await network.receivedContact(from: packet.from, body: content.body, source: source!) }
                try commitSeen(packet.messageId, from: packet.from, timestamp: packet.timestamp, now: now)
            default:
                try store.checkedWrite(pending, try Self.pendingRecord(message).jsonData())
                do { try network.configuration.rules.commit(event, body: content.body) } catch {
                    try? store.checkedDelete(pending)
                    throw error
                }
                try commitSeen(packet.messageId, from: packet.from, timestamp: packet.timestamp, now: now)
                guard try await handOver(message, key: pending) else { return .hold }
            }
            // 11. receipt, then acknowledgement (by the caller)
            if !core { try await receiptDelivered(to: packet.from, messageId: packet.messageId, outcome: .delivered(message)) }
            return .delivered(message)
        } catch let r as Reject {
            if core { return .dropped(ACEError.Code(rawValue: r.code) ?? .invalidBody) }
            try await sendReceipt(to: packet.from, messageId: packet.messageId, outcome: "rejected", code: r.code)
            return .rejected(r.code)
        } catch let e as ACEError where e.category == .permanent {
            if core { return .dropped(e.code) }
            try await sendReceipt(to: packet.from, messageId: packet.messageId, outcome: "rejected", code: e.outcomeCode)
            return .rejected(e.outcomeCode)
        }
    }

    private func commitSeen(_ messageId: String, from: String, timestamp: Int, now: Int) throws {
        // Journal first (a failed write leaves `seen` unchanged), then memory, then any compaction of the committed state.
        guard try seen.accepts(messageId, from: from, timestamp: timestamp) else { return }
        try record(messageId, from: from, timestamp: timestamp)
        try seen.commit(messageId, from: from, timestamp: timestamp, floor: ReplayDetector.floor(now))
        if journal % Self.compactEvery == 0 { try compact() }
    }

    // MARK: Delivery journal

    private static func pendingKey(_ from: String, _ messageId: String) -> String {
        pendingPrefix + pairDigest(from, messageId) + ".json"
    }

    private static func pendingRecord(_ m: ReceivedMessage) -> JSONValue {
        ["from": .string(m.from), "to": .string(m.to), "messageId": .string(m.messageId), "timestamp": .number(Double(m.timestamp)),
         "content": m.content.jsonValue]
    }

    /// Hand a journaled message to the host, then remove its journal entry; false when the host has no capacity (the entry
    /// stays pending).
    private func handOver(_ message: ReceivedMessage, key: String) async throws -> Bool {
        do { try await onMessage?(message) } catch let e as ACEError where e.code == .receiverCapacity { return false }
        catch let e as ACEError { throw ACEError(e.category == .permanent ? .storageFailed : e.code, e.message) }
        catch { throw ACEError(.storageFailed, "\(error)") }
        try store.checkedDelete(key)
        return true
    }

    /// Finish an interrupted hand-over from its journal entry: the rules' `commit` again (idempotent per messageId), the
    /// seen entry, then the host. A transient failure leaves the entry pending; a rule refusing the commit (it never ran)
    /// removes it and throws. False when the host has no capacity.
    private func recover(_ key: String) async throws -> Bool {
        guard let raw = try store.checkedRead(key) else { return true }
        guard let v = JSONValue(stored: raw), let from = v["from"]?.stringValue, let to = v["to"]?.stringValue,
              let id = v["messageId"]?.stringValue, let ts = v["timestamp"]?.wireInt, let c = v["content"]?.objectValue,
              let content = PrivateContent(stored: c) else {
            throw ACEError(.storageFailed, "\(key) is corrupt")
        }
        let message = ReceivedMessage(from: from, to: to, messageId: id, timestamp: ts, content: content)
        let event = ProfileEvent(direction: .receive, from: from, to: to, messageId: id, timestamp: ts, type: content.type, threadId: content.threadId)
        do { try network.configuration.rules.commit(event, body: content.body) } catch let e as ACEError where e.category == .permanent {
            try store.checkedDelete(key)
            throw e
        }
        try commitSeen(id, from: from, timestamp: ts, now: try now())
        return try await handOver(message, key: key)
    }

    /// One receipt attempt (06 § Receipts). A renewal permit it carries counts as issued only once it was sent (05 §
    /// Delivery permits). A transient failure is a retry (the sender's retry is deduplicated and receipted again); no
    /// route means no receipt.
    private func sendReceipt(to peer: String, messageId: String, outcome: String, code: String? = nil, prekey: String? = nil) async throws {
        var body: [String: JSONValue] = ["messageId": .string(messageId), "outcome": .string(outcome)]
        if let code { body["code"] = .string(code) }
        if let prekey { body["prekey"] = .string(prekey) }
        let renewal = try await network.renewalPermit(for: peer)
        if let renewal { body["permit"] = renewal }
        do {
            try await network.sendCore(to: peer, type: CoreTypes.receipt, body: body)
        } catch let e as ACEError where e.category != .permanent {
            throw e
        } catch {
            return
        }
        if let renewal { try network.admission.noteIssued(peer, permit: renewal) }
    }

    /// The `delivered` receipt of a packet already processed; a transient failure is `ReceiptUnsent` (see `fetched`).
    private func receiptDelivered(to peer: String, messageId: String, outcome: ReceiveOutcome) async throws {
        do {
            try await sendReceipt(to: peer, messageId: messageId, outcome: "delivered")
        } catch let e as ACEError where e.category != .permanent {
            throw ReceiptUnsent(error: e, outcome: outcome)
        }
    }

    // MARK: Core rules

    /// The core receipt rules, then a renewal permit valid with issuer = sender, subject = self.
    private func checkReceipt(_ body: [String: JSONValue], state: KelState, now: Int) throws {
        try checkReceiptBody(.object(body))
        if let permit = body["permit"] {
            guard (try? verifyPermit(permit, issuer: state, subject: identity.getACEId(), now: now)) != nil else {
                throw ACEError(.invalidBody, "receipt.permit is not valid")
            }
        }
    }

    private func applyReceipt(from: String, _ body: [String: JSONValue]) async throws {
        if let permit = body["permit"] { try await network.holdTheirPermit(permit, from: from) { $0.map { $0.state != .blocked } ?? false } }
        let entry = try await network.outbox.handleReceipt(from: from, body: body)
        await network.configuration.onReceipt?(from, body, entry)
    }

    /// An embedded PublishedAgent (a contact's `source`, a recovery's `admission.source`) verified as naming `from`, never
    /// older than the pin (01 § Pinning; a stranger usually has none).
    private func verifiedSource(_ raw: JSONValue, from: String, pinned: KelState?, now: Int) async throws -> VerifiedAgent {
        guard raw["descriptor"]?["aceId"]?.stringValue == from else { throw ACEError(.invalidAuthorization, "source does not name the sender") }
        let pins = try await network.peers.delegationPins(for: raw)
        return try verifyPublishedAgent(raw, now: now, allowLoopback: network.configuration.allowLoopbackRelays, pinned: pinned, delegationPins: pins)
    }

    /// The contact rules beyond the verified `source`: note bytes, the profile is installed here with the digest the source
    /// lists, the permit (request / accepted) is issued by `from` to us; a reply needs a `pending` entry for that profile.
    private func checkContact(_ body: [String: JSONValue], record: AdmissionRecord?, source: VerifiedAgent, now: Int) throws -> VerifiedAgent {
        let me = identity.getACEId()
        guard let note = body["note"]?.stringValue, note.utf8.count <= ACELimits.maxNoteBytes, let kind = body["kind"]?.stringValue,
              let profile = body["profile"]?.stringValue else { throw ACEError(.invalidBody, "contact body") }
        guard let mine = network.profiles.manifest(profile), mine.id != ProfileManifest.core.id, source.descriptor.profiles.contains(mine.ref) else {
            throw ACEError(.invalidBody, "contact profile is not shared")
        }
        if kind == "rejected" {
            guard body["permit"] == nil else { throw ACEError(.invalidBody, "rejected contacts carry no permit") }
        } else {
            guard let permit = body["permit"], (try? verifyPermit(permit, issuer: source.state, subject: me, now: now)) != nil else {
                throw ACEError(.invalidBody, "contact permit is not valid")
            }
        }
        if kind != "request" {
            // A reply to our pending request for this profile, or (admitted) the answer to a permit refresh.
            guard let record, record.acceptsReply(profile: profile) else {
                throw ACEError(.notPermitted, "unexpected contact reply")
            }
        }
        return source
    }

    /// A sender the receiver cannot authenticate from a pin: 5, 6, 7 first (a stranger costs one decapsulation; at a
    /// `closed` agent its relays queued it only on a permit we issued). A message whose `admission.proof` is valid is a
    /// recovery candidate when `recoverable` (no pin at all); otherwise only a contact candidate goes on, a stranger's only
    /// at an `open` agent (05 § Receiver admission). Every failure is a silent drop.
    private func unauthenticated(_ packet: Packet, record: AdmissionRecord?, recoverable: Bool) async throws -> ReceiveOutcome {
        let now = try now()
        guard (try? checkPacketTime(packet, now: now)) != nil else { return .dropped(.staleTimestamp) }
        let content: PrivateContent
        do { content = try PrivateContent(json: try decrypt(packet, now: now)) } catch let e as ACEError where e.category == .permanent {
            return .dropped(e.code)
        }
        if recoverable, let admission = content.admission, validProof(admission.proof, from: packet.from, now: now) {
            return try await recovered(packet, content: content, admission: admission, now: now)
        }
        // 05 § Flow: strangers only while this identity's published card record is `open` (no record is `closed`).
        if record == nil, try network.publishedContact() != .open { return .dropped(.notPermitted) }
        return try await contactCandidate(packet, content: content, record: record, now: now)
    }

    /// `proof` is a permit we issued to `from`, valid under our current KEL now (05 § Admission recovery step 2): a local
    /// check of our own signature, before any network lookup.
    private func validProof(_ proof: JSONValue, from: String, now: Int) -> Bool {
        guard let mine = try? checkUsable(identity, now: now) else { return false }
        return (try? verifyPermit(proof, issuer: mine, subject: from, now: now)) != nil
    }

    /// Admission recovery (05 § Admission recovery step 3), with no network lookup: an uninstalled type is dropped; the
    /// carried `source` must verify naming the sender under the pin rules (01 § Pinning), and the packet signature and the
    /// reply permit under it. Only then is the sender recorded `admitted` (a new row with no profile; a block recorded
    /// meanwhile wins) with `proof` as the newest permit issued to it, `source` pinned, the permit held, and step 8 follows.
    private func recovered(_ packet: Packet, content: PrivateContent, admission: Admission, now: Int) async throws -> ReceiveOutcome {
        let from = packet.from
        guard network.profiles.installs(content) else { return .dropped(.unsupportedSchema) }
        let source: VerifiedAgent
        do {
            source = try await verifiedSource(admission.source, from: from, pinned: try await network.peers.pinned(from), now: now)
            try verifyPacketSignature(packet, sender: source.state, now: now)
            guard (try? verifyPermit(admission.permit, issuer: source.state, subject: identity.getACEId(), now: now)) != nil else {
                throw ACEError(.invalidAuthorization, "admission permit is not valid")
            }
        } catch let e as ACEError where e.category == .permanent {
            return .dropped(e.code)
        }
        var blocked = false
        let record = try network.admission.update(from) { r in
            guard r?.state != .blocked else { blocked = true; return r }
            var r = r ?? AdmissionRecord(aceId: from, state: .admitted, updatedAt: 0)
            r.state = .admitted
            if (r.issuedPermit?["issuedAt"]?.wireInt ?? -1) < (admission.proof["issuedAt"]?.wireInt ?? 0) { r.issuedPermit = admission.proof }
            return r
        }
        if blocked { return .dropped(.notPermitted) }
        try await network.peers.adoptOrUsable(source)
        return try await authenticated(packet, content: content, state: source.state, record: record, now: now)
    }

    /// The contact-candidate path: no pinned KEL, so only an `ace:contact:1` packet is processed, authenticated by its
    /// embedded `source` (1, 2, 5, 6, 7, 8, authenticate by `source`, 9, 10, ack). A stranger (`record` nil,
    /// `open` agents only) may only send `request` and is never pinned; a peer already in the table (e.g. pending) may send
    /// any kind. Every failure is a silent drop.
    private func contactCandidate(_ packet: Packet, content: PrivateContent, record: AdmissionRecord?, now: Int) async throws -> ReceiveOutcome {
        let stranger = record == nil
        guard content.type == CoreTypes.contact, !stranger || content.body["kind"] == "request",
              (try? network.profiles.validate(content)) != nil else {
            return .dropped(.notPermitted)
        }
        let source: VerifiedAgent
        do {
            let raw = content.body["source"] ?? .null
            // M5: a stranger's source is bounded before any of its signatures is verified (05 § Receiver admission).
            if stranger { try checkStrangerSource(raw) }
            // A stranger usually has no pin; a peer in the table may (its pin bounds the source, 01 § Pinning).
            let s = try await verifiedSource(raw, from: packet.from, pinned: try await network.peers.pinned(packet.from), now: now)
            source = try checkContact(content.body, record: record, source: s, now: now)
            try verifyPacketSignature(packet, sender: source.state, now: now)
        } catch let e as ACEError where e.category == .permanent {
            return .dropped(e.code)
        }
        // 9 before any profile rule (06 § Receive pipeline).
        if seen.contains(packet.messageId, from: packet.from) { return .duplicate }
        if seen.covers(sender: packet.from, timestamp: packet.timestamp) { return .dropped(.replayHorizon) }
        do {
            try network.configuration.rules.check(ProfileEvent(direction: .receive, from: packet.from, to: packet.to, messageId: packet.messageId,
                                                               timestamp: packet.timestamp, type: content.type, threadId: content.threadId),
                                                  body: content.body)
        } catch let e as ACEError where e.category == .permanent {
            return .dropped(e.code)
        }
        if !stranger { try await network.peers.adoptOrUsable(source) }
        try await network.receivedContact(from: packet.from, body: content.body, source: source)
        try commitSeen(packet.messageId, from: packet.from, timestamp: packet.timestamp, now: now)
        var delivered = content
        delivered.prekey = nil  // the offered peer prekey never reaches the host
        return .delivered(ReceivedMessage(from: packet.from, to: packet.to, messageId: packet.messageId, timestamp: packet.timestamp,
                                          content: delivered))
    }
}

/// The core receipt rules beyond the schema (06 § Receipts), `invalid_body`: `messageId` a UUIDv4; `code` exactly when
/// rejected (outcome-code grammar); `prekey` (64 lowercase hex) exactly when `code` is `unknown_prekey`; `permit` an object.
public func checkReceiptBody(_ body: JSONValue) throws {
    guard let o = body.objectValue, let id = o["messageId"]?.stringValue, isMessageId(id) else {
        throw ACEError(.invalidBody, "receipt messageId must be a UUIDv4")
    }
    let rejected = o["outcome"] == "rejected"
    if let code = o["code"] {
        guard rejected, let s = code.stringValue, isOutcomeCode(s) else { throw ACEError(.invalidBody, "receipt code must be present exactly when rejected") }
    } else if rejected {
        throw ACEError(.invalidBody, "receipt code must be present exactly when rejected")
    }
    let unknownPrekey = o["code"] == "unknown_prekey"
    if let prekey = o["prekey"] {
        guard unknownPrekey, let s = prekey.stringValue, isSHA256Hex(s) else {
            throw ACEError(.invalidBody, "receipt prekey must be present exactly with unknown_prekey")
        }
    } else if unknownPrekey {
        throw ACEError(.invalidBody, "receipt prekey must be present exactly with unknown_prekey")
    }
    if let permit = o["permit"], permit.objectValue == nil { throw ACEError(.invalidBody, "receipt permit must be an object") }
}

/// The outcome-code grammar `^[a-z0-9_]{1,64}$`.
public func isOutcomeCode(_ value: String) -> Bool {
    let u = Array(value.utf8)
    return (1...64).contains(u.count) && u.allSatisfy { ($0 >= 0x61 && $0 <= 0x7A) || ($0 >= 0x30 && $0 <= 0x39) || $0 == 0x5F }
}
