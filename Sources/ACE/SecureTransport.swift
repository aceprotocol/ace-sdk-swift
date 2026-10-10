import Foundation

/// The Inbox's verdict on the inner envelope, carried to the sender in the receipt (`SecureAccept`).
public enum SecureOutcome: Sendable, Equatable {
    case delivered
    case duplicate
    /// The Inbox permanently refused the envelope; `code` is its error code (`^[a-z0-9_]{1,64}$`).
    case rejected(code: String)
    var receipt: String {
        switch self {
        case .delivered: return "delivered"
        case .duplicate: return "duplicate"
        case .rejected(let code): return "rejected:\(code)"
        }
    }
    init?(receipt: String) {
        switch receipt {
        case "delivered": self = .delivered
        case "duplicate": self = .duplicate
        default:
            guard receipt.hasPrefix("rejected:"), isRemoteCode(String(receipt.dropFirst(9))) else { return nil }
            self = .rejected(code: String(receipt.dropFirst(9)))
        }
    }
    /// The Inbox verdict for a `SecureAccept`. A retryable outcome throws so the frame is not completed.
    public init(_ outcome: ReceiveOutcome) throws {
        switch outcome {
        case .delivered: self = .delivered
        case .duplicate: self = .duplicate
        // A permanent rejection is a completed frame: the verdict travels to the sender in the receipt.
        case .quarantined(let error, _): self = .rejected(code: error.code.rawValue)
        case .retryable(let error): throw error
        }
    }
}

/// Fresh, authenticated MLS group per delivery. No static-message fallback.
public actor SecureTransport {
    public static let messageType = MessageType(rawValue: "urn:ace:secure-delivery:2")!
    public static let schemaDigest = sha256Hex(Data("ace.secure-delivery.v2:hello,offer,data,ack;fresh-pairwise-mls;exact-envelope;outcome-receipt;120s".utf8))
    public struct Route: Sendable {
        public let attempt: String
        public let kind: String
        public let expiresAt: Int
    }
    public typealias Exchange = @Sendable (ACEMessage, Route) async throws -> ACEMessage
    /// Run the original Inbox, including profiles and durable idempotent host delivery, and
    /// return its outcome. Throw only for retryable failures (storage, handler, busy): then no
    /// receipt is released and the sender's attempt expires.
    public typealias Accept = @Sendable (Data) async throws -> SecureOutcome
    private struct Frame: Sendable {
        var body: [String: JSONValue]
        var kind: String { body["kind"]!.stringValue! }
        var attempt: String { body["attempt"]!.stringValue! }
        var expiresAt: Int { body["expiresAt"]!.intValue! }
        var messageId: String { body["messageId"]!.stringValue! }
        var digest: String { body["digest"]!.stringValue! }
        var nonce: String { body["nonce"]!.stringValue! }
        func matches(_ other: Frame) -> Bool {
            ["attempt", "expiresAt", "messageId", "digest"].allSatisfy { body[$0] == other.body[$0] }
        }
        func receipt(_ outcome: SecureOutcome) -> Data { Data((receiptPrefix + outcome.receipt).utf8) }
        var receiptPrefix: String { "ace.delivery.outcome.v1:\(attempt):\(nonce):\(messageId):\(digest):" }
    }
    private struct Incoming {
        let peer: String
        let hello: Frame
        let offer: Frame
        let response: ACEMessage
        let generation: Int
        let session: PairwiseMLS
    }
    /// Journal row `secure/in/<attempt>.json` after the data frame. `outcome` is nil until the
    /// Inbox handed the envelope over; `response` (the receipt) exists only once the outcome is
    /// known, since it is encrypted in the attempt's group. Nil members are written as `null`.
    private struct Received: Codable {
        let version: Int
        let generation: Int
        let expiresAt: Int
        let peer: String
        let input: String
        var envelope: ACEMessage?
        var response: ACEMessage?
        var outcome: String?
        func encode(to encoder: any Encoder) throws {
            var c = encoder.container(keyedBy: CodingKeys.self)
            try c.encode(version, forKey: .version); try c.encode(generation, forKey: .generation)
            try c.encode(expiresAt, forKey: .expiresAt); try c.encode(peer, forKey: .peer); try c.encode(input, forKey: .input)
            try c.encode(envelope, forKey: .envelope); try c.encode(response, forKey: .response); try c.encode(outcome, forKey: .outcome)
        }
    }
    private let identity: any ACEIdentity
    private let engine: any MLSEngine
    let store: any ACEStore
    nonisolated let clock: @Sendable () -> Int
    private var sessions: [String: Incoming] = [:]
    /// Next time-based sweep of expired `secure/in/` rows; a full table sweeps at once.
    private var nextSweep = 0
    private static let sweepSeconds = 30
    private static let maxInboundRows = 1024
    /// Frames whose signature, decryption and shape already verified, by packet and sender keys.
    /// `route` then `respond` (or `read`) of one packet verifies it once; admission and expiry,
    /// which change with time and policy, are rechecked on every read.
    private var verified: [String: Frame] = [:]
    private static let verifiedCap = 32
    private var closed = false
    private var outgoing = 0
    private var responding = false
    private var waiters: [CheckedContinuation<Void, Never>] = []

    public init(identity: any ACEIdentity, engine: any MLSEngine, store: any ACEStore,
                clock: @escaping @Sendable () -> Int = systemClock) {
        self.identity = identity; self.engine = engine; self.store = store; self.clock = clock
    }
    private nonisolated static func peerKey(_ peer: String) -> String { "secure/peers/\(sha256Hex(Data(peer.utf8))).json" }
    private nonisolated static func peerLock(_ peer: String) -> String { "secure-peer-\(sha256Hex(Data(peer.utf8)).prefix(48))" }
    /// Local administrator only. Remote roles, discovery and incoming packets cannot enable peers.
    public nonisolated static func setPeerAllowed(store: any ACEStore, peer: String, allowed: Bool) throws {
        guard isACEId(peer) else { throw MLSError("invalid_session_input") }
        try store.coordinate(peerLock(peer)) { data in
            let old = try data.read(peerKey(peer)).map { try JSONValue(json: $0) }
            var generation = 0
            if let old {
                guard let row = peerRow(old, peer: peer) else { throw MLSError("invalid_delivery_policy") }
                generation = row.generation
            }
            guard generation >= 0, generation < maxSafeInteger else { throw MLSError("session_limit") }
            try data.write(peerKey(peer), JSONValue.object(["version": 1, "peer": .string(peer),
                "generation": .number(Double(generation + 1)), "allowed": .bool(allowed)]).jsonData())
        }
    }
    /// A well-formed peer policy row for `peer`; nil when its shape is wrong.
    private nonisolated static func peerRow(_ row: JSONValue, peer: String) -> (allowed: Bool, generation: Int)? {
        guard Set(row.objectValue?.keys.map { $0 } ?? []) == Set(["version", "peer", "allowed", "generation"]),
              row["version"]?.intValue == 1, row["peer"]?.stringValue == peer,
              let allowed = row["allowed"]?.boolValue, let generation = row["generation"]?.intValue, generation > 0 else { return nil }
        return (allowed, generation)
    }
    /// The policy generation of an enabled peer; nil for a missing, malformed or disabled row.
    private nonisolated static func admission(store: any ACEStore, peer: String) throws -> Int? {
        guard let raw = try store.read(peerKey(peer)), let json = try? JSONValue(json: raw),
              let row = peerRow(json, peer: peer), row.allowed else { return nil }
        return row.generation
    }
    /// Local admission read, before any peer resolution or pin. Never throws: an invalid id, a
    /// missing, unreadable or malformed row is `false`.
    public nonisolated static func isPeerAllowed(store: any ACEStore, peer: String) -> Bool {
        guard isACEId(peer) else { return false }
        return ((try? admission(store: store, peer: peer)) ?? nil) != nil
    }
    @discardableResult private func allowed(_ peer: String) throws -> Int {
        guard !closed else { throw MLSError("session_closed") }
        guard let generation = try Self.admission(store: store, peer: peer) else { throw MLSError("delivery_peer_disabled") }
        return generation
    }
    private func packet(_ peer: VerifiedPeer, _ f: Frame) throws -> ACEMessage {
        try createMessage(sender: identity, recipient: peer, type: Self.messageType, body: f.body,
                          timestamp: clock(), schemaDigest: Self.schemaDigest)
    }
    private func read(_ packet: ACEMessage, _ peer: VerifiedPeer) throws -> Frame {
        try allowed(peer.aceId)
        let key = sha256Hex(Data((envelopeFingerprint(packet) + peer.aceId + peer.scheme.rawValue).utf8) + peer.encryptionPublicKey)
        let frame = try verified[key] ?? verify(packet, peer)
        if verified[key] == nil {
            if verified.count >= Self.verifiedCap { verified.removeAll() }
            verified[key] = frame
        }
        guard frame.expiresAt > clock(), frame.expiresAt <= clock() + ACELimits.secureAttemptSeconds else { throw MLSError("delivery_expired") }
        return frame
    }
    /// The time-independent checks of a frame: ACE signature, recipient, decryption and shape.
    private func verify(_ packet: ACEMessage, _ peer: VerifiedPeer) throws -> Frame {
        let parsed = try parseMessage(packet, receiver: identity, sender: peer, replay: ReplayDetector(clock: clock), clock: clock)
        guard parsed.type == Self.messageType, parsed.schemaDigest == Self.schemaDigest, parsed.threadId == nil else {
            throw MLSError("secure_delivery_required")
        }
        let body = parsed.body
        let extra = ["hello": [], "offer": ["nonce", "keyPackage"], "data": ["nonce", "welcome", "ciphertext"], "ack": ["nonce", "ciphertext"]]
        guard let kind = body["kind"]?.stringValue, let fields = extra[kind],
              Set(body.keys) == Set(["kind", "attempt", "expiresAt", "messageId", "digest"] + fields),
              isSha256Hex(body["attempt"]?.stringValue ?? ""), isSha256Hex(body["digest"]?.stringValue ?? ""),
              isMessageId(body["messageId"]?.stringValue ?? ""), let expires = body["expiresAt"]?.intValue, expires >= 0 else {
            throw MLSError("invalid_delivery_frame")
        }
        if kind != "hello", !isSha256Hex(body["nonce"]?.stringValue ?? "") { throw MLSError("invalid_delivery_frame") }
        for name in ["keyPackage", "welcome", "ciphertext"] where body[name] != nil {
            guard let value = body[name]?.stringValue,
                  value.utf8.count <= (name == "keyPackage" ? PairwiseMLS.maxKeyPackageBytes : PairwiseMLS.maxMessageBytes) else {
                throw MLSError("invalid_delivery_frame")
            }
        }
        guard expires <= parsed.timestamp + ACELimits.secureAttemptSeconds else { throw MLSError("delivery_expired") }
        return Frame(body: body)
    }
    /// Routing metadata is returned only after full ACE signature, recipient and expiry checks.
    public func route(_ packet: ACEMessage, peer: VerifiedPeer) throws -> Route {
        let frame = try read(packet, peer)
        return Route(attempt: frame.attempt, kind: frame.kind, expiresAt: frame.expiresAt)
    }
    /// Call from Outbox.deliver; throw on an uncertain result so the exact application ID is retained.
    public func deliver(_ envelope: ACEMessage, peer: VerifiedPeer, exchange: @escaping Exchange) async throws {
        let inner = try decodeEnvelope(envelope.jsonData())
        guard inner.from == identity.getACEId(), inner.to == peer.aceId else { throw MLSError("invalid_delivery_frame") }
        try verifyEnvelopeSignature(inner, scheme: identity.getSigningScheme(), signingPublicKey: identity.getSigningPublicKey())
        guard inner.timestamp >= clock() - ACELimits.offlineWindowSeconds else {
            throw ACEError(.envelopeExpired, "Original application envelope exceeds offline retention")
        }
        let bytes = inner.jsonData()
        guard bytes.count <= PairwiseMLS.maxPlaintextBytes else { throw MLSError("session_limit") }
        guard outgoing < 32 else { throw MLSError("session_limit") }
        outgoing += 1; defer { outgoing -= 1 }
        let generation = try allowed(peer.aceId)
        let hello = Frame(body: ["kind": "hello", "attempt": .string(randomHex(32)), "expiresAt": .number(Double(clock() + ACELimits.secureAttemptSeconds)),
            "messageId": .string(inner.messageId), "digest": .string(envelopeFingerprint(inner))])
        // Bounded at the attempt deadline (13: bounded network timeouts and cancellation): a stuck
        // exchange is cancelled and no longer holds an outgoing slot.
        let request: Exchange = { [clock = self.clock] packet, route in
            do { return try await withDeadline(seconds: min(ACELimits.secureAttemptSeconds, hello.expiresAt - clock())) { try await exchange(packet, route) } }
            catch let error as ACEError where error.code == .envelopeExpired { throw MLSError("delivery_expired") }
        }
        let offer = try read(await request(packet(peer, hello), Route(attempt: hello.attempt, kind: "offer", expiresAt: hello.expiresAt)), peer)
        guard offer.kind == "offer", hello.matches(offer) else { throw MLSError("invalid_delivery_frame") }
        let session = try PairwiseMLS(engine: engine, store: store, local: inner.from, peer: inner.to)
        do {
            let welcome = try session.create(keyPackage: offer.body["keyPackage"]!.stringValue!).message!
            let cipher = try session.send(bytes).message!
            var body = hello.body; body["kind"] = "data"; body["nonce"] = offer.body["nonce"]
            body["welcome"] = .string(welcome); body["ciphertext"] = .string(cipher)
            let data = Frame(body: body), output = try packet(peer, data)
            // No sender journal: an interrupted attempt is abandoned and the next deliver starts a fresh one.
            guard try allowed(peer.aceId) == generation else { throw MLSError("delivery_peer_disabled") }
            guard clock() < hello.expiresAt else { throw MLSError("delivery_expired") }
            let ack = try read(await request(output, Route(attempt: hello.attempt, kind: "ack", expiresAt: hello.expiresAt)), peer)
            guard ack.kind == "ack", hello.matches(ack), ack.nonce == offer.nonce else { throw MLSError("invalid_delivery_frame") }
            let plaintext = try session.receive(ack.body["ciphertext"]!.stringValue!).plaintextData()
            let prefix = Data(data.receiptPrefix.utf8)
            guard plaintext.starts(with: prefix), let rest = String(data: plaintext.dropFirst(prefix.count), encoding: .utf8),
                  let outcome = SecureOutcome(receipt: rest) else { throw MLSError("invalid_delivery_receipt") }
            // The sender snapshot is checked after the receipt, before its verdict is reported (13).
            guard try allowed(peer.aceId) == generation else { throw MLSError("delivery_peer_disabled") }
            if case .rejected(let code) = outcome {
                throw ACEError(.deliveryRejected, "the receiver's Inbox rejected the envelope: \(code)", remoteCode: code)
            }
            try session.close()
        } catch { try? session.close(); throw error }
        guard clock() < hello.expiresAt else { throw MLSError("delivery_expired") }
    }
    private func enter() async {
        if responding { await withCheckedContinuation { waiters.append($0) } }
        else { responding = true }
    }
    private func leave() {
        if waiters.isEmpty { responding = false } else { waiters.removeFirst().resume() }
    }
    /// Network boundary. Never pass unwrapped application packets to the application Inbox.
    public func respond(_ packet: ACEMessage, peer: VerifiedPeer, accept: Accept) async throws -> ACEMessage {
        await enter(); defer { leave() }
        let f = try read(packet, peer)
        guard f.kind == "hello" || f.kind == "data" else { throw MLSError("invalid_delivery_frame") }
        let held = try store.lock(Self.peerLock(peer.aceId)); defer { held.release() }
        let generation = try allowed(peer.aceId); try sweep()
        let key = "secure/in/\(f.attempt).json"
        if f.kind == "hello" {
            if let active = sessions[f.attempt] {
                guard active.peer == peer.aceId, active.generation == generation, active.hello.matches(f) else { throw MLSError("invalid_delivery_frame") }
                return active.response
            }
            // A prior attempt never gets a replacement key package after process loss.
            guard try store.read(key) == nil else { throw MLSError("session_closed") }
            guard sessions.count < 32, try inboundRoom() else { throw MLSError("session_limit") }
            let session = try PairwiseMLS(engine: engine, store: store, local: identity.getACEId(), peer: peer.aceId)
            do {
                var body = f.body; body["kind"] = "offer"; body["nonce"] = .string(randomHex(32)); body["keyPackage"] = .string(session.state.keyPackage)
                let offer = Frame(body: body), response = try self.packet(peer, offer)
                try store.write(key, JSONValue.object(["version": 1, "peer": .string(peer.aceId), "expiresAt": .number(Double(f.expiresAt)), "generation": .number(Double(generation)),
                    "response": try JSONValue(json: response.jsonData())]).jsonData())
                sessions[f.attempt] = Incoming(peer: peer.aceId, hello: f, offer: offer, response: response, generation: generation, session: session)
                return response
            } catch { try? session.close(); throw error }
        }
        let input = sha256Hex(try JSONValue.object(f.body).jsonData())
        guard let raw = try store.read(key) else { throw MLSError("session_closed") }
        let response: ACEMessage
        if try JSONValue(json: raw)["input"] != nil {
            let saved = try JSONDecoder().decode(Received.self, from: raw)
            guard saved.version == 1, saved.peer == peer.aceId, saved.generation == generation, saved.input == input else { throw MLSError("invalid_delivery_frame") }
            // Decrypted but never handed over (the Inbox failed and the group is gone): the sender's
            // attempt expires and it starts a fresh one, which the Inbox deduplicates.
            guard saved.outcome != nil else { throw MLSError(saved.envelope == nil ? "invalid_delivery_journal" : "session_closed") }
            guard let prepared = saved.response else { throw MLSError("invalid_delivery_journal") }
            response = prepared
        } else {
            guard let active = sessions[f.attempt], active.peer == peer.aceId, active.generation == generation, active.hello.matches(f), active.offer.nonce == f.nonce else {
                throw MLSError("session_closed")
            }
            defer { sessions[f.attempt] = nil; try? active.session.close() }
            _ = try active.session.join(welcome: f.body["welcome"]!.stringValue!)
            let decoded = try active.session.receive(f.body["ciphertext"]!.stringValue!).plaintextData()
            let envelope = try decodeEnvelope(decoded)
            guard envelope.from == peer.aceId, envelope.to == identity.getACEId(), envelope.messageId == f.messageId,
                  envelopeFingerprint(envelope) == f.digest else { throw MLSError("invalid_delivery_frame") }
            var received = Received(version: 1, generation: generation, expiresAt: f.expiresAt, peer: peer.aceId, input: input, envelope: envelope, response: nil, outcome: nil)
            try store.write(key, encodeSortedJSON(received))
            // The receipt is NEVER produced before the Inbox commits: its outcome is the Inbox's verdict.
            let outcome = try await accept(envelope.jsonData())
            if case .rejected(let code) = outcome, !isRemoteCode(code) { throw MLSError("invalid_session_input") }
            let cipher = try active.session.send(f.receipt(outcome)).message!
            response = try self.packet(peer, Frame(body: ["kind": "ack", "attempt": .string(f.attempt), "expiresAt": .number(Double(f.expiresAt)),
                "messageId": .string(f.messageId), "digest": .string(f.digest), "nonce": .string(f.nonce), "ciphertext": .string(cipher)]))
            received.envelope = nil; received.response = response; received.outcome = outcome.receipt
            // Durable before release; a replayed data frame for this attempt returns the same receipt.
            try store.write(key, encodeSortedJSON(received))
        }
        guard clock() < f.expiresAt else { throw MLSError("delivery_expired") }
        try allowed(peer.aceId)
        return response
    }
    /// Room for another inbound attempt row; a full table is swept before it is refused.
    private func inboundRoom() throws -> Bool {
        if try store.list(prefix: "secure/in/").count < Self.maxInboundRows { return true }
        try sweep(force: true)
        return try store.list(prefix: "secure/in/").count < Self.maxInboundRows
    }
    /// Delete expired `secure/in/` rows (at most every `sweepSeconds`, or now when `force`) and
    /// close expired in-memory sessions.
    private func sweep(force: Bool = false) throws {
        let now = clock()
        if force || now >= nextSweep {
            nextSweep = now + Self.sweepSeconds
            for key in try store.list(prefix: "secure/in/") {
                guard let raw = try store.read(key) else { continue }
                if let expires = try JSONValue(json: raw)["expiresAt"]?.intValue, expires <= now { try store.delete(key) }
            }
        }
        for (id, active) in sessions where active.hello.expiresAt <= now {
            sessions[id] = nil; try active.session.close()
        }
    }
    /// True while an offer this transport issued still awaits its data frame. A short-lived
    /// receive may wait for it up to the handshake deadline (13); otherwise its keys are lost.
    public func pendingHandshakes() -> Bool { sessions.values.contains { $0.hello.expiresAt > clock() } }
    public func close() async throws {
        closed = true
        await enter(); defer { leave() }
        var failure: (any Error)?
        for active in sessions.values {
            do { try active.session.close() } catch { failure = failure ?? error }
        }
        sessions.removeAll()
        if let failure { throw failure }
    }
}

/// Race `operation` against a `seconds` deadline (`delivery_expired`), cancelling the loser. The
/// caller resumes at the deadline even if `operation` ignores cancellation.
func withDeadline<T: Sendable>(seconds: Int, _ operation: @escaping @Sendable () async throws -> T) async throws -> T {
    guard seconds > 0 else { throw MLSError("delivery_expired") }
    let gate = DeadlineGate<T>()
    return try await withTaskCancellationHandler {
        try await withCheckedThrowingContinuation { continuation in
            gate.wait(continuation)
            gate.attach(Task { do { gate.finish(.success(try await operation())) } catch { gate.finish(.failure(error)) } })
            gate.attach(Task {
                try? await Task.sleep(for: .seconds(seconds))
                gate.finish(.failure(MLSError("delivery_expired")))
            })
        }
    } onCancel: { gate.finish(.failure(CancellationError())) }
}

/// First result wins: resumes the continuation once and cancels the racing tasks.
private final class DeadlineGate<T: Sendable>: @unchecked Sendable {
    private let lock = NSLock()
    private var continuation: CheckedContinuation<T, any Error>?
    private var result: Result<T, any Error>?
    private var tasks: [Task<Void, Never>] = []
    func wait(_ c: CheckedContinuation<T, any Error>) {
        let ready: Result<T, any Error>? = lock.withLock {
            if result == nil { continuation = c }
            return result
        }
        if let ready { c.resume(with: ready) }
    }
    func attach(_ task: Task<Void, Never>) {
        let finished: Bool = lock.withLock {
            if result == nil { tasks.append(task) }
            return result != nil
        }
        if finished { task.cancel() }
    }
    func finish(_ r: Result<T, any Error>) {
        let pending: (CheckedContinuation<T, any Error>?, [Task<Void, Never>])? = lock.withLock {
            guard result == nil else { return nil }
            result = r
            defer { continuation = nil; tasks = [] }
            return (continuation, tasks)
        }
        guard let (c, racing) = pending else { return }
        racing.forEach { $0.cancel() }
        c?.resume(with: r)
    }
}
