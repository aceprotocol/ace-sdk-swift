import Foundation

/// The result of `SecureMailbox.pull`.
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

/// The HTTP reply for one direct-delivery request (`SecureMailbox.receiveDirect`; 08 § Direct
/// Delivery, Receiver). The application serves it: status `status`,
/// `Content-Type: application/json`, body `bodyData`.
public struct DirectReply: Sendable {
    /// 200, 400, 413 or 503.
    public let status: Int
    /// `{"ok":true,"messageId":…}` or `{"ok":false,"error":<code>}`.
    public let body: [String: JSONValue]
    /// The receive outcome, when the `message` member reached the application Inbox.
    public let outcome: ReceiveOutcome?

    /// `body` serialized as compact JSON.
    public var bodyData: Data { JSONWriter.serialize(JSONValue.object(body).jvalue ?? .object([:])) }

    static func fail(_ status: Int, _ error: String, _ outcome: ReceiveOutcome? = nil) -> DirectReply {
        DirectReply(status: status, body: ["ok": false, "error": .string(error)], outcome: outcome)
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

/// The only network receive boundary: relay pull / SSE follow / direct POST for
/// SecureTransport. Only authenticated MLS plaintext reaches the application Inbox, via
/// `Inbox.receive(_:)`. One mailbox owns the relay cursor per identity/store. Open the
/// application Inbox separately.
public actor SecureMailbox {
    public typealias Send = @Sendable (ACEMessage, VerifiedPeer) async throws -> DeliveryPath
    private struct Waiting { let peer: String; var packet: ACEMessage? }
    private let identity: any ACEIdentity
    private let store: any ACEStore
    private let peers: PeerStore
    private let relay: RelayClient
    private let secure: SecureTransport
    private let inbox: Inbox
    private let send: Send
    private let held: any ACEStoreLock
    /// `openSecureMailbox`: closes the Inbox and frees the engine at `close()`, once.
    private var dispose: (@Sendable () async -> Void)?
    private let cursorKey: String
    private var currentCursor: String?
    private var waiting: [String: Waiting] = [:]
    private var closed = false
    private var receiving = false
    private var waiters: [CheckedContinuation<Void, Never>] = []
    private var observerID: UUID?
    private var observer: AsyncThrowingStream<ReceiveOutcome, Error>.Continuation?

    /// The manual form: the caller owns `inbox` and the engine; `close()` closes `secure` only.
    /// `openSecureMailbox` composes all three.
    public static func open(identity: any ACEIdentity, store: any ACEStore, peers: PeerStore,
                            relay: RelayClient, secure: SecureTransport, inbox: Inbox, send: @escaping Send) throws -> SecureMailbox {
        try open(identity: identity, store: store, peers: peers, relay: relay, secure: secure, inbox: inbox, send: send, dispose: nil)
    }
    static func open(identity: any ACEIdentity, store: any ACEStore, peers: PeerStore, relay: RelayClient, secure: SecureTransport,
                     inbox: Inbox, send: @escaping Send, dispose: (@Sendable () async -> Void)?) throws -> SecureMailbox {
        let held = try store.lock("secure-mailbox", timeout: 0)
        do {
            let key = "secure/cursors/\(sha256Hex(Data(relay.baseURLString.utf8))).json"
            var cursor: String?
            if let raw = try store.read(key) {
                let row = try JSONValue(json: raw)
                guard row["version"]?.intValue == 1, row["identity"]?.stringValue == identity.getACEId(),
                      let value = row["cursor"]?.stringValue, isStreamCursor(value) else { throw ACEError(.storageFailed, "Invalid secure cursor") }
                cursor = value
            }
            return SecureMailbox(identity: identity, store: store, peers: peers, relay: relay, secure: secure,
                                 inbox: inbox, send: send, held: held, cursorKey: key, cursor: cursor, dispose: dispose)
        } catch { held.release(); throw error }
    }
    private init(identity: any ACEIdentity, store: any ACEStore, peers: PeerStore, relay: RelayClient,
                 secure: SecureTransport, inbox: Inbox, send: @escaping Send, held: any ACEStoreLock, cursorKey: String, cursor: String?,
                 dispose: (@Sendable () async -> Void)?) {
        self.identity = identity; self.store = store; self.peers = peers; self.relay = relay; self.secure = secure
        self.inbox = inbox; self.send = send; self.held = held; self.cursorKey = cursorKey; currentCursor = cursor; self.dispose = dispose
    }
    public var cursor: String? { currentCursor }
    private func enter() async {
        if receiving { await withCheckedContinuation { waiters.append($0) } } else { receiving = true }
    }
    private func leave() {
        if waiters.isEmpty { receiving = false } else { waiters.removeFirst().resume() }
    }
    private func checkOpen() throws { if closed { throw ACEError(.receiverBusy, "Secure mailbox is closed") } }
    /// Success means the destination Inbox durably accepted this exact envelope, not just relay acceptance.
    public func deliver(_ envelope: ACEMessage, peer: VerifiedPeer) async throws -> DeliveryPath {
        try checkOpen()
        let path = LockedBox<DeliveryPath?>(nil)
        try await secure.deliver(envelope, peer: peer) { request, expected in
            try await self.exchange(request, expected: expected, peer: peer, path: path)
        }
        return path.value ?? .relay
    }
    private func exchange(_ packet: ACEMessage, expected: SecureTransport.Route, peer: VerifiedPeer, path: LockedBox<DeliveryPath?>) async throws -> ACEMessage {
        try checkOpen()
        let key = expected.attempt + "/" + expected.kind
        guard waiting[key] == nil, waiting.count < 32 else { throw ACEError(.limitExceeded, "Too many secure handshakes") }
        waiting[key] = Waiting(peer: peer.aceId); defer { waiting[key] = nil }
        let deadline = ContinuousClock.now.advanced(by: .seconds(ACELimits.secureAttemptSeconds))
        let sent = try await send(packet, peer); path.update { $0 = sent }
        while ContinuousClock.now < deadline {
            try Task.checkCancellation(); try checkOpen()
            if let response = waiting[key]?.packet { return response }
            let result = await pull(limit: ACELimits.maxInboxPage, maxPages: 1)
            if let error = result.blocked { throw error }
            if let response = waiting[key]?.packet { return response }
            try await Task.sleep(for: .milliseconds(250))
        }
        throw MLSError("delivery_expired")
    }
    private func advance(_ stream: String) throws {
        guard currentCursor == nil || compareStreamIds(stream, currentCursor!) > 0 else { return }
        try store.write(cursorKey, JSONValue.object(["version": 1, "identity": .string(identity.getACEId()), "cursor": .string(stream)]).jsonData())
        currentCursor = stream
    }
    private func ingest(_ raw: Data) async throws -> [ReceiveOutcome] {
        try checkOpen()
        guard raw.count <= ACELimits.maxEnvelopeBytes else { throw ACEError(.invalidEnvelope, "Envelope too large") }
        return try await ingest(decodeEnvelope(raw))
    }
    private func ingest(_ envelope: ACEMessage) async throws -> [ReceiveOutcome] {
        // Admission before any peer resolution: a stranger's frame costs no relay lookup and no pin.
        guard SecureTransport.isPeerAllowed(store: secure.store, peer: envelope.from) else { throw MLSError("delivery_peer_disabled") }
        let peer = try await peers.resolve(envelope.from)
        let route = try await secure.route(envelope, peer: peer)
        if route.kind == "offer" || route.kind == "ack" {
            let key = route.attempt + "/" + route.kind
            if waiting[key]?.peer == peer.aceId, waiting[key]?.packet == nil { waiting[key]?.packet = envelope }
            return []
        }
        let results = LockedBox<[ReceiveOutcome]>([])
        let inbox = inbox
        let response = try await secure.respond(envelope, peer: peer) { bytes in
            let result = try await inbox.receive(bytes)
            let outcome = try SecureOutcome(result)
            results.update { $0.append(result) }; return outcome
        }
        // Replies use the relay so two direct requests cannot wait on each other's receive lock.
        try await relay.send(response)
        return results.value
    }
    private func errorOutcome(_ error: any Error, raw: Data) throws -> ReceiveOutcome {
        let quarantined: ACEError
        if let ace = error as? ACEError {
            guard ace.category == .permanent else { throw ace }
            quarantined = ace
        } else if let mls = error as? MLSError {
            guard mls.isPermanent else { throw ACEError(.storageFailed, mls.code) }
            quarantined = ACEError(.invalidBody, mls.code)
        } else { throw ACEError(.storageFailed, "Secure delivery failed") }
        return .quarantined(quarantined, fingerprint: (try? decodeEnvelope(raw)).map(envelopeFingerprint))
    }
    private func publish(_ outcomes: [ReceiveOutcome]) {
        for outcome in outcomes {
            if case .dropped = observer?.yield(outcome) {
                observer?.finish(throwing: ACEError(.limitExceeded, "Secure listener fell behind; recover from the durable application log"))
                observer = nil
            }
        }
    }
    public func pull(limit: Int = ACELimits.maxInboxPage, maxPages: Int? = nil) async -> PullResult {
        await enter(); defer { leave() }
        var outcomes: [ReceiveOutcome] = []
        do {
            try checkOpen()
            guard (1...ACELimits.maxInboxPage).contains(limit), maxPages == nil || maxPages! > 0 else { throw ACEError(.invalidArgument, "Invalid page bounds") }
            var pages = 0
            while !Task.isCancelled {
                if let maxPages, pages >= maxPages { return PullResult(outcomes: outcomes, blocked: nil, hasMore: true) }
                let page = try await relay.fetchInbox(identity, since: currentCursor, limit: limit); pages += 1
                for entry in page.entries {
                    if let cursor = currentCursor, compareStreamIds(entry.streamId, cursor) <= 0 { continue }
                    let next: [ReceiveOutcome]
                    do { next = try await ingest(entry.message) }
                    catch { next = [try errorOutcome(error, raw: entry.message)] }
                    try advance(entry.streamId)
                    outcomes += next; publish(next)
                }
                if page.entries.count < limit { return PullResult(outcomes: outcomes, blocked: nil) }
            }
            return PullResult(outcomes: outcomes, blocked: nil, hasMore: true)
        } catch { return PullResult(outcomes: outcomes, blocked: ACEError.wrap(error)) }
    }
    public func receiveDirect(_ body: Data) async -> DirectReply {
        // Not accepting (08 § Receiver): not a fault of the request, so the sender falls back to the relay.
        guard !closed else { return .fail(503, "internal_error") }
        guard body.count <= ACELimits.maxDirectBodyBytes else { return .fail(413, "payload_too_large") }
        await enter(); defer { leave() }
        do {
            let value = try JSONValue(json: body)
            guard let message = value["message"] else { return .fail(400, "invalid_argument") }
            let raw = try message.jsonData()
            try checkOpen()
            guard raw.count <= ACELimits.maxEnvelopeBytes else { throw ACEError(.invalidEnvelope, "Envelope too large") }
            let envelope = try decodeEnvelope(raw)
            let outcomes = try await ingest(envelope); publish(outcomes)
            return DirectReply(status: 200, body: ["ok": true, "messageId": .string(envelope.messageId)], outcome: outcomes.first)
        } catch {
            if closed { return .fail(503, "internal_error") } // closed meanwhile
            if let ace = error as? ACEError { return .fail(ace.category == .permanent ? 400 : 503, ace.code.rawValue) }
            if let mls = error as? MLSError { return mls.isPermanent ? .fail(400, mls.code) : .fail(503, "storage_failed") }
            return .fail(503, "storage_failed")
        }
    }
    public nonisolated func follow(onLive: (@Sendable () -> Void)? = nil) -> AsyncThrowingStream<ReceiveOutcome, Error> {
        AsyncThrowingStream(bufferingPolicy: .bufferingOldest(64)) { continuation in
            let task = Task { await self.runFollow(continuation, onLive: onLive) }
            continuation.onTermination = { _ in task.cancel() }
        }
    }
    private func runFollow(_ continuation: AsyncThrowingStream<ReceiveOutcome, Error>.Continuation, onLive: (@Sendable () -> Void)?) async {
        guard observer == nil else { continuation.finish(throwing: ACEError(.receiverBusy, "Already following")); return }
        let id = UUID(); observerID = id; observer = continuation
        defer { if observerID == id { observer = nil; observerID = nil } }
        do {
            let backlog = await pull()
            if let error = backlog.blocked { throw error }
            for try await _ in relay.listen(identity, since: currentCursor, onOpen: { onLive?() }) {
                // Fetch from the durable cursor. An SSE event is a wake-up, never authority or a cursor commit.
                let result = await pull()
                if let error = result.blocked { throw error }
            }
            continuation.finish()
        } catch { continuation.finish(throwing: error is CancellationError ? nil : error) }
    }
    public func close() async {
        closed = true
        observer?.finish(); observer = nil
        await enter(); defer { leave() }
        try? await secure.close()
        if let dispose { self.dispose = nil; await dispose() }
        held.release()
    }
    deinit { held.release() }
}

/// The `Inbox.open` options other than the shared identity, store and peers (`openSecureMailbox`).
public struct InboxSetup: Sendable {
    public var onMessage: Inbox.MessageHandler
    public var capacity: Int
    public var offlineWindowSeconds: Int
    public var clock: @Sendable () -> Int
    public var principal: InboxPrincipal?
    public var commerce: Bool
    public var schemas: [String: SchemaValidator]

    public init(onMessage: @escaping Inbox.MessageHandler, capacity: Int = ACELimits.defaultReplayCapacity,
                offlineWindowSeconds: Int = ACELimits.offlineWindowSeconds, clock: @escaping @Sendable () -> Int = systemClock,
                principal: InboxPrincipal? = nil, commerce: Bool = false, schemas: [String: SchemaValidator] = [:]) {
        self.onMessage = onMessage; self.capacity = capacity; self.offlineWindowSeconds = offlineWindowSeconds
        self.clock = clock; self.principal = principal; self.commerce = commerce; self.schemas = schemas
    }
}

/// The recommended way to open the network receive boundary: `Inbox.open` with `inbox`, then
/// `SecureTransport(identity:engine:store:clock:)`, then a `SecureMailbox` owning all three, so
/// one `close()` releases the receive lock, the transport and the engine (`ClosableMLSEngine.close`,
/// when the engine has one). A failure after the Inbox opened closes it (no leaked `receive`
/// lock) before rethrowing; the engine is then still the caller's to close. `send` carries every
/// handshake frame (default `relay.send`; direct hosts pass `deliverDirectOrRelay(relay:endpoint:)`).
public func openSecureMailbox(identity: any ACEIdentity, store: any ACEStore, peers: PeerStore, relay: RelayClient,
                              engine: any MLSEngine, inbox setup: InboxSetup, send: SecureMailbox.Send? = nil,
                              clock: @escaping @Sendable () -> Int = systemClock) async throws -> SecureMailbox {
    let inbox = try await Inbox.open(identity: identity, store: store, peers: peers, onMessage: setup.onMessage, capacity: setup.capacity,
                                     offlineWindowSeconds: setup.offlineWindowSeconds, clock: setup.clock, principal: setup.principal,
                                     commerce: setup.commerce, schemas: setup.schemas)
    do {
        let secure = SecureTransport(identity: identity, engine: engine, store: store, clock: clock)
        return try SecureMailbox.open(identity: identity, store: store, peers: peers, relay: relay, secure: secure, inbox: inbox,
                                      send: send ?? relaySend(relay),
                                      dispose: { await inbox.close(); (engine as? any ClosableMLSEngine)?.close() })
    } catch {
        await inbox.close()   // the open failure is the error to surface
        throw error
    }
}

/// The `Outbox.deliver` transport for `peer`: every frame of the handshake goes out through
/// `send` (default `relay.send`; direct hosts pass `deliverDirectOrRelay(relay:endpoint:)`) and
/// its signed reply is read back through the relay (`SecureRelayReplies`, for a sender while
/// another process owns its mailbox). The result is the path the frames took.
public func secureTransportFor(identity: any ACEIdentity, secure: SecureTransport, relay: RelayClient, peer: VerifiedPeer,
                               send: SecureMailbox.Send? = nil) -> @Sendable (ACEMessage) async throws -> DeliveryPath {
    let replies = SecureRelayReplies(identity: identity, secure: secure, relay: relay, peer: peer,
                                     send: send ?? relaySend(relay))
    return { envelope in
        try await secure.deliver(envelope, peer: peer) { packet, route in try await replies.exchange(packet, expected: route) }
        return await replies.path
    }
}

/// `outbox.deliver(requestId, transport: secureTransportFor(…))`: returns once the peer's Inbox
/// durably committed the envelope. On failure the operation stays pending under `requestId`;
/// retry that ID, never stage a new one.
@discardableResult
public func deliverSecure(_ outbox: Outbox, _ requestId: String, identity: any ACEIdentity, secure: SecureTransport,
                          relay: RelayClient, peer: VerifiedPeer, send: SecureMailbox.Send? = nil) async throws -> DeliveryPath {
    try await outbox.deliver(requestId, transport: secureTransportFor(identity: identity, secure: secure, relay: relay, peer: peer, send: send))
}

/// The default `SecureMailbox.Send`: every frame through the relay.
private func relaySend(_ relay: RelayClient) -> SecureMailbox.Send { { packet, _ in try await relay.send(packet); return .relay } }

/// A value shared with a `@Sendable` callback.
private final class LockedBox<Value>: @unchecked Sendable {
    private let lock = NSLock()
    private var stored: Value
    init(_ value: Value) { stored = value }
    var value: Value { lock.withLock { stored } }
    func update(_ body: (inout Value) -> Void) { lock.withLock { body(&stored) } }
}
