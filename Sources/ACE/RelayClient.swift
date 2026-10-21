//
//  RelayClient.swift
//  ACE SDK
//
//  HTTP client for the relay binding (07-relay): opaque packets, descriptors, card records, blocks, inbox.
//

import Foundation

/// Relay HTTP client (07 § Client rules). Authenticated calls sign the `X-ACE-*` headers (real timestamp, fresh nonce,
/// this relay's canonical URL as the audience). A 409 replay retries once with a fresh nonce. Redirects are never followed. Every
/// PublishedAgent and CardBundle the relay returns is verified (`verifyPublishedAgent`, `verifyCardBundle`) before it is
/// handed out.
///
/// Error mapping (first match): 1xx / 3xx / unexpected 2xx / ≥ 600 → `relay_protocol_error`; 408, 5xx →
/// `relay_unavailable`; any 429 → `relay_unavailable` (honoring `Retry-After`); 403
/// `not_registered` / `not_permitted` → the same code; 404 `unknown_peer` → `unknown_peer`; any other 4xx →
/// `relay_rejected`. `status` and `relayCode` are kept; `retryAfterSeconds` only on transient errors.
public actor RelayClient {
    /// A response or SSE `data` as a whole: its deepest wrapper, an inbox page, holds packets at depth 3 (02 § JSON values).
    private static let responseDepth = ACELimits.maxJSONDepth + 3

    /// A packet, PublishedAgent or CardBundle inside a response is within `MAX_JSON_DEPTH` on its own (02 § JSON values); otherwise the
    /// whole response is `relay_protocol_error`, never a dropped entry.
    private static func contained(_ value: JSONValue) throws {
        try checkJSONValue(value, code: .relayProtocolError)
    }

    public enum RegisterStatus: String, Sendable {
        case registered, idempotent, refreshed, rotated
    }

    /// One inbox entry: the stream ID and the packet JSON as served (decoded by the Inbox).
    public struct InboxEntry: Sendable, Equatable {
        public let streamId: String
        public let packet: Data
    }

    public struct InboxPage: Sendable {
        public let entries: [InboxEntry]
        public let cursor: String?
    }

    /// One SSE `catchup` / `message` event: the stream ID and the packet JSON from `data: {"packet": …}`.
    public struct Event: Sendable, Equatable {
        public let streamId: String
        public let packet: Data
        public let catchup: Bool
    }

    public struct DirectoryPage: Sendable {
        /// Verified agents.
        public let agents: [VerifiedAgent]
        /// Entries dropped because they failed verification.
        public let rejected: Int
        public let cursor: String?
    }

    /// The canonical base URL (02 § Relay URLs).
    public nonisolated let baseURL: URL
    /// `baseURL` as a string: the normalized relay key (also the auth audience).
    public nonisolated let baseURLString: String
    /// Development only: loopback `http` relays, here and in the descriptors this client verifies.
    public nonisolated let allowLoopbackRelays: Bool
    /// The blocked-address policy (07 § Client rules) runs before every connection: set for relays named by peers.
    private let checksAddresses: Bool
    let session: URLSession
    /// `session` was made by this client (`foreign`), which invalidates it on deinit; a host's session is never touched.
    let ownsSession: Bool
    /// `listen`'s own session (see `init`); created on first use.
    private var streamSession: URLSession?
    private let timeout: TimeInterval
    private let maxResponseBytes: Int
    /// The injected clock, read raw: a reading outside [0, 2^53 − 1] is `invalid_argument` (sdk-py `unix_now`), never
    /// clamped — a clamped −1 would verify peer records at t = 0.
    private let clock: @Sendable () -> Int
    private let sleeper: @Sendable (Double) async throws -> Void
    private let noRedirect = NoRedirectDelegate()
    private var lastRegistrationTimestamp = 0
    /// Persists the registration ordering timestamp across processes (see `init`).
    private let registrationStore: (any ACEStore)?

    /// Reconnect attempts after which `listen` fails with `relay_unavailable`.
    static let maxConnectFailures = 10
    static let maxBackoffSeconds = 30.0
    static let idleTimeoutSeconds = 90.0
    /// Events buffered for a slow consumer; when full, reading the socket pauses.
    static let listenBuffer = 64

    /// `baseURL` must normalize to a canonical relay URL (02 § Relay URLs): `https`, or `http` to a loopback host with
    /// `allowLoopbackRelays` (development only); anything else is `invalid_argument`.
    ///
    /// `session` carries every request-response call. `listen` does not use it directly:
    /// it opens a dedicated session from a copy of `session.configuration` (same
    /// protocol classes, proxy, TLS and cookie settings, and the same delegate) with
    /// `timeoutIntervalForResource = .infinity` and `timeoutIntervalForRequest = 90 s`,
    /// the idle limit after which `listen` reconnects. A host session tuned for short
    /// calls (a 60 s resource timeout, say) therefore cannot kill the SSE stream, and a
    /// silent stream is still detected.
    ///
    /// `store`: persist the last registration / unregister timestamp per (relay, identity) under lock
    /// `relay-registration`, so several processes sharing an identity keep it strictly increasing (07 § Registration).
    /// Without it the ordering is per `RelayClient` instance.
    public init(
        baseURL: URL,
        session: URLSession = .shared,
        timeout: TimeInterval = 10,
        maxResponseBytes: Int = ACELimits.maxPageBytes,
        clock: @escaping @Sendable () -> Int = systemClock,
        store: (any ACEStore)? = nil,
        allowLoopbackRelays: Bool = false
    ) throws {
        try self.init(baseURL: baseURL, session: session, timeout: timeout, maxResponseBytes: maxResponseBytes,
                      clock: clock, sleeper: RelayClient.taskSleeper, store: store, allowLoopbackRelays: allowLoopbackRelays)
    }

    /// The default client for a relay named in a peer's descriptor (untrusted input, 07 § Client rules).
    /// Each request resolves the host once, rejects any blocked answer, and connects to a vetted numeric IP.
    /// TLS still verifies the original hostname and sends it as SNI; HTTP uses the original authority.
    /// Connections have bounded headers/body reads and no redirects, cookies, cache or credentials; a system proxy is
    /// used only when a direct connection fails, and it still targets the vetted address.
    /// `http` and loopback addresses require the explicit development flag `allowLoopbackRelays`.
    public static func foreign(_ url: String, allowLoopbackRelays: Bool = false, timeout: TimeInterval = 10,
                               clock: @escaping @Sendable () -> Int = systemClock) throws -> RelayClient {
        let normalized = try normalizeRelayURL(url)
        guard isRelayRoute(normalized, allowLoopback: allowLoopbackRelays) else {
            throw ACEError(.invalidArgument, "a peer's relay must be a canonical https relay URL")
        }
        let config = URLSessionConfiguration.ephemeral
        config.httpCookieStorage = nil
        config.httpShouldSetCookies = false
        config.urlCredentialStorage = nil
        config.urlCache = nil
        // URLRequest.timeoutInterval is an idle timeout; the resource timeout is the whole-request deadline (sdk-ts
        // pinned-https, sdk-py `_net`), which URLSession otherwise leaves at 7 days.
        config.timeoutIntervalForRequest = timeout
        config.timeoutIntervalForResource = timeout
        return try RelayClient(baseURL: URL(string: normalized)!, session: URLSession(configuration: config), timeout: timeout,
                               maxResponseBytes: ACELimits.maxPageBytes, clock: clock, sleeper: taskSleeper, store: nil,
                               allowLoopbackRelays: allowLoopbackRelays, checksAddresses: true, ownsSession: true)
    }

    /// The production backoff sleeper: `Task.sleep`, which a cancelled task interrupts.
    static let taskSleeper: @Sendable (Double) async throws -> Void = { try await Task.sleep(nanoseconds: UInt64($0 * 1_000_000_000)) }

    init(
        baseURL: URL, session: URLSession, timeout: TimeInterval, maxResponseBytes: Int,
        clock: @escaping @Sendable () -> Int, sleeper: @escaping @Sendable (Double) async throws -> Void,
        store: (any ACEStore)? = nil, allowLoopbackRelays: Bool = false, checksAddresses: Bool = false, ownsSession: Bool = false
    ) throws {
        let normalized = try normalizeRelayURL(baseURL.absoluteString)
        guard isRelayRoute(normalized, allowLoopback: allowLoopbackRelays), let url = URL(string: normalized) else {
            throw ACEError(.invalidArgument, "baseURL must be a canonical relay URL (https; loopback http only in development)")
        }
        guard timeout.isFinite, timeout > 0, maxResponseBytes > 0 else { throw ACEError(.invalidArgument, "timeout and maxResponseBytes must be positive") }
        self.baseURL = url
        self.baseURLString = normalized
        self.session = session
        self.timeout = timeout
        self.maxResponseBytes = maxResponseBytes
        self.clock = clock
        self.sleeper = sleeper
        self.registrationStore = store
        self.allowLoopbackRelays = allowLoopbackRelays
        self.checksAddresses = checksAddresses
        self.ownsSession = ownsSession
    }

    /// The next strictly increasing registration-ordering timestamp, at least `floor` (persisted when a store is set).
    private func nextRegistrationTimestamp(_ identity: any ACEIdentity, floor: Int) throws -> Int {
        guard let store = registrationStore else {
            lastRegistrationTimestamp = max(floor, lastRegistrationTimestamp + 1)
            return lastRegistrationTimestamp
        }
        let key = "relay/registration/\(pairDigest(baseURLString, identity.getACEId())).json"
        return try store.withLock("relay-registration") {
            var stored = -1
            if let raw = try store.checkedRead(key) {
                guard let ts = JSONValue(stored: raw)?["timestamp"]?.wireInt else { throw ACEError(.storageFailed, "\(key) is malformed") }
                stored = ts
            }
            let ts = max(floor, stored + 1, lastRegistrationTimestamp + 1)
            try store.checkedWrite(key, try JSONValue.object(["version": 1, "timestamp": .number(Double(ts))]).jsonData())
            lastRegistrationTimestamp = ts
            return ts
        }
    }

    /// Every session this client made is invalidated (a URLSession lives until invalidated).
    deinit {
        streamSession?.finishTasksAndInvalidate()
        if ownsSession { session.finishTasksAndInvalidate() }
    }

    /// The session `listen` connects with (see `init`).
    func listenSession() -> URLSession {
        if let streamSession { return streamSession }
        let config = session.configuration
        config.timeoutIntervalForResource = .infinity
        config.timeoutIntervalForRequest = Self.idleTimeoutSeconds
        let made = URLSession(configuration: config, delegate: session.delegate, delegateQueue: nil)
        streamSession = made
        return made
    }

    // MARK: API

    /// `POST /v1/register` with a registration request signed at `max(now, last + 1)` for this relay (action
    /// `register-request` over `encodePayload(lastHashHex, audience)`). Body-signed, never retried.
    @discardableResult
    public func register(_ identity: any ACEIdentity) async throws -> RegisterStatus {
        let ts = try nextRegistrationTimestamp(identity, floor: try unixNow(clock))
        let body = try createRegistrationRequest(identity: identity, timestamp: ts, audience: baseURLString)
        let v = try await call("POST", "/v1/register", body: try body.jsonData())
        guard let s = v["status"]?.stringValue, let status = RegisterStatus(rawValue: s) else {
            throw ACEError(.relayProtocolError, "unexpected register status")
        }
        return status
    }

    /// `POST /v1/unregister`.
    public func unregister(_ identity: any ACEIdentity) async throws {
        _ = try await call("POST", "/v1/unregister", auth: (identity, .unregister))
    }

    /// `POST /v1/descriptor` (the PublishedAgent must list this relay in `relays`).
    public func publish(_ agent: VerifiedAgent) async throws {
        _ = try await call("POST", "/v1/descriptor", body: try agent.source.jsonData())
    }

    /// A relay response verified by `verify`, of identity `aceId` when given (`idOf`). Any failure is
    /// `relay_protocol_error`: a conformant relay refused the document on input, so serving it is the relay's fault, never
    /// a verdict on the peer (a permanent code would let one bad route end a lookup the next route serves).
    private func verified<T>(_ value: JSONValue, _ what: String, _ aceId: String?, idOf: (T) -> String,
                             _ verify: (JSONValue, Int) throws -> T) throws -> T {
        try Self.contained(value)  // never a skipped entry
        let now = try unixNow(clock)
        let doc: T
        do {
            doc = try verify(value, now)
        } catch {
            throw ACEError(.relayProtocolError, "relay served an invalid \(what)" + ((error as? ACEError).map { ": \($0.message)" } ?? ""))
        }
        guard aceId == nil || idOf(doc) == aceId else { throw ACEError(.relayProtocolError, "\(what) identity mismatch") }
        return doc
    }

    private func agent(_ source: JSONValue, _ aceId: String?) throws -> VerifiedAgent {
        try verified(source, "descriptor", aceId, idOf: \.aceId) { try verifyPublishedAgent($0, now: $1, allowLoopback: allowLoopbackRelays) }
    }

    /// `GET /v1/descriptor/{aceId}`: anonymous; the unexpired descriptor of any registered identity (`unknown_peer`
    /// otherwise).
    public func descriptor(_ aceId: String) async throws -> VerifiedAgent {
        guard isACEId(aceId) else { throw ACEError(.invalidArgument, "invalid ACE ID") }
        return try agent(try await call("GET", "/v1/descriptor/" + aceId), aceId)
    }

    /// `POST /v1/card`: publish this identity's CardBundle (verified first; its KEL must equal the registered KEL and the
    /// handle is set once, else the relay refuses it).
    public func publishCard(_ bundle: CardBundle) async throws {
        _ = try verifyCardBundle(bundle, now: try unixNow(clock), allowLoopback: allowLoopbackRelays)
        _ = try await call("POST", "/v1/card", body: try bundle.jsonData())
    }

    /// A served CardBundle, verified (`verified`: any failure is `relay_protocol_error`).
    private func cardBundle(_ value: JSONValue, _ aceId: String?) throws -> CardBundle {
        try verified(value, "card record", aceId, idOf: \.aceId) { try verifyCardBundle($0, now: $1, allowLoopback: allowLoopbackRelays) }.bundle
    }

    /// `GET /v1/card/{aceId}`: anonymous; the stored card record of a registered identity (`unknown_peer` otherwise).
    public func card(_ aceId: String) async throws -> CardBundle {
        guard isACEId(aceId) else { throw ACEError(.invalidArgument, "invalid ACE ID") }
        return try cardBundle(try await call("GET", "/v1/card/" + aceId), aceId)
    }

    /// `GET /v1/handles/{handle}`: the card record of the identity the handle is bound to at this relay. A record whose
    /// `home` is not this relay or whose `handle` differs is `unknown_peer` (04 § Card record).
    public func handle(_ name: String) async throws -> CardBundle {
        guard isHandle(name) else { throw ACEError(.invalidArgument, "invalid handle") }
        let bundle = try cardBundle(try await call("GET", "/v1/handles/" + name), nil)
        guard bundle["card"]?["home"]?.stringValue == baseURLString, bundle["card"]?["handle"]?.stringValue == name else {
            throw ACEError(.unknownPeer, "the record does not hold this handle at this relay")
        }
        return bundle
    }

    /// `GET /v1/descriptors`: the public directory (identities whose card record is listed), optionally only agents
    /// listing `profile`.
    public func directory(profile: String? = nil, cursor: String? = nil, limit: Int = ACELimits.defaultPageLimit) async throws -> DirectoryPage {
        guard (1...ACELimits.maxInboxPage).contains(limit) else { throw ACEError(.invalidArgument, "limit must be 1...\(ACELimits.maxInboxPage)") }
        var query = [("limit", String(limit))]
        if let profile { query.append(("profile", profile)) }
        if let cursor { query.append(("cursor", cursor)) }
        let value = try await call("GET", "/v1/descriptors", query: query)
        guard let list = value["agents"]?.arrayValue, list.count <= limit else { throw ACEError(.relayProtocolError, "invalid directory page") }
        var agents: [VerifiedAgent] = [], rejected = 0
        for v in list {
            try Self.contained(v)
            guard let a = try? agent(v, nil) else { rejected += 1; continue }  // does not verify: dropped
            // Filtered by the exact profile ID when one was requested.
            guard profile.map({ p in a.descriptor.profiles.contains { $0.id == p } }) ?? true else {
                throw ACEError(.relayProtocolError, "directory entry does not match the query")
            }
            agents.append(a)
        }
        return DirectoryPage(agents: agents, rejected: rejected, cursor: try nullableField(value, "cursor") { $0.stringValue })
    }

    /// `POST /v1/blocks {peer, blocked, revision}` (action `block`).
    public func setBlock(_ identity: any ACEIdentity, peer: String, blocked: Bool, revision: Int) async throws {
        let body: JSONValue = ["peer": .string(peer), "blocked": .bool(blocked), "revision": .number(Double(revision))]
        _ = try await call("POST", "/v1/blocks", body: try body.jsonData(), auth: (identity, .block(peer: peer, blocked: blocked, revision: revision)))
    }

    /// `PUT /v1/wake {gateway, token}` (action `wake`, 07 § Wake hints): register or replace the gateway this relay wakes
    /// when entries are queued for `identity`. `gateway` is a canonical relay URL (loopback `http` only with
    /// `allowLoopbackRelays`) and `token` the gateway's `^[A-Za-z0-9_-]{22,512}$` token (`invalid_argument`). A relay
    /// without wake hints answers `relay_rejected` with relay code `not_found`.
    public func setWake(_ identity: any ACEIdentity, gateway: String, token: String) async throws {
        // Signing validates gateway and token; a loopback http gateway is this client's development policy.
        guard isRelayRoute(gateway, allowLoopback: allowLoopbackRelays) else {
            throw ACEError(.invalidArgument, "wake gateway must be a canonical https URL (loopback http only in development)")
        }
        let body: JSONValue = ["gateway": .string(gateway), "token": .string(token)]
        _ = try await call("PUT", "/v1/wake", body: try body.jsonData(), auth: (identity, .setWake(gateway: gateway, token: token)))
    }

    /// `DELETE /v1/wake` (action `wake`): remove the wake registration (idempotent).
    public func clearWake(_ identity: any ACEIdentity) async throws {
        _ = try await call("DELETE", "/v1/wake", auth: (identity, .clearWake))
    }

    /// `POST /v1/send {packet, permit?}`. `{ok: true}` means queued, never delivered. A permit not issued by `packet.to` to
    /// `packet.from` is `invalid_argument` (never sent).
    public func send(_ packet: Packet, permit: JSONValue? = nil) async throws {
        // A permit is a bearer credential: attach it only to a packet it authorizes.
        if let permit, permit["issuer"]?.stringValue != packet.to || permit["subject"]?.stringValue != packet.from {
            throw ACEError(.invalidArgument, "the permit must be issued by packet.to to packet.from")
        }
        var o: [String: JSONValue] = ["packet": packet.jsonValue]
        if let permit { o["permit"] = permit }
        _ = try await call("POST", "/v1/send", body: try JSONValue.object(o).jsonData())
    }

    /// `GET /v1/inbox` (non-destructive). `since` is a stream ID (`nil` = from the start); `limit` 1…100.
    public func fetchInbox(_ identity: any ACEIdentity, since: String? = nil, limit: Int = ACELimits.maxInboxPage) async throws -> InboxPage {
        let since = since ?? "-"
        let auth = RelayAuthRequest.inbox(since: since, limit: limit)
        try auth.validate()
        var q: [(String, String)] = []
        if since != "-" { q.append(("since", since)) }
        q.append(("limit", String(limit)))
        let v = try await call("GET", "/v1/inbox", query: q, auth: (identity, auth))
        guard let list = v["messages"]?.arrayValue, list.count <= limit else {
            throw ACEError(.relayProtocolError, "messages must be a list of at most limit entries")
        }
        let entries: [InboxEntry] = try list.map { e in
            guard let id = e["streamId"]?.stringValue, isStreamCursor(id), let p = e["packet"] else {
                throw ACEError(.relayProtocolError, "inbox entries must be {streamId, packet}")
            }
            try Self.contained(p)
            return InboxEntry(streamId: id, packet: try p.jsonData())
        }
        return InboxPage(entries: entries, cursor: try nullableField(v, "cursor") { $0.stringValue })
    }

    /// `POST /v1/inbox/ack?through=` (action `inbox-ack`): deletes entries up to and including `through`.
    public func ackInbox(_ identity: any ACEIdentity, through: String) async throws {
        _ = try await call("POST", "/v1/inbox/ack", query: [("through", through)], auth: (identity, .inboxAck(through: through)))
    }

    /// `GET /v1/listen` as a stream of `catchup` / `message` events.
    ///
    /// Reconnects with backoff 1, 2, 4 … 30 s (honoring `Retry-After`), resuming after the last yielded `streamId`. `drain`
    /// or a clean end after progress reconnects at once; ten consecutive failures end the stream with `relay_unavailable`.
    /// At most 64 events wait for the consumer (TCP backpressure beyond). `onOpen` runs on each established connection;
    /// an error it throws ends the stream. Cancelling the consumer cancels the request.
    public nonisolated func listen(_ identity: any ACEIdentity, since: String? = nil,
                                   onOpen: (@Sendable () throws -> Void)? = nil) -> AsyncThrowingStream<Event, Error> {
        AsyncThrowingStream(bufferingPolicy: .bufferingOldest(Self.listenBuffer)) { continuation in
            let task = Task {
                do {
                    try await self.runListen(identity, since: since, onOpen: onOpen, continuation)
                    continuation.finish()
                } catch let hook as OnOpenFailure {
                    continuation.finish(throwing: hook.error)
                } catch {
                    continuation.finish(throwing: error is CancellationError ? nil : error)
                }
            }
            continuation.onTermination = { _ in task.cancel() }
        }
    }

    // MARK: Listen internals

    /// An error thrown by `onOpen`, carried past the reconnect logic unchanged.
    private struct OnOpenFailure: Error { let error: any Error }

    private func runListen(_ identity: any ACEIdentity, since: String?, onOpen: (@Sendable () throws -> Void)?,
                           _ out: AsyncThrowingStream<Event, Error>.Continuation) async throws {
        var cursor = since ?? "-"
        guard cursor == "-" || isStreamCursor(cursor) else { throw ACEError(.invalidArgument, "since must be a stream ID") }
        var failures = 0
        while true {
            try Task.checkCancellation()
            do {
                // A clean end (drain or EOF) reconnects at once if the connection made progress;
                // one that delivered only `connected`, heartbeats or nothing is a failure.
                if try await connectOnce(identity, cursor: &cursor, onOpen: onOpen, out, onProgress: { failures = 0 }) {
                    failures = 0
                    continue
                }
                throw ACEError(.relayUnavailable, "listen stream ended without progress")
            } catch let e as ACEError where e.code == .relayUnavailable {
                failures += 1
                if failures >= Self.maxConnectFailures { throw e }
                var delay = min(pow(2, Double(failures - 1)), Self.maxBackoffSeconds)
                if let ra = e.retryAfterSeconds { delay = min(max(delay, Double(ra)), Self.maxBackoffSeconds) }
                try await sleeper(delay)
            }
        }
    }

    /// One connection; returns after `drain` or a clean end of stream, with whether it made
    /// progress (a `catchup`, `message` or `drain` frame).
    private func connectOnce(_ identity: any ACEIdentity, cursor: inout String, onOpen: (@Sendable () throws -> Void)?,
                             _ out: AsyncThrowingStream<Event, Error>.Continuation,
                             onProgress: () -> Void) async throws -> Bool {
        var q: [(String, String)] = []
        if cursor != "-" { q.append(("since", cursor)) }
        var bytes: RelayResponseBytes?
        var http: HTTPURLResponse?
        for attempt in 0..<2 {
            var request = try makeRequest("GET", "/v1/listen", query: q, body: nil)
            // URLSession's request timeout is an idle timeout: a silent stream is dropped.
            request.timeoutInterval = max(timeout, Self.idleTimeoutSeconds)
            request.setValue("text/event-stream", forHTTPHeaderField: "Accept")
            try addAuth(&request, identity, .listen(since: cursor))
            let h: HTTPURLResponse
            let b: RelayResponseBytes
            do {
                (b, h) = try await responseBytes(request, streaming: true)
            } catch {
                throw transportError(error, "listen connect failed")
            }
            if h.statusCode == 200 {
                bytes = b
                http = h
                break
            }
            let data = try await readBounded(b)
            if (200..<300).contains(h.statusCode) {
                throw ACEError(.relayProtocolError, "unexpected listen HTTP \(h.statusCode)", status: h.statusCode)
            }
            let error = mapStatus(h, data)
            if attempt == 0, h.statusCode == 409, error.relayCode == "replay" { continue }
            throw error
        }
        guard let bytes, let http else { throw ACEError(.relayProtocolError, "listen connect failed") }
        defer { bytes.cancel() }
        guard mediaType(http) == "text/event-stream" else {
            throw ACEError(.relayProtocolError, "listen response is not text/event-stream")
        }
        do { try onOpen?() } catch { throw OnOpenFailure(error: error) }
        var parser = SSEParser(maxLine: ACELimits.maxSendBodyBytes)
        // Cancel the data task itself on task cancellation, so a stream that only carries
        // heartbeats (or nothing) is torn down at once; every exit path cancels it too.
        do {
            return try await withTaskCancellationHandler {
                try await readEvents(bytes, &parser, cursor: &cursor, out, onProgress: onProgress)
            } onCancel: {
                bytes.cancel()
            }
        } catch let e as ACEError {
            throw e
        } catch {
            throw transportError(error, "listen stream failed")
        }
    }

    /// Feed the stream to `parser`; returns at `drain` or end of stream, with whether the
    /// connection made progress (a `catchup`, `message` or `drain` frame, each of which calls
    /// `onProgress`; `connected`, other types and comments do not).
    private func readEvents(_ bytes: RelayResponseBytes, _ parser: inout SSEParser, cursor: inout String,
                            _ out: AsyncThrowingStream<Event, Error>.Continuation, onProgress: () -> Void) async throws -> Bool {
        var sawEvent = false
        for try await byte in bytes {
            guard let frame = try parser.feed(byte) else { continue }
            try Task.checkCancellation()
            switch frame.event {
            case "catchup", "message":
                sawEvent = true
                guard let id = frame.id, isStreamCursor(id) else {
                    throw ACEError(.relayProtocolError, "SSE event without a valid stream id")
                }
                // `data: {"packet": …}` (02 § JSON values); anything else is a protocol error.
                guard let packet = (try? JSONParser.parse(Data(frame.data), maxDepth: Self.responseDepth))?["packet"],
                      let bytes = try? packet.jsonData() else {
                    throw ACEError(.relayProtocolError, #"SSE data must be {"packet": …} within MAX_JSON_DEPTH + 3"#)
                }
                try Self.contained(packet)
                cursor = id
                onProgress()
                try await out.yieldWaiting(Event(streamId: id, packet: bytes, catchup: frame.event == "catchup"))
            case "drain":
                onProgress()
                return true
            default:
                break  // connected, or an unknown type: not progress
            }
        }
        // A stream that ends inside a line was dropped, not closed (sdk-py `_SSELines`): a failure.
        if parser.midLine { throw ACEError(.relayUnavailable, "listen stream ended mid-line") }
        return sawEvent
    }

    // MARK: HTTP

    /// `unregister` is signed at `max(now, last registration + 1)` (it must exceed the stored registration timestamp) and
    /// becomes the new barrier: a later `register` is signed above it, since the relay refuses a registration timestamp at
    /// or below the unregister barrier (`identity_conflict`).
    private func addAuth(_ request: inout URLRequest, _ identity: any ACEIdentity, _ auth: RelayAuthRequest) throws {
        var timestamp = try unixNow(clock)  // a bad clock reading is `invalid_argument` before any request
        if auth.action == "unregister" { timestamp = try nextRegistrationTimestamp(identity, floor: timestamp) }
        for (k, v) in try createAuthHeaders(identity, request: auth, timestamp: timestamp, audience: baseURLString) {
            request.setValue(v, forHTTPHeaderField: k)
        }
    }

    private func makeRequest(_ method: String, _ path: String, query: [(String, String)], body: Data?) throws -> URLRequest {
        var s = baseURLString + path
        if !query.isEmpty {
            s += "?" + query.map { "\(percentEncode($0.0))=\(percentEncode($0.1))" }.joined(separator: "&")
        }
        guard let url = URL(string: s) else { throw ACEError(.invalidArgument, "cannot build relay URL") }
        var r = URLRequest(url: url)
        r.httpMethod = method
        r.timeoutInterval = timeout
        r.setValue("application/json", forHTTPHeaderField: "Accept")
        if let body {
            r.httpBody = body
            r.setValue("application/json", forHTTPHeaderField: "Content-Type")
        }
        return r
    }

    private func call(_ method: String, _ path: String, query: [(String, String)] = [], body: Data? = nil,
                      auth: (any ACEIdentity, RelayAuthRequest)? = nil) async throws -> JSONValue {
        var attempt = 0
        while true {
            var request = try makeRequest(method, path, query: query, body: body)
            if let auth { try addAuth(&request, auth.0, auth.1) }
            let (http, data) = try await perform(request)
            if http.statusCode == 200 {
                // 02 § JSON values: a response deeper than MAX_JSON_DEPTH + 3 is a protocol error.
                guard let v = try? JSONParser.parse(data, maxDepth: Self.responseDepth), v.objectValue != nil else {
                    throw ACEError(.relayProtocolError, "relay response is not a JSON object within MAX_JSON_DEPTH + 3", status: http.statusCode)
                }
                return v
            }
            if (200..<300).contains(http.statusCode) {
                throw ACEError(.relayProtocolError, "unexpected relay HTTP \(http.statusCode)", status: http.statusCode)
            }
            let error = mapStatus(http, data)
            if http.statusCode == 409, error.relayCode == "replay", auth != nil, attempt == 0 {
                attempt += 1
                continue
            }
            throw error
        }
    }

    private func responseBytes(_ request: URLRequest, streaming: Bool) async throws -> (RelayResponseBytes, HTTPURLResponse) {
        if checksAddresses {
            return try await PinnedRelayTransport.open(request, allowLoopback: allowLoopbackRelays,
                                                       timeout: timeout, streaming: streaming)
        }
        let source = streaming ? listenSession() : session
        let (bytes, response) = try await source.bytes(for: request, delegate: noRedirect)
        guard let http = response as? HTTPURLResponse else {
            bytes.task.cancel()
            throw ACEError(.relayProtocolError, "not an HTTP response")
        }
        return (RelayResponseBytes(bytes), http)
    }

    private func perform(_ request: URLRequest) async throws -> (HTTPURLResponse, Data) {
        do {
            let (bytes, http) = try await responseBytes(request, streaming: false)
            return (http, try await readBounded(bytes))
        } catch let e as ACEError {
            throw e
        } catch {
            throw transportError(error, "relay request failed")
        }
    }

    /// Map a URLSession failure: cancellation stays cancellation, anything else is `relay_unavailable`.
    private func transportError(_ error: Error, _ what: String) -> Error {
        if let error = error as? ACEError { return error }
        if error is CancellationError || (Task.isCancelled && (error as? URLError)?.code == .cancelled) {
            return CancellationError()
        }
        return ACEError(.relayUnavailable, "\(what): \(error.localizedDescription)")
    }

    private func readBounded(_ bytes: RelayResponseBytes) async throws -> Data {
        defer { bytes.cancel() }
        var data = Data()
        do {
            for try await b in bytes {
                data.append(b)
                if data.count > maxResponseBytes {
                    throw ACEError(.relayProtocolError, "relay response exceeds \(maxResponseBytes) bytes")
                }
            }
        } catch let e as ACEError {
            throw e
        } catch {
            throw transportError(error, "relay read failed")
        }
        return data
    }

    private func mapStatus(_ http: HTTPURLResponse, _ data: Data) -> ACEError {
        relayError(status: http.statusCode, retryAfter: http.value(forHTTPHeaderField: "Retry-After"), body: data)
    }

    /// Absent or null is `nil`; present but malformed is `relay_protocol_error`.
    /// A required field whose value may be `null`.
    private func nullableField<T>(_ v: JSONValue, _ key: String, _ get: (JSONValue) -> T?) throws -> T? {
        guard let f = v[key], !f.isNull else { return nil }
        guard let t = get(f) else { throw ACEError(.relayProtocolError, "\(key) is malformed") }
        return t
    }
}

private func percentEncode(_ s: String) -> String {
    var allowed = CharacterSet.alphanumerics.intersection(CharacterSet(charactersIn: Unicode.Scalar(0)...Unicode.Scalar(127)))
    allowed.insert(charactersIn: "-._~")
    return s.addingPercentEncoding(withAllowedCharacters: allowed) ?? s
}

/// The numeric addresses `host` resolves to (`getaddrinfo`, off the cooperative pool). An IP literal resolves to itself.
func resolveAddresses(_ host: String) async throws -> [String] {
    try await withCheckedThrowingContinuation { (c: CheckedContinuation<[String], Error>) in
        DispatchQueue.global().async {
            var hints = addrinfo(ai_flags: 0, ai_family: AF_UNSPEC, ai_socktype: SOCK_STREAM, ai_protocol: 0, ai_addrlen: 0,
                                 ai_canonname: nil, ai_addr: nil, ai_next: nil)
            var list: UnsafeMutablePointer<addrinfo>?
            guard getaddrinfo(host, nil, &hints, &list) == 0 else {
                c.resume(throwing: ACEError(.relayUnavailable, "\(host) does not resolve"))
                return
            }
            defer { freeaddrinfo(list) }
            var out: [String] = [], cursor = list
            while let ai = cursor {
                var buf = [CChar](repeating: 0, count: Int(NI_MAXHOST))
                if getnameinfo(ai.pointee.ai_addr, ai.pointee.ai_addrlen, &buf, socklen_t(buf.count), nil, 0, NI_NUMERICHOST) == 0 {
                    out.append(String(cString: buf))
                }
                cursor = ai.pointee.ai_next
            }
            c.resume(returning: out)
        }
    }
}

/// `127.0.0.0/8`, `::1` and their IPv4-mapped forms.
func isLoopbackAddress(_ address: String) -> Bool {
    let bare = address.lowercased()
    return bare == "::1" || bare.hasPrefix("127.") || bare.hasPrefix("::ffff:127.")
}

/// Task delegate that refuses every HTTP redirect: the 3xx response itself is returned.
final class NoRedirectDelegate: NSObject, URLSessionTaskDelegate, Sendable {
    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest request: URLRequest) async -> URLRequest? { nil }
}

/// Map one non-2xx relay response to an `ACEError` (07 § Client rules). The
/// single 409 `replay` retry happens before this mapping.
///
/// `relayCode` is the body's `error` string (at most 64 characters) and the message is
/// `relay HTTP <status>[ <relayCode>][: <message, at most 500 characters>]` (sdk-py `_map_relay_response`).
func relayError(status: Int, retryAfter: String?, body: Data) -> ACEError {
    let obj = (try? JSONParser.parse(body))?.objectValue
    func prefix(_ s: String, _ n: Int) -> String { String(String.UnicodeScalarView(s.unicodeScalars.prefix(n))) }
    let relayCode = obj?["error"]?.stringValue.map { prefix($0, 64) }
    let detail = relayCode == nil ? nil : obj?["message"]?.stringValue.map { prefix($0, 500) }
    var message = "relay HTTP \(status)"
    if let relayCode, !relayCode.isEmpty { message += " \(relayCode)" }
    if let detail, !detail.isEmpty { message += ": \(detail)" }
    let code: ACEError.Code
    switch status {
    case 100..<200, 300..<400: code = .relayProtocolError
    case 408, 429, 500..<600: code = .relayUnavailable
    case 403 where relayCode == "not_registered": code = .notRegistered
    case 403 where relayCode == "not_permitted": code = .notPermitted
    case 404 where relayCode == "unknown_peer": code = .unknownPeer
    case 400..<500: code = .relayRejected
    default: code = .relayProtocolError
    }
    let seconds = code.category == .transient ? retryAfter.flatMap(parseRetryAfter) : nil
    return ACEError(code, message, status: status, relayCode: relayCode, retryAfterSeconds: seconds)
}

/// `Retry-After` as delay-seconds (`^[0-9]+$`); any other form (HTTP-date, fraction) is nil. A value beyond `Int.max`
/// saturates to `Int.max` (Python keeps the big integer; every use caps the delay at 30 s).
func parseRetryAfter(_ value: String) -> Int? {
    guard !value.isEmpty, value.utf8.allSatisfy({ $0 >= 0x30 && $0 <= 0x39 }) else { return nil }
    return Int(value) ?? Int.max
}

/// At most 2048 characters and equal to its own normalization: the form part of a canonical relay URL (02 § Relay URL);
/// `isRelayRoute` adds the scheme and host rules.
package func isCanonicalRelayURL(_ value: String) -> Bool {
    value.utf8.count <= 2048 && (try? normalizeRelayURL(value)) == value
}

/// Normalize a relay base URL (02 § Relay URLs): lowercase http(s) scheme
/// and host (ASCII `[A-Za-z0-9.-]+` or a bracketed IPv6 literal), no userinfo / query /
/// fragment / whitespace or control characters, port without leading zeros, default
/// port dropped, trailing `/` removed, the rest of the path verbatim. Failures are
/// `invalid_argument`. The result is the inbox cursor key.
func normalizeRelayURL(_ s: String) throws -> String {
    func bad(_ why: String) -> ACEError { ACEError(.invalidArgument, "relay URL \(why)") }
    let u = Array(s.utf8)
    guard !u.contains(where: { $0 <= 0x20 || $0 == 0x7F }) else { throw bad("must not contain whitespace or control characters") }
    guard !u.contains(UInt8(ascii: "?")), !u.contains(UInt8(ascii: "#")) else { throw bad("must not have a query or fragment") }
    guard let sep = s.range(of: "://") else { throw bad("must be an absolute http(s) URL") }
    let scheme = s[..<sep.lowerBound].lowercased()
    guard scheme == "http" || scheme == "https" else { throw bad("must use http or https") }
    let rest = s[sep.upperBound...]
    let pathStart = rest.firstIndex(of: "/") ?? rest.endIndex
    let authority = rest[..<pathStart]
    var path = String(rest[pathStart...])
    guard !authority.contains("@") else { throw bad("must not contain userinfo") }
    var host: Substring
    var portText: Substring?
    if authority.hasPrefix("[") {
        guard let close = authority.firstIndex(of: "]") else { throw bad("has an invalid host") }
        host = authority[...close]
        let after = authority[authority.index(after: close)...]
        if !after.isEmpty {
            guard after.hasPrefix(":") else { throw bad("has an invalid host") }
            portText = after.dropFirst()
        }
        let inner = host.dropFirst().dropLast()
        var v6 = in6_addr()
        guard !inner.isEmpty, inner.allSatisfy({ $0.isHexDigit || $0 == ":" || $0 == "." }),
              inet_pton(AF_INET6, String(inner), &v6) == 1 else { throw bad("has an invalid IPv6 host") }
    } else {
        if let colon = authority.firstIndex(of: ":") {
            host = authority[..<colon]
            portText = authority[authority.index(after: colon)...]
        } else {
            host = authority
        }
        guard host.allSatisfy({ ($0.isASCII && ($0.isLetter || $0.isNumber)) || $0 == "-" || $0 == "." }) else {
            throw bad("host must be ASCII [A-Za-z0-9.-]")
        }
    }
    guard !host.isEmpty else { throw bad("has an empty host") }
    var port = ""
    if let portText {
        guard !portText.isEmpty, portText.count <= 5, portText.first != "0",
              portText.allSatisfy({ $0.isASCII && $0.isNumber }),
              let n = Int(portText), (1...65535).contains(n) else { throw bad("has an invalid port") }
        if !((scheme == "https" && n == 443) || (scheme == "http" && n == 80)) { port = ":\(n)" }
    }
    while path.hasSuffix("/") { path.removeLast() }
    let out = "\(scheme)://\(host.lowercased())\(port)\(path)"
    guard URL(string: out) != nil else { throw bad("is not a valid URL") }
    return out
}

/// Incremental SSE parser over bytes.
struct SSEParser {
    struct Frame {
        var id: String?
        var event = "message"
        var data: [UInt8] = []
    }

    let maxLine: Int
    private var line: [UInt8] = []
    private var frame = Frame()
    private var hasData = false
    /// The previous byte was CR, so an LF right after it ends no further line.
    private var afterCR = false

    init(maxLine: Int) { self.maxLine = maxLine }

    /// Bytes of an unterminated line are buffered (the stream so far ends mid-line).
    var midLine: Bool { !line.isEmpty }

    /// Feed one byte; returns a frame at each blank line that ends an event with a `data`
    /// field (07 § Client rules, Listen); `id` and `event` apply to that event only. Lines
    /// end with CR, LF or CRLF.
    mutating func feed(_ b: UInt8) throws -> Frame? {
        let wasCR = afterCR
        afterCR = b == 0x0D
        if b == 0x0A && wasCR { return nil }
        if b != 0x0A && b != 0x0D {
            line.append(b)
            if line.count > maxLine {
                throw ACEError(.relayProtocolError, "SSE line exceeds \(maxLine) bytes")
            }
            return nil
        }
        defer { line.removeAll(keepingCapacity: true) }
        if line.isEmpty {
            defer { frame = Frame(); hasData = false }
            return hasData ? frame : nil
        }
        if line[0] == UInt8(ascii: ":") { return nil }
        let colon = line.firstIndex(of: UInt8(ascii: ":")) ?? line.count
        let field = String(decoding: line[..<colon], as: UTF8.self)
        var value = colon < line.count ? Array(line[(colon + 1)...]) : []
        if value.first == 0x20 { value.removeFirst() }
        switch field {
        case "id": frame.id = String(decoding: value, as: UTF8.self)
        case "event": frame.event = String(decoding: value, as: UTF8.self)
        case "data":
            if hasData { frame.data.append(0x0A) }
            frame.data.append(contentsOf: value)
            hasData = true
            if frame.data.count > maxLine { throw ACEError(.relayProtocolError, "SSE data exceeds \(maxLine) bytes") }
        default: break
        }
        return nil
    }
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
