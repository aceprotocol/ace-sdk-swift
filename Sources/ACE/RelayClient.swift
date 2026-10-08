//
//  RelayClient.swift
//  ACE SDK
//
//  HTTP client for the relay API (08-relay).
//

import Foundation

/// Relay HTTP client (08-relay § Client Rules). Authenticated calls use `X-ACE-*` headers
/// with `timestamp = max(now, last + 1)` and retry once on 409 `replay`.
///
/// Redirects are never followed (every request, `listen` included, runs with a task
/// delegate that refuses them). Error mapping: network errors and timeouts →
/// `relay_unavailable`; a non-2xx status maps as in 08 § Client Rules, Responses
/// (1xx / 3xx → `relay_protocol_error`; 408, 5xx and 429 `rate_limited` (or no code) →
/// `relay_unavailable`; any other 429 → `relay_rejected`; 400 `envelope_expired`,
/// 403 `not_registered`, 404 `unknown_peer` → the same code; other 4xx → `relay_rejected`),
/// keeping `status` and `relayCode`. `retryAfterSeconds` is set only from an integer
/// `Retry-After` on a transient error. An oversized, empty or malformed 2xx body, or a
/// present-but-malformed field, is `relay_protocol_error`.
public actor RelayClient {
    public enum RegisterStatus: String, Sendable {
        case registered, idempotent, refreshed, rotated
    }

    public struct InboxEntry: Sendable, Equatable {
        public let streamId: String
        /// The `message` JSON as served by the relay, undecoded (`Inbox.receive` decodes it).
        public let message: Data
    }

    public struct InboxPage: Sendable {
        public let entries: [InboxEntry]
        public let cursor: String?
    }

    /// One SSE `catchup` / `message` event. `message` is the raw frame data, not parsed.
    public struct Event: Sendable, Equatable {
        public let streamId: String
        public let message: Data
        public let catchup: Bool
    }

    public struct DiscoverPage: Sendable {
        /// Verified peers; `profile` is unverified relay metadata.
        public let agents: [VerifiedPeer]
        /// Entries dropped because they failed verification.
        public let rejected: Int
        public let cursor: String?
    }

    public struct Intent: Sendable, Equatable {
        public let intentId: String
        public let from: String
        public let need: String
        public let tags: [String]
        public let maxPrice: String?
        public let currency: String?
        public let ttl: Int
        public let createdAt: Int
        public let expiresAt: Int
    }

    public struct IntentPage: Sendable {
        public let intents: [Intent]
        public let cursor: String?
    }

    public enum WebhookStatus: String, Sendable {
        case active, disabled
    }

    public struct PostedIntent: Sendable, Equatable {
        public let intentId: String
        public let expiresAt: Int
    }

    /// The caller's webhook as `GET /v1/webhook` reports it (the secret is never returned).
    public struct Webhook: Sendable, Equatable {
        public let url: String
        public let status: WebhookStatus
        public let failures: Int
        public let updatedAt: Int
        public let lastDeliveredAt: Int?
        public let lastError: String?
    }

    /// The normalized base URL (08 § Client Rules, Relay URL).
    public nonisolated let baseURL: URL
    /// `baseURL` as a string: the normalized relay key. Use it for
    /// `ReceiveSource.relay(url:)`; `Inbox` keys cursors by it.
    public nonisolated let baseURLString: String
    private let session: URLSession
    /// `listen`'s own session (see `init`); created on first use.
    private var streamSession: URLSession?
    private let timeout: TimeInterval
    private let maxResponseBytes: Int
    private let clock: @Sendable () -> Int
    private let sleeper: @Sendable (Double) async throws -> Void
    private let noRedirect = NoRedirectDelegate()
    private var lastAuthTimestamp = 0

    /// Reconnect attempts after which `listen` fails with `relay_unavailable`.
    static let maxConnectFailures = 10
    static let maxBackoffSeconds = 30.0
    static let idleTimeoutSeconds = 90.0
    /// Events buffered for a slow consumer; when full, reading the socket pauses.
    static let listenBuffer = 64

    /// `baseURL` is normalized per 08 § Client Rules, Relay URL: http(s) only, no userinfo,
    /// query, fragment or whitespace / control characters (`invalid_argument`).
    ///
    /// `session` carries every request-response call. `listen` does not use it directly:
    /// it opens a dedicated session from a copy of `session.configuration` (same
    /// protocol classes, proxy, TLS and cookie settings, and the same delegate) with
    /// `timeoutIntervalForResource = .infinity` and `timeoutIntervalForRequest = 90 s`,
    /// the idle limit after which `listen` reconnects. A host session tuned for short
    /// calls (a 60 s resource timeout, say) therefore cannot kill the SSE stream, and a
    /// silent stream is still detected.
    public init(
        baseURL: URL,
        session: URLSession = .shared,
        timeout: TimeInterval = 10,
        maxResponseBytes: Int = 16 << 20,
        clock: @escaping @Sendable () -> Int = systemClock
    ) throws {
        try self.init(baseURL: baseURL, session: session, timeout: timeout, maxResponseBytes: maxResponseBytes,
                      clock: clock, sleeper: { try await Task.sleep(nanoseconds: UInt64($0 * 1_000_000_000)) })
    }

    init(
        baseURL: URL, session: URLSession, timeout: TimeInterval, maxResponseBytes: Int,
        clock: @escaping @Sendable () -> Int, sleeper: @escaping @Sendable (Double) async throws -> Void
    ) throws {
        let normalized = try normalizeRelayURL(baseURL.absoluteString)
        guard let url = URL(string: normalized) else { throw ACEError(.invalidArgument, "baseURL is not a valid URL") }
        guard timeout > 0, maxResponseBytes > 0 else { throw ACEError(.invalidArgument, "timeout and maxResponseBytes must be positive") }
        self.baseURL = url
        self.baseURLString = normalized
        self.session = session
        self.timeout = timeout
        self.maxResponseBytes = maxResponseBytes
        self.clock = wireClock(clock)
        self.sleeper = sleeper
    }

    deinit {
        streamSession?.finishTasksAndInvalidate()
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

    /// `POST /v1/register` with a fresh registration request.
    @discardableResult
    /// The request is body-signed, not header-authenticated, so the relay never answers it
    /// with `replay` and it is not retried.
    public func register(_ identity: any ACEIdentity, profile: RegistrationProfile = .keep) async throws -> RegisterStatus {
        let req = try createRegistrationRequest(identity: identity, profile: profile, timestamp: nextTimestamp())
        let v = try await call("POST", "/v1/register", body: req.jsonData())
        guard let s = v["status"]?.stringValue, let status = RegisterStatus(rawValue: s) else {
            throw ACEError(.relayProtocolError, "unexpected register response")
        }
        return status
    }

    /// `POST /v1/unregister`.
    public func unregister(_ identity: any ACEIdentity) async throws {
        _ = try await call("POST", "/v1/unregister", auth: (identity, .unregister))
    }

    /// `GET /v1/peer`; the record's `aceId` must equal `aceId` and it must verify.
    public func lookupPeer(_ aceId: String) async throws -> VerifiedPeer {
        guard isACEId(aceId) else { throw ACEError(.invalidArgument, "aceId must be an ACE ID") }
        let v = try await call("GET", "/v1/peer", query: [("aceId", aceId)])
        let record = try PeerRecord.parse(v)
        guard record.aceId == aceId else { throw ACEError(.invalidPeer, "relay returned a different aceId") }
        return try verifyPeerRecord(record)
    }

    /// `GET /v1/discover`; unverifiable entries are dropped and counted in `rejected`.
    /// `tags` are joined with `,` (a tag containing `,` is `invalid_argument`).
    public func discover(_ query: DiscoverQuery = DiscoverQuery()) async throws -> DiscoverPage {
        var q: [(String, String)] = []
        if let v = query.q { q.append(("q", v)) }
        if let v = query.tags { q.append(("tags", try joinTags(v))) }
        if let v = query.chain { q.append(("chain", v)) }
        if let v = query.scheme { q.append(("scheme", v)) }
        if let v = query.online { q.append(("online", v ? "true" : "false")) }
        if let v = query.account { q.append(("account", v)) }
        if let v = query.limit { q.append(("limit", String(v))) }
        if let v = query.cursor { q.append(("cursor", v)) }
        let v = try await call("GET", "/v1/discover", query: q)
        guard let list = v["agents"]?.arrayValue else { throw ACEError(.relayProtocolError, "unexpected discover response") }
        var agents: [VerifiedPeer] = []
        var rejected = 0
        for entry in list {
            if let peer = try? verifyPeerRecord(PeerRecord.parse(entry)) { agents.append(peer) } else { rejected += 1 }
        }
        return DiscoverPage(agents: agents, rejected: rejected, cursor: try nullableField(v, "cursor") { $0.stringValue })
    }

    /// `POST /v1/send`. Exact duplicates are acknowledged by the relay.
    public func send(_ env: ACEMessage) async throws {
        let body = JSONWriter.serialize(.object(["message": env.jvalue]))
        _ = try await call("POST", "/v1/send", body: body)
    }

    /// `GET /v1/inbox`. `since` is a stream ID (`nil` or `"-"` = from the start); `limit` 1…100.
    /// More than `limit` entries is `relay_protocol_error`.
    public func fetchInbox(_ identity: any ACEIdentity, since: String? = nil, limit: Int = ACELimits.maxInboxPage) async throws -> InboxPage {
        let since = since ?? "-"
        let auth = RelayAuthRequest.inbox(since: since, limit: limit)
        try auth.validate()
        var q: [(String, String)] = []
        if since != "-" { q.append(("since", since)) }
        q.append(("limit", String(limit)))
        let v = try await call("GET", "/v1/inbox", query: q, auth: (identity, auth))
        guard let list = v["messages"]?.arrayValue else { throw ACEError(.relayProtocolError, "unexpected inbox response") }
        guard list.count <= limit else { throw ACEError(.relayProtocolError, "inbox page has more than \(limit) entries") }
        let entries: [InboxEntry] = try list.map { e in
            guard let id = e["streamId"]?.stringValue, isStreamCursor(id), let m = e["message"] else {
                throw ACEError(.relayProtocolError, "malformed inbox entry")
            }
            return InboxEntry(streamId: id, message: JSONWriter.serialize(m))
        }
        return InboxPage(entries: entries, cursor: try nullableField(v, "cursor") { $0.stringValue })
    }

    /// `POST /v1/intents`. `tags` is always sent (possibly empty), mirroring the signed payload.
    public func postIntent(_ identity: any ACEIdentity, need: String, tags: [String] = [], maxPrice: String? = nil,
                           currency: String? = nil, ttl: Int) async throws -> PostedIntent {
        let auth = RelayAuthRequest.intent(need: need, tags: tags, maxPrice: maxPrice, currency: currency, ttl: ttl)
        var o: [String: JValue] = ["need": .string(need), "ttl": .number(String(ttl)), "tags": .array(tags.map { .string($0) })]
        if let maxPrice { o["maxPrice"] = .string(maxPrice) }
        if let currency { o["currency"] = .string(currency) }
        let v = try await call("POST", "/v1/intents", body: JSONWriter.serialize(.object(o)), auth: (identity, auth))
        guard let id = v["intentId"]?.stringValue, let expiresAt = v["expiresAt"]?.wireInt else {
            throw ACEError(.relayProtocolError, "unexpected intent response")
        }
        return PostedIntent(intentId: id, expiresAt: expiresAt)
    }

    /// `GET /v1/intents`. `tags` are joined with `,` (a tag containing `,` is `invalid_argument`).
    public func listIntents(q: String? = nil, tags: [String]? = nil, limit: Int? = nil, cursor: String? = nil) async throws -> IntentPage {
        var query: [(String, String)] = []
        if let q { query.append(("q", q)) }
        if let tags { query.append(("tags", try joinTags(tags))) }
        if let limit { query.append(("limit", String(limit))) }
        if let cursor { query.append(("cursor", cursor)) }
        let v = try await call("GET", "/v1/intents", query: query)
        guard let list = v["intents"]?.arrayValue else { throw ACEError(.relayProtocolError, "unexpected intents response") }
        let intents: [Intent] = try list.map { i in
            guard let id = i["intentId"]?.stringValue, let from = i["from"]?.stringValue, let need = i["need"]?.stringValue,
                  let ttl = i["ttl"]?.wireInt, let createdAt = i["createdAt"]?.wireInt, let expiresAt = i["expiresAt"]?.wireInt else {
                throw ACEError(.relayProtocolError, "malformed intent")
            }
            guard let tagList = i["tags"]?.arrayValue else { throw ACEError(.relayProtocolError, "malformed intent tags") }
            let tags: [String] = try tagList.map {
                guard let t = $0.stringValue else { throw ACEError(.relayProtocolError, "malformed intent tags") }
                return t
            }
            return Intent(intentId: id, from: from, need: need, tags: tags,
                          maxPrice: try optionalField(i, "maxPrice") { $0.stringValue },
                          currency: try optionalField(i, "currency") { $0.stringValue },
                          ttl: ttl, createdAt: createdAt, expiresAt: expiresAt)
        }
        return IntentPage(intents: intents, cursor: try nullableField(v, "cursor") { $0.stringValue })
    }

    /// `PUT /v1/webhook`: set or replace the caller's webhook.
    public func setWebhook(_ identity: any ACEIdentity, url: String, secret: String) async throws {
        let auth = RelayAuthRequest.webhook(.put(url: url, secret: secret))
        let body = JSONWriter.serialize(.object(["url": .string(url), "secret": .string(secret)]))
        _ = try await call("PUT", "/v1/webhook", body: body, auth: (identity, auth))
    }

    /// `GET /v1/webhook`; `nil` when none is set.
    public func getWebhook(_ identity: any ACEIdentity) async throws -> Webhook? {
        let v = try await call("GET", "/v1/webhook", auth: (identity, .webhook(.get)))
        guard let w = v["webhook"] else { throw ACEError(.relayProtocolError, "unexpected webhook response") }
        if w.isNull { return nil }
        guard let url = w["url"]?.stringValue, let status = w["status"]?.stringValue.flatMap(WebhookStatus.init),
              let failures = w["failures"]?.wireInt, let updatedAt = w["updatedAt"]?.wireInt else {
            throw ACEError(.relayProtocolError, "malformed webhook")
        }
        return Webhook(url: url, status: status, failures: failures, updatedAt: updatedAt,
                       lastDeliveredAt: try optionalField(w, "lastDeliveredAt") { $0.wireInt },
                       lastError: try optionalField(w, "lastError") { $0.stringValue })
    }

    /// `DELETE /v1/webhook` (idempotent).
    public func clearWebhook(_ identity: any ACEIdentity) async throws {
        _ = try await call("DELETE", "/v1/webhook", auth: (identity, .webhook(.delete)))
    }

    /// `GET /v1/listen` as a stream of `catchup` / `message` events.
    ///
    /// Reconnects internally with backoff 1, 2, 4 … 30 s (honoring `Retry-After`), resuming
    /// after the last yielded `streamId`. `drain` or a clean end of stream reconnects at once
    /// when that connection carried a `catchup`, `message` or `drain` frame; one that
    /// delivered only `connected`, heartbeats or nothing counts as a failure. Only those three
    /// frame types reset the failure count; 90 s without a byte reconnects. Ten consecutive
    /// failures end the stream with `relay_unavailable`; a non-retryable status ends it
    /// with the mapped error; a frame larger than `MAX_ENVELOPE_BYTES + 512` ends it with
    /// `relay_protocol_error`.
    ///
    /// At most 64 events wait for the consumer; while the buffer is full the socket is not
    /// read (TCP backpressure), so memory stays bounded.
    ///
    /// `onOpen` is called each time a connection is established (HTTP 200,
    /// `text/event-stream`), before its first event. An error it throws ends the stream
    /// with that error (it is not retried). Cancelling the consuming task or
    /// dropping the stream cancels the HTTP request at once, also while the stream only
    /// carries heartbeats and during a backoff sleep. Uses the dedicated stream session
    /// described in `init`.
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
        var bytes: URLSession.AsyncBytes?
        var http: HTTPURLResponse?
        let session = listenSession()
        for attempt in 0..<2 {
            var request = try makeRequest("GET", "/v1/listen", query: q, body: nil)
            // URLSession's request timeout is an idle timeout: a silent stream is dropped.
            request.timeoutInterval = max(timeout, Self.idleTimeoutSeconds)
            request.setValue("text/event-stream", forHTTPHeaderField: "Accept")
            try addAuth(&request, identity, .listen(since: cursor))
            let response: URLResponse
            let b: URLSession.AsyncBytes
            do {
                (b, response) = try await session.bytes(for: request, delegate: noRedirect)
            } catch {
                throw transportError(error, "listen connect failed")
            }
            guard let h = response as? HTTPURLResponse else { throw ACEError(.relayProtocolError, "not an HTTP response") }
            if h.statusCode == 200 {
                bytes = b
                http = h
                break
            }
            let error = mapStatus(h, try await readBounded(b))
            if attempt == 0, h.statusCode == 409, error.relayCode == "replay" { continue }
            throw error
        }
        guard let bytes, let http else { throw ACEError(.relayProtocolError, "listen connect failed") }
        guard mediaType(http) == "text/event-stream" else {
            bytes.task.cancel()
            throw ACEError(.relayProtocolError, "listen response is not text/event-stream")
        }
        do { try onOpen?() } catch { throw OnOpenFailure(error: error) }
        var parser = SSEParser(maxLine: ACELimits.maxEnvelopeBytes + 512)
        // Cancel the data task itself on task cancellation, so a stream that only carries
        // heartbeats (or nothing) is torn down at once; every exit path cancels it too.
        let dataTask = bytes.task
        defer { dataTask.cancel() }
        do {
            return try await withTaskCancellationHandler {
                try await readEvents(bytes, &parser, cursor: &cursor, out, onProgress: onProgress)
            } onCancel: {
                dataTask.cancel()
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
    private func readEvents(_ bytes: URLSession.AsyncBytes, _ parser: inout SSEParser, cursor: inout String,
                            _ out: AsyncThrowingStream<Event, Error>.Continuation, onProgress: () -> Void) async throws -> Bool {
        var sawEvent = false
        for try await byte in bytes {
            guard let frame = try parser.feed(byte) else { continue }
            try Task.checkCancellation()
            switch frame.event {
            case "catchup", "message":
                sawEvent = true
                guard let id = frame.id, isStreamCursor(id) else { throw ACEError(.relayProtocolError, "SSE event without a valid stream id") }
                // The data is yielded as is: the Inbox quarantines what does not decode.
                cursor = id
                onProgress()
                try await out.yieldWaiting(Event(streamId: id, message: Data(frame.data), catchup: frame.event == "catchup"))
            case "drain":
                onProgress()
                return true
            default:
                break  // connected, or an unknown type: not progress
            }
        }
        return sawEvent
    }

    // MARK: HTTP

    private func nextTimestamp() -> Int {
        let ts = max(clock(), lastAuthTimestamp + 1)
        lastAuthTimestamp = ts
        return ts
    }

    private func addAuth(_ request: inout URLRequest, _ identity: any ACEIdentity, _ auth: RelayAuthRequest) throws {
        for (k, v) in try createAuthHeaders(identity: identity, request: auth, timestamp: nextTimestamp()) {
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
                      auth: (any ACEIdentity, RelayAuthRequest)? = nil) async throws -> JValue {
        var attempt = 0
        while true {
            var request = try makeRequest(method, path, query: query, body: body)
            if let auth { try addAuth(&request, auth.0, auth.1) }
            let (http, data) = try await perform(request)
            if (200..<300).contains(http.statusCode) {
                guard let v = try? JSONParser.parse(data), v.objectValue != nil else {
                    throw ACEError(.relayProtocolError, "relay response is not a JSON object", status: http.statusCode)
                }
                return v
            }
            let error = mapStatus(http, data)
            if http.statusCode == 409, error.relayCode == "replay", auth != nil, attempt == 0 {
                attempt += 1
                continue
            }
            throw error
        }
    }

    private func perform(_ request: URLRequest) async throws -> (HTTPURLResponse, Data) {
        do {
            let (bytes, response) = try await session.bytes(for: request, delegate: noRedirect)
            guard let http = response as? HTTPURLResponse else { throw ACEError(.relayProtocolError, "not an HTTP response") }
            return (http, try await readBounded(bytes))
        } catch let e as ACEError {
            throw e
        } catch {
            throw transportError(error, "relay request failed")
        }
    }

    /// Map a URLSession failure: cancellation stays cancellation, anything else is `relay_unavailable`.
    private func transportError(_ error: Error, _ what: String) -> Error {
        if error is CancellationError || (Task.isCancelled && (error as? URLError)?.code == .cancelled) {
            return CancellationError()
        }
        return ACEError(.relayUnavailable, "\(what): \(error.localizedDescription)")
    }

    private func readBounded(_ bytes: URLSession.AsyncBytes) async throws -> Data {
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
    private func nullableField<T>(_ v: JValue, _ key: String, _ get: (JValue) -> T?) throws -> T? {
        guard let f = v[key], !f.isNull else { return nil }
        guard let t = get(f) else { throw ACEError(.relayProtocolError, "\(key) is malformed") }
        return t
    }

    /// A field that may be absent; present (`null` included) it must be well-formed.
    private func optionalField<T>(_ v: JValue, _ key: String, _ get: (JValue) -> T?) throws -> T? {
        guard let f = v[key] else { return nil }
        guard let t = get(f) else { throw ACEError(.relayProtocolError, "\(key) is malformed") }
        return t
    }
}

private func percentEncode(_ s: String) -> String {
    var allowed = CharacterSet.alphanumerics.intersection(CharacterSet(charactersIn: Unicode.Scalar(0)...Unicode.Scalar(127)))
    allowed.insert(charactersIn: "-._~")
    return s.addingPercentEncoding(withAllowedCharacters: allowed) ?? s
}

/// Tags joined with `,` for a query parameter; a tag containing `,` is `invalid_argument`.
private func joinTags(_ tags: [String]) throws -> String {
    guard !tags.contains(where: { $0.contains(",") }) else { throw ACEError.invalidArgument("tags must be strings without ','") }
    return tags.joined(separator: ",")
}

/// Map one non-2xx relay response to an `ACEError` (08 § Client Rules, Responses). The
/// single 409 `replay` retry happens before this mapping.
func relayError(status: Int, retryAfter: String?, body: Data) -> ACEError {
    let json = try? JSONParser.parse(body)
    let relayCode = json?.objectValue?["error"]?.stringValue
    let message = json?.objectValue?["message"]?.stringValue.map { String($0.prefix(500)) } ?? "HTTP \(status)"
    let code: ACEError.Code
    switch status {
    case 100..<200, 300..<400: code = .relayProtocolError
    case 408, 500..<600: code = .relayUnavailable
    case 429: code = relayCode == nil || relayCode == "rate_limited" ? .relayUnavailable : .relayRejected
    case 400 where relayCode == "envelope_expired": code = .envelopeExpired
    case 403 where relayCode == "not_registered": code = .notRegistered
    case 404 where relayCode == "unknown_peer": code = .unknownPeer
    case 400..<500: code = .relayRejected
    default: code = .relayProtocolError
    }
    let seconds = code.category == .transient ? retryAfter.flatMap(parseRetryAfter) : nil
    return ACEError(code, code == .relayProtocolError ? "unexpected HTTP \(status)" : message,
                    status: status, relayCode: relayCode, retryAfterSeconds: seconds)
}

/// `Retry-After` as delay-seconds (`^[0-9]+$`); any other form (HTTP-date, fraction) is nil.
private func parseRetryAfter(_ value: String) -> Int? {
    guard !value.isEmpty, value.utf8.allSatisfy({ $0 >= 0x30 && $0 <= 0x39 }) else { return nil }
    return Int(value)
}

/// Normalize a relay base URL (08 § Client Rules, Relay URL): lowercase http(s) scheme
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

    /// Feed one byte; returns a frame at each blank line that ends an event with a `data`
    /// field (08 § Client Rules, Listen); `id` and `event` apply to that event only. Lines
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
