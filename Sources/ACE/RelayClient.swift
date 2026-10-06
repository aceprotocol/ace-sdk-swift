//
//  RelayClient.swift
//  ACE SDK
//
//  HTTP client for the relay API (08-relay).
//

import Foundation

/// Relay HTTP client. Authenticated calls use `X-ACE-*` headers with
/// `timestamp = max(now, last + 1)` and retry once on 409 `replay`.
///
/// Error mapping: network errors, timeouts, 5xx, 408 and 429 → `relay_unavailable`
/// (with `retryAfterSeconds`); an oversized or malformed body → `relay_protocol_error`;
/// 400 `envelope_expired` → `envelope_expired`; 404 `unknown_peer` → `unknown_peer`;
/// 403 `not_registered` → `not_registered`; any other 4xx → `relay_rejected` (with
/// `status` and `relayCode`).
public actor RelayClient {
    public enum RegisterStatus: String, Sendable {
        case registered, idempotent, refreshed, rotated
    }

    public struct InboxEntry: Sendable, Equatable {
        public let streamId: String
        /// The envelope JSON as served by the relay (decode with `decodeEnvelope`).
        public let envelope: Data
    }

    public struct InboxPage: Sendable {
        public let entries: [InboxEntry]
        public let cursor: String?
    }

    /// One SSE `catchup` / `message` event.
    public struct Event: Sendable, Equatable {
        public let streamId: String
        public let envelope: Data
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

    public struct PostedIntent: Sendable, Equatable {
        public let intentId: String
        public let expiresAt: Int
    }

    /// The normalized base URL (lowercase scheme and host, no trailing `/`).
    public nonisolated let baseURL: URL
    /// `baseURL` as a string: the normalized relay key (lowercase scheme and host, no
    /// trailing `/`). Use it for `ReceiveSource.relay(url:)`; `Inbox` keys cursors by it.
    public nonisolated let baseURLString: String
    private let session: URLSession
    /// `listen`'s own session (see `init`); created on first use.
    private var streamSession: URLSession?
    private let timeout: TimeInterval
    private let maxResponseBytes: Int
    private let clock: @Sendable () -> Int
    private let sleeper: @Sendable (Double) async throws -> Void
    private var lastAuthTimestamp = 0

    /// Reconnect attempts after which `listen` fails with `relay_unavailable`.
    static let maxConnectFailures = 10
    static let maxBackoffSeconds = 30.0
    static let idleTimeoutSeconds = 90.0
    /// Events buffered for a slow consumer; when full, reading the socket pauses.
    static let listenBuffer = 64

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
        guard let normalized = normalizeRelayURL(baseURL.absoluteString), let url = URL(string: normalized) else {
            throw ACEError(.invalidArgument, "baseURL must be an absolute http(s) URL")
        }
        guard timeout > 0, maxResponseBytes > 0 else { throw ACEError(.invalidArgument, "timeout and maxResponseBytes must be positive") }
        self.baseURL = url
        self.baseURLString = normalized
        self.session = session
        self.timeout = timeout
        self.maxResponseBytes = maxResponseBytes
        self.clock = clock
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
    public func register(_ identity: any ACEIdentity, profile: RegistrationProfile = .keep) async throws -> RegisterStatus {
        var attempt = 0
        while true {
            let req = try createRegistrationRequest(identity: identity, profile: profile, timestamp: nextTimestamp())
            do {
                let v = try await call("POST", "/v1/register", body: req.jsonData())
                guard let s = v["status"]?.stringValue, let status = RegisterStatus(rawValue: s) else {
                    throw ACEError(.relayProtocolError, "unexpected register response")
                }
                return status
            } catch let e as ACEError where e.relayCode == "replay" && attempt == 0 {
                attempt += 1
            }
        }
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
    public func discover(_ query: DiscoverQuery = DiscoverQuery()) async throws -> DiscoverPage {
        var q: [(String, String)] = []
        if let v = query.q { q.append(("q", v)) }
        if let v = query.tags { q.append(("tags", v)) }
        if let v = query.chain { q.append(("chain", v)) }
        if let v = query.scheme { q.append(("scheme", v)) }
        if let v = query.online { q.append(("online", v ? "true" : "false")) }
        if let v = query.limit { q.append(("limit", String(v))) }
        if let v = query.cursor { q.append(("cursor", v)) }
        let v = try await call("GET", "/v1/discover", query: q)
        guard let list = v["agents"]?.arrayValue else { throw ACEError(.relayProtocolError, "unexpected discover response") }
        var agents: [VerifiedPeer] = []
        var rejected = 0
        for entry in list {
            if let peer = try? verifyPeerRecord(PeerRecord.parse(entry)) { agents.append(peer) } else { rejected += 1 }
        }
        return DiscoverPage(agents: agents, rejected: rejected, cursor: try optionalCursor(v))
    }

    /// `POST /v1/send`. Exact duplicates are acknowledged by the relay.
    public func send(_ env: ACEMessage) async throws {
        let body = JSONWriter.serialize(.object(["message": env.jvalue]))
        _ = try await call("POST", "/v1/send", body: body)
    }

    /// `GET /v1/inbox`. `since` is a stream ID (`nil` = from the start); `limit` 1…100.
    public func fetchInbox(_ identity: any ACEIdentity, since: String? = nil, limit: Int = ACELimits.maxInboxPage) async throws -> InboxPage {
        let auth = RelayAuthRequest.inbox(since: since ?? "-", limit: limit)
        try auth.validate()
        var q: [(String, String)] = []
        if let since { q.append(("since", since)) }
        q.append(("limit", String(limit)))
        let v = try await call("GET", "/v1/inbox", query: q, auth: (identity, auth))
        guard let list = v["messages"]?.arrayValue else { throw ACEError(.relayProtocolError, "unexpected inbox response") }
        let entries: [InboxEntry] = try list.map { e in
            guard let id = e["streamId"]?.stringValue, isStreamCursor(id), let m = e["message"] else {
                throw ACEError(.relayProtocolError, "malformed inbox entry")
            }
            return InboxEntry(streamId: id, envelope: JSONWriter.serialize(m))
        }
        return InboxPage(entries: entries, cursor: try optionalCursor(v))
    }

    /// `POST /v1/intents`.
    public func postIntent(_ identity: any ACEIdentity, need: String, tags: [String] = [], maxPrice: String? = nil,
                           currency: String? = nil, ttl: Int) async throws -> PostedIntent {
        let auth = RelayAuthRequest.intent(need: need, tags: tags, maxPrice: maxPrice, currency: currency, ttl: ttl)
        try auth.validate()
        var o: [String: JValue] = ["need": .string(need), "ttl": .number(String(ttl))]
        if !tags.isEmpty { o["tags"] = .array(tags.map { .string($0) }) }
        if let maxPrice { o["maxPrice"] = .string(maxPrice) }
        if let currency { o["currency"] = .string(currency) }
        let v = try await call("POST", "/v1/intents", body: JSONWriter.serialize(.object(o)), auth: (identity, auth))
        guard let id = v["intentId"]?.stringValue, let expiresAt = v["expiresAt"]?.wireInt else {
            throw ACEError(.relayProtocolError, "unexpected intent response")
        }
        return PostedIntent(intentId: id, expiresAt: expiresAt)
    }

    /// `GET /v1/intents`.
    public func listIntents(q: String? = nil, tags: String? = nil, limit: Int? = nil, cursor: String? = nil) async throws -> IntentPage {
        var query: [(String, String)] = []
        if let q { query.append(("q", q)) }
        if let tags { query.append(("tags", tags)) }
        if let limit { query.append(("limit", String(limit))) }
        if let cursor { query.append(("cursor", cursor)) }
        let v = try await call("GET", "/v1/intents", query: query)
        guard let list = v["intents"]?.arrayValue else { throw ACEError(.relayProtocolError, "unexpected intents response") }
        let intents: [Intent] = try list.map { i in
            guard let id = i["intentId"]?.stringValue, let from = i["from"]?.stringValue, let need = i["need"]?.stringValue,
                  let ttl = i["ttl"]?.wireInt, let createdAt = i["createdAt"]?.wireInt, let expiresAt = i["expiresAt"]?.wireInt else {
                throw ACEError(.relayProtocolError, "malformed intent")
            }
            let tags = i["tags"]?.arrayValue?.compactMap(\.stringValue) ?? []
            return Intent(intentId: id, from: from, need: need, tags: tags, maxPrice: i["maxPrice"]?.stringValue,
                          currency: i["currency"]?.stringValue, ttl: ttl, createdAt: createdAt, expiresAt: expiresAt)
        }
        return IntentPage(intents: intents, cursor: try optionalCursor(v))
    }

    /// `GET /v1/listen` as a stream of `catchup` / `message` events.
    ///
    /// Reconnects internally with backoff 1, 2, 4 … 30 s (honoring `Retry-After`), resuming
    /// after the last yielded `streamId`; `drain` reconnects at once; `connected` and
    /// heartbeats are ignored; 90 s without a byte reconnects. Ten consecutive failed
    /// connects end the stream with `relay_unavailable`; a non-retryable status ends it
    /// with the mapped error; a frame larger than `MAX_ENVELOPE_BYTES + 512` ends it with
    /// `relay_protocol_error`.
    ///
    /// At most 64 events wait for the consumer; while the buffer is full the socket is not
    /// read (TCP backpressure), so memory stays bounded.
    ///
    /// `onConnect` is called each time a connection is established (HTTP 200,
    /// `text/event-stream`), before its first event. Cancelling the consuming task or
    /// dropping the stream cancels the HTTP request at once, also while the stream only
    /// carries heartbeats and during a backoff sleep. Uses the dedicated stream session
    /// described in `init`.
    public nonisolated func listen(_ identity: any ACEIdentity, since: String? = nil,
                                   onConnect: (@Sendable () -> Void)? = nil) -> AsyncThrowingStream<Event, Error> {
        AsyncThrowingStream(bufferingPolicy: .bufferingOldest(Self.listenBuffer)) { continuation in
            let task = Task {
                do {
                    try await self.runListen(identity, since: since, onConnect: onConnect, continuation)
                    continuation.finish()
                } catch {
                    continuation.finish(throwing: error is CancellationError ? nil : error)
                }
            }
            continuation.onTermination = { _ in task.cancel() }
        }
    }

    // MARK: Listen internals

    private func runListen(_ identity: any ACEIdentity, since: String?, onConnect: (@Sendable () -> Void)?,
                           _ out: AsyncThrowingStream<Event, Error>.Continuation) async throws {
        var cursor = since ?? "-"
        guard cursor == "-" || isStreamCursor(cursor) else { throw ACEError(.invalidArgument, "since must be a stream ID") }
        var failures = 0
        while true {
            try Task.checkCancellation()
            do {
                // A clean end (drain or EOF) reconnects at once.
                try await connectOnce(identity, cursor: &cursor, onConnect: onConnect, out, onProgress: { failures = 0 })
                failures = 0
                continue
            } catch let e as ACEError where e.code == .relayUnavailable {
                failures += 1
                if failures >= Self.maxConnectFailures { throw e }
                var delay = min(pow(2, Double(failures - 1)), Self.maxBackoffSeconds)
                if let ra = e.retryAfterSeconds { delay = min(max(delay, Double(ra)), Self.maxBackoffSeconds) }
                try await sleeper(delay)
            }
        }
    }

    /// One connection; returns after `drain` or a clean end of stream.
    private func connectOnce(_ identity: any ACEIdentity, cursor: inout String, onConnect: (@Sendable () -> Void)?,
                             _ out: AsyncThrowingStream<Event, Error>.Continuation,
                             onProgress: () -> Void) async throws {
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
                (b, response) = try await session.bytes(for: request)
            } catch {
                if error is CancellationError || (Task.isCancelled && (error as? URLError)?.code == .cancelled) {
                    throw CancellationError()
                }
                throw ACEError(.relayUnavailable, "listen connect failed: \(error.localizedDescription)")
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
        let media = (http.value(forHTTPHeaderField: "Content-Type") ?? "")
            .split(separator: ";", maxSplits: 1).first.map { $0.trimmingCharacters(in: .whitespaces).lowercased() } ?? ""
        guard media == "text/event-stream" else {
            bytes.task.cancel()
            throw ACEError(.relayProtocolError, "listen response is not text/event-stream")
        }
        onProgress()
        onConnect?()
        var parser = SSEParser(maxLine: ACELimits.maxEnvelopeBytes + 512)
        // Cancel the data task itself on task cancellation, so a stream that only carries
        // heartbeats (or nothing) is torn down at once; every exit path cancels it too.
        let dataTask = bytes.task
        defer { dataTask.cancel() }
        do {
            try await withTaskCancellationHandler {
                try await readEvents(bytes, &parser, cursor: &cursor, out, onProgress: onProgress)
            } onCancel: {
                dataTask.cancel()
            }
        } catch let e as ACEError {
            throw e
        } catch {
            if error is CancellationError || (Task.isCancelled && (error as? URLError)?.code == .cancelled) {
                throw CancellationError()
            }
            throw ACEError(.relayUnavailable, "listen stream failed: \(error.localizedDescription)")
        }
    }

    /// Feed the stream to `parser`; returns at `drain` or end of stream.
    private func readEvents(_ bytes: URLSession.AsyncBytes, _ parser: inout SSEParser, cursor: inout String,
                            _ out: AsyncThrowingStream<Event, Error>.Continuation, onProgress: () -> Void) async throws {
        for try await byte in bytes {
            guard let frame = try parser.feed(byte) else { continue }
            try Task.checkCancellation()
            switch frame.event {
            case "catchup", "message":
                guard let id = frame.id, isStreamCursor(id), !frame.data.isEmpty else { continue }
                cursor = id
                onProgress()
                try await out.yieldWaiting(Event(streamId: id, envelope: Data(frame.data), catchup: frame.event == "catchup"))
            case "drain":
                return
            default:
                onProgress()
            }
        }
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
                guard !data.isEmpty else { return .object([:]) }
                do { return try JSONParser.parse(data) } catch {
                    throw ACEError(.relayProtocolError, "malformed relay response", status: http.statusCode)
                }
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
            let (bytes, response) = try await session.bytes(for: request)
            guard let http = response as? HTTPURLResponse else { throw ACEError(.relayProtocolError, "not an HTTP response") }
            return (http, try await readBounded(bytes))
        } catch let e as ACEError {
            throw e
        } catch {
            if error is CancellationError || (Task.isCancelled && (error as? URLError)?.code == .cancelled) {
                throw CancellationError()
            }
            throw ACEError(.relayUnavailable, "relay request failed: \(error.localizedDescription)")
        }
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
            if error is CancellationError || (Task.isCancelled && (error as? URLError)?.code == .cancelled) {
                throw CancellationError()
            }
            throw ACEError(.relayUnavailable, "relay read failed: \(error.localizedDescription)")
        }
        return data
    }

    private func mapStatus(_ http: HTTPURLResponse, _ data: Data) -> ACEError {
        let status = http.statusCode
        let body = try? JSONParser.parse(data)
        let relayCode = body?["error"]?.stringValue
        let message = body?["message"]?.stringValue.map { String($0.prefix(500)) } ?? "HTTP \(status)"
        let retryAfter = http.value(forHTTPHeaderField: "Retry-After").flatMap { Int($0.trimmingCharacters(in: .whitespaces)) }
        if status >= 500 || status == 408 || status == 429 {
            return ACEError(.relayUnavailable, message, status: status, relayCode: relayCode, retryAfterSeconds: retryAfter)
        }
        if status == 400 && relayCode == "envelope_expired" {
            return ACEError(.envelopeExpired, message, status: status, relayCode: relayCode)
        }
        if status == 404 && relayCode == "unknown_peer" {
            return ACEError(.unknownPeer, message, status: status, relayCode: relayCode)
        }
        if status == 403 && relayCode == "not_registered" {
            return ACEError(.notRegistered, message, status: status, relayCode: relayCode)
        }
        if (400..<500).contains(status) {
            return ACEError(.relayRejected, message, status: status, relayCode: relayCode)
        }
        return ACEError(.relayProtocolError, "unexpected HTTP \(status)", status: status, relayCode: relayCode)
    }

    private func optionalCursor(_ v: JValue) throws -> String? {
        guard let c = v["cursor"], !c.isNull else { return nil }
        guard let s = c.stringValue else { throw ACEError(.relayProtocolError, "cursor must be a string or null") }
        return s
    }
}

private func percentEncode(_ s: String) -> String {
    var allowed = CharacterSet.alphanumerics.intersection(CharacterSet(charactersIn: Unicode.Scalar(0)...Unicode.Scalar(127)))
    allowed.insert(charactersIn: "-._~")
    return s.addingPercentEncoding(withAllowedCharacters: allowed) ?? s
}

/// Lowercase scheme and host, no trailing `/` (Appendix A cursor keys).
func normalizeRelayURL(_ s: String) -> String? {
    guard var c = URLComponents(string: s), let scheme = c.scheme?.lowercased(), scheme == "https" || scheme == "http",
          let host = c.host, !host.isEmpty else { return nil }
    c.scheme = scheme
    c.host = host.lowercased()
    c.query = nil
    c.fragment = nil
    guard var out = c.string else { return nil }
    while out.hasSuffix("/") { out.removeLast() }
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

    init(maxLine: Int) { self.maxLine = maxLine }

    /// Feed one byte; returns a frame at each blank line that carried fields.
    mutating func feed(_ b: UInt8) throws -> Frame? {
        if b != 0x0A {
            line.append(b)
            if line.count > maxLine {
                throw ACEError(.relayProtocolError, "SSE line exceeds \(maxLine) bytes")
            }
            return nil
        }
        if line.last == 0x0D { line.removeLast() }
        defer { line.removeAll(keepingCapacity: true) }
        if line.isEmpty {
            defer { frame = Frame(); hasData = false }
            return frame.id != nil || hasData || frame.event != "message" ? frame : nil
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
