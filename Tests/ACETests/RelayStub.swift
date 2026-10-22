import Foundation
@testable import ACE


struct StubResponse: Sendable {
    var status: Int
    var headers: [String: String] = ["Content-Type": "application/json"]
    var chunks: [Data] = []

    static func json(_ status: Int, _ object: Any, headers: [String: String] = [:]) -> StubResponse {
        var h = ["Content-Type": "application/json"]
        h.merge(headers) { $1 }
        return StubResponse(status: status, headers: h, chunks: [try! JSONSerialization.data(withJSONObject: object)])
    }

    static func error(_ status: Int, _ code: String, headers: [String: String] = [:]) -> StubResponse {
        json(status, ["error": code], headers: headers)
    }

    static func sse(_ frames: [String]) -> StubResponse {
        StubResponse(status: 200, headers: ["Content-Type": "text/event-stream"], chunks: frames.map { Data($0.utf8) })
    }

    /// No answer at all: the request stays in flight until the client cancels its task.
    static let suspended = StubResponse(status: -2)
}

typealias StubHandler = @Sendable (URLRequest, Data) -> StubResponse

/// URLProtocol that routes by host to a registered handler.
final class StubURLProtocol: URLProtocol, @unchecked Sendable {
    private static let lock = NSLock()
    nonisolated(unsafe) private static var handlers: [String: StubHandler] = [:]

    static func register(host: String, _ handler: @escaping StubHandler) {
        lock.lock(); handlers[host] = handler; lock.unlock()
    }

    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        Self.lock.lock()
        let handler = request.url?.host.flatMap { Self.handlers[$0] }
        Self.lock.unlock()
        guard let handler else {
            client?.urlProtocol(self, didFailWithError: URLError(.cannotFindHost))
            return
        }
        var body = request.httpBody ?? Data()
        if body.isEmpty, let stream = request.httpBodyStream {
            stream.open()
            var buf = [UInt8](repeating: 0, count: 65536)
            while stream.hasBytesAvailable {
                let n = stream.read(&buf, maxLength: buf.count)
                if n <= 0 { break }
                body.append(buf, count: n)
            }
            stream.close()
        }
        let r = handler(request, body)
        if r.status == StubResponse.suspended.status { return }
        if r.status < 0 {
            client?.urlProtocol(self, didFailWithError: URLError(.networkConnectionLost))
            return
        }
        let response = HTTPURLResponse(url: request.url!, statusCode: r.status, httpVersion: "HTTP/1.1", headerFields: r.headers)!
        if (300..<400).contains(r.status), let location = r.headers["Location"].flatMap(URL.init(string:)) {
            // Offer the redirect to the session; a delegate that refuses it gets this response.
            client?.urlProtocol(self, wasRedirectedTo: URLRequest(url: location), redirectResponse: response)
        }
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        for c in r.chunks { client?.urlProtocol(self, didLoad: c) }
        client?.urlProtocolDidFinishLoading(self)
    }

    override func stopLoading() {}
}

func stubSession() -> URLSession {
    let config = URLSessionConfiguration.ephemeral
    config.protocolClasses = [StubURLProtocol.self]
    return URLSession(configuration: config)
}

/// Wait for `condition`, an event the test observes, polling every 10 ms. The `hangGuardSeconds` bound is a hang
/// guard only, far above any normal latency: no passing run depends on it.
func settles(_ condition: () -> Bool) async -> Bool {
    let deadline = ContinuousClock.now + .seconds(hangGuardSeconds)
    while ContinuousClock.now < deadline {
        if condition() { return true }
        try? await Task.sleep(for: .milliseconds(10))
    }
    return condition()
}

/// `settles` for a condition read across an actor boundary.
func settles(_ condition: () async -> Bool) async -> Bool {
    let deadline = ContinuousClock.now + .seconds(hangGuardSeconds)
    while ContinuousClock.now < deadline {
        if await condition() { return true }
        try? await Task.sleep(for: .milliseconds(10))
    }
    return await condition()
}

func uniqueHost() -> String { "relay-\(UUID().uuidString.lowercased().prefix(8)).test" }

func makeRelay(_ handler: @escaping StubHandler, clock: @escaping @Sendable () -> Int = systemClock, maxResponseBytes: Int = 1 << 20,
               sleeper: @escaping @Sendable (Double) async throws -> Void = { _ in }) throws -> RelayClient {
    let host = uniqueHost()
    StubURLProtocol.register(host: host, handler)
    return try RelayClient(baseURL: URL(string: "https://\(host)/")!, session: stubSession(), timeout: 5,
                           maxResponseBytes: maxResponseBytes, clock: clock, sleeper: sleeper)
}

extension StubResponse {
    /// A JSON body from a `JSONValue`.
    static func json(_ status: Int, _ value: JSONValue, headers: [String: String] = [:]) -> StubResponse {
        var h = ["Content-Type": "application/json"]
        h.merge(headers) { $1 }
        return StubResponse(status: status, headers: h, chunks: [try! value.jsonData()])
    }

    /// A raw body with a content type (Python `raw_responses`).
    static func raw(_ status: Int, _ body: String, _ contentType: String) -> StubResponse {
        StubResponse(status: status, headers: ["Content-Type": contentType], chunks: [Data(body.utf8)])
    }
}


/// An in-memory relay implementing the 07 endpoints the SDK calls (one host shared by every test agent).
final class FakeRelay: @unchecked Sendable {
    let host: String
    var url: String { "https://\(host)" }
    private let lock = NSLock()
    private let clock: @Sendable () -> Int
    private var kels: [String: KelState] = [:]
    private var agents: [String: VerifiedAgent] = [:]
    /// Stored card bundles by ACE ID.
    private var cards: [String: JSONValue] = [:]
    /// Handle bindings (permanent, set once per identity).
    private var handles: [String: String] = [:]
    private var queues: [String: [(id: String, packet: Data)]] = [:]
    private var blocks: [String: [String: (blocked: Bool, revision: Int)]] = [:]
    private var wakes: [String: (gateway: String, token: String)] = [:]
    private var seq = 0
    private(set) var sends: [String] = []
    private(set) var requests: [String] = []
    /// When set, `/v1/send` answers this status/code once.
    var failSend: (Int, String)?
    /// Paths answered 503 (the relay is unreachable for them).
    var down: Set<String> = []

    init(clock: @escaping @Sendable () -> Int = systemClock) {
        self.clock = clock
        host = uniqueHost()
        StubURLProtocol.register(host: host) { [self] req, body in self.handle(req, body) }
    }

    func client(clock: @escaping @Sendable () -> Int = systemClock) throws -> RelayClient {
        try RelayClient(baseURL: URL(string: url)!, session: stubSession(), timeout: 5, maxResponseBytes: 16 << 20, clock: clock,
                        sleeper: { _ in })
    }

    func withLock<R>(_ body: () throws -> R) rethrows -> R { lock.lock(); defer { lock.unlock() }; return try body() }

    var requestCount: Int { withLock { requests.count } }
    func queued(_ aceId: String) -> [Data] { withLock { (queues[aceId] ?? []).map(\.packet) } }
    /// Queue `packet` for `aceId` as a send without a permit would (a forger needs no credentials for a public agent).
    func inject(to aceId: String, _ packet: Data) { withLock { seq += 1; queues[aceId, default: []].append(("\(seq)-0", packet)) } }
    /// Remove and return `aceId`'s queued packets (a slow relay holding them).
    func take(_ aceId: String) -> [Data] { withLock { let q = queues[aceId] ?? []; queues[aceId] = []; return q.map(\.packet) } }
    /// The block `owner` registered for `peer` (nil when none).
    func blocked(by owner: String, _ peer: String) -> Bool? { withLock { blocks[owner]?[peer]?.blocked } }
    /// The wake registration `aceId` holds (nil when none).
    func wake(_ aceId: String) -> (gateway: String, token: String)? { withLock { wakes[aceId] } }
    func registered(_ aceId: String) -> KelState? { withLock { kels[aceId] } }
    func sendCount(to aceId: String) -> Int { withLock { sends.filter { $0 == aceId }.count } }
    /// The stored card bundle of `aceId`.
    func card(_ aceId: String) -> JSONValue? { withLock { cards[aceId] } }
    /// Store `bundle` as `aceId`'s card record as is (a relay that skips the 07 checks).
    func setCard(_ aceId: String, _ bundle: JSONValue) { withLock { cards[aceId] = bundle } }
    /// Bind `handle` to `aceId` as is.
    func bindHandle(_ handle: String, to aceId: String) { withLock { handles[handle] = aceId } }
    func handleOwner(_ handle: String) -> String? { withLock { handles[handle] } }
    /// The stored PublishedAgent of `aceId` (nil when none was published).
    func publishedAgent(_ aceId: String) -> VerifiedAgent? { withLock { agents[aceId] } }
    /// Drop `aceId`'s stored PublishedAgent (a relay that lost it).
    func dropAgent(_ aceId: String) { withLock { agents[aceId] = nil } }

    /// The unexpired descriptor of a registered identity.
    private func live(_ aceId: String, now: Int) -> VerifiedAgent? {
        guard kels[aceId] != nil, let a = agents[aceId], now < a.descriptor.expiresAt else { return nil }
        return a
    }

    private func handleOf(_ aceId: String) -> String? { handles.first { $0.value == aceId }?.key }

    private func err(_ status: Int, _ code: String) -> StubResponse { .json(status, ["error": .string(code)] as JSONValue) }
    private let ok = StubResponse.json(200, ["ok": true] as JSONValue)

    func handle(_ req: URLRequest, _ raw: Data) -> StubResponse {
        withLock {
            let path = req.url!.path, method = req.httpMethod ?? "GET"
            requests.append("\(method) \(path)")
            if down.contains(path) { return err(503, "internal_error") }
            var query: [String: String] = [:]
            for item in URLComponents(url: req.url!, resolvingAgainstBaseURL: false)?.queryItems ?? [] { query[item.name] = item.value }
            let headers = req.allHTTPHeaderFields ?? [:]
            let body = try? JSONValue(json: raw)
            let now = clock()
            switch (method, path) {
            case ("POST", "/v1/register"):
                guard let body, let st = try? verifyRegistration(body, now: now) else { return err(400, "invalid_kel") }
                kels[st.aceId] = st
                return .json(200, ["ok": true, "status": "registered"] as JSONValue)
            case ("POST", "/v1/descriptor"):
                guard let body, let a = try? verifyPublishedAgent(body, now: now) else { return err(401, "invalid_authorization") }
                guard let registered = kels[a.aceId] else { return err(403, "not_registered") }
                guard registered.lastHash == a.state.lastHash else { return err(409, "kel_conflict") }
                guard a.descriptor.relays.contains(url) else { return err(400, "invalid_argument") }
                if let old = agents[a.aceId], old.descriptor.issuedAt >= a.descriptor.issuedAt, old.source != a.source { return err(409, "stale_descriptor") }
                agents[a.aceId] = a
                return ok
            case ("POST", "/v1/card"):
                guard let body, let v = try? verifyCardBundle(body, now: now) else { return err(401, "invalid_authorization") }
                let r = v.record
                guard let registered = kels[r.aceId] else { return err(403, "not_registered") }
                guard registered.lastHash == v.state.lastHash else { return err(409, "kel_conflict") }
                if let old = cards[r.aceId]?["card"], let oldAt = old["issuedAt"]?.wireInt,
                   oldAt > r.issuedAt || (oldAt == r.issuedAt && (try? documentDigest(old)) != (try? documentDigest(r.value))) {
                    return err(409, "stale_descriptor")
                }
                // 07: a handle is set once per identity and never reassigned; a record naming another home claims nothing here.
                if r.home == url {
                    if let bound = handleOf(r.aceId) {
                        guard r.handle == bound else { return err(400, "invalid_argument") }
                    } else if let h = r.handle {
                        guard handles[h] == nil else { return err(409, "handle_taken") }
                        handles[h] = r.aceId
                    }
                }
                cards[r.aceId] = body
                return ok
            case ("POST", "/v1/blocks"):
                guard let peer = body?["peer"]?.stringValue, let b = body?["blocked"]?.boolValue, let rev = body?["revision"]?.wireInt,
                      let caller = authed(headers, .block(peer: peer, blocked: b, revision: rev), now: now) else { return err(401, "invalid_signature") }
                if let old = blocks[caller]?[peer], old.revision >= rev { return err(409, "stale_revision") }
                blocks[caller, default: [:]][peer] = (b, rev)
                return ok
            case ("PUT", "/v1/wake"):
                guard let o = body?.objectValue, Set(o.keys) == ["gateway", "token"], let g = o["gateway"]?.stringValue,
                      let t = o["token"]?.stringValue else { return err(400, "invalid_argument") }
                guard let caller = authed(headers, .setWake(gateway: g, token: t), now: now) else { return err(401, "invalid_signature") }
                wakes[caller] = (g, t)
                return ok
            case ("DELETE", "/v1/wake"):
                guard raw.isEmpty, let caller = authed(headers, .clearWake, now: now) else { return err(401, "invalid_signature") }
                wakes[caller] = nil
                return ok
            case ("POST", "/v1/send"):
                guard let pv = body?["packet"], let packet = try? Packet(json: try pv.jsonData()) else { return err(400, "invalid_packet") }
                guard kels[packet.to] != nil else { return err(404, "unknown_peer") }
                sends.append(packet.to)
                if let f = failSend { failSend = nil; return err(f.0, f.1) }
                let bytes = packet.jsonData()
                if queues[packet.to]?.contains(where: { $0.packet == bytes }) == true { return ok }
                if blocks[packet.to]?[packet.from]?.blocked == true { return err(403, "not_permitted") }
                if let permit = body?["permit"] {
                    guard (try? verifyPermit(permit, issuer: kels[packet.to]!, subject: packet.from, now: now)) != nil else { return err(403, "not_permitted") }
                } else {
                    guard cards[packet.to]?["card"]?["contact"]?.stringValue == "open", live(packet.to, now: now) != nil else {
                        return err(403, "not_permitted")
                    }
                }
                seq += 1
                queues[packet.to, default: []].append(("\(seq)-0", bytes))
                return ok
            case ("GET", "/v1/inbox"):
                let limit = Int(query["limit"] ?? "100") ?? 100
                guard let caller = authed(headers, .inbox(since: query["since"] ?? "-", limit: limit), now: now) else {
                    return err(401, "invalid_signature")
                }
                let page = Array((queues[caller] ?? []).prefix(limit))
                return .json(200, ["messages": .array(page.map { ["streamId": .string($0.id), "packet": try! JSONValue(json: $0.packet)] }),
                                   "cursor": page.last.map { .string($0.id) } ?? .null] as JSONValue)
            case ("POST", "/v1/inbox/ack"):
                guard let through = query["through"], let caller = authed(headers, .inboxAck(through: through), now: now),
                      let n = Int(through.split(separator: "-")[0]) else {
                    return err(401, "invalid_signature")
                }
                queues[caller]?.removeAll { Int($0.id.split(separator: "-")[0])! <= n }
                return ok
            default:
                if method == "GET", path.hasPrefix("/v1/descriptor/") {
                    let id = String(path.dropFirst("/v1/descriptor/".count))
                    guard let a = live(id, now: now) else { return err(404, "unknown_peer") }
                    return .json(200, a.source)
                }
                if method == "GET", path.hasPrefix("/v1/card/") {
                    let id = String(path.dropFirst("/v1/card/".count))
                    guard kels[id] != nil, let c = cards[id] else { return err(404, "unknown_peer") }
                    return .json(200, c)
                }
                if method == "GET", path.hasPrefix("/v1/handles/") {
                    let h = String(path.dropFirst("/v1/handles/".count))
                    guard let owner = handles[h], kels[owner] != nil, let c = cards[owner], c["card"]?["home"]?.stringValue == url else {
                        return err(404, "unknown_peer")
                    }
                    return .json(200, c)
                }
                if method == "GET", path == "/v1/cards" {
                    var list = agents.values.filter { a in
                        cards[a.aceId]?["card"]?["listed"] == true && cards[a.aceId]?["card"]?["home"]?.stringValue == url
                            && live(a.aceId, now: now) != nil
                    }.sorted { $0.aceId < $1.aceId }
                    if let tag = query["tag"] {
                        list = list.filter { cards[$0.aceId]?["card"]?["card"]?["tags"]?.arrayValue?.contains(.string(tag)) == true }
                    }
                    if let profile = query["profile"] { list = list.filter { $0.descriptor.profiles.contains { $0.id == profile } } }
                    let page = list.prefix(query["limit"].flatMap { Int($0) } ?? ACELimits.defaultPageLimit).compactMap { cards[$0.aceId] }
                    return .json(200, ["cards": .array(page), "cursor": .null] as JSONValue)
                }
                return err(404, "not_found")
            }
        }
    }

    /// The authenticated caller, or nil: a minimal 07 § Authentication verifier (the relay-side verifiers live in sdk-ts).
    private func authed(_ headers: [String: String], _ request: RelayAuthRequest, now: Int) -> String? {
        var h: [String: String] = [:]
        for (k, v) in headers { h[k.lowercased()] = v }
        guard let id = h["x-ace-id"], let st = kels[id], let ts = h["x-ace-timestamp"].flatMap({ Int($0) }),
              let seq = h["x-ace-seq"].flatMap({ Int($0) }), let sig = h["x-ace-signature"], h["x-ace-audience"] == url,
              let nonce = h["x-ace-nonce"], abs(now - ts) <= ACELimits.timestampWindowSeconds,
              let payload = try? authPayload(request, audience: url, nonce: nonce),
              (try? verifyOperational(SignatureEnvelope(value: sig, seq: seq), state: st, action: request.action, timestamp: ts,
                                      payload: payload, now: now)) != nil else { return nil }
        return id
    }

    /// A minimal 07 § Registration verifier: the request's audience is this relay, its KEL verifies and the
    /// `register-request` signature over `encodePayload(lastHashHex, audience)` verifies.
    private func verifyRegistration(_ body: JSONValue, now: Int) throws -> KelState {
        guard body["audience"]?.stringValue == url, let ts = body["timestamp"]?.wireInt, let kel = body["kel"]?.arrayValue,
              let sig = SignatureEnvelope(operational: body["signature"]) else { throw ACEError(.invalidArgument) }
        let st = try ACEKel.verify(kel.map { $0.objectValue ?? [:] }, now: now)
        guard st.aceId == body["aceId"]?.stringValue else { throw ACEError(.invalidArgument) }
        try verifyOperational(sig, state: st, action: "register-request", timestamp: ts,
                              payload: ACESigning.encodePayload(st.lastHash, url), now: now)
        return st
    }
}
