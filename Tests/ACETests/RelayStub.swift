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
        if r.status < 0 {
            client?.urlProtocol(self, didFailWithError: URLError(.networkConnectionLost))
            return
        }
        let response = HTTPURLResponse(url: request.url!, statusCode: r.status, httpVersion: "HTTP/1.1", headerFields: r.headers)!
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

func uniqueHost() -> String { "relay-\(UUID().uuidString.lowercased().prefix(8)).test" }

func makeRelay(_ handler: @escaping StubHandler, clock: @escaping @Sendable () -> Int = systemClock) throws -> RelayClient {
    let host = uniqueHost()
    StubURLProtocol.register(host: host, handler)
    return try RelayClient(baseURL: URL(string: "https://\(host)/")!, session: stubSession(), timeout: 5,
                           maxResponseBytes: 1 << 20, clock: clock, sleeper: { _ in })
}

func peerRecord(_ id: some ACEIdentity, registeredAt: Int) throws -> PeerRecord {
    let req = try createRegistrationRequest(identity: id, timestamp: registeredAt)
    return PeerRecord(aceId: req.aceId, scheme: req.scheme.rawValue, encryptionPublicKey: req.encryptionPublicKey,
                      signingPublicKey: req.signingPublicKey, registrationSignature: req.signature, registeredAt: registeredAt)
}

func peerRecordJSON(_ r: PeerRecord) -> [String: Any] {
    try! JSONSerialization.jsonObject(with: JSONEncoder().encode(r)) as! [String: Any]
}

/// A minimal in-memory relay: peers, send, inbox and a one-shot listen.
final class FakeRelay: @unchecked Sendable {
    private let lock = NSLock()
    var peers: [String: PeerRecord] = [:]
    var queues: [String: [(String, Data)]] = [:]
    var seq = 0
    var sendError: String?
    var requests: [String] = []

    func add(_ record: PeerRecord) {
        lock.lock(); peers[record.aceId] = record; lock.unlock()
    }

    func enqueue(_ env: ACEMessage) -> String {
        lock.lock(); defer { lock.unlock() }
        seq += 1
        let id = "1741000000000-\(seq)"
        queues[env.to, default: []].append((id, env.jsonData()))
        return id
    }

    func handle(_ req: URLRequest, _ body: Data) -> StubResponse {
        let url = req.url!
        let comps = URLComponents(url: url, resolvingAgainstBaseURL: false)!
        let q = Dictionary(uniqueKeysWithValues: (comps.queryItems ?? []).map { ($0.name, $0.value ?? "") })
        lock.lock()
        requests.append(url.path)
        lock.unlock()
        switch url.path {
        case "/v1/peer":
            lock.lock(); let r = peers[q["aceId"] ?? ""]; lock.unlock()
            guard let r else { return .error(404, "unknown_peer") }
            return .json(200, peerRecordJSON(r))
        case "/v1/send":
            if let e = sendError { return .error(400, e) }
            let obj = try! JSONSerialization.jsonObject(with: body) as! [String: Any]
            let env = try! decodeEnvelope(JSONSerialization.data(withJSONObject: obj["message"]!))
            _ = enqueue(env)
            return .json(200, ["ok": true])
        case "/v1/inbox":
            let me = req.value(forHTTPHeaderField: "X-ACE-Id") ?? ""
            let since = q["since"]
            let limit = Int(q["limit"] ?? "100")!
            lock.lock()
            let all = queues[me] ?? []
            lock.unlock()
            let after = all.filter { since == nil || compareStreamIds($0.0, since!) > 0 }.prefix(limit)
            let messages = after.map { ["streamId": $0.0, "message": try! JSONSerialization.jsonObject(with: $0.1)] }
            return .json(200, ["messages": messages, "cursor": after.last?.0 as Any? ?? NSNull()])
        default:
            return .error(404, "not_found")
        }
    }
}
