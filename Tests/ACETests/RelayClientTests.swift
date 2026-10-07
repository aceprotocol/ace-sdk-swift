import Foundation
import Testing
@testable import ACE

@Suite("RelayClient")
struct RelayClientTests {
    let alice = Fixtures.agent("alice")
    let bob = Fixtures.agent("bob")

    @Test func baseURLIsNormalized() throws {
        let r = try RelayClient(baseURL: URL(string: "HTTPS://Relay.Example.COM/")!)
        #expect(r.baseURL.absoluteString == "https://relay.example.com")
        #expect(throws: ACEError.self) { try RelayClient(baseURL: URL(string: "ftp://x.example")!) }
    }

    @Test func lookupPeerVerifiesRecord() async throws {
        let record = try peerRecord(bob, registeredAt: 1741000000)
        let relay = try makeRelay { req, _ in
            #expect(req.url?.path == "/v1/peer")
            return .json(200, peerRecordJSON(record))
        }
        let peer = try await relay.lookupPeer(bob.getACEId())
        #expect(peer.encryptionPublicKey == bob.getEncryptionPublicKey())
        #expect(peer.source == .relay)
        await expectCodeAsync(.invalidPeer) { try await relay.lookupPeer(alice.getACEId()) }
    }

    @Test func lookupRejectsForgedBinding() async throws {
        var json = peerRecordJSON(try peerRecord(bob, registeredAt: 1741000000))
        json["encryptionPublicKey"] = ACEBase64.encode(alice.getEncryptionPublicKey())
        let data = ACETests.json(json)
        let relay = try makeRelay { _, _ in StubResponse(status: 200, chunks: [data]) }
        await expectCodeAsync(.invalidPeer) { try await relay.lookupPeer(bob.getACEId()) }
    }

    @Test func errorMapping() async throws {
        let cases: [(StubResponse, ACEError.Code)] = [
            (.error(503, "x", headers: ["Retry-After": "7"]), .relayUnavailable),
            (.error(429, "rate_limited"), .relayUnavailable),
            (.error(408, "x"), .relayUnavailable),
            (.error(404, "unknown_peer"), .unknownPeer),
            (.error(403, "not_registered"), .notRegistered),
            (.error(400, "envelope_expired"), .envelopeExpired),
            (.error(400, "invalid_envelope"), .relayRejected),
            (.error(409, "message_id_conflict"), .relayRejected),
            (StubResponse(status: 200, chunks: [Data("not json".utf8)]), .relayProtocolError),
            (StubResponse(status: -1), .relayUnavailable),
        ]
        for (response, code) in cases {
            let relay = try makeRelay { _, _ in response }
            do {
                _ = try await relay.lookupPeer(bob.getACEId())
                Issue.record("expected \(code)")
            } catch let e as ACEError {
                #expect(e.code == code, "\(response.status): \(e)")
                if response.status == 503 { #expect(e.retryAfterSeconds == 7) }
                if code == .relayRejected { #expect(e.status == response.status && e.relayCode != nil) }
            }
        }
    }

    @Test func oversizedResponseIsProtocolError() async throws {
        let host = uniqueHost()
        StubURLProtocol.register(host: host) { _, _ in StubResponse(status: 200, chunks: [Data(repeating: 0x20, count: 2048)]) }
        let relay = try RelayClient(baseURL: URL(string: "https://\(host)")!, session: stubSession(), timeout: 5,
                                    maxResponseBytes: 1024, clock: systemClock, sleeper: { _ in })
        await expectCodeAsync(.relayProtocolError) { try await relay.lookupPeer(bob.getACEId()) }
    }

    @Test func authenticatedCallsRetryOnceOnReplayWithIncreasingTimestamps() async throws {
        let seen = Locked<[Int]>([])
        let relay = try makeRelay({ req, _ in
            let ts = Int(req.value(forHTTPHeaderField: "X-ACE-Timestamp")!)!
            let auth = try! parseAuthHeaders(req.allHTTPHeaderFields!)
            try! verifyAuthHeaders(auth, request: .inbox(since: "-", limit: 100), aceId: Fixtures.agent("alice").getACEId(),
                                   scheme: .ed25519, signingPublicKey: Fixtures.agent("alice").getSigningPublicKey(), clock: { 1741000000 })
            let count = seen.mutate { $0.append(ts); return $0.count }
            return count == 1 ? .error(409, "replay") : .json(200, ["messages": [], "cursor": NSNull()])
        }, clock: { 1741000000 })
        let page = try await relay.fetchInbox(alice)
        #expect(page.entries.isEmpty && page.cursor == nil)
        #expect(seen.value == [1741000000, 1741000001])
    }

    @Test func fetchInboxReturnsRawEnvelopes() async throws {
        let fake = FakeRelay()
        let env = try createMessage(sender: alice, recipient: try peerOf(bob), type: .text, body: ["message": "hi"],
                                    threads: try ThreadStateMachine(localAceId: alice.getACEId()))
        let id = fake.enqueue(env)
        let relay = try makeRelay(fake.handle)
        let page = try await relay.fetchInbox(bob, limit: 10)
        #expect(page.entries.count == 1 && page.entries[0].streamId == id && page.cursor == id)
        #expect(try decodeEnvelope(page.entries[0].envelope) == env)
        await expectCodeAsync(.invalidArgument) { try await relay.fetchInbox(bob, limit: 101) }
    }

    @Test func webhookRoundTrip() async throws {
        let fake = FakeRelay()
        fake.add(try peerRecord(alice, registeredAt: 1741000000))
        let relay = try makeRelay(fake.handle)
        #expect(try await relay.getWebhook(alice) == nil)
        try await relay.setWebhook(alice, url: "https://agent.example.com/wake", secret: "0123456789abcdef0123456789abcdef")
        let w = try await relay.getWebhook(alice)
        #expect(w?.url == "https://agent.example.com/wake")
        #expect(w?.status == .active)
        #expect(w?.failures == 0 && w?.lastDeliveredAt == nil && w?.lastError == nil)
        try await relay.clearWebhook(alice)
        #expect(try await relay.getWebhook(alice) == nil)
        await expectCodeAsync(.invalidArgument) { try await relay.setWebhook(alice, url: "http://x.example", secret: "0123456789abcdef") }
        await expectCodeAsync(.notRegistered) { try await relay.getWebhook(bob) }
    }

    @Test func getWebhookRejectsMalformedOptionalFields() async throws {
        let fake = FakeRelay()
        fake.add(try peerRecord(alice, registeredAt: 1741000000))
        let relay = try makeRelay(fake.handle)
        try await relay.setWebhook(alice, url: "https://agent.example.com/wake", secret: "0123456789abcdef0123456789abcdef")
        let id = try alice.getACEId()
        let base = fake.webhooks[id]!
        func with(_ extra: [String: Any]) { fake.webhooks[id] = base.merging(extra) { _, new in new } }
        with(["lastDeliveredAt": 1741000001, "lastError": "http_500"])
        let ok = try await relay.getWebhook(alice)
        #expect(ok?.lastDeliveredAt == 1741000001 && ok?.lastError == "http_500")
        with(["lastDeliveredAt": NSNull(), "lastError": NSNull()])
        let nulls = try await relay.getWebhook(alice)
        #expect(nulls?.lastDeliveredAt == nil && nulls?.lastError == nil)
        for extra: [String: Any] in [["lastDeliveredAt": "yesterday"], ["lastDeliveredAt": 1.5], ["lastDeliveredAt": -1], ["lastError": 42]] {
            with(extra)
            await expectCodeAsync(.relayProtocolError) { try await relay.getWebhook(alice) }
        }
    }

    @Test func sendPostsEnvelopeAndMapsExpired() async throws {
        let fake = FakeRelay()
        let relay = try makeRelay(fake.handle)
        let env = try createMessage(sender: alice, recipient: try peerOf(bob), type: .text, body: ["message": "hi"],
                                    threads: try ThreadStateMachine(localAceId: alice.getACEId()))
        try await relay.send(env)
        #expect(fake.queues[bob.getACEId()]?.count == 1)
        fake.sendError = "envelope_expired"
        await expectCodeAsync(.envelopeExpired) { try await relay.send(env) }
    }

    @Test func registerAndIntents() async throws {
        let relay = try makeRelay { req, body in
            switch req.url!.path {
            case "/v1/register":
                let result = try? verifyRegistrationRequest(body)
                return result == nil ? .error(400, "invalid_registration") : .json(200, ["ok": true, "status": "registered"])
            case "/v1/intents" where req.httpMethod == "POST":
                let auth = try! parseAuthHeaders(req.allHTTPHeaderFields!)
                let a = Fixtures.agent("alice")
                try! verifyAuthHeaders(auth, request: .intent(need: "x", tags: ["a", "b"], maxPrice: "5", currency: nil, ttl: 60),
                                       aceId: a.getACEId(), scheme: .ed25519, signingPublicKey: a.getSigningPublicKey())
                return .json(201, ["intentId": "i1", "expiresAt": 99])
            case "/v1/intents":
                return .json(200, ["intents": [["intentId": "i1", "from": Fixtures.agent("alice").getACEId(), "need": "x",
                                                "tags": ["a"], "ttl": 60, "createdAt": 1, "expiresAt": 61]], "cursor": NSNull()])
            case "/v1/unregister":
                #expect(req.value(forHTTPHeaderField: "X-ACE-Signature") != nil)
                return .json(200, ["ok": true])
            default:
                return .error(404, "x")
            }
        }
        #expect(try await relay.register(alice, profile: .replace(AgentProfile(name: "Alice"))) == .registered)
        #expect(try await relay.postIntent(alice, need: "x", tags: ["a", "b"], maxPrice: "5", ttl: 60) == .init(intentId: "i1", expiresAt: 99))
        let page = try await relay.listIntents(q: "x")
        #expect(page.intents.count == 1 && page.intents[0].tags == ["a"])
        try await relay.unregister(alice)
    }

    @Test func discoverDropsUnverifiable() async throws {
        let good = peerRecordJSON(try peerRecord(bob, registeredAt: 1741000000))
        var bad = good
        bad["registeredAt"] = 1741000001
        let data = json(["agents": [good, bad], "cursor": "c2"])
        let relay = try makeRelay { _, _ in StubResponse(status: 200, chunks: [data]) }
        let page = try await relay.discover(DiscoverQuery(q: "a b+c"))
        #expect(page.agents.count == 1 && page.rejected == 1 && page.cursor == "c2")
    }

    // MARK: listen

    private func frame(_ id: String, _ env: ACEMessage, event: String = "message") -> String {
        "id: \(id)\nevent: \(event)\ndata: \(String(decoding: env.jsonData(), as: UTF8.self))\n\n"
    }

    @Test func listenParsesReconnectsAndResumes() async throws {
        let env = try createMessage(sender: alice, recipient: try peerOf(bob), type: .text, body: ["message": "hi"],
                                    threads: try ThreadStateMachine(localAceId: alice.getACEId()))
        let calls = Locked<[String]>([])
        let f = frame
        let relay = try makeRelay { req, _ in
            let since = URLComponents(url: req.url!, resolvingAgainstBaseURL: false)!.queryItems?.first { $0.name == "since" }?.value ?? "-"
            let n = calls.mutate { $0.append(since); return $0.count }
            switch n {
            case 1: return .sse(["event: connected\ndata: {}\n\n", ": heartbeat\n\n", f("1-1", env, "catchup"), "event: drain\ndata: {}\n\n"])
            case 2: return StubResponse(status: -1)
            case 3: return .error(503, "x", headers: ["Retry-After": "2"])
            case 4: return .sse([f("1-2", env, "message")])
            default: return .error(401, "invalid_signature")
            }
        }
        var events: [RelayClient.Event] = []
        do {
            for try await e in relay.listen(bob) { events.append(e) }
            Issue.record("expected relay_rejected")
        } catch let e as ACEError {
            #expect(e.code == .relayRejected)
        }
        #expect(events.map(\.streamId) == ["1-1", "1-2"])
        #expect(events[0].catchup && !events[1].catchup)
        #expect(try decodeEnvelope(events[1].envelope) == env)
        #expect(calls.value == ["-", "1-1", "1-1", "1-1", "1-2"])
    }

    @Test func listenGivesUpAfterTenFailedConnects() async throws {
        let calls = Locked(0)
        let delays = Locked<[Double]>([])
        let host = uniqueHost()
        StubURLProtocol.register(host: host) { _, _ in
            calls.mutate { $0 += 1 }
            return .error(503, "x", headers: ["Retry-After": "45"])
        }
        let relay = try RelayClient(baseURL: URL(string: "https://\(host)")!, session: stubSession(), timeout: 5,
                                    maxResponseBytes: 1 << 20, clock: systemClock, sleeper: { d in delays.mutate { $0.append(d) } })
        await expectCodeAsync(.relayUnavailable) { for try await _ in relay.listen(bob) {} }
        #expect(calls.value == 10)
        #expect(delays.value == Array(repeating: 30, count: 9))
    }

    @Test func listenOversizedFrameIsProtocolError() async throws {
        let big = "data: " + String(repeating: "x", count: ACELimits.maxEnvelopeBytes + 600) + "\n\n"
        let relay = try makeRelay { _, _ in .sse(["id: 1-1\n", big]) }
        await expectCodeAsync(.relayProtocolError) { for try await _ in relay.listen(bob) {} }
    }

    @Test func sseParser() throws {
        var p = SSEParser(maxLine: 100)
        var frames: [SSEParser.Frame] = []
        for b in Array("id: 5-1\r\nevent: catchup\r\ndata: a\r\ndata: b\r\n\r\n: c\n\n".utf8) {
            if let f = try p.feed(b) { frames.append(f) }
        }
        #expect(frames.count == 1)
        #expect(frames[0].id == "5-1" && frames[0].event == "catchup" && String(decoding: frames[0].data, as: UTF8.self) == "a\nb")
    }
}

final class Locked<T>: @unchecked Sendable {
    private let lock = NSLock()
    private var v: T
    init(_ v: T) { self.v = v }
    var value: T { lock.lock(); defer { lock.unlock() }; return v }
    @discardableResult
    func mutate<R>(_ f: (inout T) -> R) -> R { lock.lock(); defer { lock.unlock() }; return f(&v) }
}
