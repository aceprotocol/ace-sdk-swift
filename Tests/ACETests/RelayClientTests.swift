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
            (.error(429, "recipient_inbox_full", headers: ["Retry-After": "7"]), .relayRejected),
            (.error(301, "x", headers: ["Location": "https://elsewhere.test/"]), .relayProtocolError),
            (StubResponse(status: 200, chunks: [Data("not json".utf8)]), .relayProtocolError),
            (StubResponse(status: 200, chunks: []), .relayProtocolError),
            (StubResponse(status: 200, chunks: [Data("[]".utf8)]), .relayProtocolError),
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
                if code == .relayRejected { #expect(e.status == response.status && e.relayCode != nil && e.retryAfterSeconds == nil) }
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
        #expect(try decodeEnvelope(page.entries[0].message) == env)
        await expectCodeAsync(.invalidArgument) { try await relay.fetchInbox(bob, limit: 101) }
    }

    @Test func redirectsAreNeverFollowed() async throws {
        let followed = Locked(0)
        let target = uniqueHost()
        StubURLProtocol.register(host: target) { _, _ in followed.mutate { $0 += 1 }; return .json(200, ["ok": true]) }
        let relay = try makeRelay { _, _ in StubResponse(status: 307, headers: ["Location": "https://\(target)/v1/listen"]) }
        await expectCodeAsync(.relayProtocolError) { try await relay.lookupPeer(bob.getACEId()) }
        await expectCodeAsync(.relayProtocolError) { for try await _ in relay.listen(alice) {} }
        #expect(followed.value == 0)
    }

    @Test func registerIsNotRetriedOnReplay() async throws {
        let calls = Locked(0)
        let relay = try makeRelay { _, _ in calls.mutate { $0 += 1 }; return .error(409, "replay") }
        await expectCodeAsync(.relayRejected) { try await relay.register(alice) }
        #expect(calls.value == 1)
    }

    @Test func fetchInboxIsStrict() async throws {
        let queries = Locked<[String]>([])
        let entry: [String: Any] = ["streamId": "1-1", "message": ["x": 1]]
        let page = json(["messages": [entry, entry], "cursor": "1-1"])
        let relay = try makeRelay { req, _ in
            queries.mutate { $0.append(req.url?.query ?? "") }
            return StubResponse(status: 200, chunks: [page])
        }
        await expectCodeAsync(.relayProtocolError) { try await relay.fetchInbox(bob, since: "-", limit: 1) }
        #expect(try await relay.fetchInbox(bob, since: "-", limit: 2).entries.count == 2)
        #expect(queries.value == ["limit=1", "limit=2"])  // "-" (start) is not sent
        let badCursor = try makeRelay { _, _ in .json(200, ["messages": [], "cursor": 5]) }
        await expectCodeAsync(.relayProtocolError) { try await badCursor.fetchInbox(bob) }
    }

    @Test func intentsAreStrict() async throws {
        let posted = Locked<[String: Any]?>(nil)
        let listed = Locked<String?>(nil)
        let intent: [String: Any] = ["intentId": "i1", "from": Fixtures.agent("alice").getACEId(), "need": "x",
                                     "tags": ["a"], "ttl": 60, "createdAt": 1, "expiresAt": 61]
        let response = Locked<[String: Any]>(intent)
        let relay = try makeRelay { req, body in
            if req.httpMethod == "POST" {
                posted.mutate { $0 = try? JSONSerialization.jsonObject(with: body) as? [String: Any] }
                return .json(201, ["intentId": "i1", "expiresAt": 99])
            }
            listed.mutate { $0 = URLComponents(url: req.url!, resolvingAgainstBaseURL: false)?.queryItems?.first { $0.name == "tags" }?.value }
            return .json(200, ["intents": [response.value], "cursor": NSNull()])
        }
        _ = try await relay.postIntent(alice, need: "x", ttl: 60)
        #expect(posted.value?["tags"] as? [String] == [])
        #expect(try await relay.listIntents(tags: ["a", "b"]).intents[0].ext == nil)
        #expect(listed.value == "a,b")
        await expectCodeAsync(.invalidArgument) { try await relay.listIntents(tags: ["a,b"]) }
        await expectCodeAsync(.invalidArgument) { try await relay.discover(DiscoverQuery(tags: ["a,b"])) }
        var withPrice = intent
        withPrice["ext"] = [commerceExt: ["maxPrice": "5", "currency": "USDC"], "urn:x:1": ["k": 1]]
        response.mutate { $0 = withPrice }
        let priced = try await relay.listIntents().intents[0]
        #expect(priced.commerce == CommerceIntentExt(maxPrice: "5", currency: "USDC") && priced.ext?["urn:x:1"] == ["k": 1])
        let breakages: [([String: Any]) -> [String: Any]] = [
            { var v = $0; v.removeValue(forKey: "tags"); return v },
            { $0.merging(["tags": "a"]) { $1 } },
            { $0.merging(["tags": [1]]) { $1 } },
            { $0.merging(["ext": "x"]) { $1 } },
            { $0.merging(["ext": NSNull()]) { $1 } },
            { $0.merging(["ext": ["x": [:]]]) { $1 } },  // key not namespaced
            { $0.merging(["ext": [commerceExt: ["maxPrice": "5"]]]) { $1 } },  // currency missing
            { $0.merging(["ext": [commerceExt: ["maxPrice": 5, "currency": "USDC"]]]) { $1 } },
        ]
        for brk in breakages {
            response.mutate { $0 = brk(intent) }
            await expectCodeAsync(.relayProtocolError) { try await relay.listIntents() }
        }
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

    @Test func listenRejectsEventsWithoutValidStreamId() async throws {
        for frame in ["event: message\ndata: {}\n\n", "id: \(String(repeating: "1", count: 21))-0\nevent: message\ndata: {}\n\n"] {
            let relay = try makeRelay({ _, _ in .sse([frame]) })
            await expectCodeAsync(.relayProtocolError) { for try await _ in relay.listen(alice) {} }
        }
    }

    @Test func listenYieldsPoisonFramesRaw() async throws {
        // Frame data is not parsed by the client: the Inbox quarantines what does not decode.
        let relay = try makeRelay({ _, _ in .sse(["id: 1-0\nevent: catchup\ndata:\n\n", "id: 1-1\nevent: message\ndata: not json\n\n"]) })
        var events: [RelayClient.Event] = []
        for try await e in relay.listen(alice) {
            events.append(e)
            if events.count == 2 { break }
        }
        #expect(events.map(\.streamId) == ["1-0", "1-1"])
        #expect(events[0].message.isEmpty && events[0].catchup)
        #expect(events[1].message == Data("not json".utf8) && !events[1].catchup)
    }

    @Test func getWebhookRejectsMalformedOptionalFields() async throws {
        let fake = FakeRelay()
        fake.add(try peerRecord(alice, registeredAt: 1741000000))
        let relay = try makeRelay(fake.handle)
        try await relay.setWebhook(alice, url: "https://agent.example.com/wake", secret: "0123456789abcdef0123456789abcdef")
        let id = alice.getACEId()
        let base = fake.webhooks[id]!
        func with(_ extra: [String: Any]) { fake.webhooks[id] = base.merging(extra) { _, new in new } }
        with(["lastDeliveredAt": 1741000001, "lastError": "http_500"])
        let ok = try await relay.getWebhook(alice)
        #expect(ok?.lastDeliveredAt == 1741000001 && ok?.lastError == "http_500")
        for extra: [String: Any] in [["lastDeliveredAt": "yesterday"], ["lastDeliveredAt": 1.5], ["lastDeliveredAt": -1], ["lastDeliveredAt": NSNull()],
                                     ["lastError": 42], ["lastError": NSNull()]] {
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
                let posted = try! JSONSerialization.jsonObject(with: body) as! [String: Any]
                #expect((posted["ext"] as? [String: Any])?.keys.sorted() == [commerceExt])
                try! verifyAuthHeaders(auth, request: .intent(need: "x", tags: ["a", "b"], ext: [commerceExt: ["maxPrice": "5", "currency": "USDC"]], ttl: 60),
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
        #expect(try await relay.postIntent(alice, need: "x", tags: ["a", "b"], ext: [commerceExt: CommerceIntentExt(maxPrice: "5", currency: "USDC").jsonValue], ttl: 60) == .init(intentId: "i1", expiresAt: 99))
        await expectCodeAsync(.invalidArgument) { try await relay.postIntent(alice, need: "x", ext: [commerceExt: ["maxPrice": "5"]], ttl: 60) }
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

    @Test func discoverSendsAccount() async throws {
        let seen = Locked<[String?]>([])
        let data = json(["agents": [Any]()])
        let relay = try makeRelay { req, _ in
            let v = URLComponents(url: req.url!, resolvingAgainstBaseURL: false)!.queryItems?.first { $0.name == "account" }?.value
            seen.mutate { $0.append(v) }
            return StubResponse(status: 200, chunks: [data])
        }
        let acc = "eip155:1:0x" + String(repeating: "ab", count: 20)
        _ = try await relay.discover(DiscoverQuery(account: acc))
        _ = try await relay.discover(DiscoverQuery())
        #expect(seen.mutate { $0 } == [acc, nil])
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
        #expect(try decodeEnvelope(events[1].message) == env)
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

    @Test func listenConnectedOnlyStreamsCountAsFailures() async throws {
        // 200, `connected`, then a clean end, forever: neither `connected` nor heartbeats are
        // progress, so each connection is a failure and the stream ends after ten.
        let calls = Locked(0)
        let delays = Locked<[Double]>([])
        let host = uniqueHost()
        StubURLProtocol.register(host: host) { _, _ in
            calls.mutate { $0 += 1 }
            return .sse(["event: connected\ndata: {}\n\n", ": hb\n\n"])
        }
        let relay = try RelayClient(baseURL: URL(string: "https://\(host)")!, session: stubSession(), timeout: 5,
                                    maxResponseBytes: 1 << 20, clock: systemClock, sleeper: { d in delays.mutate { $0.append(d) } })
        await expectCodeAsync(.relayUnavailable) { for try await _ in relay.listen(bob) {} }
        #expect(calls.value == 10)
        #expect(delays.value == [1, 2, 4, 8, 16, 30, 30, 30, 30])
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

        // Only an event with data is dispatched; id and event do not carry over.
        var r = SSEParser(maxLine: 100)
        var some: [SSEParser.Frame] = []
        for b in Array("id: 1-0\nevent: message\n\ndata: a\n\nid: 2-0\nevent: drain\n\n".utf8) {
            if let f = try r.feed(b) { some.append(f) }
        }
        #expect(some.count == 1)
        #expect(some.first?.id == nil && some.first?.event == "message" && some.first?.data == Array("a".utf8))

        // CR-only and mixed line endings.
        for text in ["id: 5-2\revent: message\rdata: x\r\r", "id: 5-2\nevent: message\r\ndata: x\r\r\n"] {
            var q = SSEParser(maxLine: 100)
            var got: [SSEParser.Frame] = []
            for b in Array(text.utf8) { if let f = try q.feed(b) { got.append(f) } }
            #expect(got.count == 1, "\(text.debugDescription)")
            #expect(got.first?.id == "5-2" && got.first?.event == "message" && got.first?.data == Array("x".utf8))
        }
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
