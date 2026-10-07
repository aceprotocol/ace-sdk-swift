import Foundation
import Testing
@testable import ACE

/// A public address for the injected resolver.
private let publicAddress: [[UInt8]] = [[93, 184, 216, 34]]

private func endpointHost(_ handler: @escaping StubHandler) -> String {
    let host = "peer-\(UUID().uuidString.lowercased().prefix(8)).test"
    StubURLProtocol.register(host: host, handler)
    return "https://\(host)/ace/receive"
}

private func post(_ endpoint: String, _ env: ACEMessage, resolve: @escaping @Sendable (String) -> [[UInt8]]? = { _ in publicAddress })
    async throws {
    try await postDirect(endpoint: endpoint, envelope: env, timeout: 5, session: stubSession(), resolve: resolve)
}

@Suite("Direct delivery")
struct DirectTests {
    let alice = Fixtures.agent("alice")
    let bob = Fixtures.agent("bob")

    private func rfq(_ p: Pair, threadId: String = "d1") async throws -> ACEMessage {
        let bobPeer = try await p.alicePeers.get(p.bob.getACEId())!
        return try createMessage(sender: p.alice, recipient: bobPeer, type: .rfq, body: ["need": "x"],
                                 threads: try ThreadStateMachine(localAceId: p.alice.getACEId()), threadId: threadId,
                                 timestamp: p.clock.now)
    }

    private func request(_ env: ACEMessage) -> Data {
        JSONWriter.serialize(.object(["message": env.jvalue, "extra": .bool(true)]))
    }

    // MARK: receiver

    @Test func receiveDirectDeliversAndAcknowledgesDuplicates() async throws {
        let p = try await Pair()
        let sink = Sink()
        let bIn = try await p.inbox(p.bob, sink)
        let env = try await rfq(p)
        let first = await bIn.receiveDirect(request(env))
        #expect(first.status == 200 && first.body == ["ok": true, "messageId": .string(env.messageId)])
        #expect(first.outcome.map(isDelivered) == true && sink.has(env))
        #expect(try JSONValue(json: first.bodyData) == .object(first.body))
        let again = await bIn.receiveDirect(request(env))
        #expect(again.status == 200 && again.body["messageId"] == .string(env.messageId))
        #expect(again.outcome.map(isDuplicate) == true)

        // Pipeline rejection → 400 with its code; nothing persisted for a direct source.
        p.clock.now += 1000
        let fresh = await bIn.receiveDirect(request(try await rfq(p, threadId: "d2")))
        #expect(fresh.status == 200)
        let old = try await rfq(p, threadId: "d3")
        p.clock.now += 400
        let late = await bIn.receiveDirect(request(old))
        #expect(late.status == 400 && late.body["error"] == "stale_timestamp")
        #expect(try p.bobStore.list(prefix: "quarantine/").isEmpty)

        // Retryable → 503 with its code.
        sink.failing = true
        let busy = await bIn.receiveDirect(request(try await rfq(p, threadId: "d4")))
        #expect(busy.status == 503 && busy.body["error"] == "handler_failed")
        sink.failing = false

        // A closed inbox is not accepting: 503 internal_error (the sender falls back to the relay).
        await bIn.close()
        let closed = await bIn.receiveDirect(request(try await rfq(p, threadId: "d5")))
        #expect(closed.status == 503 && closed.body["error"] == "internal_error" && closed.outcome == nil)
        let closedBig = await bIn.receiveDirect(Data(count: ACELimits.maxDirectBodyBytes + 1))
        #expect(closedBig.status == 503)
    }

    @Test func receiveThrowsOnMisuse() async throws {
        let p = try await Pair()
        let bIn = try await p.inbox(p.bob, Sink())
        let env = try await rfq(p)
        await expectCodeAsync(.invalidArgument) { try await bIn.receive(env.jsonData(), source: .relay(url: "ftp://x.example", streamId: "1-1")) }
        await expectCodeAsync(.invalidArgument) { try await bIn.receive(env.jsonData(), source: .relay(url: "https://x.example?a", streamId: nil)) }
        await expectCodeAsync(.invalidArgument) { try await bIn.receive(env.jsonData(), source: .relay(url: "https://x.example", streamId: "x")) }
        // Bytes that are not an envelope are an outcome, not a throw.
        let junk = try await bIn.receive(Data("not json".utf8), source: .direct)
        #expect(code(junk) == .invalidEnvelope)
        await bIn.close()
        await expectCodeAsync(.invalidArgument) { try await bIn.receive(env.jsonData(), source: .direct) }
    }

    // MARK: sender

    @Test func postDirectSucceedsOnlyOnOkTrue() async throws {
        let env = try await rfq(try await Pair())
        let seen = Locked<Data?>(nil)
        let ok = endpointHost { req, body in
            #expect(req.httpMethod == "POST" && req.value(forHTTPHeaderField: "Content-Type") == "application/json")
            seen.mutate { $0 = body }
            return .json(200, ["ok": true, "messageId": env.messageId])
        }
        try await post(ok, env)
        let sent = try JSONParser.parse(seen.value!)
        #expect(try decodeEnvelope(JSONWriter.serialize(sent["message"]!)) == env)

        let cases: [(StubResponse, ACEError.Code?, String?)] = [  // nil: success
            (.json(200, ["ok": false]), .directUnavailable, nil),
            (StubResponse(status: 200, chunks: [Data("ok".utf8)]), .directUnavailable, nil),
            (.json(202, ["ok": true]), nil, nil),
            (.json(400, ["ok": false, "error": "invalid_envelope"]), .directRejected, "invalid_envelope"),
            (.json(413, ["ok": false, "error": "payload_too_large"]), .directRejected, "payload_too_large"),
            (StubResponse(status: 400, chunks: [Data("bad".utf8)]), .directRejected, nil),
            // remoteCode only when it matches ^[a-z0-9_]{1,64}$ (peer-controlled text otherwise)
            (.json(400, ["ok": false, "error": "Bad\u{1B}[31m"]), .directRejected, nil),
            (.json(400, ["ok": false, "error": String(repeating: "a", count: 65)]), .directRejected, nil),
            (.json(400, ["ok": false, "error": String(repeating: "a", count: 64)]), .directRejected,
             String(repeating: "a", count: 64)),
            (.json(400, ["ok": false, "error": ""]), .directRejected, nil),
            (.json(429, ["ok": false, "error": "rate_limited"]), .directUnavailable, nil),
            (.json(503, ["ok": false, "error": "handler_failed"]), .directUnavailable, nil),
            (.json(404, ["error": "not_found"]), .directUnavailable, nil),
            (StubResponse(status: 302, headers: ["Location": "https://elsewhere.test/"]), .directUnavailable, nil),
            (StubResponse(status: -1), .directUnavailable, nil),
        ]
        for (response, expected, receiverCode) in cases {
            let endpoint = endpointHost { _, _ in response }
            do {
                try await post(endpoint, env)
                #expect(expected == nil, "\(response.status): expected \(String(describing: expected))")
            } catch let e as ACEError {
                #expect(e.code == expected, "\(response.status): \(e)")
                if expected == .directRejected { #expect(e.remoteCode == receiverCode && e.relayCode == nil && e.status == response.status) }
            }
        }
    }

    @Test func postDirectRefusesUnsafeEndpoints() async throws {
        let env = try await rfq(try await Pair())
        let called = Locked(0)
        let endpoint = endpointHost { _, _ in called.mutate { $0 += 1 }; return .json(200, ["ok": true]) }
        await expectCodeAsync(.invalidArgument) { try await post(endpoint.replacingOccurrences(of: "https:", with: "http:"), env) }
        await expectCodeAsync(.invalidArgument) { try await post("not a url", env) }
        await expectCodeAsync(.invalidArgument) { try await post(endpoint, env, resolve: { _ in [[10, 0, 0, 1]] }) }
        await expectCodeAsync(.invalidArgument) { try await post(endpoint, env, resolve: { _ in publicAddress + [[127, 0, 0, 1]] }) }
        let v6 = [UInt8](repeating: 0, count: 15) + [1]  // ::1
        await expectCodeAsync(.invalidArgument) { try await post(endpoint, env, resolve: { _ in [v6] }) }
        await expectCodeAsync(.directUnavailable) { try await post(endpoint, env, resolve: { _ in nil }) }
        await expectCodeAsync(.invalidArgument) { try await postDirect(endpoint: endpoint, envelope: env, timeout: 0) }
        #expect(called.value == 0)
    }

    @Test func directOrRelayFallsBackOnlyWhenAllowed() async throws {
        let env = try await rfq(try await Pair())
        let relayed = Locked(0)
        let send: @Sendable (ACEMessage) async throws -> Void = { _ in relayed.mutate { $0 += 1 } }
        func transport(_ result: ACEError?) -> @Sendable (ACEMessage) async throws -> DeliveryPath {
            deliverDirectOrRelay(send: send, endpoint: "https://peer.example/ace") { _, _ in if let result { throw result } }
        }
        #expect(try await transport(nil)(env) == .direct && relayed.value == 0)
        #expect(try await transport(ACEError(.directUnavailable))(env) == .relay && relayed.value == 1)
        #expect(try await transport(ACEError(.invalidArgument))(env) == .relay && relayed.value == 2)
        await expectCodeAsync(.directRejected) { try await transport(ACEError(.directRejected))(env) }
        #expect(relayed.value == 2)
        let noEndpoint = deliverDirectOrRelay(send: send, endpoint: nil) { _, _ in Issue.record("direct without endpoint") }
        #expect(try await noEndpoint(env) == .relay && relayed.value == 3)
    }

    @Test func outboxReportsTheDeliveringPath() async throws {
        let p = try await Pair()
        let out = try await p.outbox(p.alice)
        let bobPeer = try await p.alicePeers.get(p.bob.getACEId())!
        let staged = try await out.stage(recipient: bobPeer, type: .rfq, body: ["need": "x"], threadId: "dp")
        let path = try await out.deliver(staged.requestId,
                                         transport: deliverDirectOrRelay(send: { _ in }, endpoint: "https://bob.example/ace") { _, _ in })
        #expect(path == .direct)
        #expect(try await out.pending().isEmpty)
    }

    @Test func isBlockedAddressRejectsNonLiterals() {
        #expect(isBlockedAddress("localhost") && isBlockedAddress("") && isBlockedAddress("fe80::1%en0"))
        #expect(!isBlockedAddress("8.8.8.8"))
    }
}
