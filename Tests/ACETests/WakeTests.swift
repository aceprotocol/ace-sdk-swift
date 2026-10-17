//
//  WakeTests.swift
//  07 § Wake hints: `PUT` / `DELETE /v1/wake` (action `wake`), the client-side gateway / token check and the 404 of a
//  relay without the feature.
//

import Foundation
import Testing
@testable import ACE

private let gateway = "https://push.example/v1/ace-wake"
private let token = "aZ09_-aZ09_-aZ09_-aZ09_-"

struct WakeTests {
    @Test func setAndClearWakeAreSignedWakeRequests() async throws {
        let clock = TestClock(systemClock()), relay = FakeRelay(clock: clock.fn)
        let peer = try await NetPeer.make(relay, clock: clock)
        try await peer.network.setWake(gateway: gateway, token: token)
        // the FakeRelay verifies the six headers over action `wake`, payload encodePayload(gateway, token)
        #expect(relay.wake(peer.aceId)?.gateway == gateway && relay.wake(peer.aceId)?.token == token)
        try await peer.network.clearWake()
        #expect(relay.wake(peer.aceId) == nil)
        try await peer.network.clearWake()  // idempotent
        #expect(relay.withLock { relay.requests.filter { $0.hasSuffix(" /v1/wake") } } == ["PUT /v1/wake", "DELETE /v1/wake", "DELETE /v1/wake"])
    }

    @Test func wakeRequestShapes() async throws {
        let identity = try makeIdentity(now: systemClock())
        let seen = LockedValue<[(String, String, [String: String], Data)]>([])
        let relay = try makeRelay { req, body in
            seen.value.append((req.httpMethod ?? "", req.url!.path, req.allHTTPHeaderFields ?? [:], body))
            return .json(200, ["ok": true] as JSONValue)
        }
        try await relay.setWake(identity, gateway: gateway, token: token)
        try await relay.clearWake(identity)
        let (put, del) = (seen.value[0], seen.value[1])
        #expect(put.0 == "PUT" && put.1 == "/v1/wake" && put.2["Content-Type"] == "application/json")
        #expect(try JSONValue(json: put.3) == ["gateway": .string(gateway), "token": .string(token)])
        #expect(del.0 == "DELETE" && del.1 == "/v1/wake" && del.3.isEmpty)
        for (_, _, h, _) in seen.value {
            #expect(["X-ACE-Audience", "X-ACE-Nonce", "X-ACE-Id", "X-ACE-Timestamp", "X-ACE-Seq", "X-ACE-Signature"].allSatisfy { h[$0] != nil })
        }
        // the signatures verify under action `wake` over the expected action payloads
        let state = identity.getState()
        for ((_, _, h, _), payload) in zip(seen.value, [ACESigning.encodePayload(gateway, token), Data()]) {
            let ap = ACESigning.encodePayload([.string(h["X-ACE-Audience"]!), .string(h["X-ACE-Nonce"]!), .data(payload)])
            let m = try ACESigning.message(aceId: identity.getACEId(), timestamp: Int(h["X-ACE-Timestamp"]!)!, seq: Int(h["X-ACE-Seq"]!)!, payload: ap)
            #expect(ACESigning.verifySignature(message: m, action: "wake", signature: try ACEBase64.decode(h["X-ACE-Signature"]!),
                                               publicKey: state.signing!.publicKey))
        }
    }

    @Test func relayWithoutWakeHintsIsRelayRejected() async throws {
        let identity = try makeIdentity(now: systemClock())
        let relay = try makeRelay { _, _ in .error(404, "not_found") }
        for clear in [false, true] {
            do {
                if clear { try await relay.clearWake(identity) } else { try await relay.setWake(identity, gateway: gateway, token: token) }
                Issue.record("expected relay_rejected")
            } catch let e as ACEError {
                #expect(e.code == .relayRejected && e.relayCode == "not_found" && e.status == 404)
            }
        }
    }

    @Test func invalidGatewayOrTokenIsRefusedBeforeAnyRequest() async throws {
        let identity = try makeIdentity(now: systemClock())
        let calls = LockedValue(0)
        let relay = try makeRelay { _, _ in calls.value += 1; return .json(200, ["ok": true] as JSONValue) }
        // The grammar is covered by the vectors (auth.wake.invalid); here: the loopback policy and a bad token, unsent.
        for (g, t) in [("http://push.example", token), ("http://localhost:8080", token), (gateway, token + "=")] {
            await expectCodeAsync(.invalidArgument) { try await relay.setWake(identity, gateway: g, token: t) }
        }
        #expect(calls.value == 0)
        // loopback http only under allowLoopbackRelays
        let host = uniqueHost()
        StubURLProtocol.register(host: host) { _, _ in calls.value += 1; return .json(200, ["ok": true] as JSONValue) }
        let dev = try RelayClient(baseURL: URL(string: "https://\(host)")!, session: stubSession(), timeout: 5, allowLoopbackRelays: true)
        try await dev.setWake(identity, gateway: "http://localhost:8080", token: token)
        #expect(calls.value == 1)
    }
}
