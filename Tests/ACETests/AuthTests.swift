//
//  AuthTests.swift
//  ACE SDK
//
//  The client side of relay authentication and registration (07 § Authentication, § Registration). Relay-side
//  verification lives in sdk-ts; the vectors' `auth` section checks the signed bytes.
//

import Foundation
import Testing
@testable import ACE

private let audience = "https://relay.example"

/// The header signature verifies over `M(aceId, ts, seq, encodePayload(audience, nonce, actionPayload))` with ctx `action`.
private func verifies(_ h: [String: String], _ req: RelayAuthRequest, _ identity: any ACEIdentity, action: String? = nil) throws -> Bool {
    let m = try ACESigning.message(aceId: identity.getACEId(), timestamp: Int(h["X-ACE-Timestamp"]!)!, seq: Int(h["X-ACE-Seq"]!)!,
                                   payload: try authPayload(req, audience: h["X-ACE-Audience"]!, nonce: h["X-ACE-Nonce"]!))
    return ACESigning.verifySignature(message: m, action: action ?? req.action, signature: try ACEBase64.decode(h["X-ACE-Signature"]!),
                                      publicKey: identity.getSigningPublicKey())
}

@Suite("Auth")
struct AuthTests {
    @Test func headersSignTheAudienceNonceAndActionPayload() throws {
        let a = try makeIdentity(now: NOW)
        for req: RelayAuthRequest in [
            .listen(since: "-"), .inbox(since: "1-0", limit: 7), .unregister, .inboxAck(through: "5-0"),
            .block(peer: "ace:sha256:" + String(repeating: "a", count: 64), blocked: true, revision: 3),
        ] {
            let h = try createAuthHeaders(a, request: req, timestamp: NOW, audience: audience)
            #expect(Set(h.keys) == ["X-ACE-Id", "X-ACE-Timestamp", "X-ACE-Seq", "X-ACE-Signature", "X-ACE-Audience", "X-ACE-Nonce"])
            #expect(h["X-ACE-Id"] == a.getACEId() && h["X-ACE-Timestamp"] == String(NOW) && h["X-ACE-Seq"] == "1")
            #expect(h["X-ACE-Signature"]!.count == 4412 && isSHA256Hex(h["X-ACE-Nonce"]!))
            #expect(try verifies(h, req, a))
            #expect(try !verifies(h, req, a, action: req.action != "listen" ? "listen" : "inbox"))
        }
        let first = try createAuthHeaders(a, request: .unregister, timestamp: NOW, audience: audience)
        #expect(try createAuthHeaders(a, request: .unregister, timestamp: NOW, audience: audience)["X-ACE-Nonce"] != first["X-ACE-Nonce"])
        try a.delegate(now: NOW + 1, notAfter: nil)
        #expect(try createAuthHeaders(a, request: .unregister, timestamp: NOW + 1, audience: audience)["X-ACE-Seq"] == "2")
    }

    @Test func createAuthHeadersRefusesUnusableIdentityAndMalformedInput() throws {
        let a = try makeIdentity(now: NOW)
        try a.delegate(now: NOW + 1, notAfter: NOW + 10)
        _ = try createAuthHeaders(a, request: .unregister, timestamp: NOW + 9, audience: audience)
        expectCode(.identityUnavailable) { try createAuthHeaders(a, request: .unregister, timestamp: NOW + 10, audience: audience) }
        // Malformed input is invalid_argument before the identity is asked.
        expectCode(.invalidArgument) { try createAuthHeaders(a, request: .unregister, timestamp: -1, audience: audience) }
        expectCode(.invalidArgument) { try createAuthHeaders(a, request: .inbox(since: "x", limit: 1), timestamp: NOW, audience: audience) }
        expectCode(.invalidArgument) { try createAuthHeaders(a, request: .inbox(since: "-", limit: 101), timestamp: NOW, audience: audience) }
        expectCode(.invalidArgument) { try createAuthHeaders(a, request: .inboxAck(through: "-"), timestamp: NOW, audience: audience) }
        expectCode(.invalidArgument) { try createAuthHeaders(a, request: .unregister, timestamp: NOW, audience: audience, nonce: "AB") }
    }

    @Test(arguments: [-1, 1 << 53, Int.min, Int.max])
    func badInjectedClockIsInvalidArgument(_ value: Int) {
        do {
            _ = try unixNow { value }
            Issue.record("expected invalid_argument")
        } catch let e as ACEError {
            #expect(e.code == .invalidArgument && e.message == "clock must return integer Unix seconds")
        } catch {
            Issue.record("\(error)")
        }
    }

    /// The 02 § Signing actions payloads.
    @Test func actionPayloads() throws {
        let peer = "ace:sha256:" + String(repeating: "b", count: 64)
        #expect(RelayAuthRequest.block(peer: peer, blocked: true, revision: 7).payload() == ACESigning.encodePayload(peer, "block", "7"))
        #expect(RelayAuthRequest.block(peer: peer, blocked: false, revision: 8).payload() == ACESigning.encodePayload(peer, "unblock", "8"))
        #expect(RelayAuthRequest.inboxAck(through: "12-3").payload() == ACESigning.encodePayload("12-3"))
        #expect(RelayAuthRequest.inbox(since: "-", limit: 20).payload() == ACESigning.encodePayload("-", "20"))
        #expect(RelayAuthRequest.unregister.payload().isEmpty)
        #expect(RelayAuthRequest.inboxAck(through: "12-3").action == "inbox-ack" && RelayAuthRequest.block(peer: peer, blocked: true, revision: 1).action == "block")
    }

    @Test func audienceIsHTTPSOrLoopbackHTTP() throws {
        // 02 § Relay URLs: an audience is https, or http to a loopback host (a relay's own development setup)
        let nonce = String(repeating: "a", count: 64)
        for ok in ["https://relay.example", "http://127.0.0.1:8080", "http://[::1]:8080"] {
            #expect(throws: Never.self) { _ = try authPayload(.unregister, audience: ok, nonce: nonce) }
        }
        expectCode(.invalidArgument) { _ = try authPayload(.unregister, audience: "http://relay.example", nonce: nonce) }
        #expect(try authPayload(.listen(since: "-"), audience: audience, nonce: nonce)
                == ACESigning.encodePayload([.string(audience), .string(nonce), .data(ACESigning.encodePayload("-"))]))
    }

    @Test func registrationRequestSignsTheLastHashAndAudience() throws {
        let a = try makeIdentity(now: NOW)
        let reg = try createRegistrationRequest(identity: a, timestamp: NOW, audience: "https://Relay.Example/")
        #expect(Set(reg.objectValue!.keys) == ["aceId", "kel", "timestamp", "audience", "signature"])
        #expect(reg["audience"] == "https://relay.example")
        let st = a.getState()
        try verifyOperational(SignatureEnvelope(operational: reg["signature"])!, state: st, action: "register-request", timestamp: NOW,
                              payload: ACESigning.encodePayload(st.lastHash, "https://relay.example"), now: NOW)
        expectCode(.invalidSignature) {
            try verifyOperational(SignatureEnvelope(operational: reg["signature"])!, state: st, action: "register-request", timestamp: NOW,
                                  payload: ACESigning.encodePayload(st.lastHash, "https://other.example"), now: NOW)
        }
        expectCode(.invalidArgument) { try createRegistrationRequest(identity: a, timestamp: NOW, audience: "ftp://relay.example") }
    }
}
