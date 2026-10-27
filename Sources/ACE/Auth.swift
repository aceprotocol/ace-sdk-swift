//
//  Auth.swift
//  ACE SDK
//
//  Client side of relay authentication and registration (07 § Authentication, § Registration). Relay-side verification
//  is provided by sdk-ts only.
//

import Foundation

/// What an authenticated relay call signs. `since` / `through` are `"-"` or `<ms>-<seq>`.
public enum RelayAuthRequest: Sendable, Equatable {
    case listen(since: String)
    case inbox(since: String, limit: Int)
    case inboxAck(through: String)
    case unregister
    case block(peer: String, blocked: Bool, revision: Int)
    /// `PUT /v1/wake` (07 § Wake hints).
    case setWake(gateway: String, token: String)
    /// `DELETE /v1/wake`.
    case clearWake

    public var action: String {
        switch self {
        case .listen: return "listen"
        case .inbox: return "inbox"
        case .inboxAck: return "inbox-ack"
        case .unregister: return "unregister"
        case .block: return "block"
        case .setWake, .clearWake: return "wake"
        }
    }

    /// Validate the request (`invalid_argument`).
    func validate() throws {
        switch self {
        case .listen(let since):
            guard isStreamCursor(since) || since == "-" else { throw ACEError(.invalidArgument, "since must be '-' or '<ms>-<seq>'") }
        case .inboxAck(let through):
            guard isStreamCursor(through) else { throw ACEError(.invalidArgument, "through must be '<ms>-<seq>'") }
        case .inbox(let since, let limit):
            guard isStreamCursor(since) || since == "-" else { throw ACEError(.invalidArgument, "since must be '-' or '<ms>-<seq>'") }
            guard (1...ACELimits.maxInboxPage).contains(limit) else {
                throw ACEError(.invalidArgument, "limit must be an integer in 1..\(ACELimits.maxInboxPage)")
            }
        case .block(let peer, _, let revision):
            guard isACEId(peer), isWireInt(revision) else { throw ACEError(.invalidArgument, "invalid block") }
        case .setWake(let gateway, let token):
            // Like the audience, loopback HTTP is accepted here; `RelayClient.setWake` applies `allowLoopbackRelays`.
            guard isRelayRoute(gateway, allowLoopback: true), isWakeToken(token) else {
                throw ACEError(.invalidArgument, "wake needs a canonical relay URL gateway and a token")
            }
        case .unregister, .clearWake:
            break
        }
    }

    /// The action payload (02 § Signing actions): `listen` `encodePayload(sinceOrDash)`, `inbox`
    /// `encodePayload(sinceOrDash, decimal(limit))`, `inbox-ack` `encodePayload(through)`, `unregister` empty, `block`
    /// `encodePayload(peer, "block" | "unblock", decimal(revision))`, `wake` `encodePayload(gateway, token)` or empty (clear).
    func payload() -> Data {
        switch self {
        case .listen(let since): return ACESigning.encodePayload(since)
        case .inboxAck(let through): return ACESigning.encodePayload(through)
        case .inbox(let since, let limit): return ACESigning.encodePayload(since, String(limit))
        case .block(let peer, let blocked, let revision): return ACESigning.encodePayload(peer, blocked ? "block" : "unblock", String(revision))
        case .setWake(let gateway, let token): return ACESigning.encodePayload(gateway, token)
        case .unregister, .clearWake: return Data()
        }
    }
}

/// `^[0-9]{1,20}-[0-9]{1,20}$` (a relay stream ID).
func isStreamCursor(_ s: String) -> Bool {
    let parts = s.utf8.split(separator: UInt8(ascii: "-"), omittingEmptySubsequences: false)
    return parts.count == 2 && parts.allSatisfy { (1...20).contains($0.count) && $0.allSatisfy { $0 >= 0x30 && $0 <= 0x39 } }
}

/// `^[A-Za-z0-9_-]{22,512}$` (a wake token, 07 § Wake hints).
func isWakeToken(_ s: String) -> Bool {
    (22...512).contains(s.utf8.count) && s.utf8.allSatisfy { b in
        (b >= 0x30 && b <= 0x39) || (b >= 0x41 && b <= 0x5A) || (b >= 0x61 && b <= 0x7A) || b == 0x5F || b == 0x2D
    }
}

/// `encodePayload(audience, nonce, actionPayload)`: what a header-authenticated request signs (07 § Authentication).
/// `invalid_argument` for a malformed request, an audience that is not a relay URL or a nonce that is not 64 lowercase
/// hex.
package func authPayload(_ request: RelayAuthRequest, audience: String, nonce: String) throws -> Data {
    try request.validate()
    // The audience is a relay's own configured URL: loopback HTTP is its development setup.
    guard isRelayRoute(audience, allowLoopback: true), isSHA256Hex(nonce) else {
        throw ACEError(.invalidArgument, "invalid relay audience or nonce")
    }
    return ACESigning.encodePayload([.string(audience), .string(nonce), .data(request.payload())])
}

/// The six `X-ACE-*` headers of one relay call (07 § Authentication): a delegated signature with ctx = the request's
/// action over `authPayload` at `max(timestamp, ts of the identity's last KEL event)` (the signer's `t`, sent as
/// `X-ACE-Timestamp`), a fresh nonce per call. `invalid_argument` for a malformed request or timestamp;
/// `identity_unavailable` when the identity cannot sign at that time.
public func createAuthHeaders(_ identity: any ACEIdentity, request: RelayAuthRequest, timestamp: Int, audience: String,
                              nonce: String? = nil) throws -> [String: String] {
    guard isWireInt(timestamp) else { throw ACEError(.invalidArgument, "timestamp must be an integer in [0, 2^53-1]") }
    let timestamp = try recordTime(identity, now: timestamp)
    let nonce = nonce ?? randomHex(32)
    let sig = try operationalSign(identity, action: request.action, timestamp: timestamp,
                                  payload: try authPayload(request, audience: audience, nonce: nonce))
    return [
        "X-ACE-Audience": audience,
        "X-ACE-Nonce": nonce,
        "X-ACE-Id": identity.getACEId(),
        "X-ACE-Timestamp": String(timestamp),
        "X-ACE-Seq": String(sig.seq),
        "X-ACE-Signature": sig.value,
    ]
}

/// A `POST /v1/register` body `{aceId, kel, timestamp, audience, signature}` (07 § Registration) signed at
/// `max(timestamp, ts of the identity's last KEL event)` with action `register-request` over `encodePayload(lastHashHex, audience)`. `audience` is the canonical URL of the relay
/// the request is meant for, so no relay can replay it to another (`invalid_argument` when not a relay URL).
public func createRegistrationRequest(identity: any ACEIdentity, timestamp: Int, audience: String) throws -> JSONValue {
    let aud = try normalizeRelayURL(audience)
    let timestamp = try recordTime(identity, now: timestamp)
    let state = try checkUsable(identity, now: timestamp)
    let signature = try operationalSign(identity, action: "register-request", timestamp: timestamp,
                                        payload: ACESigning.encodePayload([.string(state.lastHash), .string(aud)]))
    return ["aceId": .string(identity.getACEId()), "kel": ExportJSON.kelValue(try identity.getKel()),
            "timestamp": .number(Double(timestamp)), "audience": .string(aud), "signature": signature.jsonValue]
}
