//
//  Auth.swift
//  ACE SDK
//
//  Relay request authentication headers (08-relay).
//

import Foundation

/// A `/v1/webhook` call. Its HTTP method is the first field of the `webhook` payload; only `PUT`
/// carries `url` and `secret`.
public enum WebhookMethod: Sendable, Equatable {
    case put(url: String, secret: String)
    case get, delete

    public var verb: String {
        switch self {
        case .put: return "PUT"
        case .get: return "GET"
        case .delete: return "DELETE"
        }
    }
}

/// What an authenticated relay call signs. `since` is `"-"` or `<ms>-<seq>`.
public enum RelayAuthRequest: Sendable, Equatable {
    case listen(since: String)
    case inbox(since: String, limit: Int)
    case unregister
    case intent(need: String, tags: [String], maxPrice: String?, currency: String?, ttl: Int)
    case webhook(WebhookMethod)

    public var action: String {
        switch self {
        case .listen: return "listen"
        case .inbox: return "inbox"
        case .unregister: return "unregister"
        case .intent: return "intent"
        case .webhook: return "webhook"
        }
    }

    /// Validate the request (`invalid_argument`).
    func validate() throws {
        switch self {
        case .listen(let since):
            guard isStreamCursor(since) || since == "-" else { throw ACEError.invalidArgument("since must be '-' or '<ms>-<seq>'") }
        case .inbox(let since, let limit):
            guard isStreamCursor(since) || since == "-" else { throw ACEError.invalidArgument("since must be '-' or '<ms>-<seq>'") }
            guard (1...ACELimits.maxInboxPage).contains(limit) else {
                throw ACEError.invalidArgument("limit must be an integer in 1..\(ACELimits.maxInboxPage)")
            }
        case .unregister:
            break
        case .intent(_, let tags, _, _, let ttl):
            guard !tags.contains(where: { $0.contains(",") }) else { throw ACEError.invalidArgument("tags must be strings without ','") }
            guard isWireInt(ttl) else { throw ACEError.invalidArgument("ttl must be an integer in [0, 2^53-1]") }
        case .webhook(.put(let url, let secret)):
            guard isHTTPSURL(url) else { throw ACEError.invalidArgument("url must match the ACE HTTPS URL grammar") }
            guard isWebhookSecret(secret) else {
                throw ACEError.invalidArgument("secret must be 16..128 characters without control characters")
            }
        case .webhook(.get), .webhook(.delete):
            break
        }
    }

    func payload() -> Data {
        switch self {
        case .listen(let since):
            return ACESigning.encodePayload(since)
        case .inbox(let since, let limit):
            return ACESigning.encodePayload(since, String(limit))
        case .unregister:
            return Data()
        case .intent(let need, let tags, let maxPrice, let currency, let ttl):
            return ACESigning.encodePayload(need, tags.joined(separator: ","), maxPrice ?? "", currency ?? "", String(ttl))
        case .webhook(let method):
            guard case .put(let url, let secret) = method else { return ACESigning.encodePayload(method.verb, "", "") }
            return ACESigning.encodePayload(method.verb, url, secret)
        }
    }

    func signData(aceId: String, timestamp: Int) throws -> Data {
        try validate()
        return try ACESigning.buildSignData(action: action, aceId: aceId, timestamp: timestamp, payload: payload())
    }
}

/// `^[0-9]{1,20}-[0-9]{1,20}$` (a relay stream ID).
func isStreamCursor(_ s: String) -> Bool {
    let parts = s.utf8.split(separator: UInt8(ascii: "-"), omittingEmptySubsequences: false)
    return parts.count == 2 && parts.allSatisfy { (1...20).contains($0.count) && $0.allSatisfy { $0 >= 0x30 && $0 <= 0x39 } }
}

/// A webhook secret: 16..128 characters (Unicode scalars), none in U+0000–U+001F or U+007F.
public func isWebhookSecret(_ s: String) -> Bool {
    let n = s.unicodeScalars.count
    return n >= 16 && n <= 128 && !hasControlCharacter(s)
}

/// Parsed `X-ACE-*` headers.
public struct RelayAuth: Sendable, Equatable {
    public let aceId: String
    public let timestamp: Int
    public let signature: String
}

/// `X-ACE-Id` / `X-ACE-Timestamp` / `X-ACE-Signature` for one relay call.
public func createAuthHeaders(identity: any ACEIdentity, request: RelayAuthRequest, timestamp: Int) throws -> [String: String] {
    guard isWireInt(timestamp) else {
        throw ACEError.invalidArgument("timestamp must be an integer in [0, 2^53-1]")
    }
    let aceId = identity.getACEId()
    let sig = try identity.sign(try request.signData(aceId: aceId, timestamp: timestamp))
    return [
        "X-ACE-Id": aceId,
        "X-ACE-Timestamp": String(timestamp),
        "X-ACE-Signature": encodeSignature(sig, scheme: identity.getSigningScheme()),
    ]
}

/// Case-insensitive lookup of the three headers; `invalid_argument` on missing or malformed values.
/// The signature encoding is checked only by `verifyAuthHeaders`.
public func parseAuthHeaders(_ headers: [String: String]) throws -> RelayAuth {
    var found: [String: String] = [:]
    for (k, v) in headers {
        let key = k.lowercased()
        guard ["x-ace-id", "x-ace-timestamp", "x-ace-signature"].contains(key), found[key] == nil else { continue }
        found[key] = v
    }
    guard let aceId = found["x-ace-id"], isACEId(aceId) else {
        throw ACEError.invalidArgument("X-ACE-Id is missing or not an ACE ID")
    }
    guard let tsText = found["x-ace-timestamp"], let ts = parseTimestampHeader(tsText) else {
        throw ACEError.invalidArgument("X-ACE-Timestamp is missing or malformed")
    }
    guard let sig = found["x-ace-signature"], !sig.isEmpty, sig.count <= 512 else {
        throw ACEError.invalidArgument("X-ACE-Signature is missing")
    }
    return RelayAuth(aceId: aceId, timestamp: ts, signature: sig)
}

/// A timestamp header value: `^(0|[1-9][0-9]{0,15})$` and at most 2^53 − 1.
func parseTimestampHeader(_ s: String) -> Int? {
    guard isTimestampHeader(s), let ts = Int(s), isWireInt(ts) else { return nil }
    return ts
}

/// `^(0|[1-9][0-9]{0,15})$`.
private func isTimestampHeader(_ s: String) -> Bool {
    let u = Array(s.utf8)
    guard !u.isEmpty, u.count <= 16, u.allSatisfy({ $0 >= 0x30 && $0 <= 0x39 }) else { return false }
    return u.count == 1 || u[0] != 0x30
}

/// Stateless: it does not remember accepted signatures. Relays enforce the
/// once-only rule for each (action, aceId, signature) themselves (08-relay).
///
/// Check order: `auth.aceId != aceId` → `invalid_argument`; `|now − ts| > window` →
/// `stale_timestamp`; bad encoding or signature → `invalid_signature`.
public func verifyAuthHeaders(
    _ auth: RelayAuth,
    request: RelayAuthRequest,
    aceId: String,
    scheme: SigningScheme,
    signingPublicKey: Data,
    clock: @Sendable () -> Int = systemClock,
    windowSeconds: Int = ACELimits.timestampWindowSeconds
) throws {
    try checkWindowSeconds(windowSeconds)
    try request.validate()
    guard auth.aceId == aceId else { throw ACEError.invalidArgument("X-ACE-Id does not match the signer") }
    guard isWithinWindow(now: wireNow(clock), ts: auth.timestamp, window: windowSeconds) else {
        throw ACEError(.staleTimestamp, "X-ACE-Timestamp is outside the freshness window")
    }
    let sig = try decodeSignature(auth.signature, scheme: scheme, code: .invalidSignature)
    guard ACESigning.verify(signData: try request.signData(aceId: auth.aceId, timestamp: auth.timestamp),
                            signature: sig, scheme: scheme, publicKey: signingPublicKey) else {
        throw ACEError(.invalidSignature, "X-ACE-Signature does not verify")
    }
}
