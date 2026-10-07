//
//  Webhook.swift
//  ACE SDK
//
//  Webhook notification signing and verification (08-relay § Webhooks).
//

import CryptoKit
import Foundation

/// A verified webhook notification: a wake-up hint that `aceId` has a message at `streamId`.
public struct WebhookNotification: Sendable, Equatable {
    public let aceId: String
    public let streamId: String
}

/// `sha256=<lowercase hex HMAC-SHA256(secret, decimal(timestamp) || "." || body)>`.
/// Relay-side; internal here (the agent only verifies).
func signWebhookNotification(secret: String, timestamp: Int, body: Data) -> String {
    var mac = HMAC<SHA256>(key: SymmetricKey(data: Data(secret.utf8)))
    mac.update(data: Data("\(timestamp).".utf8))
    mac.update(data: body)
    return "sha256=" + hexEncode(Data(mac.finalize()))
}

/// Verify `X-ACE-Webhook-Timestamp` / `X-ACE-Webhook-Signature` over the raw `body`.
///
/// Check order (mirrors the TS SDK): timestamp malformed or above 2^53 − 1 →
/// `invalid_argument`; signature not shaped `sha256=<64 lowercase hex>` →
/// `invalid_signature`; `windowSeconds` outside [0, 2^53 − 1] → `invalid_argument`;
/// `|now − ts| > window` → `stale_timestamp`; HMAC (constant-time) → `invalid_signature`;
/// body not `{"event":"message","aceId","streamId"}` → `invalid_argument`.
public func verifyWebhookNotification(
    secret: String,
    timestamp: String,
    signature: String,
    body: Data,
    clock: @Sendable () -> Int = systemClock,
    windowSeconds: Int = ACELimits.timestampWindowSeconds
) throws -> WebhookNotification {
    guard let ts = parseTimestampHeader(timestamp) else {
        throw ACEError.invalidArgument("X-ACE-Webhook-Timestamp is malformed")
    }
    guard isWebhookSignature(signature) else {
        throw ACEError(.invalidSignature, "X-ACE-Webhook-Signature is malformed")
    }
    try checkWindowSeconds(windowSeconds)
    guard isWithinWindow(now: wireNow(clock), ts: ts, window: windowSeconds) else {
        throw ACEError(.staleTimestamp, "X-ACE-Webhook-Timestamp is outside the freshness window")
    }
    let expected = signWebhookNotification(secret: secret, timestamp: ts, body: body)
    guard constantTimeEqual(Data(expected.utf8), Data(signature.utf8)) else {
        throw ACEError(.invalidSignature, "X-ACE-Webhook-Signature does not verify")
    }
    guard let v = try? JSONParser.parse(body),
          v["event"]?.stringValue == "message",
          let aceId = v["aceId"]?.stringValue, isACEId(aceId),
          let streamId = v["streamId"]?.stringValue, isStreamCursor(streamId) else {
        throw ACEError.invalidArgument("notification body must be {event: message, aceId, streamId}")
    }
    return WebhookNotification(aceId: aceId, streamId: streamId)
}

/// `^sha256=[0-9a-f]{64}$`.
private func isWebhookSignature(_ s: String) -> Bool {
    let u = Array(s.utf8)
    guard u.count == 71, u.starts(with: Array("sha256=".utf8)) else { return false }
    return u[7...].allSatisfy(isLowerHex)
}
