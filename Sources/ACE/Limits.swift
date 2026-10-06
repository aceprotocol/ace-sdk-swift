//
//  Limits.swift
//  ACE SDK
//
//  Normative size limits (04-messages "Size Limits") and SDK constants.
//

import Foundation

public enum ACELimits {
    /// UTF-8 body JSON before encryption.
    public static let maxPlaintextBytes = 65508
    /// `nonce ‖ ct ‖ tag` (decoded `encryption.payload`).
    public static let maxPayloadBytes = 65536
    /// Serialized envelope; relay request body limit; SSE data limit.
    public static let maxEnvelopeBytes = 131072
    /// Top-level object = depth 0.
    public static let maxJSONDepth = 32
    /// Thread ID length in Unicode code points.
    public static let maxThreadIdLength = 256
    /// Future bound and relay freshness.
    public static let timestampWindowSeconds = 300
    /// Default receiver floor = now − 7 days; relay message TTL MUST be ≤ this.
    public static let offlineWindowSeconds = 604800
    public static let maxRegistrationFileBytes = 1048576
    /// `/v1/inbox` `limit` maximum.
    public static let maxInboxPage = 100

    public static let kemSeedSize = 32
    public static let kemPublicKeySize = 1216
    public static let kemCiphertextSize = 1120
    public static let defaultReplayCapacity = 100000
}

/// 2^53 − 1: the largest wire integer.
let maxSafeInteger = 9_007_199_254_740_991

/// The default clock: integer Unix seconds.
@usableFromInline @Sendable func systemClock() -> Int { Int(Date().timeIntervalSince1970) }
