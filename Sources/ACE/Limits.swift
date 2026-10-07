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
    /// Non-terminal economic threads one peer may hold open with this agent (04). A
    /// message that would open one more is `limit_exceeded`.
    public static let maxOpenThreadsPerPeer = 1000

    public static let kemSeedSize = 32
    public static let kemPublicKeySize = 1216
    public static let kemCiphertextSize = 1120
    public static let defaultReplayCapacity = 100000
}

/// 2^53 − 1: the largest wire integer.
let maxSafeInteger = 9_007_199_254_740_991

/// An integer in [0, 2^53-1], the range every wire integer must fall in.
func isWireInt(_ v: Int) -> Bool { (0...maxSafeInteger).contains(v) }

/// `|now − ts| <= window`, overflow-safe: a negative window, or a gap too large for `Int`,
/// is outside the window (never traps, unlike `abs(now - ts)` on extreme clocks).
func isWithinWindow(now: Int, ts: Int, window: Int) -> Bool {
    guard window >= 0 else { return false }
    let (delta, overflow) = now.subtractingReportingOverflow(ts)
    return !overflow && delta.magnitude <= UInt(window)
}

/// `a + b`, saturating to `Int.max` / `Int.min` instead of trapping (clock arithmetic).
func clampedAdd(_ a: Int, _ b: Int) -> Int {
    let (r, overflow) = a.addingReportingOverflow(b)
    return overflow ? (b > 0 ? .max : .min) : r
}

/// `a − b`, saturating to `Int.max` / `Int.min` instead of trapping (clock arithmetic).
func clampedSub(_ a: Int, _ b: Int) -> Int {
    let (r, overflow) = a.subtractingReportingOverflow(b)
    return overflow ? (b < 0 ? .max : .min) : r
}

/// The default clock: integer Unix seconds.
@usableFromInline @Sendable func systemClock() -> Int { Int(Date().timeIntervalSince1970) }
