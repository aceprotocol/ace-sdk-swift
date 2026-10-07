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
    /// Direct-delivery request body (`{"message": envelope}`): `maxEnvelopeBytes + 1024`
    /// (08 § Direct Delivery).
    public static let maxDirectBodyBytes = maxEnvelopeBytes + 1024
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
    /// The largest value an `ACEStore` accepts (64 MiB), so nothing is written that cannot be read back.
    public static let maxStoreValueBytes = 64 << 20
    /// Default `ACEStore` lock timeout.
    public static let defaultLockTimeoutSeconds: TimeInterval = 10
}

/// 2^53 − 1: the largest wire integer.
let maxSafeInteger = 9_007_199_254_740_991

/// An integer in [0, 2^53-1], the range every wire integer must fall in.
func isWireInt(_ v: Int) -> Bool { (0...maxSafeInteger).contains(v) }

/// `|now − ts| <= window`, overflow-safe for any `ts`; a negative window admits nothing.
func isWithinWindow(now: Int, ts: Int, window: Int) -> Bool {
    guard window >= 0 else { return false }
    let (delta, overflow) = now.subtractingReportingOverflow(ts)
    return !overflow && delta.magnitude <= UInt(window)
}

/// The clock's reading clamped to [0, 2^53 − 1]. Every injected clock is read through this
/// (or `wireClock`), so `now` ± a window or a stored wire timestamp cannot overflow.
func wireNow(_ clock: () -> Int) -> Int { min(max(clock(), 0), maxSafeInteger) }

/// `clock` wrapped by `wireNow`, for types that store the clock.
func wireClock(_ clock: @escaping @Sendable () -> Int) -> @Sendable () -> Int { { wireNow(clock) } }

/// `max(0, now − window)`: the oldest timestamp still inside the window (`window` ≥ 0).
func windowFloor(now: Int, window: Int = ACELimits.timestampWindowSeconds) -> Int { max(0, now - window) }

/// `windowSeconds` must be a wire integer (`invalid_argument`).
func checkWindowSeconds(_ windowSeconds: Int) throws {
    guard isWireInt(windowSeconds) else { throw ACEError.invalidArgument("windowSeconds must be an integer in [0, 2^53-1]") }
}

/// The default clock: integer Unix seconds.
@usableFromInline @Sendable func systemClock() -> Int { Int(Date().timeIntervalSince1970) }
