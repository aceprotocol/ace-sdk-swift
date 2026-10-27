//
//  Limits.swift
//  ACE SDK
//
//  The normative constants (02 § Constants) and SDK constants.
//

import Foundation

public enum ACELimits {
    // 02 § Constants (checked against protocol-contract.json by ace-spec/scripts/check-sdk-artifacts.py).
    public static let timestampWindowSeconds = 300
    public static let offlineWindowSeconds = 604_800
    /// Canonical private content `{type, schemaDigest, threadId?, body, prekey, admission?}` (1 MiB + 128 KiB).
    public static let maxPlaintextBytes = 1_179_648
    public static let maxPacketBytes = 2_097_152
    /// `POST /v1/send` body: a packet plus room for a permit.
    public static let maxSendBodyBytes = maxPacketBytes + 65_536
    public static let maxPublishedAgentBytes = 1_048_576
    /// Top-level object = depth 0.
    public static let maxJSONDepth = 32
    public static let maxTypeBytes = 256
    /// Thread ID length in Unicode code points.
    public static let maxThreadIdLength = 256
    public static let maxKelEvents = 256
    /// Longest `dlg` signing-key lifetime, `notAfter - ts` (366 days, 01 rule 4).
    public static let maxSigningKeyLifetime = 31_622_400
    /// Longest descriptor lifetime (`expiresAt - issuedAt`, 7 days).
    public static let maxDescriptorSeconds = 604_800
    public static let maxPermitSeconds = 2_592_000
    /// A receipt carries a fresh permit when the peer's permit has less than this left (15 days).
    public static let permitRenewalSeconds = 1_296_000
    /// Superseded prekeys a vault keeps.
    public static let maxPrekeys = 16
    public static let maxExtBytes = 32_768
    /// Canonical JSON of a card record (04 § Card record).
    public static let maxCardRecordBytes = 16_384
    /// Entries of a card record `pay`.
    public static let maxPayAccounts = 8
    public static let maxNoteBytes = 512
    /// Maximum and default `limit` of inbox and directory pages.
    public static let maxInboxPage = 100
    public static let maxPageBytes = 8_388_608
    public static let maxManifestBytes = 65_536
    public static let maxPendingContactRequests = 16
    /// Lifetime of a held incoming contact request (an outgoing `pending` entry lives `offlineWindowSeconds`).
    public static let contactRequestTTLSeconds = 86_400
    /// Bound on a stranger's contact `source` KEL, checked before any signature (05 § Receiver admission).
    public static let maxStrangerKelEvents = 32
    /// Relay stranger allowance (07 § Send), relay-side: the client only names them.
    public static let strangerAllowance = 16
    public static let strangerNetworkAllowance = 2
    public static let minBlockCap = 256
    /// Minimum interval between pin refreshes of one sender in the receive pipeline (06 step 3).
    public static let pinRefreshIntervalSeconds = 30
    /// Fetches of one inbox entry without a final disposition before it is quarantined.
    public static let maxFetchAttempts = 3

    // SDK constants.
    /// The reference prekey rotation period.
    public static let prekeyRotationSeconds = 86_400
    /// The reference descriptor lifetime (the default `lifetime`; at most `maxDescriptorSeconds`).
    public static let defaultDescriptorSeconds = 86_400
    public static let kemSeedSize = 32
    public static let kemPublicKeySize = 1216
    public static let kemCiphertextSize = 1120
    public static let defaultReplayCapacity = 100_000
    /// The largest value an `ACEStore` accepts (64 MiB), so nothing is written that cannot be read back.
    public static let maxStoreValueBytes = 64 << 20
    /// Default `ACEStore` lock timeout.
    public static let defaultLockTimeoutSeconds: TimeInterval = 10
}

/// 2^53 − 1: the largest wire integer.
package let maxSafeInteger = 9_007_199_254_740_991

/// An integer in [0, 2^53-1], the range every wire integer must fall in.
package func isWireInt(_ v: Int) -> Bool { (0...maxSafeInteger).contains(v) }

/// Unix seconds from `clock` (injected for tests) or the system clock; a reading outside [0, 2^53 − 1] is
/// `invalid_argument`.
package func unixNow(_ clock: (() -> Int)?) throws -> Int {
    try unixNow(clock ?? systemClock)
}

/// `unixNow` of a given clock. No reading is ever clamped.
package func unixNow(_ clock: () -> Int) throws -> Int {
    let value = clock()
    guard isWireInt(value) else { throw ACEError(.invalidArgument, "clock must return integer Unix seconds") }
    return value
}

/// The default clock: integer Unix seconds.
@Sendable public func systemClock() -> Int { Int(Date().timeIntervalSince1970) }
