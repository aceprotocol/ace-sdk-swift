//
//  Errors.swift
//  ACE SDK
//
//  The single ACE SDK error type. Every SDK-originated failure is an `ACEError`.
//

import Foundation

/// Every SDK-originated failure. `category` is a fixed function of `code`.
///
/// Equality compares `code` only (message, status, relayCode and retryAfterSeconds are
/// diagnostics), so `#expect(throws: ACEError(.replay)) { … }` and `error == ACEError(.replay)`
/// match any `replay` failure.
public struct ACEError: Error, CustomStringConvertible, Sendable, Equatable {

    /// Stable, cross-language error codes (identical strings in the TS and Python SDKs).
    public enum Code: String, Sendable, CaseIterable {
        // permanent (06 § Error codes)
        case invalidArgument = "invalid_argument"
        case invalidPacket = "invalid_packet"
        case unsupportedVersion = "unsupported_version"
        case wrongRecipient = "wrong_recipient"
        case invalidSignature = "invalid_signature"
        case invalidAuthorization = "invalid_authorization"
        case staleTimestamp = "stale_timestamp"
        case stalePeerBinding = "stale_peer_binding"
        case decryptionFailed = "decryption_failed"
        case unknownPrekey = "unknown_prekey"
        case unsupportedSchema = "unsupported_schema"
        case invalidBody = "invalid_body"
        case replayHorizon = "replay_horizon"
        case invalidKel = "invalid_kel"
        case kelConflict = "kel_conflict"
        case unknownPeer = "unknown_peer"
        case notRegistered = "not_registered"
        case notPermitted = "not_permitted"
        case relayRejected = "relay_rejected"
        case blockedAddress = "blocked_address"
        case deliveryRejected = "delivery_rejected"
        case expired = "expired"
        // permanent: commerce profile rule codes (profiles/commerce.md § Check order)
        case transitionNotAllowed = "transition_not_allowed"
        case wrongRole = "wrong_role"
        case wrongParty = "wrong_party"
        case badReference = "bad_reference"
        case limitExceeded = "limit_exceeded"
        /// permanent: a third-party profile rule's own outcome code (`ACEError(rule:)`; the code is `outcomeCode`).
        case ruleRejected = "rule_rejected"
        // transient
        case relayUnavailable = "relay_unavailable"
        case relayProtocolError = "relay_protocol_error"
        case fetchFailed = "fetch_failed"
        // local
        case storageFailed = "storage_failed"
        case identityUnavailable = "identity_unavailable"
        case lockBusy = "lock_busy"
        case receiverCapacity = "receiver_capacity"
        /// local: a profile-ruled message on that thread is still in flight (sent, no `delivered` receipt yet); retry
        /// after its receipt.
        case threadBusy = "thread_busy"

        /// The fixed category of this code.
        public var category: Category {
            switch self {
            case .relayUnavailable, .relayProtocolError, .fetchFailed:
                return .transient
            case .storageFailed, .identityUnavailable, .lockBusy, .receiverCapacity, .threadBusy:
                return .local
            default:
                return .permanent
            }
        }
    }

    /// `permanent`: retrying the same input fails again. `transient`: network / relay.
    /// `local`: storage, key hardware or the host handler; retryable.
    public enum Category: String, Sendable {
        case permanent, transient, local
    }

    public let code: Code
    public let message: String
    /// HTTP status, for relay failures.
    public let status: Int?
    /// The relay's `error` code, when the relay returned one.
    public let relayCode: String?
    /// Seconds from a `Retry-After` header, when present.
    public let retryAfterSeconds: Int?
    /// For `rule_rejected`: the profile rule's own code (outcome-code grammar).
    public let ruleCode: String?

    public init(
        _ code: Code,
        _ message: String = "",
        status: Int? = nil,
        relayCode: String? = nil,
        retryAfterSeconds: Int? = nil
    ) {
        self.code = code
        self.message = message.isEmpty ? code.rawValue : message
        self.status = status
        self.relayCode = relayCode
        self.retryAfterSeconds = retryAfterSeconds
        self.ruleCode = nil
    }

    /// A permanent rejection by a profile rule with its own outcome code (`^[a-z0-9_]{1,64}$`, 06 § Error codes): a
    /// built-in code becomes that code, any other is `rule_rejected` carrying it in `ruleCode`. A code outside the grammar
    /// is `invalid_argument`. The receiver's `rejected` receipt carries `outcomeCode`.
    public init(rule code: String, _ message: String = "") {
        if let known = Code(rawValue: code), known != .ruleRejected {
            self = ACEError(known, message)
            return
        }
        guard isOutcomeCode(code) else {
            self = ACEError(.invalidArgument, "profile rule code must match ^[a-z0-9_]{1,64}$")
            return
        }
        self.code = .ruleRejected
        self.message = message.isEmpty ? code : message
        self.status = nil
        self.relayCode = nil
        self.retryAfterSeconds = nil
        self.ruleCode = code
    }

    /// The code on the wire (a `rejected` receipt): `ruleCode` for `rule_rejected`, else `code`.
    public var outcomeCode: String { ruleCode ?? code.rawValue }

    public var category: Category { code.category }

    /// `category != .permanent`.
    public var isTransient: Bool { category != .permanent }

    /// Same `code` (and `ruleCode` for `rule_rejected`); the other fields are ignored.
    public static func == (lhs: ACEError, rhs: ACEError) -> Bool {
        lhs.code == rhs.code && (lhs.code != .ruleRejected || lhs.ruleCode == rhs.ruleCode)
    }

    public var description: String {
        message == outcomeCode ? outcomeCode : "\(outcomeCode): \(message)"
    }
}
