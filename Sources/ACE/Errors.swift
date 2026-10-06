//
//  Errors.swift
//  ACE SDK
//
//  The single ACE SDK error type. Every SDK-originated failure is an `ACEError`.
//

import Foundation

/// Every SDK-originated failure. `category` is a fixed function of `code`.
public struct ACEError: Error, CustomStringConvertible, Sendable, Equatable {

    /// Stable, cross-language error codes (identical strings in the TS and Python SDKs).
    public enum Code: String, Sendable, CaseIterable {
        // permanent
        case invalidArgument = "invalid_argument"
        case invalidEnvelope = "invalid_envelope"
        case unsupportedVersion = "unsupported_version"
        case wrongRecipient = "wrong_recipient"
        case invalidSignature = "invalid_signature"
        case invalidAuthorization = "invalid_authorization"
        case schemeMismatch = "scheme_mismatch"
        case staleTimestamp = "stale_timestamp"
        case replay = "replay"
        case decryptionFailed = "decryption_failed"
        case invalidBody = "invalid_body"
        case transitionNotAllowed = "transition_not_allowed"
        case wrongRole = "wrong_role"
        case wrongParty = "wrong_party"
        case badReference = "bad_reference"
        case limitExceeded = "limit_exceeded"
        case invalidKey = "invalid_key"
        case invalidRegistration = "invalid_registration"
        case invalidProfile = "invalid_profile"
        case invalidPeer = "invalid_peer"
        case stalePeerBinding = "stale_peer_binding"
        case unknownPeer = "unknown_peer"
        case notRegistered = "not_registered"
        case relayRejected = "relay_rejected"
        case envelopeExpired = "envelope_expired"
        case pendingSendConflict = "pending_send_conflict"
        case blockedAddress = "blocked_address"
        // transient
        case relayUnavailable = "relay_unavailable"
        case relayProtocolError = "relay_protocol_error"
        case fetchFailed = "fetch_failed"
        // local
        case storageFailed = "storage_failed"
        case identityUnavailable = "identity_unavailable"
        case handlerFailed = "handler_failed"
        case receiverBusy = "receiver_busy"

        /// The fixed category of this code.
        public var category: Category {
            switch self {
            case .relayUnavailable, .relayProtocolError, .fetchFailed:
                return .transient
            case .storageFailed, .identityUnavailable, .handlerFailed, .receiverBusy:
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
    /// HTTP status, for relay / fetch failures.
    public let status: Int?
    /// The relay's `error` code, when the relay returned one.
    public let relayCode: String?
    /// Seconds from a `Retry-After` header, when present.
    public let retryAfterSeconds: Int?

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
    }

    public var category: Category { code.category }

    /// `category != .permanent`.
    public var isTransient: Bool { category != .permanent }

    public var description: String {
        message == code.rawValue ? code.rawValue : "\(code.rawValue): \(message)"
    }
}

extension ACEError {
    static func invalidArgument(_ message: String) -> ACEError { ACEError(.invalidArgument, message) }
}
