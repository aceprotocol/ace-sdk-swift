//
//  Delegation.swift
//  ACE SDK
//
//  The optional `ace:delegation:1` profile (profiles/delegation.md): credentials by which an issuer declares that a
//  subject acts on its behalf, the descriptor extension that publishes them and the message that hands one over.
//
//  A credential grants no execution, payment or communication right; the issuer revokes it by not renewing. Descriptor
//  verification checks the extension's shape only: a client that needs to know whether `subject` acts for `issuer` pins
//  the issuer (`NetworkClient.verifyDelegation`) and verifies the credential under that pin (`verifyDelegationCredential`).
//  A `NetworkClient` with `ProfileManifest.delegation` installed runs `delegationRules` itself.
//

import Foundation

public let delegationProfileId = "ace:delegation:1"
/// The hand-over message type; also the action credentials are signed with (02 § Signing actions).
public let delegationType = "ace:delegation:1"
/// Credentials in one descriptor extension.
public let maxDelegationCredentials = 4
/// Longest credential lifetime, `expiresAt - issuedAt` (7 days).
public let maxDelegationCredentialLifetime = 604_800

private func unauthorized(_ message: String) -> ACEError { ACEError(.invalidAuthorization, message) }

/// A credential `{issuer, subject, issuedAt, expiresAt, signature}`: `issuer` declares that `subject` acts on its behalf.
public struct DelegationCredential: Sendable, Equatable {
    public let issuer: String
    public let subject: String
    public let issuedAt: Int
    public let expiresAt: Int
    public let signature: SignatureEnvelope

    public var jsonValue: JSONValue {
        ["issuer": .string(issuer), "subject": .string(subject), "issuedAt": .number(Double(issuedAt)),
         "expiresAt": .number(Double(expiresAt)), "signature": signature.jsonValue]
    }

    /// The closed credential and its field grammar at `now`: ACE IDs with `issuer != subject`, `issuedAt <= now + 300`,
    /// `issuedAt < expiresAt <= issuedAt + 7 days`, a delegated signature's shape. No expiry, no signature check
    /// (`invalid_authorization`).
    package init(_ value: JSONValue, now: Int) throws {
        guard let o = value.objectValue, Set(o.keys) == ["issuer", "subject", "issuedAt", "expiresAt", "signature"],
              let issuer = o["issuer"]?.stringValue, isACEId(issuer), let subject = o["subject"]?.stringValue, isACEId(subject),
              issuer != subject else {
            throw unauthorized("credential must be {issuer, subject, issuedAt, expiresAt, signature}")
        }
        let (issued, expires) = try checkLifetime(o, now: now, maximum: maxDelegationCredentialLifetime, what: "credential", requireLive: false)
        guard let signature = SignatureEnvelope(operational: o["signature"]) else {
            throw unauthorized("credential signature must be {scheme: ml-dsa-65, seq, value}")
        }
        self.issuer = issuer
        self.subject = subject
        self.issuedAt = issued
        self.expiresAt = expires
        self.signature = signature
    }
}

/// A credential from `issuer` declaring that `subject` acts on its behalf, issued at `max(now, ts of the issuer's last KEL
/// event)` for `ttl` seconds (default and maximum 7 days; `invalid_argument` outside that).
public func createDelegationCredential(issuer: any ACEIdentity, subject: String, now: Int? = nil, ttl: Int? = nil) throws -> DelegationCredential {
    guard isACEId(subject), subject != issuer.getACEId() else { throw ACEError(.invalidArgument, "subject must be another ACE ID") }
    let lifetime = ttl ?? maxDelegationCredentialLifetime
    guard (1...maxDelegationCredentialLifetime).contains(lifetime) else {
        throw ACEError(.invalidArgument, "ttl must be 1...\(maxDelegationCredentialLifetime) seconds")
    }
    let at = try recordTime(issuer, now: now)
    let signed = try signDocument(issuer, action: delegationType, claims: [
        "issuer": .string(issuer.getACEId()), "subject": .string(subject),
        "issuedAt": .number(Double(at)), "expiresAt": .number(Double(at + lifetime)),
    ])
    return try DelegationCredential(.object(signed), now: at)
}

/// Descriptor `ext["ace:delegation:1"]`: the closed `{credentials}` with 1–4 credentials of distinct issuers, each naming
/// `subject` (the descriptor's `aceId`). Shape only: no expiry and no signature (`invalid_authorization`).
public func validateDelegationExt(_ value: JSONValue, subject: String, now: Int) throws -> [DelegationCredential] {
    guard let o = value.objectValue, Set(o.keys) == ["credentials"] else { throw unauthorized("delegation ext must be {credentials}") }
    guard let items = o["credentials"]?.arrayValue, (1...maxDelegationCredentials).contains(items.count) else {
        throw unauthorized("delegation ext must hold 1-\(maxDelegationCredentials) credentials")
    }
    let credentials = try items.map { try DelegationCredential($0, now: now) }
    guard credentials.allSatisfy({ $0.subject == subject }) else { throw unauthorized("a delegation credential must name the descriptor's aceId") }
    guard Set(credentials.map(\.issuer)).count == credentials.count else { throw unauthorized("delegation credential issuers must be distinct") }
    return credentials
}

/// `value` if it is a live credential of `issuer` (the issuer's pinned KEL state): its shape, `now < expiresAt` and an
/// operational signature of `issuer` with action `ace:delegation:1`. `stale_peer_binding` from the signature check passes
/// through; any other failure is `invalid_authorization`.
public func verifyDelegationCredential(_ value: JSONValue, issuer: KelState, now: Int) throws -> DelegationCredential {
    let c = try DelegationCredential(value, now: now)
    guard c.issuer == issuer.aceId else { throw unauthorized("the credential names another issuer") }
    guard now < c.expiresAt else { throw unauthorized("credential expired") }
    try verifyDocument(value.objectValue!, state: issuer, action: delegationType, now: now)
    return c
}

/// `ProfileRules` for the `ace:delegation:1` message: the issuer hands a credential to its subject. `check` requires the
/// credential to be the sender's, about the recipient and live (on receive also signed under the sender's pin, read from
/// `peers`); any failure is `invalid_body`. `commit` changes no state: the application stores the credential and
/// publishes it in its `ext`.
public struct DelegationRules: ProfileRules {
    public let peers: PeerStore
    public let localAceId: String
    public var types: Set<String> { [delegationType] }

    public func check(_ event: ProfileEvent, body: [String: JSONValue]) throws {
        do {
            let now = try peers.clockNow()
            let raw = body["credential"] ?? .null
            let c = try DelegationCredential(raw, now: now)
            guard c.issuer == event.from, c.subject == event.to else {
                throw unauthorized("the credential must be from the sender about the recipient")
            }
            guard now < c.expiresAt else { throw unauthorized("credential expired") }
            if event.direction == .receive {
                guard let pinned = try peers.pinnedState(event.from) else { throw unauthorized("the sender is not pinned") }
                _ = try verifyDelegationCredential(raw, issuer: pinned, now: now)
            }
        } catch let e as ACEError where e.code != .storageFailed {
            throw ACEError(.invalidBody, "delegation: \(e.message)")
        }
    }

    public func commit(_ event: ProfileEvent, body: [String: JSONValue]) throws {}
}

/// The `ace:delegation:1` message rule; `peers` supplies the sender's pin and the clock.
public func delegationRules(peers: PeerStore, localAceId: String) -> DelegationRules {
    DelegationRules(peers: peers, localAceId: localAceId)
}
