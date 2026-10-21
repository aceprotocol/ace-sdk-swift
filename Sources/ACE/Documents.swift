//
//  Documents.swift
//  ACE SDK
//
//  Signed documents: the descriptor (`PublishedAgent = {kel, descriptor}`), the card record (`CardBundle = {kel, card}`),
//  the delegation credential, the delivery permit, and the ERC-8004 binding helper. Every document signature is an operational signature over
//  `M(issuer, issuedAt, seq, canonical(claims))` (claims = the document without `signature`). None of them grants
//  execution, payment or shell rights.
//

import Foundation

private func unauthorized(_ message: String) -> ACEError { ACEError(.invalidAuthorization, message) }

/// Exactly the members `required` plus any of `optional`.
private func hasMembers(_ o: [String: JSONValue], _ required: Set<String>, optional: Set<String> = []) -> Bool {
    let keys = Set(o.keys)
    return required.isSubset(of: keys) && keys.isSubset(of: required.union(optional))
}

/// `claims` plus `signature`, signed by `identity` under `action` at `claims.issuedAt`.
package func signDocument(_ identity: any ACEIdentity, action: String, claims: [String: JSONValue]) throws -> [String: JSONValue] {
    guard let issuedAt = claims["issuedAt"]?.wireInt else { throw ACEError(.invalidArgument, "issuedAt must be a wire integer") }
    var doc = claims
    doc["signature"] = try operationalSign(identity, action: action, timestamp: issuedAt, payload: try JSONValue.object(claims).jsonData()).jsonValue
    return doc
}

/// The document signature by `state`'s identity at `now` (01 § Operational signatures): `stale_peer_binding` for a
/// superseded or expired signing delegation or a signer not usable at `now`, `invalid_authorization` for any other failure.
package func verifyDocument(_ o: [String: JSONValue], state: KelState, action: String, now: Int) throws {
    guard let sig = SignatureEnvelope(operational: o["signature"]), let issuedAt = o["issuedAt"]?.wireInt else {
        throw unauthorized("\(action) signature must be {scheme: ml-dsa-65, seq, value}")
    }
    do {
        try verifyOperational(sig, state: state, action: action, timestamp: issuedAt, payload: try documentClaims(o), now: now)
    } catch let e as ACEError where e.code != .stalePeerBinding {
        throw unauthorized("\(action): \(e.message)")
    }
}

/// The `issuedAt` of a descriptor or card record signed at `now`: never before the last event of the signer's log, so
/// the record is never older than the `dlg` that delegated its key (a clock behind that event still signs a valid record).
private func recordTime(_ identity: any ACEIdentity, now: Int?) throws -> Int {
    let at = try identityNow(now)
    return max(at, try identity.getKel().last.flatMap { wireInt($0["ts"]) } ?? at)
}

/// A descriptor or card record is signed no earlier than the `dlg` its `signature.seq` names (04 § Verification step 3):
/// an earlier `issuedAt` is `stale_peer_binding`. A recovery that forks the log can delegate the same key at the same
/// `seq`; a record signed on the abandoned branch is older than the new `dlg` and never verifies under the new log.
private func checkSignedAfterDelegation(_ o: [String: JSONValue], state: KelState) throws {
    guard let seq = o["signature"]?["seq"]?.wireInt, seq == state.signing?.seq, state.events.indices.contains(seq),
          let issuedAt = o["issuedAt"]?.wireInt, let dlgTs = wireInt(state.events[seq]["ts"]) else { return }
    guard issuedAt >= dlgTs else { throw ACEError(.stalePeerBinding, "signed before its signing delegation") }
}

/// `issuedAt <= now + 300`, `issuedAt < expiresAt`, `now < expiresAt` (unless `!requireLive`), `expiresAt - issuedAt <=
/// maximum`. Returns `(issuedAt, expiresAt)`.
@discardableResult
private func checkLifetime(_ o: [String: JSONValue], now: Int, maximum: Int, what: String, requireLive: Bool = true) throws -> (Int, Int) {
    guard let issued = o["issuedAt"]?.wireInt, let expires = o["expiresAt"]?.wireInt else { throw unauthorized("\(what) lifetime must be wire integers") }
    guard issued <= now + ACELimits.timestampWindowSeconds, issued < expires, !requireLive || now < expires, expires - issued <= maximum else {
        throw unauthorized("\(what) is not within its lifetime")
    }
    return (issued, expires)
}

private func kelEvents(_ v: JSONValue?) throws -> [KelEvent] {
    guard let items = v?.arrayValue else { throw unauthorized("kel must be an array") }
    return try items.map {
        guard let o = $0.objectValue else { throw unauthorized("kel must hold event objects") }
        return o
    }
}

private func verifiedKel(_ v: JSONValue?, now: Int) throws -> KelState {
    do { return try ACEKel.verify(try kelEvents(v), now: now) } catch let e as ACEError where e.code != .invalidAuthorization {
        throw unauthorized("kel: \(e.message)")
    }
}

// MARK: - Card

private let tagRegex = try! NSRegularExpression(pattern: "^[a-z0-9-]{1,32}$")

/// `card` (a card record's member): self-asserted presentation metadata. The reserved tag `hosted` says a custodian holds the keys.
public struct AgentCard: Sendable, Equatable {
    /// 1–64 characters without control characters.
    public var name: String?
    /// 0–256 characters without control characters.
    public var description: String?
    /// An ACE HTTPS URL.
    public var image: String?
    /// At most 10 distinct tags matching `^[a-z0-9-]{1,32}$`.
    public var tags: [String]?

    public static let hostedTag = "hosted"

    public init(name: String? = nil, description: String? = nil, image: String? = nil, tags: [String]? = nil) {
        self.name = name
        self.description = description
        self.image = image
        self.tags = tags
    }

    public var jsonValue: JSONValue {
        var o: [String: JSONValue] = [:]
        if let name { o["name"] = .string(name) }
        if let description { o["description"] = .string(description) }
        if let image { o["image"] = .string(image) }
        if let tags { o["tags"] = .array(tags.map { .string($0) }) }
        return .object(o)
    }

    /// The closed card rules (`invalid_authorization`).
    package init(_ v: JSONValue?) throws {
        guard let o = v?.objectValue, hasMembers(o, [], optional: ["name", "description", "image", "tags"]) else {
            throw unauthorized("card must be {name?, description?, image?, tags?}")
        }
        func text(_ key: String, _ lo: Int, _ hi: Int) throws -> String? {
            guard let v = o[key] else { return nil }
            guard let s = v.stringValue, (lo...hi).contains(s.unicodeScalars.count), !hasControlCharacter(s) else {
                throw unauthorized("card.\(key) must be \(lo)-\(hi) characters without control characters")
            }
            return s
        }
        name = try text("name", 1, 64)
        description = try text("description", 0, 256)
        image = try text("image", 1, 2048)
        if let image, !isHTTPSURL(image) { throw unauthorized("card.image must be an HTTPS URL") }
        if let raw = o["tags"] {
            guard let list = raw.arrayValue, list.count <= 10, Set(list).count == list.count else {
                throw unauthorized("card.tags must hold at most 10 distinct tags")
            }
            tags = try list.map { t in
                guard let s = t.stringValue, regexFullMatch(tagRegex, s) else { throw unauthorized("card.tags items must match ^[a-z0-9-]{1,32}$") }
                return s
            }
        } else {
            tags = nil
        }
    }
}

// MARK: - Relay URLs and handles

/// The handle grammar `[a-z][a-z0-9_-]{2,31}`.
public func isHandle(_ value: String) -> Bool {
    let u = Array(value.utf8)
    guard (3...32).contains(u.count), (0x61...0x7A).contains(u[0]) else { return false }
    return u.dropFirst().allSatisfy { (0x61...0x7A).contains($0) || (0x30...0x39).contains($0) || $0 == 0x5F || $0 == 0x2D }
}

/// A canonical relay URL (02 § Relay URLs): HTTPS, at most 2048 characters, equal to its normalization, host in the ACE
/// HTTPS host grammar. `allowLoopback` (explicit development configuration only) also admits `http` on a loopback host.
public func isRelayRoute(_ value: String, allowLoopback: Bool = false) -> Bool {
    guard isCanonicalRelayURL(value) else { return false }
    if value.hasPrefix("https://") { return isHTTPSURL(value) }
    guard allowLoopback else { return false }
    let loopback = ["http://localhost", "http://127.0.0.1", "http://[::1]"]
    return loopback.contains { value == $0 || value.hasPrefix($0 + ":") || value.hasPrefix($0 + "/") }
}

// MARK: - ERC-8004

/// `{agentRegistry, agentId}`: a descriptor's pointer to an on-chain ERC-8004 agent. `agentRegistry` is CAIP-10; `agentId`
/// is the registry's chain-native identifier: for an `eip155` registry a decimal string of at most 78 digits, for any
/// other CAIP-2 namespace 1–128 characters of `[A-Za-z0-9]` (e.g. a Solana base58 address). The binding holds only when
/// the agent's registration file also points back (`verifyErc8004Registration`); reading the chain is the host's job.
public struct ERC8004Binding: Sendable, Hashable {
    public let agentRegistry: String
    public let agentId: String

    /// `invalid_argument` for a malformed registry or ID.
    public init(agentRegistry: String, agentId: String) throws {
        guard isCAIP10(agentRegistry) else { throw ACEError(.invalidArgument, "agentRegistry must be CAIP-10") }
        let u = Array(agentId.utf8)
        if agentRegistry.split(separator: ":", maxSplits: 1).first == "eip155" {
            guard (1...78).contains(u.count), u.allSatisfy({ (0x30...0x39).contains($0) }), u.count == 1 || u[0] != 0x30 else {
                throw ACEError(.invalidArgument, "agentId must be a decimal string of at most 78 digits for an eip155 registry")
            }
        } else {
            let alnum: (UInt8) -> Bool = { (0x30...0x39).contains($0) || (0x41...0x5A).contains($0) || (0x61...0x7A).contains($0) }
            guard (1...128).contains(u.count), u.allSatisfy(alnum) else {
                throw ACEError(.invalidArgument, "agentId must be 1-128 characters of [A-Za-z0-9]")
            }
        }
        self.agentRegistry = agentRegistry
        self.agentId = agentId
    }

    public var jsonValue: JSONValue { ["agentRegistry": .string(agentRegistry), "agentId": .string(agentId)] }
}

/// True when the ERC-8004 registration file (the agent's tokenURI document) is a JSON object whose `services` array lists a
/// service `{"name": "ACE", "endpoint": aceId}`. Pure; malformed input is false.
public func verifyErc8004Registration(_ registrationJson: Data, aceId: String) -> Bool {
    guard isACEId(aceId), let v = try? JSONValue(json: registrationJson) else { return false }
    return verifyErc8004Registration(v, aceId: aceId)
}

/// `verifyErc8004Registration` of a parsed registration file.
public func verifyErc8004Registration(_ registration: JSONValue, aceId: String) -> Bool {
    guard isACEId(aceId) else { return false }
    return registration["services"]?.arrayValue?.contains { $0["name"] == "ACE" && $0["endpoint"]?.stringValue == aceId } ?? false
}

// MARK: - Delegation credential

/// A verified delegation edge: `issuer` (controller) declares that `subject` (delegate) acts on its behalf. It grants no
/// execution, payment or communication right; the issuer revokes it by not renewing.
public struct VerifiedDelegation: Sendable, Equatable {
    public let issuer: String
    public let subject: String
    public let issuedAt: Int
    public let expiresAt: Int
    /// The issuer's verified KEL.
    public let issuerState: KelState
    /// `{kel, credential}` as carried in the descriptor.
    public let entry: JSONValue
}

/// `{issuer, subject, issuedAt, expiresAt, signature}` signed by `issuer` (action `delegation`), valid for
/// `lifetime` seconds (at most 7 days). Returns the descriptor entry `{kel, credential}`.
public func createDelegation(issuer: any ACEIdentity, subject: String, now: Int? = nil,
                             lifetime: Int = ACELimits.maxCredentialSeconds) throws -> JSONValue {
    guard isACEId(subject), subject != issuer.getACEId() else { throw ACEError(.invalidArgument, "subject must be another ACE ID") }
    let at = try identityNow(now)
    guard (1...ACELimits.maxCredentialSeconds).contains(lifetime) else {
        throw ACEError(.invalidArgument, "lifetime must be 1...\(ACELimits.maxCredentialSeconds) seconds")
    }
    let credential = try signDocument(issuer, action: "delegation", claims: [
        "issuer": .string(issuer.getACEId()), "subject": .string(subject),
        "issuedAt": .number(Double(at)), "expiresAt": .number(Double(at + lifetime)),
    ])
    return ["kel": ExportJSON.kelValue(try issuer.getKel()), "credential": .object(credential)]
}

/// Verify a descriptor entry `{kel, credential}` for `subject` (04 § Delegations, in order): shape and lifetime bounds,
/// the issuer's KEL, the signature by its current signing delegation (usable at `now`), then `now < expiresAt`. Every failure is
/// `invalid_authorization`. `pinned`: the verifier's pin for the issuer, when it holds one; the carried KEL is then
/// reconciled with it (01 § Pinning), so a fork, or an older prefix whose credential is signed by a delegation the pin
/// superseded, is invalid.
public func verifyDelegation(_ entry: JSONValue, subject: String, now: Int, pinned: KelState? = nil) throws -> VerifiedDelegation {
    let (verified, live) = try checkDelegationEntry(entry, subject: subject, now: now, pinned: pinned)
    guard live else { throw unauthorized("delegation has expired") }
    return verified
}

/// `verifyDelegation` that reports an entry failing only by expiry as `live == false` (dropped from a descriptor, not
/// invalid). Every other failure, the issuer's KEL included, is `invalid_authorization`.
package func checkDelegationEntry(_ entry: JSONValue, subject: String, now: Int, pinned: KelState? = nil) throws -> (VerifiedDelegation, live: Bool) {
    guard let e = entry.objectValue, hasMembers(e, ["kel", "credential"]), let c = e["credential"]?.objectValue,
          hasMembers(c, ["issuer", "subject", "issuedAt", "expiresAt", "signature"]),
          let issuer = c["issuer"]?.stringValue, isACEId(issuer), c["subject"]?.stringValue == subject, issuer != subject else {
        throw unauthorized("delegation must be {kel, credential} for this subject")
    }
    let (issued, expires) = try checkLifetime(c, now: now, maximum: ACELimits.maxCredentialSeconds, what: "delegation", requireLive: false)
    var state: KelState
    do {
        state = try verifiedKel(e["kel"], now: now)
        if let pinned, pinned.aceId == state.aceId {
            state = try ACEKel.extend(pinned: pinned, verified: state).state
        }
        guard state.aceId == issuer else { throw unauthorized("delegation kel is not the issuer's KEL") }
        try verifyDocument(c, state: state, action: "delegation", now: now)
    } catch let err as ACEError where err.code != .invalidAuthorization {
        throw unauthorized("delegation: \(err.message)")
    }
    let verified = VerifiedDelegation(issuer: issuer, subject: subject, issuedAt: issued, expiresAt: expires, issuerState: state, entry: entry)
    return (verified, now < expires)
}

/// The bounds on a stranger's contact `source` (05 § Receiver admission), checked before any signature: its KEL and each
/// delegation entry's KEL hold at most `ACELimits.maxStrangerKelEvents` events and it carries at most
/// `ACELimits.maxStrangerDelegations` delegation entries (`not_permitted`; the request is dropped).
public func checkStrangerSource(_ source: JSONValue) throws {
    func short(_ v: JSONValue?) -> Bool { (v?.arrayValue?.count).map { $0 <= ACELimits.maxStrangerKelEvents } ?? false }
    guard let o = source.objectValue, let d = o["descriptor"]?.objectValue, short(o["kel"]) else {
        throw ACEError(.notPermitted, "stranger source exceeds the KEL bound")
    }
    let entries: [JSONValue]
    if let raw = d["delegations"] {
        guard let list = raw.arrayValue else { throw ACEError(.notPermitted, "stranger source carries too many delegations") }
        entries = list
    } else {
        entries = []
    }
    guard entries.count <= ACELimits.maxStrangerDelegations else { throw ACEError(.notPermitted, "stranger source carries too many delegations") }
    guard entries.allSatisfy({ $0.objectValue != nil && short($0["kel"]) }) else {
        throw ACEError(.notPermitted, "stranger delegation exceeds the KEL bound")
    }
}

/// The closed shape of a delegation entry, part of a descriptor's shape (04 § Verification step 1, before any KEL or
/// signature work): `{kel, credential: {issuer: ACE ID, subject: string, issuedAt, expiresAt: wire integers,
/// signature: operational signature shape}}`. The entry's rules (04 § Delegations) are checked in step 4.
private func isDelegationEntryShape(_ entry: JSONValue) -> Bool {
    guard let e = entry.objectValue, hasMembers(e, ["kel", "credential"]), let c = e["credential"]?.objectValue, hasMembers(c, ["issuer", "subject", "issuedAt", "expiresAt", "signature"]),
          let issuer = c["issuer"]?.stringValue, isACEId(issuer), c["subject"]?.stringValue != nil,
          c["issuedAt"]?.wireInt != nil, c["expiresAt"]?.wireInt != nil, SignatureEnvelope(operational: c["signature"]) != nil else { return false }
    return true
}

/// The verifier's pins for the delegation issuers `source` names, read through `pin` (01 § Pinning).
package func delegationPins(_ source: JSONValue, pin: (String) throws -> KelState?) throws -> [String: KelState] {
    var pins: [String: KelState] = [:]
    for entry in source["descriptor"]?["delegations"]?.arrayValue ?? [] {
        guard let who = delegationIssuer(entry), pins[who] == nil else { continue }
        if let state = try pin(who) { pins[who] = state }
    }
    return pins
}

/// The ACE ID a delegation entry names as `credential.issuer`, or nil: what its issuer's pin is looked up by.
package func delegationIssuer(_ entry: JSONValue) -> String? {
    entry["credential"]?["issuer"]?.stringValue.flatMap { isACEId($0) ? $0 : nil }
}

/// The `erc8004` entry shape `{agentRegistry: CAIP-10, agentId: decimal}` (`invalid_authorization`).
package func validateErc8004Entry(_ item: JSONValue) throws -> ERC8004Binding {
    guard let b = item.objectValue, hasMembers(b, ["agentRegistry", "agentId"]), let reg = b["agentRegistry"]?.stringValue,
          let id = b["agentId"]?.stringValue, let binding = try? ERC8004Binding(agentRegistry: reg, agentId: id) else {
        throw unauthorized("erc8004 entries must be {agentRegistry: CAIP-10, agentId: decimal}")
    }
    return binding
}

// MARK: - Permit

/// A verified delivery permit: `issuer` (the receiver) lets `subject` deliver to it. Communication only.
public struct VerifiedPermit: Sendable, Equatable {
    public let issuer: String
    public let subject: String
    public let issuedAt: Int
    public let expiresAt: Int
    /// The permit object as signed.
    public let value: JSONValue
}

/// `{issuer, subject, issuedAt, expiresAt, signature}` (action `delivery-permit`), valid for `lifetime` seconds (at most
/// 30 days).
public func createPermit(identity: any ACEIdentity, subject: String, now: Int? = nil, lifetime: Int = ACELimits.maxPermitSeconds) throws -> JSONValue {
    guard isACEId(subject), subject != identity.getACEId() else { throw ACEError(.invalidArgument, "permit subject must be another ACE ID") }
    let at = try identityNow(now)
    guard (1...ACELimits.maxPermitSeconds).contains(lifetime) else {
        throw ACEError(.invalidArgument, "lifetime must be 1...\(ACELimits.maxPermitSeconds) seconds")
    }
    return .object(try signDocument(identity, action: "delivery-permit", claims: [
        "issuer": .string(identity.getACEId()), "subject": .string(subject), "issuedAt": .number(Double(at)),
        "expiresAt": .number(Double(at + lifetime)),
    ]))
}

/// Verify a permit issued by `issuer` (its verified KEL) to `subject` at `now`: `invalid_authorization`, or
/// `stale_peer_binding` for a signature by a superseded or expired delegation or an issuer not usable at `now`.
public func verifyPermit(_ value: JSONValue, issuer: KelState, subject: String, now: Int) throws -> VerifiedPermit {
    guard let p = value.objectValue, hasMembers(p, ["issuer", "subject", "issuedAt", "expiresAt", "signature"]),
          p["issuer"]?.stringValue == issuer.aceId, p["subject"]?.stringValue == subject, isACEId(subject), subject != issuer.aceId else {
        throw unauthorized("permit does not bind this issuer and subject")
    }
    let (issued, expires) = try checkLifetime(p, now: now, maximum: ACELimits.maxPermitSeconds, what: "permit")
    try verifyDocument(p, state: issuer, action: "delivery-permit", now: now)
    return VerifiedPermit(issuer: issuer.aceId, subject: subject, issuedAt: issued, expiresAt: expires, value: value)
}

// MARK: - Descriptor

/// The verified claims of a descriptor.
public struct Descriptor: Sendable, Equatable {
    public let aceId: String
    public let issuedAt: Int
    public let expiresAt: Int
    public let relays: [String]
    public let prekey: Prekey
    public let profiles: [ProfileRef]
    /// Profile-defined members keyed by profile ID (each key is in `profiles`); validated by the profile, not by core.
    public let ext: [String: JSONValue]?
    /// The unexpired, verified delegations (expired entries are dropped).
    public internal(set) var delegations: [VerifiedDelegation]
    public let erc8004: [ERC8004Binding]
}

/// A verified `PublishedAgent`: the KEL state, the descriptor claims and the signed source as received.
public struct VerifiedAgent: Sendable, Equatable {
    public let state: KelState
    public let descriptor: Descriptor
    /// `{kel, descriptor}` exactly as signed (never merged with unsigned metadata).
    public let source: JSONValue

    public var aceId: String { state.aceId }
}

/// What `createPublishedAgent` puts in a descriptor besides the identity and the timestamps.
public struct DescriptorClaims: Sendable {
    public var relays: [String]
    public var prekey: Prekey
    public var profiles: [ProfileRef]
    public var ext: [String: JSONValue]?
    /// `{kel, credential}` entries from `createDelegation` (by controllers of this identity).
    public var delegations: [JSONValue]
    public var erc8004: [ERC8004Binding]

    public init(relays: [String], prekey: Prekey, profiles: [ProfileRef] = [], ext: [String: JSONValue]? = nil, delegations: [JSONValue] = [],
                erc8004: [ERC8004Binding] = []) {
        self.relays = relays
        self.prekey = prekey
        self.profiles = profiles
        self.ext = ext
        self.delegations = delegations
        self.erc8004 = erc8004
    }
}

/// Sign a descriptor (action `agent-descriptor`, `issuedAt = max(now, ts of the last KEL event)`) valid `lifetime` seconds (86,400 by default, at most
/// `ACELimits.maxDescriptorSeconds`) and return the verified `PublishedAgent {kel, descriptor}`. Any invalid claim is
/// `invalid_authorization` (the result is verified before return).
public func createPublishedAgent(identity: any ACEIdentity, claims: DescriptorClaims, now: Int? = nil,
                                 lifetime: Int = ACELimits.defaultDescriptorSeconds, allowLoopback: Bool = false) throws -> VerifiedAgent {
    let at = try recordTime(identity, now: now)
    guard (1...ACELimits.maxDescriptorSeconds).contains(lifetime) else {
        throw ACEError(.invalidArgument, "lifetime must be 1...\(ACELimits.maxDescriptorSeconds) seconds")
    }
    var d: [String: JSONValue] = [
        "aceId": .string(identity.getACEId()), "issuedAt": .number(Double(at)), "expiresAt": .number(Double(at + lifetime)),
        "relays": .array(claims.relays.map { .string($0) }), "prekey": claims.prekey.jsonValue,
        "profiles": .array(claims.profiles.map(\.jsonValue)),
    ]
    if let ext = claims.ext, !ext.isEmpty { d["ext"] = .object(ext) }
    if !claims.delegations.isEmpty { d["delegations"] = .array(claims.delegations) }
    if !claims.erc8004.isEmpty { d["erc8004"] = .array(claims.erc8004.map(\.jsonValue)) }
    let descriptor = try signDocument(identity, action: "agent-descriptor", claims: d)
    let source: JSONValue = ["kel": ExportJSON.kelValue(try identity.getKel()), "descriptor": .object(descriptor)]
    return try verifyPublishedAgent(source, now: at, allowLoopback: allowLoopback)
}

/// The `ext` value rules of the official profiles: `ace:commerce:1` is `validateCommerceExt`; `ace:text:1` defines none
/// (any key is invalid). Third-party values are opaque objects.
private func checkOfficialExt(_ key: String, _ value: JSONValue) throws {
    switch key {
    case ProfileManifest.text.id, ProfileManifest.core.id:
        throw unauthorized("\(key) defines no ext")
    case ProfileManifest.commerce.id:
        try validateCommerceExt(value)
    default:
        return
    }
}

/// `ext["ace:commerce:1"]`: `{settlement: [1–10 distinct {method: "stablecoin", asset: CAIP-19} | {method: "stripe-link"}]}`
/// (`invalid_authorization`).
public func validateCommerceExt(_ value: JSONValue) throws {
    guard let o = value.objectValue, hasMembers(o, ["settlement"]), let list = o["settlement"]?.arrayValue,
          (1...10).contains(list.count), Set(list).count == list.count, list.allSatisfy({ entry in
              guard let e = entry.objectValue else { return false }
              switch e["method"]?.stringValue {
              case "stablecoin": return hasMembers(e, ["method", "asset"]) && (e["asset"]?.stringValue).map(isCAIP19) == true
              case "stripe-link": return hasMembers(e, ["method"])
              default: return false
              }
          }) else { throw unauthorized("ext[ace:commerce:1] must be {settlement: [1-10 settlement methods]}") }
}

/// The descriptor signature of `source` under `state` (the verifier's newest state for that identity) at `now`:
/// `stale_peer_binding` for a superseded or expired delegation, `invalid_authorization` otherwise.
package func verifyDescriptorSignature(_ source: JSONValue, state: KelState, now: Int) throws {
    guard let d = source["descriptor"]?.objectValue, d["aceId"]?.stringValue == state.aceId else {
        throw unauthorized("descriptor must name the KEL's aceId")
    }
    try checkSignedAfterDelegation(d, state: state)
    try verifyDocument(d, state: state, action: "agent-descriptor", now: now)
}

/// Verify a `PublishedAgent` at `now` (04 § Verification, first failure wins): shape (`invalid_authorization`), the KEL
/// (`invalid_kel` / `invalid_signature`; usable at `now`), the descriptor signature (`stale_peer_binding` /
/// `invalid_authorization`), then the delegations (expired entries dropped; other failures `invalid_authorization`).
/// `allowLoopback` admits loopback HTTP relays (development only). `pinned` is the verifier's pin for this identity: the
/// carried KEL is reconciled with it under the fork rules (`kel_conflict`) and the signature must verify under the
/// resulting newest state, so a descriptor carrying an older prefix signed by a superseded delegation is
/// `stale_peer_binding`; the returned `state` is that newest state.
/// `delegationPins` maps delegation issuers to the verifier's pins for them; each entry's issuer KEL is reconciled with its
/// pin the same way (a failure is `invalid_authorization`).
public func verifyPublishedAgent(_ source: JSONValue, now: Int, allowLoopback: Bool = false, pinned: KelState? = nil,
                                 delegationPins: [String: KelState] = [:]) throws -> VerifiedAgent {
    try verifyPublishedAgent(source, now: now, allowLoopback: allowLoopback, pinned: pinned, kelNow: nil, delegationPins: delegationPins)
}

/// The KEL a signed document carries, verified (at `max(now, kelNow)`) and usable at `now`, deriving `aceId`, then
/// reconciled with `pinned` when given (fork rules) and usable again: the state the document's signature verifies under.
private func carriedKel(_ kel: JSONValue?, aceId: String, pinned: KelState?, now: Int, kelNow: Int? = nil) throws -> KelState {
    // the KEL's structure is step 2 (`invalid_kel`), not the document's shape
    guard let events = kel?.arrayValue else { throw ACEError(.invalidKel, "kel must be an array") }
    var state = try ACEKel.verify(events.map { $0.objectValue ?? [:] }, now: max(now, kelNow ?? now))
    guard ACEKel.isUsable(state, now: now) else { throw ACEError(.invalidKel, "identity has no live signing delegation") }
    guard state.aceId == aceId else { throw unauthorized("kel does not derive aceId") }
    if let pinned {
        state = try ACEKel.extend(pinned: pinned, events: state.events, now: now).state
        // 01 § Operational signatures rule 5: the signer, after reconciliation with the pin, is usable at `now`.
        guard ACEKel.isUsable(state, now: now) else { throw ACEError(.stalePeerBinding, "pinned identity has no live signing delegation") }
    }
    return state
}

/// `kelNow`: verify the carried KEL at `max(now, kelNow)` (a stored descriptor re-verified at its `issuedAt` beside a pin that
/// grew later); everything else at `now`.
package func verifyPublishedAgent(_ source: JSONValue, now: Int, allowLoopback: Bool, pinned: KelState?, kelNow: Int?,
                                  delegationPins: [String: KelState] = [:]) throws -> VerifiedAgent {
    try checkJSONValue(source, code: .invalidAuthorization)  // depth counts from the agent's root (02 § JSON values)
    guard let size = try? source.jsonData().count, size <= ACELimits.maxPublishedAgentBytes else {
        throw unauthorized("published agent exceeds \(ACELimits.maxPublishedAgentBytes) bytes")
    }
    guard let o = source.objectValue, hasMembers(o, ["kel", "descriptor"]), let d = o["descriptor"]?.objectValue,
          hasMembers(d, ["aceId", "issuedAt", "expiresAt", "relays", "prekey", "profiles", "signature"],
                     optional: ["ext", "delegations", "erc8004"]),
          let aceId = d["aceId"]?.stringValue, isACEId(aceId), SignatureEnvelope(operational: d["signature"]) != nil else {
        throw unauthorized("descriptor has unknown, missing or malformed members")
    }
    let (issuedAt, expiresAt) = try checkLifetime(d, now: now, maximum: ACELimits.maxDescriptorSeconds, what: "descriptor")
    guard let routes = d["relays"]?.arrayValue, (1...4).contains(routes.count) else { throw unauthorized("relays must hold 1-4 routes") }
    let relays = try routes.map { r -> String in
        guard let s = r.stringValue, isRelayRoute(s, allowLoopback: allowLoopback) else { throw unauthorized("relays must be canonical relay URLs") }
        return s
    }
    guard Set(relays).count == relays.count else { throw unauthorized("relays must be distinct") }
    guard let prekey = Prekey(d["prekey"]) else { throw unauthorized("prekey must be {id = sha256(publicKey), publicKey: 1216 bytes}") }
    guard let list = d["profiles"]?.arrayValue, list.count <= 32 else { throw unauthorized("profiles must hold at most 32 entries") }
    let profiles = try list.map { p -> ProfileRef in
        guard let ref = ProfileRef(p), ref.id != ProfileManifest.core.id else { throw unauthorized("profiles entries must be {id, digest} (never ace:core:1)") }
        return ref
    }
    guard Set(profiles.map(\.id)).count == profiles.count else { throw unauthorized("profile IDs must be distinct") }
    var ext: [String: JSONValue]?
    if let raw = d["ext"] {
        guard let e = raw.objectValue, Set(e.keys).isSubset(of: Set(profiles.map(\.id))), e.values.allSatisfy({ $0.objectValue != nil }),
              !e.isEmpty, try raw.jsonData().count <= ACELimits.maxExtBytes else {
            throw unauthorized("ext keys must be listed profiles, values objects, canonical JSON at most \(ACELimits.maxExtBytes) bytes")
        }
        for (k, v) in e { try checkOfficialExt(k, v) }
        ext = e
    }
    var delegationItems: [JSONValue] = []
    if let raw = d["delegations"] {
        guard let items = raw.arrayValue, (1...4).contains(items.count) else { throw unauthorized("delegations must hold 1-4 entries") }
        let issuers = items.map { $0["credential"]?["issuer"]?.stringValue ?? "" }
        guard Set(issuers).count == issuers.count, items.allSatisfy(isDelegationEntryShape) else {
            throw unauthorized("delegations must be {kel, credential} with distinct issuers")
        }
        delegationItems = items
    }
    var erc8004: [ERC8004Binding] = []
    if let raw = d["erc8004"] {
        guard let items = raw.arrayValue, (1...4).contains(items.count), Set(items).count == items.count else {
            throw unauthorized("erc8004 must hold 1-4 distinct entries")
        }
        erc8004 = try items.map(validateErc8004Entry)
    }
    let state = try carriedKel(o["kel"], aceId: aceId, pinned: pinned, now: now, kelNow: kelNow)
    try verifyDescriptorSignature(source, state: state, now: now)
    var delegations: [VerifiedDelegation] = []
    for item in delegationItems {
        let pin = delegationIssuer(item).flatMap { delegationPins[$0] }
        let (verified, live) = try checkDelegationEntry(item, subject: aceId, now: now, pinned: pin)
        if live { delegations.append(verified) }  // an entry failing only by expiry is dropped
    }
    return VerifiedAgent(state: state, descriptor: Descriptor(
        aceId: aceId, issuedAt: issuedAt, expiresAt: expiresAt, relays: relays, prekey: prekey, profiles: profiles, ext: ext, delegations: delegations, erc8004: erc8004), source: source)
}

// MARK: - Card record (04 § Card record)

/// Whether strangers' contact requests are processed (05 § Flow). No card record is `closed`.
public enum Contact: String, Sendable {
    case open, closed
}

/// The publication unit of a card record: the closed JSON object `{kel, card}` (canonical JSON at most
/// `ACELimits.maxPublishedAgentBytes`).
public typealias CardBundle = JSONValue

/// The verified claims of a card record: an agent's durable identity facts. It has no expiry.
public struct CardRecord: Sendable, Equatable {
    public let aceId: String
    public let issuedAt: Int
    /// The canonical relay URL holding the record; `handle` is in its namespace.
    public let home: String
    /// Set once: every later record of this identity at `home` carries the same handle.
    public let handle: String?
    public let card: AgentCard
    /// 1–`ACELimits.maxPayAccounts` distinct CAIP-10 accounts the agent asks to be paid at (claimed, not proven).
    public let pay: [String]?
    public let contact: Contact
    /// Whether the home relay's directory lists this identity.
    public let listed: Bool
    public let signature: SignatureEnvelope
    /// The record object exactly as signed.
    public let value: JSONValue
}

/// A verified CardBundle: the KEL state, the record and the bundle as received.
public struct VerifiedCard: Sendable, Equatable {
    public let state: KelState
    public let record: CardRecord
    /// `{kel, card}` exactly as signed.
    public let bundle: CardBundle
    /// Whether a live descriptor confirmed the KEL it verified under, in this lookup or an earlier one recorded with the
    /// pin (`lookupCard`); false when only a bundle's own KEL vouches for it: from `verifyCardBundle` alone, or a lookup of
    /// an identity that has had no live descriptor since it was pinned that way (04 § Card record).
    public internal(set) var kelLive = false

    public var aceId: String { record.aceId }
}

/// A CAIP-10 account ID (`namespace:reference:address`): `isCAIP10` under the name sdk-ts (`isCaip10Account`) and sdk-py
/// (`is_caip10_account`) export.
public func isCaip10Account(_ value: String) -> Bool { isCAIP10(value) }

/// A signed document's canonical claims: the document without `signature`.
private func documentClaims(_ o: [String: JSONValue]) throws -> Data {
    try JSONValue.object(o.filter { $0.key != "signature" }).jsonData()
}

/// The SHA-256 (hex) of a signed document's canonical claims.
package func documentDigest(_ document: JSONValue) throws -> String {
    guard let o = document.objectValue else { throw ACEError(.invalidArgument, "a document is an object") }
    return sha256Hex(try documentClaims(o))
}

/// The card record's settings: its claims less `aceId`, `issuedAt` and `signature`.
package func cardClaims(home: String, handle: String?, card: AgentCard, pay: [String]?, contact: Contact, listed: Bool) -> [String: JSONValue] {
    var claims: [String: JSONValue] = ["home": .string(home), "card": card.jsonValue, "contact": .string(contact.rawValue), "listed": .bool(listed)]
    if let handle { claims["handle"] = .string(handle) }
    if let pay { claims["pay"] = .array(pay.map { .string($0) }) }
    return claims
}

/// Create and sign this identity's CardBundle `{kel, card}` (action `card-record` at `issuedAt = max(now, ts of the last
/// KEL event)`), verified before it
/// is returned (`invalid_authorization` for any invalid claim).
public func createCardRecord(identity: any ACEIdentity, home: String, handle: String? = nil, card: AgentCard = AgentCard(),
                             pay: [String]? = nil, contact: Contact, listed: Bool, now: Int? = nil,
                             allowLoopback: Bool = false) throws -> CardBundle {
    let at = try recordTime(identity, now: now)
    var claims = cardClaims(home: home, handle: handle, card: card, pay: pay, contact: contact, listed: listed)
    claims["aceId"] = .string(identity.getACEId())
    claims["issuedAt"] = .number(Double(at))
    let record = try signDocument(identity, action: "card-record", claims: claims)
    let bundle: JSONValue = ["kel": ExportJSON.kelValue(try identity.getKel()), "card": .object(record)]
    _ = try verifyCardBundle(bundle, now: at, allowLoopback: allowLoopback)
    return bundle
}

/// Verify a CardBundle at `now` (04 § Card record, first failure wins): shape, both size bounds and the field rules
/// (`invalid_authorization`); the KEL usable at `now` (`invalid_kel` / `invalid_signature`) naming `aceId`
/// (`invalid_authorization`); the signature as an operational signature of that KEL, reconciled with `pinned` when given
/// (`stale_peer_binding` / `invalid_authorization`). No expiry check. `allowLoopback` admits a loopback HTTP `home`
/// (development only).
public func verifyCardBundle(_ value: JSONValue, now: Int, allowLoopback: Bool = false, pinned: KelState? = nil) throws -> VerifiedCard {
    guard let o = value.objectValue, hasMembers(o, ["kel", "card"]) else { throw unauthorized("card bundle must be {kel, card}") }
    try checkJSONValue(value, code: .invalidAuthorization)  // bounds the depth before anything recurses
    guard let size = try? value.jsonData().count, size <= ACELimits.maxPublishedAgentBytes else {
        throw unauthorized("card bundle exceeds \(ACELimits.maxPublishedAgentBytes) bytes")
    }
    guard let r = o["card"]?.objectValue,
          hasMembers(r, ["aceId", "issuedAt", "home", "card", "contact", "listed", "signature"], optional: ["handle", "pay"]),
          let aceId = r["aceId"]?.stringValue, isACEId(aceId), let signature = SignatureEnvelope(operational: r["signature"]) else {
        throw unauthorized("invalid card record shape")
    }
    guard let recordSize = try? JSONValue.object(r).jsonData().count, recordSize <= ACELimits.maxCardRecordBytes else {
        throw unauthorized("card record exceeds \(ACELimits.maxCardRecordBytes) bytes")
    }
    guard let issuedAt = r["issuedAt"]?.wireInt, issuedAt <= now + ACELimits.timestampWindowSeconds else {
        throw unauthorized("invalid card record issuedAt")
    }
    guard let home = r["home"]?.stringValue, isRelayRoute(home, allowLoopback: allowLoopback) else {
        throw unauthorized("home must be a canonical relay URL")
    }
    var handle: String?
    if let h = r["handle"] {
        guard let s = h.stringValue, isHandle(s) else { throw unauthorized("handle must match [a-z][a-z0-9_-]{2,31}") }
        guard URLComponents(string: home)?.path.isEmpty ?? false else {
            throw unauthorized("a handle needs a home without a path (it resolves at https://host)")
        }
        handle = s
    }
    let card = try AgentCard(r["card"])
    var pay: [String]?
    if let raw = r["pay"] {
        guard let items = raw.arrayValue, case let list = items.compactMap(\.stringValue), list.count == items.count,
              (1...ACELimits.maxPayAccounts).contains(list.count), Set(list).count == list.count, list.allSatisfy(isCAIP10) else {
            throw unauthorized("pay must hold 1-\(ACELimits.maxPayAccounts) distinct CAIP-10 accounts")
        }
        pay = list
    }
    guard let contact = r["contact"]?.stringValue.flatMap(Contact.init(rawValue:)) else { throw unauthorized("contact must be open or closed") }
    guard let listed = r["listed"]?.boolValue else { throw unauthorized("listed must be a boolean") }
    let state = try carriedKel(o["kel"], aceId: aceId, pinned: pinned, now: now)
    try checkSignedAfterDelegation(r, state: state)
    try verifyDocument(r, state: state, action: "card-record", now: now)
    let record = CardRecord(aceId: aceId, issuedAt: issuedAt, home: home, handle: handle, card: card, pay: pay, contact: contact,
                            listed: listed, signature: signature, value: .object(r))
    return VerifiedCard(state: state, record: record, bundle: value)
}
