//
//  Discovery.swift
//  ACE SDK
//
//  Peers: relay peer records, registration files, well-known fetch, profiles.
//

import Foundation

// MARK: - VerifiedPeer

/// Where a peer binding came from.
public enum PeerSource: String, Codable, Sendable {
    /// A relay `PeerRecord` with a verified `registrationSignature`.
    case relay
    /// A registration file (no signed timestamp; `registeredAt` is the pin time).
    case registration
}

/// A peer whose keys were verified. Obtain only from `verifyPeerRecord`,
/// `verifyRegistrationFile`, `verifyRegistrationRequest`, `PeerStore` or `RelayClient`.
public struct VerifiedPeer: Sendable, Equatable {
    public let aceId: String
    public let scheme: SigningScheme
    public let signingPublicKey: Data
    public let encryptionPublicKey: Data
    public let registeredAt: Int
    /// The relay binding signature; `nil` for a registration-file peer.
    public let registrationSignature: String?
    public let source: PeerSource
    /// Discovery profile as served by the relay. **Unverified** metadata: it is
    /// self-asserted and not covered by the binding signature. Never use it for trust decisions.
    public let profile: AgentProfile?

    /// The peer's principal record (verified when the peer was verified, 09).
    public var principal: PrincipalRecord? { profile?.principal }

    init(aceId: String, scheme: SigningScheme, signingPublicKey: Data, encryptionPublicKey: Data, registeredAt: Int,
         registrationSignature: String?, source: PeerSource, profile: AgentProfile?) {
        self.aceId = aceId
        self.scheme = scheme
        self.signingPublicKey = signingPublicKey
        self.encryptionPublicKey = encryptionPublicKey
        self.registeredAt = registeredAt
        self.registrationSignature = registrationSignature
        self.source = source
        self.profile = profile
    }

    /// ed25519: Base58 of the signing key; secp256k1: EIP-55 address.
    public var address: String {
        signingAddress(scheme: scheme, signingPublicKey: signingPublicKey)
    }
}

// MARK: - Strict JSON readers

private func optString(_ o: [String: JValue], _ key: String, _ code: ACEError.Code, _ what: String) throws -> String? {
    guard let v = o[key], !v.isNull else { return nil }
    guard let s = v.stringValue else { throw ACEError(code, "\(what).\(key) must be a string") }
    return s
}

private func reqString(_ o: [String: JValue], _ key: String, _ code: ACEError.Code, _ what: String) throws -> String {
    guard let s = try optString(o, key, code, what) else { throw ACEError(code, "\(what).\(key) is required") }
    return s
}

private func optStringList(_ o: [String: JValue], _ key: String, _ code: ACEError.Code, _ what: String) throws -> [String]? {
    guard let v = o[key], !v.isNull else { return nil }
    guard let a = v.arrayValue else { throw ACEError(code, "\(what).\(key) must be an array of strings") }
    return try a.map {
        guard let s = $0.stringValue else { throw ACEError(code, "\(what).\(key) must be an array of strings") }
        return s
    }
}

private func optObject(_ o: [String: JValue], _ key: String, _ code: ACEError.Code, _ what: String) throws -> [String: JValue]? {
    guard let v = o[key], !v.isNull else { return nil }
    guard let d = v.objectValue else { throw ACEError(code, "\(what).\(key) must be an object") }
    return d
}

extension AgentProfile {
    /// Parse the wire shape; type errors are `invalid_profile`. Unknown top-level fields
    /// are dropped; `pricing` may contain only `currency` and `maxAmount`. The other members'
    /// `validateProfile` checks run before `principal` is parsed (08 order, R-P45), so a bad
    /// member is `invalid_profile` even when the principal is malformed too.
    static func parse(_ v: JValue) throws -> AgentProfile {
        let code = ACEError.Code.invalidProfile
        guard let o = v.objectValue else { throw ACEError(code, "profile must be a JSON object") }
        var pricing: ProfilePricing?
        if let p = try optObject(o, "pricing", code, "profile") {
            let extra = Set(p.keys).subtracting(["currency", "maxAmount"])
            guard extra.isEmpty else { throw ACEError(code, "profile.pricing has unknown fields: \(extra.sorted().prefix(3))") }
            pricing = ProfilePricing(
                currency: try reqString(p, "currency", code, "profile.pricing"),
                maxAmount: try optString(p, "maxAmount", code, "profile.pricing")
            )
        }
        var profile = AgentProfile(
            name: try optString(o, "name", code, "profile"),
            description: try optString(o, "description", code, "profile"),
            image: try optString(o, "image", code, "profile"),
            tags: try optStringList(o, "tags", code, "profile"),
            capabilities: try optStringList(o, "capabilities", code, "profile"),
            chains: try optStringList(o, "chains", code, "profile"),
            endpoint: try optString(o, "endpoint", code, "profile"),
            pricing: pricing
        )
        try validateProfile(profile)
        profile.principal = try o["principal"].flatMap { $0.isNull ? nil : try PrincipalRecord.parse($0) }
        return profile
    }

    var jvalue: JValue {
        var o: [String: JValue] = [:]
        if let name { o["name"] = .string(name) }
        if let description { o["description"] = .string(description) }
        if let image { o["image"] = .string(image) }
        if let tags { o["tags"] = .array(tags.map { .string($0) }) }
        if let capabilities { o["capabilities"] = .array(capabilities.map { .string($0) }) }
        if let chains { o["chains"] = .array(chains.map { .string($0) }) }
        if let endpoint { o["endpoint"] = .string(endpoint) }
        if let pricing {
            var p: [String: JValue] = ["currency": .string(pricing.currency)]
            if let m = pricing.maxAmount { p["maxAmount"] = .string(m) }
            o["pricing"] = .object(p)
        }
        if let principal { o["principal"] = principal.jvalue }
        return .object(o)
    }
}

extension RegistrationFile {
    /// Parse the wire JSON shape; type errors are `invalid_registration`.
    static func parse(_ v: JValue) throws -> RegistrationFile {
        let code = ACEError.Code.invalidRegistration
        guard let d = v.objectValue else { throw ACEError(code, "registration file must be a JSON object") }
        guard let signing = try optObject(d, "signing", code, "registration") else {
            throw ACEError(code, "registration.signing is required")
        }
        guard let tierValue = d["tier"]?.wireInt, let tier = IdentityTier(rawValue: tierValue) else {
            throw ACEError(code, "registration.tier must be 0 or 1")
        }
        var capabilities: [Capability]?
        if let v = d["capabilities"], !v.isNull {
            guard let caps = v.arrayValue else { throw ACEError(code, "registration.capabilities must be an array") }
            capabilities = try caps.map { c in
                guard let c = c.objectValue else { throw ACEError(code, "registration.capabilities entries must be objects") }
                var pricing: PricingInfo?
                if let p = try optObject(c, "pricing", code, "capability") {
                    pricing = PricingInfo(
                        model: try reqString(p, "model", code, "capability.pricing"),
                        amount: try reqString(p, "amount", code, "capability.pricing"),
                        currency: try reqString(p, "currency", code, "capability.pricing")
                    )
                }
                return Capability(
                    id: try reqString(c, "id", code, "capability"),
                    description: try reqString(c, "description", code, "capability"),
                    input: try optString(c, "input", code, "capability"),
                    output: try optString(c, "output", code, "capability"),
                    pricing: pricing
                )
            }
        }
        var chains: [ChainInfo]?
        if let v = d["chains"], !v.isNull {
            guard let list = v.arrayValue else { throw ACEError(code, "registration.chains must be an array") }
            chains = try list.map { c in
                guard let c = c.objectValue else { throw ACEError(code, "registration.chains entries must be objects") }
                return ChainInfo(network: try reqString(c, "network", code, "chain"), address: try reqString(c, "address", code, "chain"))
            }
        }
        var hardwareBacking: HardwareBacking?
        if let hb = try optString(d, "hardwareBacking", code, "registration") {
            guard let parsed = HardwareBacking(rawValue: hb) else { throw ACEError(code, "registration.hardwareBacking is unknown") }
            hardwareBacking = parsed
        }
        let schemeText = try reqString(signing, "scheme", code, "signing")
        guard let scheme = SigningScheme(rawValue: schemeText) else { throw ACEError(code, "unsupported signing.scheme") }
        return RegistrationFile(
            ace: try reqString(d, "ace", code, "registration"),
            id: try reqString(d, "id", code, "registration"),
            name: try reqString(d, "name", code, "registration"),
            description: try optString(d, "description", code, "registration"),
            endpoint: try reqString(d, "endpoint", code, "registration"),
            tier: tier,
            hardwareBacking: hardwareBacking,
            signing: SigningConfig(
                scheme: scheme,
                address: try reqString(signing, "address", code, "signing"),
                signingPublicKey: try optString(signing, "signingPublicKey", code, "signing"),
                encryptionPublicKey: try reqString(signing, "encryptionPublicKey", code, "signing")
            ),
            capabilities: capabilities,
            settlement: try optStringList(d, "settlement", code, "registration"),
            chains: chains,
            principal: try d["principal"].flatMap { $0.isNull ? nil : try PrincipalRecord.parse($0) }
        )
    }
}

extension PeerRecord {
    /// Strict parse of the wire shape; every failure is `invalid_peer`.
    static func parse(_ v: JValue) throws -> PeerRecord {
        let code = ACEError.Code.invalidPeer
        guard let o = v.objectValue else { throw ACEError(code, "peer record must be an object") }
        guard let aceId = o["aceId"]?.stringValue else { throw ACEError(code, "aceId is not an ACE ID") }
        guard let scheme = o["scheme"]?.stringValue else { throw ACEError(code, "unsupported scheme") }
        guard let enc = o["encryptionPublicKey"]?.stringValue, let sig = o["signingPublicKey"]?.stringValue else {
            throw ACEError(code, "keys must be Base64 strings")
        }
        guard let registeredAt = o["registeredAt"]?.wireInt else { throw ACEError(code, "registeredAt must be an integer") }
        guard let signature = o["registrationSignature"]?.stringValue else { throw ACEError(code, "registrationSignature must be a string") }
        var profile: AgentProfile?
        if let p = o["profile"], !p.isNull {
            do { profile = try AgentProfile.parse(p) } catch let e as ACEError { throw e.code == .invalidPrincipal ? e : ACEError(code, e.message) }
        }
        return PeerRecord(aceId: aceId, scheme: scheme, encryptionPublicKey: enc, signingPublicKey: sig,
                          registrationSignature: signature, registeredAt: registeredAt, profile: profile)
    }
}

// MARK: - Profile

private let tagRegex = try! NSRegularExpression(pattern: "^[a-z0-9][a-z0-9-]*$")
private let caip2Regex = try! NSRegularExpression(pattern: "^[-a-z0-9]{3,8}:[-_a-zA-Z0-9]{1,32}$")
private let amountRegex = try! NSRegularExpression(pattern: "^[0-9]+(\\.[0-9]+)?$")

private func regexFull(_ re: NSRegularExpression, _ s: String) -> Bool {
    guard !s.contains("\n") else { return false }
    let r = NSRange(location: 0, length: (s as NSString).length)
    return re.firstMatch(in: s, range: r)?.range == r
}

/// Validate a discovery profile and return it; failures are `invalid_profile`.
@discardableResult
public func validateProfile(_ p: AgentProfile) throws -> AgentProfile {
    let code = ACEError.Code.invalidProfile
    func text(_ value: String?, _ name: String, _ lo: Int, _ hi: Int) throws {
        guard let value else { return }
        let n = value.unicodeScalars.count
        guard n >= lo, n <= hi, !hasControlCharacter(value) else {
            throw ACEError(code, "profile.\(name) must be \(lo)-\(hi) characters without control characters")
        }
    }
    func tagList(_ items: [String]?, _ name: String, _ maxCount: Int) throws {
        guard let items else { return }
        guard items.count <= maxCount else { throw ACEError(code, "profile.\(name) has more than \(maxCount) items") }
        for item in items where item.unicodeScalars.count > 32 || !regexFull(tagRegex, item) {
            throw ACEError(code, "profile.\(name) items must be 1-32 of [a-z0-9-]")
        }
    }
    try text(p.name, "name", 1, 64)
    try text(p.description, "description", 0, 256)
    if let image = p.image, image.unicodeScalars.count > 512 || !isHTTPSURL(image) {
        throw ACEError(code, "profile.image must be an HTTPS URL of at most 512 characters")
    }
    try tagList(p.tags, "tags", 10)
    try tagList(p.capabilities, "capabilities", 20)
    if let chains = p.chains, chains.count > 10 || !chains.allSatisfy({ regexFull(caip2Regex, $0) }) {
        throw ACEError(code, "profile.chains must be at most 10 CAIP-2 identifiers")
    }
    if let endpoint = p.endpoint, !isHTTPSURL(endpoint) {
        throw ACEError(code, "profile.endpoint must be an HTTPS URL")
    }
    if let pricing = p.pricing {
        try text(pricing.currency, "pricing.currency", 1, 16)
        if let m = pricing.maxAmount, m.unicodeScalars.count > 32 || !regexFull(amountRegex, m) {
            throw ACEError(code, "profile.pricing.maxAmount must match ^[0-9]+(\\.[0-9]+)?$ (1-32 chars)")
        }
    }
    return p
}

// MARK: - Keys / binding

func decodeSigningKey(scheme: SigningScheme, _ text: String, code: ACEError.Code) throws -> Data {
    let raw = try decodeB64(text, code: code, what: "signingPublicKey", maxBytes: 64)
    guard ACESigning.isValidSigningPublicKey(scheme, raw) else {
        throw ACEError(code, "signingPublicKey is not a valid key for the scheme")
    }
    return raw
}

func bindingSignData(aceId: String, timestamp: Int, encryptionPublicKey: String, signingPublicKey: String) throws -> Data {
    try ACESigning.buildSignData(action: "register", aceId: aceId, timestamp: timestamp,
                                 payload: ACESigning.encodePayload(encryptionPublicKey, signingPublicKey))
}

/// Verify a relay `PeerRecord`: ID format, `aceId == sha256(signing key)`, a 1216-byte
/// encryption key, an integer `registeredAt`, the binding signature and the profile.
/// Every failure is `invalid_peer`, except a present `profile.principal` that fails 09
/// validation (`invalid_principal`, subject = the record's signing key, `now` from `clock`).
public func verifyPeerRecord(_ record: PeerRecord, clock: @Sendable () -> Int = systemClock) throws -> VerifiedPeer {
    let code = ACEError.Code.invalidPeer
    guard isACEId(record.aceId) else { throw ACEError(code, "aceId is not an ACE ID") }
    guard let scheme = SigningScheme(rawValue: record.scheme) else { throw ACEError(code, "unsupported scheme") }
    let signingKey = try decodeSigningKey(scheme: scheme, record.signingPublicKey, code: code)
    guard computeACEId(signingKey) == record.aceId else { throw ACEError(code, "aceId does not match the signing key") }
    let encKey = try ACEEncryption.decodeKemPublicKey(record.encryptionPublicKey, code: code)
    guard isWireInt(record.registeredAt) else {
        throw ACEError(code, "registeredAt must be an integer")
    }
    let sig = try decodeSignature(record.registrationSignature, scheme: scheme, code: code)
    let signData = try bindingSignData(aceId: record.aceId, timestamp: record.registeredAt,
                                       encryptionPublicKey: record.encryptionPublicKey, signingPublicKey: record.signingPublicKey)
    guard ACESigning.verify(signData: signData, signature: sig, scheme: scheme, publicKey: signingKey) else {
        throw ACEError(code, "registrationSignature does not verify")
    }
    var profile = record.profile
    if let pr = profile {
        do { try validateProfile(pr) } catch let e as ACEError { throw ACEError(code, e.message) }
        profile = try dropExpiredPrincipal(pr, subjectSigningPublicKey: signingKey, now: wireNow(clock))
    }
    return VerifiedPeer(aceId: record.aceId, scheme: scheme, signingPublicKey: signingKey, encryptionPublicKey: encKey,
                        registeredAt: record.registeredAt, registrationSignature: record.registrationSignature,
                        source: .relay, profile: profile)
}

/// Run all 01 rules (including the ID hash); failures are `invalid_registration`, except a
/// `principal` that fails 09 validation (`invalid_principal`; subject = the file's own signing key).
///
/// The peer's `registeredAt` is `pinnedAt` or now (a file has no signed timestamp).
public func verifyRegistrationFile(_ reg: RegistrationFile, pinnedAt: Int? = nil, clock: @Sendable () -> Int = systemClock) throws -> VerifiedPeer {
    let code = ACEError.Code.invalidRegistration
    if let pinnedAt, !isWireInt(pinnedAt) {
        throw ACEError(.invalidArgument, "pinnedAt must be an integer in [0, 2^53-1]")
    }
    guard reg.ace == "1.0" else { throw ACEError(code, "ace must be '1.0'") }
    guard isACEId(reg.id) else { throw ACEError(code, "id is not an ACE ID") }
    guard !reg.name.isEmpty, !hasControlCharacter(reg.name) else {
        throw ACEError(code, "name must be non-empty without control characters")
    }
    guard isHTTPSURL(reg.endpoint) else { throw ACEError(code, "endpoint must match the ACE HTTPS URL grammar") }
    let s = reg.signing
    let signingKey: Data
    switch s.scheme {
    case .ed25519:
        guard let key = Base58.decode(s.address), key.count == 32, Base58.encode(key) == s.address else {
            throw ACEError(code, "signing.address must be the Base58 of a 32-byte key")
        }
        if let spk = s.signingPublicKey {
            guard try decodeB64(spk, code: code, what: "signing.signingPublicKey") == key else {
                throw ACEError(code, "signing.signingPublicKey must equal Base58Decode(signing.address)")
            }
        }
        signingKey = key
    case .secp256k1:
        guard let spk = s.signingPublicKey else { throw ACEError(code, "secp256k1 requires signing.signingPublicKey") }
        signingKey = try decodeSigningKey(scheme: .secp256k1, spk, code: code)
        guard s.address.lowercased() == signingAddress(scheme: .secp256k1, signingPublicKey: signingKey).lowercased() else {
            throw ACEError(code, "signing.address does not match signing.signingPublicKey")
        }
    }
    guard computeACEId(signingKey) == reg.id else { throw ACEError(code, "id does not match the signing key") }
    let encKey = try ACEEncryption.decodeKemPublicKey(s.encryptionPublicKey, code: code)
    let now = wireNow(clock)
    let profile = try dropExpiredPrincipal(reg.principal.map { AgentProfile(principal: $0) }, subjectSigningPublicKey: signingKey, now: now)
    return VerifiedPeer(aceId: reg.id, scheme: s.scheme, signingPublicKey: signingKey, encryptionPublicKey: encKey,
                        registeredAt: pinnedAt ?? now, registrationSignature: nil, source: .registration, profile: profile)
}

// MARK: - Rollback barrier (02)

/// Outcome of adopting a candidate binding.
public enum AdoptOutcome: String, Sendable {
    case adopted, unchanged, rotated
}

/// R-P36: a principal replaces the cached one only with a strictly newer `issuedAt`, or the
/// byte-identical record at the same `issuedAt`.
private func supersedes(_ new: PrincipalRecord, _ old: PrincipalRecord) -> Bool {
    new.issuedAt > old.issuedAt || (new.issuedAt == old.issuedAt && new.jsonData() == old.jsonData())
}

/// Profile a signed (relay) candidate leaves in the pin (R-P36): an older `registeredAt` keeps the
/// cached profile (minus a cached principal expired at `now`, R-P35); otherwise the candidate's
/// replaces it, a principal only per `supersedes`, and a candidate without one withdraws it (an
/// expired cached principal is dropped first, R-P35).
private func relayProfile(pin: VerifiedPeer, candidate: VerifiedPeer, now: Int) -> AgentProfile? {
    guard candidate.registeredAt >= pin.registeredAt else {
        guard var kept = pin.profile, let old = kept.principal, old.expiresAt <= now else { return pin.profile }
        kept.principal = nil
        return kept == AgentProfile() ? nil : kept
    }
    guard var p = candidate.profile else { return nil }
    if let new = p.principal, let old = pin.profile?.principal, old.expiresAt > now, !supersedes(new, old) {
        p.principal = old
    }
    return p
}

private func withProfile(_ pin: VerifiedPeer, _ profile: AgentProfile?) -> VerifiedPeer {
    VerifiedPeer(aceId: pin.aceId, scheme: pin.scheme, signingPublicKey: pin.signingPublicKey,
                 encryptionPublicKey: pin.encryptionPublicKey, registeredAt: pin.registeredAt,
                 registrationSignature: pin.registrationSignature, source: pin.source, profile: profile)
}

/// A kept registration-file candidate replaces only the profile members it supplies (absent
/// members carry over, R-P27). `principal` is replaced only by a validated one whose `issuedAt`
/// is not older than the cached one, and never removed (R-P26) unless expired at `now` (R-P35).
private func fileProfile(cached: AgentProfile?, candidate: AgentProfile?, now: Int) -> AgentProfile? {
    // An expired cached principal is dropped (R-P35): the refreshed fetchedAt would otherwise make the pin unloadable.
    let old = cached?.principal.flatMap { $0.expiresAt > now ? $0 : nil }, new = candidate?.principal
    let keep: PrincipalRecord? = old == nil ? new : (new.map { supersedes($0, old!) } == true ? new : old)
    var m = cached ?? AgentProfile()
    if let c = candidate {
        if let v = c.name { m.name = v }
        if let v = c.description { m.description = v }
        if let v = c.image { m.image = v }
        if let v = c.tags { m.tags = v }
        if let v = c.capabilities { m.capabilities = v }
        if let v = c.chains { m.chains = v }
        if let v = c.endpoint { m.endpoint = v }
        if let v = c.pricing { m.pricing = v }
    }
    m.principal = keep
    return m == AgentProfile() ? nil : m
}

/// Pure rule used by `PeerStore.adopt`: the binding to store and the outcome.
///
/// Rotation to a different encryption key requires a signed (relay) binding with a
/// strictly newer `registeredAt`; an unsigned registration-file candidate is adopted only
/// without a pin, or as `unchanged` when its key equals the pin (pin kept as is).
func adoptDecision(pin: VerifiedPeer?, candidate: VerifiedPeer, now: Int) throws -> (VerifiedPeer, AdoptOutcome) {
    if candidate.registeredAt > now + ACELimits.timestampWindowSeconds {
        throw ACEError(.invalidPeer, "registeredAt is in the future")
    }
    guard let pin else { return (candidate, .adopted) }
    guard pin.signingPublicKey == candidate.signingPublicKey, pin.scheme == candidate.scheme else {
        throw ACEError(.invalidPeer, "signing key or scheme differs from the pinned binding")
    }
    let unsigned = candidate.registrationSignature == nil
    if pin.encryptionPublicKey == candidate.encryptionPublicKey {
        if unsigned {
            // An unsigned source never changes the binding, but a kept candidate refreshes the
            // cached profile; it can never remove or downgrade the cached principal (R-P26/R-P27).
            return (withProfile(pin, fileProfile(cached: pin.profile, candidate: candidate.profile, now: now)), .unchanged)
        }
        let newer = candidate.registeredAt > pin.registeredAt ? candidate : pin
        let merged = VerifiedPeer(
            aceId: pin.aceId, scheme: pin.scheme, signingPublicKey: pin.signingPublicKey,
            encryptionPublicKey: pin.encryptionPublicKey, registeredAt: newer.registeredAt,
            registrationSignature: newer.registrationSignature, source: newer.source,
            profile: relayProfile(pin: pin, candidate: candidate, now: now)
        )
        return (merged, .unchanged)
    }
    if unsigned {
        throw ACEError(.stalePeerBinding, "an unsigned source cannot rotate a pinned encryption key")
    }
    if candidate.registeredAt > pin.registeredAt { return (candidate, .rotated) }
    throw ACEError(.stalePeerBinding, "a different encryption key requires a newer registeredAt")
}

// MARK: - Well-known fetch

private let domainRegex = try! NSRegularExpression(
    pattern: "^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*\\.[a-zA-Z]{2,}$"
)

/// 0/8, 10/8, 100.64/10, 127/8, 169.254/16, 172.16/12, 192.0.0/24, 192.0.2/24, 192.168/16,
/// 198.18/15, 198.51.100/24, 203.0.113/24, 224/4, 240/4.
func isBlockedIPv4(_ a: [UInt8]) -> Bool {
    let (b0, b1, b2) = (a[0], a[1], a[2])
    switch b0 {
    case 0, 10, 127: return true
    case 100: return b1 & 0xC0 == 64
    case 169: return b1 == 254
    case 172: return b1 & 0xF0 == 16
    case 192: return (b1 == 0 && (b2 == 0 || b2 == 2)) || b1 == 168
    case 198: return b1 & 0xFE == 18 || (b1 == 51 && b2 == 100)
    case 203: return b1 == 0 && b2 == 113
    default: return b0 >= 224
    }
}

/// ::ffff:0:0/96 and 64:ff9b::/96 (embedded IPv4 judged); ::/96 (IPv4-compatible, includes
/// :: and ::1), ::ffff:0:0:0/96 (SIIT), 64:ff9b:1::/48, 100::/64, 2001::/32 (Teredo),
/// 2001:db8::/32, 2002::/16 (6to4), fc00::/7, fe80::/10, ff00::/8.
func isBlockedIPv6(_ a: [UInt8]) -> Bool {
    let prefix96 = Array(a[0..<12])
    if prefix96 == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF]
        || prefix96 == [0, 0x64, 0xFF, 0x9B, 0, 0, 0, 0, 0, 0, 0, 0] {
        return isBlockedIPv4(Array(a[12..<16]))
    }
    // IPv4-embedding transition ranges are blocked whole, whatever the embedded IPv4.
    if prefix96 == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] { return true }  // ::/96 (incl. :: and ::1)
    if prefix96 == [0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 0, 0] { return true }  // ::ffff:0:0:0/96
    if Array(a[0..<6]) == [0, 0x64, 0xFF, 0x9B, 0, 1] { return true }  // 64:ff9b:1::/48
    if a[0] == 0x01 && a[1] == 0x00 && a[2..<8].allSatisfy({ $0 == 0 }) { return true }
    if a[0] == 0x20 && a[1] == 0x01 && a[2] == 0x00 && a[3] == 0x00 { return true }  // 2001::/32
    if a[0] == 0x20 && a[1] == 0x01 && a[2] == 0x0D && a[3] == 0xB8 { return true }
    if a[0] == 0x20 && a[1] == 0x02 { return true }  // 2002::/16
    if a[0] & 0xFE == 0xFC { return true }
    if a[0] == 0xFE && a[1] & 0xC0 == 0x80 { return true }
    return a[0] == 0xFF
}

/// True when `address` is an IP literal in a blocked range (08 § Client Rules, Blocked
/// Addresses), or is not an IP literal at all (never treated as allowed). IPv4-mapped and
/// NAT64 (`64:ff9b::/96`) IPv6 addresses are judged by their embedded IPv4 address; other
/// IPv4-embedding transition ranges are blocked whole; an IPv6 `%zone` suffix is ignored.
public func isBlockedAddress(_ address: String) -> Bool {
    var address = address
    if address.contains(":"), let zone = address.firstIndex(of: "%") {
        address = String(address[..<zone])  // an IPv6 %zone is ignored
    }
    var v4 = in_addr()
    if inet_pton(AF_INET, address, &v4) == 1 {
        return withUnsafeBytes(of: v4) { isBlockedIPv4(Array($0)) }
    }
    var v6 = in6_addr()
    if inet_pton(AF_INET6, address, &v6) == 1 {
        return withUnsafeBytes(of: v6) { isBlockedIPv6(Array($0)) }
    }
    return true
}

/// The resolved addresses of `host` (IPv4 as 4 bytes, IPv6 as 16), or nil when resolution
/// fails or yields nothing. An IP literal resolves to itself.
func resolveAddresses(_ host: String) -> [[UInt8]]? {
    var hints = addrinfo()
    hints.ai_socktype = SOCK_STREAM
    hints.ai_protocol = IPPROTO_TCP
    var res: UnsafeMutablePointer<addrinfo>?
    guard getaddrinfo(host, "443", &hints, &res) == 0, let first = res else { return nil }
    defer { freeaddrinfo(first) }
    var out: [[UInt8]] = []
    var p: UnsafeMutablePointer<addrinfo>? = first
    while let ai = p {
        defer { p = ai.pointee.ai_next }
        guard let sa = ai.pointee.ai_addr else { continue }
        if ai.pointee.ai_family == AF_INET {
            let addr = sa.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { $0.pointee.sin_addr }
            out.append(withUnsafeBytes(of: addr) { Array($0) })
        } else if ai.pointee.ai_family == AF_INET6 {
            let addr = sa.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { $0.pointee.sin6_addr }
            out.append(withUnsafeBytes(of: addr) { Array($0) })
        }
    }
    return out.isEmpty ? nil : out
}

func isBlockedRaw(_ a: [UInt8]) -> Bool { a.count == 4 ? isBlockedIPv4(a) : isBlockedIPv6(a) }

/// Resolve `domain` with `getaddrinfo` and reject if any address is in a blocked range.
func resolveAndCheck(_ domain: String, allowPrivate: Bool) throws {
    guard let addresses = resolveAddresses(domain) else {
        throw ACEError(.fetchFailed, "DNS resolution failed for \(String(domain.prefix(100)))")
    }
    if !allowPrivate, addresses.contains(where: isBlockedRaw) {
        throw ACEError(.blockedAddress, "\(String(domain.prefix(100))) resolves to a blocked address")
    }
}

/// Task delegate that refuses every HTTP redirect: the 3xx response itself is returned.
final class NoRedirectDelegate: NSObject, URLSessionTaskDelegate, Sendable {
    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest request: URLRequest) async -> URLRequest? {
        nil
    }
}

/// GET `https://<domain>/.well-known/ace.json` with SSRF protection, then verify it.
///
/// - The domain must match the strict domain grammar (`invalid_argument`).
/// - `getaddrinfo` resolves the domain; any address in a private / reserved range is
///   `blocked_address` unless `allowPrivateAddresses`.
/// - Redirects are never followed; the content type must be `application/json`; at most
///   `maxBytes + 1` bytes are read (`URLSession.bytes`, counting abort).
/// - Network errors, timeouts, 5xx and 429 are `fetch_failed`; everything else
///   (other statuses, size, JSON, rule violations) is `invalid_registration`.
///
/// Residual risk: URLSession re-resolves the domain when connecting, so a resolver that
/// answers differently after the check (DNS rebinding) is not excluded by the address
/// check alone. Because only HTTPS with certificate validation is used, a rebind to an
/// internal address fails the TLS handshake (no valid certificate for `domain`) before
/// any HTTP bytes are sent, so no IP pinning is done here.
public func fetchRegistrationFile(
    _ domain: String,
    timeout: TimeInterval = 10,
    maxBytes: Int = ACELimits.maxRegistrationFileBytes,
    allowPrivateAddresses: Bool = false
) async throws -> RegistrationFile {
    guard regexFull(domainRegex, domain) else { throw ACEError(.invalidArgument, "invalid domain") }
    guard timeout > 0, timeout.isFinite else { throw ACEError(.invalidArgument, "timeout must be positive") }
    guard maxBytes >= 1 else { throw ACEError(.invalidArgument, "maxBytes must be a positive integer") }
    try resolveAndCheck(domain, allowPrivate: allowPrivateAddresses)
    guard let url = URL(string: "https://\(domain)/.well-known/ace.json") else {
        throw ACEError(.invalidArgument, "invalid domain")
    }
    var request = URLRequest(url: url)
    request.timeoutInterval = timeout
    request.setValue("application/json", forHTTPHeaderField: "Accept")
    let config = URLSessionConfiguration.ephemeral
    config.timeoutIntervalForRequest = timeout
    config.timeoutIntervalForResource = timeout
    let session = URLSession(configuration: config, delegate: NoRedirectDelegate(), delegateQueue: nil)
    defer { session.finishTasksAndInvalidate() }

    var body = Data()
    do {
        let (bytes, response) = try await session.bytes(for: request)
        guard let http = response as? HTTPURLResponse else { throw ACEError(.fetchFailed, "not an HTTP response") }
        if http.statusCode >= 500 || http.statusCode == 429 {
            throw ACEError(.fetchFailed, "HTTP \(http.statusCode)", status: http.statusCode)
        }
        guard http.statusCode == 200 else {
            throw ACEError(.invalidRegistration, "HTTP \(http.statusCode) (redirects are not followed)", status: http.statusCode)
        }
        guard mediaType(http) == "application/json" else {
            throw ACEError(.invalidRegistration, "content-type must be application/json")
        }
        for try await byte in bytes {
            body.append(byte)
            if body.count > maxBytes { break }
        }
    } catch let e as ACEError {
        throw e
    } catch {
        throw ACEError(.fetchFailed, "fetch failed: \(error.localizedDescription)")
    }
    guard body.count <= maxBytes else {
        throw ACEError(.invalidRegistration, "registration file exceeds \(maxBytes) bytes")
    }
    let reg = try RegistrationFile(json: body)
    _ = try verifyRegistrationFile(reg)
    return reg
}
