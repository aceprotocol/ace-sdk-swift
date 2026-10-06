//
//  Registration.swift
//  ACE SDK
//
//  Relay registration requests: public key binding plus private write authorization.
//

import Foundation

/// An explicit registration mutation. `keep` omits the profile; `remove` sends `null`.
public enum RegistrationProfile: Sendable, Equatable {
    case keep
    case remove
    case replace(AgentProfile)
}

/// `POST /v1/register` body.
public struct RegistrationRequest: Encodable, Sendable, Equatable {
    public let aceId: String
    public let encryptionPublicKey: String
    public let signingPublicKey: String
    public let scheme: SigningScheme
    public let timestamp: Int
    public let signature: String
    public let authorization: String
    public let profile: RegistrationProfile

    private enum CodingKeys: String, CodingKey {
        case aceId, encryptionPublicKey, signingPublicKey, scheme, timestamp, signature, authorization, profile
    }

    public func encode(to encoder: any Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(aceId, forKey: .aceId)
        try c.encode(encryptionPublicKey, forKey: .encryptionPublicKey)
        try c.encode(signingPublicKey, forKey: .signingPublicKey)
        try c.encode(scheme, forKey: .scheme)
        try c.encode(timestamp, forKey: .timestamp)
        try c.encode(signature, forKey: .signature)
        try c.encode(authorization, forKey: .authorization)
        switch profile {
        case .keep: break
        case .remove: try c.encodeNil(forKey: .profile)
        case .replace(let p): try c.encode(p, forKey: .profile)
        }
    }

    /// The wire JSON (compact, keys sorted).
    public func jsonData() -> Data {
        JSONWriter.serialize(jvalue)
    }

    var jvalue: JValue {
        var o: [String: JValue] = [
            "aceId": .string(aceId), "encryptionPublicKey": .string(encryptionPublicKey),
            "signingPublicKey": .string(signingPublicKey), "scheme": .string(scheme.rawValue),
            "timestamp": .number(String(timestamp)), "signature": .string(signature),
            "authorization": .string(authorization),
        ]
        switch profile {
        case .keep: break
        case .remove: o["profile"] = .null
        case .replace(let p): o["profile"] = p.jvalue
        }
        return .object(o)
    }
}

/// The `register-request` payload (02).
func registrationPayload(encryptionPublicKey: String, signingPublicKey: String, scheme: SigningScheme, profile: RegistrationProfile) -> Data {
    var fields: [ACESigning.Field] = [.string(encryptionPublicKey), .string(signingPublicKey), .string(scheme.rawValue)]
    switch profile {
    case .keep: fields.append(.string("keep"))
    case .remove: fields.append(.string("remove"))
    case .replace(let p):
        fields += [
            .string("replace"), .string(p.name ?? ""), .string(p.description ?? ""), .string(p.image ?? ""),
            .data(ACESigning.encodePayload((p.tags ?? []).map { .string($0) })),
            .data(ACESigning.encodePayload((p.capabilities ?? []).map { .string($0) })),
            .data(ACESigning.encodePayload((p.chains ?? []).map { .string($0) })),
            .string(p.endpoint ?? ""), .string(p.pricing == nil ? "absent" : "present"),
            .string(p.pricing?.currency ?? ""), .string(p.pricing?.maxAmount ?? ""),
        ]
    }
    return ACESigning.encodePayload(fields)
}

/// Build a `POST /v1/register` body: the binding signature plus the authorization of
/// this exact mutation. A replacement profile is validated (`invalid_profile`).
public func createRegistrationRequest(
    identity: any ACEIdentity,
    profile: RegistrationProfile = .keep,
    timestamp: Int? = nil
) throws -> RegistrationRequest {
    let ts = timestamp ?? systemClock()
    guard isWireInt(ts) else {
        throw ACEError(.invalidArgument, "timestamp must be an integer in [0, 2^53-1]")
    }
    let enc = identity.getEncryptionPublicKey()
    guard enc.count == ACELimits.kemPublicKeySize else {
        throw ACEError(.invalidKey, "identity encryption public key must be \(ACELimits.kemPublicKeySize) bytes")
    }
    if case .replace(let p) = profile { try validateProfile(p) }
    let epk = ACEBase64.encode(enc), spk = ACEBase64.encode(identity.getSigningPublicKey())
    let aceId = identity.getACEId(), scheme = identity.getSigningScheme()
    let signature = try identity.sign(try bindingSignData(aceId: aceId, timestamp: ts, encryptionPublicKey: epk, signingPublicKey: spk))
    let authorization = try identity.sign(try ACESigning.buildSignData(
        action: "register-request", aceId: aceId, timestamp: ts,
        payload: registrationPayload(encryptionPublicKey: epk, signingPublicKey: spk, scheme: scheme, profile: profile)
    ))
    return RegistrationRequest(
        aceId: aceId, encryptionPublicKey: epk, signingPublicKey: spk, scheme: scheme, timestamp: ts,
        signature: encodeSignature(signature, scheme: scheme),
        authorization: encodeSignature(authorization, scheme: scheme),
        profile: profile
    )
}

/// Result of `verifyRegistrationRequest`.
public struct VerifiedRegistration: Sendable {
    public let request: RegistrationRequest
    public let peer: VerifiedPeer
    /// Hex SHA-256 of the `register-request` signData.
    public let requestDigest: String
}

/// Verify a registration request body. Check order (first failure wins): schema →
/// `invalid_registration`; freshness → `stale_timestamp`; ID hash → `invalid_registration`;
/// signing / encryption key → `invalid_key`; profile → `invalid_profile`; binding →
/// `invalid_signature`; authorization → `invalid_authorization`. Unknown fields are ignored.
public func verifyRegistrationRequest(
    _ json: Data,
    clock: @Sendable () -> Int = systemClock,
    windowSeconds: Int = ACELimits.timestampWindowSeconds
) throws -> VerifiedRegistration {
    guard windowSeconds >= 0 else { throw ACEError(.invalidArgument, "windowSeconds must be a non-negative integer") }
    let code = ACEError.Code.invalidRegistration
    let v: JValue
    do { v = try JSONParser.parse(json) } catch { throw ACEError(code, "registration request is not JSON") }
    guard let body = v.objectValue else { throw ACEError(code, "registration request must be an object") }
    guard let aceId = body["aceId"]?.stringValue, isACEId(aceId),
          let schemeText = body["scheme"]?.stringValue, let scheme = SigningScheme(rawValue: schemeText),
          let ts = body["timestamp"]?.wireInt else {
        throw ACEError(code, "aceId, scheme and timestamp are required and well-formed")
    }
    guard let epk = body["encryptionPublicKey"]?.stringValue, let spk = body["signingPublicKey"]?.stringValue else {
        throw ACEError(code, "encryptionPublicKey and signingPublicKey must be strings")
    }
    guard let sigText = body["signature"]?.stringValue else { throw ACEError(code, "signature must be a string") }
    let sig = try decodeSignature(sigText, scheme: scheme, code: code)
    guard let authText = body["authorization"]?.stringValue else { throw ACEError(code, "authorization must be a string") }
    let auth = try decodeSignature(authText, scheme: scheme, code: code)
    let hasProfile = body["profile"] != nil
    let rawProfile = body["profile"]
    if let rawProfile, !rawProfile.isNull, rawProfile.objectValue == nil {
        throw ACEError(code, "profile must be an object or null")
    }
    let spkBytes = try decodeB64(spk, code: code, what: "signingPublicKey", maxBytes: 64)
    _ = try decodeB64(epk, code: code, what: "encryptionPublicKey", maxBytes: ACELimits.kemPublicKeySize + 3)
    let now = clock()
    guard abs(now - ts) <= windowSeconds else {
        throw ACEError(.staleTimestamp, "registration timestamp is outside the freshness window")
    }
    guard computeACEId(spkBytes) == aceId else { throw ACEError(code, "aceId does not match signingPublicKey") }
    let signingKey = try decodeSigningKey(scheme: scheme, spk, code: .invalidKey)
    let encKey = try ACEEncryption.decodeKemPublicKey(epk, code: .invalidKey)
    var profile: AgentProfile?
    if let rawProfile, !rawProfile.isNull {
        let p = try AgentProfile.parse(rawProfile)
        try validateProfile(p)
        profile = p
    }
    guard ACESigning.verify(signData: try bindingSignData(aceId: aceId, timestamp: ts, encryptionPublicKey: epk, signingPublicKey: spk),
                            signature: sig, scheme: scheme, publicKey: signingKey) else {
        throw ACEError(.invalidSignature, "registration binding signature does not verify")
    }
    let mutation: RegistrationProfile = !hasProfile ? .keep : (profile.map { .replace($0) } ?? .remove)
    let requestSignData = try ACESigning.buildSignData(
        action: "register-request", aceId: aceId, timestamp: ts,
        payload: registrationPayload(encryptionPublicKey: epk, signingPublicKey: spk, scheme: scheme, profile: mutation)
    )
    guard ACESigning.verify(signData: requestSignData, signature: auth, scheme: scheme, publicKey: signingKey) else {
        throw ACEError(.invalidAuthorization, "registration authorization does not verify")
    }
    let request = RegistrationRequest(aceId: aceId, encryptionPublicKey: epk, signingPublicKey: spk, scheme: scheme,
                                      timestamp: ts, signature: sigText, authorization: authText, profile: mutation)
    let peer = VerifiedPeer(aceId: aceId, scheme: scheme, signingPublicKey: signingKey, encryptionPublicKey: encKey,
                            registeredAt: ts, registrationSignature: sigText, source: .relay, profile: profile)
    return VerifiedRegistration(request: request, peer: peer, requestDigest: sha256Hex(requestSignData))
}
