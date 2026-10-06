import Foundation

/// An explicit registration mutation. Omitted profile keeps it; null removes it.
public enum RegistrationProfile: Sendable {
    case keep
    case remove
    case replace(AgentProfile)
}

public struct RegistrationRequest: Encodable, Sendable {
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
        case .replace(let value): try c.encode(value, forKey: .profile)
        }
    }
}

/// Canonical length-prefixed mutation, identical in all SDKs. Array order matters.
public func buildRegistrationPayload(
    encryptionPublicKey: String, signingPublicKey: String, scheme: SigningScheme,
    profile: RegistrationProfile = .keep
) throws -> Data {
    var fields: [ACESigning.SignField] = [.string(encryptionPublicKey), .string(signingPublicKey), .string(scheme.rawValue)]
    switch profile {
    case .keep: fields.append(.string("keep"))
    case .remove: fields.append(.string("remove"))
    case .replace(let p):
        try validateProfile(p)
        fields += [.string("replace"), .string(p.name ?? ""), .string(p.description ?? ""), .string(p.image ?? ""),
                   .data(ACESigning.encodePayload((p.tags ?? []).map { .string($0) })),
                   .data(ACESigning.encodePayload((p.capabilities ?? []).map { .string($0) })),
                   .data(ACESigning.encodePayload((p.chains ?? []).map { .string($0) })),
                   .string(p.endpoint ?? ""), .string(p.pricing == nil ? "absent" : "present"),
                   .string(p.pricing?.currency ?? ""), .string(p.pricing?.maxAmount ?? "")]
    }
    return ACESigning.encodePayload(fields)
}

/// Sign a public key binding and a separate private write authorization.
public func createRegistrationRequest(
    identity: any ACEIdentity, profile: RegistrationProfile = .keep,
    timestamp: Int = Int(Date().timeIntervalSince1970)
) throws -> RegistrationRequest {
    guard timestamp >= 0 && timestamp <= 9_007_199_254_740_991 else {
        throw ACEError.invalidRegistration("Invalid registration timestamp")
    }
    let enc = identity.getEncryptionPublicKey()
    try ACEEncryption.validatePublicKey(enc)
    let epk = enc.base64EncodedString(), spk = identity.getSigningPublicKey().base64EncodedString()
    let aceId = identity.getACEId(), scheme = identity.getSigningScheme()
    let payload = try buildRegistrationPayload(encryptionPublicKey: epk, signingPublicKey: spk, scheme: scheme, profile: profile)
    let binding = ACESigning.buildSignData(action: "register", aceId: aceId, timestamp: timestamp,
                                          payload: ACESigning.encodePayload([.string(epk), .string(spk)]))
    let signature = try identity.sign(binding).signature
    let authorization = try identity.sign(ACESigning.buildSignData(action: "register-request", aceId: aceId, timestamp: timestamp, payload: payload)).signature
    return RegistrationRequest(aceId: aceId, encryptionPublicKey: epk, signingPublicKey: spk, scheme: scheme,
                               timestamp: timestamp, signature: ACESigning.encodeSignature(signature, scheme: scheme),
                               authorization: ACESigning.encodeSignature(authorization, scheme: scheme), profile: profile)
}
