//
//  Identity.swift
//  ACE SDK
//
//  SoftwareIdentity — Tier 0 (software) ACEIdentity. Keys are held in process memory;
//  use a hardware-backed ACEIdentity (Secure Enclave, HSM) for high-value deployments.
//

import Foundation
import CryptoKit
import P256K

/// Exported private key material: `{scheme, signingPrivateKey: b64, encryptionPrivateKey: b64}`.
/// `encryptionPrivateKey` is the 32-byte X-Wing seed.
public struct SoftwareIdentityExport: Codable, Sendable, Equatable {
    public let scheme: SigningScheme
    public let signingPrivateKey: String
    public let encryptionPrivateKey: String

    public init(scheme: SigningScheme, signingPrivateKey: String, encryptionPrivateKey: String) {
        self.scheme = scheme
        self.signingPrivateKey = signingPrivateKey
        self.encryptionPrivateKey = encryptionPrivateKey
    }
}

/// Software ACE identity. Caches its expanded X-Wing key in memory (never persisted).
public final class SoftwareIdentity: ACEIdentity, @unchecked Sendable {
    private let scheme: SigningScheme
    private let signingPrivateKey: Data
    private let encryptionSeed: Data
    private let decapsulationKey: XWingMLKEM768X25519.PrivateKey
    private let signingPublicKey: Data
    private let encryptionPublicKey: Data
    private let aceId: String
    private let ed25519Key: Curve25519.Signing.PrivateKey?
    private let secp256k1Key: P256K.Recovery.PrivateKey?

    /// Build from raw keys. A 32-byte signing private key and a 32-byte X-Wing seed are
    /// required (`invalid_key`).
    public init(scheme: SigningScheme, signingPrivateKey: Data, encryptionSeed: Data) throws {
        guard signingPrivateKey.count == 32 else { throw ACEError(.invalidKey, "signing private key must be 32 bytes") }
        self.scheme = scheme
        self.signingPrivateKey = signingPrivateKey
        self.encryptionSeed = encryptionSeed
        self.decapsulationKey = try ACEEncryption.expandSeed(encryptionSeed)
        self.encryptionPublicKey = Data(decapsulationKey.publicKey.rawRepresentation)
        switch scheme {
        case .ed25519:
            let key: Curve25519.Signing.PrivateKey
            do { key = try Curve25519.Signing.PrivateKey(rawRepresentation: signingPrivateKey) } catch {
                throw ACEError(.invalidKey, "invalid ed25519 private key")
            }
            self.ed25519Key = key
            self.secp256k1Key = nil
            self.signingPublicKey = Data(key.publicKey.rawRepresentation)
        case .secp256k1:
            let key: P256K.Recovery.PrivateKey
            do { key = try P256K.Recovery.PrivateKey(dataRepresentation: [UInt8](signingPrivateKey)) } catch {
                throw ACEError(.invalidKey, "secp256k1 private key out of range")
            }
            self.ed25519Key = nil
            self.secp256k1Key = key
            self.signingPublicKey = Data(key.publicKey.dataRepresentation)
        }
        self.aceId = computeACEId(signingPublicKey)
    }

    /// Import exported key material (`invalid_key` on malformed Base64 or key sizes).
    public convenience init(export: SoftwareIdentityExport) throws {
        try self.init(
            scheme: export.scheme,
            signingPrivateKey: try decodeB64(export.signingPrivateKey, code: .invalidKey, what: "signingPrivateKey"),
            encryptionSeed: try decodeB64(export.encryptionPrivateKey, code: .invalidKey, what: "encryptionPrivateKey")
        )
    }

    /// Generate a new random identity.
    public static func generate(scheme: SigningScheme) throws -> SoftwareIdentity {
        let signing: Data
        switch scheme {
        case .ed25519:
            signing = Curve25519.Signing.PrivateKey().rawRepresentation
        case .secp256k1:
            signing = Data(try P256K.Recovery.PrivateKey().dataRepresentation)
        }
        return try SoftwareIdentity(scheme: scheme, signingPrivateKey: signing, encryptionSeed: ACEEncryption.generateSeed())
    }

    // MARK: ACEIdentity

    public func getACEId() -> String { aceId }
    public func getSigningScheme() -> SigningScheme { scheme }
    public func getSigningPublicKey() -> Data { signingPublicKey }
    public func getEncryptionPublicKey() -> Data { encryptionPublicKey }

    /// Sign a 32-byte signData digest. secp256k1 returns r‖s‖v (low-S, v ∈ {0,1}).
    public func sign(_ data: Data) throws -> Data {
        guard data.count == 32 else { throw ACEError(.invalidArgument, "signData must be 32 bytes") }
        if let ed25519Key {
            do { return try ed25519Key.signature(for: data) } catch {
                throw ACEError(.invalidKey, "ed25519 signing failed")
            }
        }
        guard let secp256k1Key else { throw ACEError(.invalidKey, "no signing key") }
        let compact = secp256k1Key.signature(for: HashDigest([UInt8](data))).compactRepresentation
        var out = Data(compact.signature)
        out.append(UInt8(compact.recoveryId))
        return out
    }

    public func decrypt(kemCiphertext: Data, payload: Data, conversationId: String) throws -> Data {
        try ACEEncryption.decrypt(kemCiphertext: kemCiphertext, payload: payload, privateKey: decapsulationKey, conversationId: conversationId)
    }

    // MARK: Convenience

    /// ed25519: Base58 of the signing key. secp256k1: EIP-55 address.
    public func getAddress() -> String {
        signingAddress(scheme: scheme, signingPublicKey: signingPublicKey)
    }

    /// Export private key material. Handle with extreme care.
    public func exportPrivateKey() -> SoftwareIdentityExport {
        SoftwareIdentityExport(
            scheme: scheme,
            signingPrivateKey: ACEBase64.encode(signingPrivateKey),
            encryptionPrivateKey: ACEBase64.encode(encryptionSeed)
        )
    }

    /// `createRegistrationFile(for: self, …)`.
    public func toRegistrationFile(
        name: String,
        endpoint: String,
        description: String? = nil,
        tier: IdentityTier = .keyOnly,
        hardwareBacking: HardwareBacking? = nil,
        capabilities: [Capability]? = nil,
        settlement: [String]? = nil,
        chains: [ChainInfo]? = nil
    ) throws -> RegistrationFile {
        try createRegistrationFile(for: self, name: name, endpoint: endpoint, description: description, tier: tier,
                                   hardwareBacking: hardwareBacking, capabilities: capabilities, settlement: settlement,
                                   chains: chains)
    }
}

/// The registration file (01) of any identity, built from its public keys and verified
/// with `verifyRegistrationFile` before it is returned (`invalid_registration` /
/// `invalid_key` when a field or key is invalid). Works for custom identities
/// (Secure Enclave, HSM): `verifyRegistrationFile(createRegistrationFile(for: id, …))` yields
/// a `VerifiedPeer` without hand-building the file.
///
/// `signing.address` is Base58(signing key) for ed25519 and the EIP-55 address for
/// secp256k1, which also carries `signingPublicKey`.
public func createRegistrationFile(
    for identity: any ACEIdentity,
    name: String,
    endpoint: String,
    description: String? = nil,
    tier: IdentityTier = .keyOnly,
    hardwareBacking: HardwareBacking? = nil,
    capabilities: [Capability]? = nil,
    settlement: [String]? = nil,
    chains: [ChainInfo]? = nil
) throws -> RegistrationFile {
    let scheme = identity.getSigningScheme()
    let signingPublicKey = identity.getSigningPublicKey()
    let reg = RegistrationFile(
        ace: "1.0",
        id: identity.getACEId(),
        name: name,
        description: description,
        endpoint: endpoint,
        tier: tier,
        hardwareBacking: hardwareBacking,
        signing: SigningConfig(
            scheme: scheme,
            address: signingAddress(scheme: scheme, signingPublicKey: signingPublicKey),
            signingPublicKey: scheme == .secp256k1 ? ACEBase64.encode(signingPublicKey) : nil,
            encryptionPublicKey: ACEBase64.encode(identity.getEncryptionPublicKey())
        ),
        capabilities: capabilities,
        settlement: settlement,
        chains: chains
    )
    _ = try verifyRegistrationFile(reg, pinnedAt: 0)
    return reg
}
