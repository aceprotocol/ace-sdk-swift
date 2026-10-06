//
//  Identity.swift
//  ACE SDK
//
//  SoftwareIdentity — Tier 0 (software) implementation of ACEIdentity.
//  Supports Ed25519 and secp256k1 signing schemes.
//
//  SECURITY NOTE: Private keys are held in process memory.
//  For production use with high-value keys, implement ACEIdentity
//  with hardware backing (Tier 1/2) — see TigerPass/SoulPass CLIs
//  for Secure Enclave examples.
//

import Foundation
import CryptoKit
import P256K

public final class SoftwareIdentity: ACEIdentity, @unchecked Sendable {

    private let scheme: SigningScheme
    private let signingPrivateKey: Data
    /// 32-byte X-Wing private key seed (expands to ML-KEM-768 + X25519 keys).
    private let encryptionSeed: Data
    /// The seed expanded once, so each decrypt skips SHAKE256 + ML-KEM keygen.
    private let decapsulationKey: XWingMLKEM768X25519.PrivateKey
    private let signingPublicKey: Data
    private let encryptionPublicKey: Data
    private let aceId: String
    private let address: String
    // Cached typed private key to avoid per-call reconstruction
    private let ed25519SigningKey: Curve25519.Signing.PrivateKey?
    private let secp256k1SigningKey: P256K.Recovery.PrivateKey?

    private init(scheme: SigningScheme, signingPrivateKey: Data, encryptionSeed: Data) throws {
        self.scheme = scheme
        self.signingPrivateKey = signingPrivateKey
        self.encryptionSeed = encryptionSeed
        self.decapsulationKey = try ACEEncryption.privateKey(fromSeed: encryptionSeed)
        self.encryptionPublicKey = Data(decapsulationKey.publicKey.rawRepresentation)

        switch scheme {
        case .ed25519:
            let privKey = try Curve25519.Signing.PrivateKey(rawRepresentation: signingPrivateKey)
            self.signingPublicKey = Data(privKey.publicKey.rawRepresentation)
            self.ed25519SigningKey = privKey
            self.secp256k1SigningKey = nil
            self.address = Base58.encode(Data(privKey.publicKey.rawRepresentation))

        case .secp256k1:
            let privKey = try P256K.Recovery.PrivateKey(dataRepresentation: [UInt8](signingPrivateKey))
            let compressed = Data(privKey.publicKey.dataRepresentation)
            self.signingPublicKey = compressed
            self.ed25519SigningKey = nil
            self.secp256k1SigningKey = privKey
            self.address = try ACE.secp256k1Address(compressed)
        }

        self.aceId = computeACEId(self.signingPublicKey)
    }

    // MARK: - Factory Methods

    /// Generate a new random identity.
    public static func generate(scheme: SigningScheme) throws -> SoftwareIdentity {
        let encSeed = ACEEncryption.generateSeed()
        let sigPriv: Data

        switch scheme {
        case .ed25519:
            let key = Curve25519.Signing.PrivateKey()
            sigPriv = Data(key.rawRepresentation)
        case .secp256k1:
            let key = try P256K.Recovery.PrivateKey()
            sigPriv = Data(key.dataRepresentation)
        }

        return try SoftwareIdentity(scheme: scheme, signingPrivateKey: sigPriv, encryptionSeed: encSeed)
    }

    /// Import from exported key material.
    /// `encryptionPrivateKey` is the Base64 of the 32-byte X-Wing seed.
    public static func fromExport(_ export: SoftwareIdentityExport) throws -> SoftwareIdentity {
        let sigPriv = try ACEBase64.decode(export.signingPrivateKey)
        let encSeed = try ACEBase64.decode(export.encryptionPrivateKey)
        return try SoftwareIdentity(scheme: export.scheme, signingPrivateKey: sigPriv, encryptionSeed: encSeed)
    }

    // MARK: - ACEIdentity Conformance

    public func getEncryptionPublicKey() -> Data {
        encryptionPublicKey
    }

    public func getSigningPublicKey() -> Data {
        signingPublicKey
    }

    public func sign(_ data: Data) throws -> (signature: Data, scheme: SigningScheme) {
        switch scheme {
        case .ed25519:
            guard let key = ed25519SigningKey else {
                throw ACEError.invalidKey("Ed25519 signing key not available")
            }
            let sig = try key.signature(for: data)
            return (signature: Data(sig), scheme: .ed25519)

        case .secp256k1:
            guard let privKey = secp256k1SigningKey else {
                throw ACEError.invalidKey("secp256k1 signing key not available")
            }
            // Sign pre-computed hash (signData is already SHA-256)
            let digest = HashDigest([UInt8](data))
            let ecdsaSig = privKey.signature(for: digest)
            let compact = ecdsaSig.compactRepresentation

            // r[32] || s[32] || v[1]. libsecp256k1 always emits low-S, as ACE verifiers require.
            var sigBytes = Data(compact.signature)
            sigBytes.append(UInt8(compact.recoveryId))

            return (signature: sigBytes, scheme: .secp256k1)
        }
    }

    public func decrypt(kemCiphertext: Data, payload: Data, conversationId: String) throws -> Data {
        return try ACEEncryption.decrypt(
            kemCiphertext: kemCiphertext,
            payload: payload,
            privateKey: decapsulationKey,
            conversationId: conversationId
        )
    }

    public func getAddress() -> String {
        address
    }

    public func getSigningScheme() -> SigningScheme {
        scheme
    }

    public func getTier() -> IdentityTier {
        .keyOnly
    }

    public func getACEId() -> String {
        aceId
    }

    // MARK: - Export

    /// Export private key material. Handle with extreme care.
    public func exportPrivateKey() -> SoftwareIdentityExport {
        SoftwareIdentityExport(
            scheme: scheme,
            signingPrivateKey: ACEBase64.encode(signingPrivateKey),
            encryptionPrivateKey: ACEBase64.encode(encryptionSeed)
        )
    }

    /// Generate a registration file for this identity.
    public func toRegistrationFile(
        name: String,
        endpoint: String,
        description: String? = nil,
        hardwareBacking: HardwareBacking? = nil,
        capabilities: [Capability]? = nil,
        settlement: [String]? = nil,
        chains: [ChainInfo]? = nil
    ) -> RegistrationFile {
        var signing = SigningConfig(
            scheme: scheme,
            address: address,
            encryptionPublicKey: ACEBase64.encode(encryptionPublicKey)
        )
        if scheme == .secp256k1 {
            signing.signingPublicKey = ACEBase64.encode(signingPublicKey)
        }

        return RegistrationFile(
            ace: "1.0",
            id: aceId,
            name: name,
            description: description,
            endpoint: endpoint,
            tier: getTier(),
            hardwareBacking: hardwareBacking,
            signing: signing,
            capabilities: capabilities,
            settlement: settlement,
            chains: chains
        )
    }
}

// MARK: - Export Type

public struct SoftwareIdentityExport: Codable, Sendable {
    public let scheme: SigningScheme
    public let signingPrivateKey: String // Base64
    public let encryptionPrivateKey: String // Base64 (32-byte X-Wing seed)

    public init(scheme: SigningScheme, signingPrivateKey: String, encryptionPrivateKey: String) {
        self.scheme = scheme
        self.signingPrivateKey = signingPrivateKey
        self.encryptionPrivateKey = encryptionPrivateKey
    }
}
