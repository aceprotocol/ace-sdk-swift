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
    private let encryptionPrivateKey: Curve25519.KeyAgreement.PrivateKey
    private let signingPublicKey: Data
    private let encryptionPublicKey: Data
    private let aceId: String
    private let address: String
    // Cached typed private key to avoid per-call reconstruction
    private let ed25519SigningKey: Curve25519.Signing.PrivateKey?
    private let secp256k1SigningKey: P256K.Recovery.PrivateKey?

    private init(scheme: SigningScheme, signingPrivateKey: Data, encryptionPrivateKey: Curve25519.KeyAgreement.PrivateKey) throws {
        self.scheme = scheme
        self.signingPrivateKey = signingPrivateKey
        self.encryptionPrivateKey = encryptionPrivateKey
        self.encryptionPublicKey = Data(encryptionPrivateKey.publicKey.rawRepresentation)

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
        let encPriv = Curve25519.KeyAgreement.PrivateKey()
        let sigPriv: Data

        switch scheme {
        case .ed25519:
            let key = Curve25519.Signing.PrivateKey()
            sigPriv = Data(key.rawRepresentation)
        case .secp256k1:
            let key = try P256K.Recovery.PrivateKey()
            sigPriv = Data(key.dataRepresentation)
        }

        return try SoftwareIdentity(scheme: scheme, signingPrivateKey: sigPriv, encryptionPrivateKey: encPriv)
    }

    /// Import from exported key material.
    public static func fromExport(_ export: SoftwareIdentityExport) throws -> SoftwareIdentity {
        let sigPriv = try ACEBase64.decode(export.signingPrivateKey)
        let encPrivBytes = try ACEBase64.decode(export.encryptionPrivateKey)
        let encPriv = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: encPrivBytes)
        return try SoftwareIdentity(scheme: export.scheme, signingPrivateKey: sigPriv, encryptionPrivateKey: encPriv)
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
            let ecdsaSig = try privKey.signature(for: digest)
            let compact = try ecdsaSig.compactRepresentation

            // Extract r, s, v
            var sigBytes = Data(compact.signature)
            let recoveryId = compact.recoveryId

            // Low-S normalization
            let order = secp256k1Order
            let s = sigBytes.suffix(32)
            let halfOrder = order.shiftedRight()
            if s.lexicographicallyPrecedes(halfOrder) == false && s != halfOrder {
                // s > order/2 → s = order - s, flip v
                let newS = order.subtract(Data(s))
                sigBytes.replaceSubrange(32..<64, with: newS)
                // Append flipped recovery ID
                sigBytes.append(UInt8(recoveryId ^ 1))
            } else {
                sigBytes.append(UInt8(recoveryId))
            }

            return (signature: sigBytes, scheme: .secp256k1)
        }
    }

    public func decrypt(ephemeralPubKey: Data, payload: Data, conversationId: String) throws -> Data {
        return try ACEEncryption.decrypt(
            ephemeralPubKey: ephemeralPubKey,
            payload: payload,
            recipientPrivateKey: encryptionPrivateKey,
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
            encryptionPrivateKey: ACEBase64.encode(Data(encryptionPrivateKey.rawRepresentation))
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
    public let encryptionPrivateKey: String // Base64

    public init(scheme: SigningScheme, signingPrivateKey: String, encryptionPrivateKey: String) {
        self.scheme = scheme
        self.signingPrivateKey = signingPrivateKey
        self.encryptionPrivateKey = encryptionPrivateKey
    }
}

// MARK: - secp256k1 Order (for low-S normalization)

/// secp256k1 curve order N
private let secp256k1Order: Data = {
    let hex = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"
    return try! ACEHex.decode(hex)
}()

// Big-endian 256-bit arithmetic helpers for low-S normalization
private extension Data {
    func shiftedRight() -> Data {
        var result = [UInt8](repeating: 0, count: count)
        var carry: UInt8 = 0
        for i in 0..<count {
            let byte = self[startIndex + i]
            result[i] = (byte >> 1) | (carry << 7)
            carry = byte & 1
        }
        return Data(result)
    }

    func subtract(_ other: Data) -> Data {
        // self - other (big-endian, assumes self >= other)
        precondition(count == other.count, "subtract requires equal-length Data (\(count) vs \(other.count))")
        var result = [UInt8](repeating: 0, count: count)
        var borrow: Int = 0
        for i in stride(from: count - 1, through: 0, by: -1) {
            let diff = Int(self[startIndex + i]) - Int(other[other.startIndex + i]) - borrow
            if diff < 0 {
                result[i] = UInt8((diff + 256) & 0xFF)
                borrow = 1
            } else {
                result[i] = UInt8(diff)
                borrow = 0
            }
        }
        return Data(result)
    }
}
