//
//  Encryption.swift
//  ACE SDK
//
//  X25519 ECDH + HKDF-SHA256 + AES-256-GCM encryption/decryption.
//
//  Encryption flow:
//    1. Generate ephemeral X25519 key pair (forward secrecy)
//    2. ECDH(ephemeralPriv, recipientPub) → SharedSecret
//    3. HKDF-SHA256(sharedSecret, salt=ACE_DH_SALT, info=conversationId) → AES-256 key
//    4. AES-256-GCM(key, nonce=random12, plaintext, aad=conversationId) → ciphertext
//    5. Output: nonce[12] || ciphertext || tag[16]
//

import Foundation
import CryptoKit

public enum ACEEncryption {

    // MARK: - Constants

    /// ACE Protocol DH HKDF salt: SHA-256("ace.protocol.dh.v1")
    /// Shared across all implementations (TS, PY, Swift).
    static let dhSalt = Data(SHA256.hash(data: Data("ace.protocol.dh.v1".utf8)))

    /// Public getter for the DH salt (read-only).
    public static func getDHSalt() -> Data { dhSalt }

    /// Maximum payload size (10 MB)
    public static let maxPayloadSize = 10 * 1024 * 1024

    /// Minimum payload: nonce[12] + GCM tag[16] = 28 bytes
    static let minPayloadLength = 28

    /// Maximum plaintext size
    public static let maxPlaintextSize = maxPayloadSize - minPayloadLength

    // MARK: - Conversation ID

    /// Compute deterministic conversation ID from two X25519 public keys.
    /// conversationId = hex(SHA-256(sort_bytes(pubA, pubB)))
    ///
    /// Sorting ensures symmetry: A→B and B→A produce the same ID.
    /// Variable-time comparison is safe here — these are public keys, not secrets.
    public static func computeConversationId(pubA: Data, pubB: Data) throws -> String {
        guard pubA.count == 32, pubB.count == 32 else {
            throw ACEError.invalidKey("X25519 public keys must be 32 bytes, got \(pubA.count) and \(pubB.count)")
        }
        let (first, second) = compareBytes(pubA, pubB) <= 0 ? (pubA, pubB) : (pubB, pubA)
        let combined = first + second
        let hash = Data(SHA256.hash(data: combined))
        return ACEHex.encode(hash)
    }

    // MARK: - Encrypt

    /// Encrypt plaintext for a recipient.
    ///
    /// - Parameters:
    ///   - plaintext: Raw message bytes
    ///   - recipientPublicKey: 32-byte X25519 public key
    ///   - conversationId: Used as HKDF info and AES-GCM AAD
    /// - Returns: Tuple of (ephemeralPubKey, payload) where payload = nonce[12] || ciphertext || tag[16]
    public static func encrypt(
        plaintext: Data,
        recipientPublicKey: Data,
        conversationId: String
    ) throws -> (ephemeralPubKey: Data, payload: Data) {
        // Validate
        try validatePublicKey(recipientPublicKey)
        guard plaintext.count <= maxPlaintextSize else {
            throw ACEError.payloadTooLarge(plaintext.count)
        }

        // 1. Generate ephemeral X25519 key pair
        let ephemeralPriv = Curve25519.KeyAgreement.PrivateKey()
        let ephemeralPub = ephemeralPriv.publicKey

        // 2. ECDH
        let recipientKey = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: recipientPublicKey)
        let sharedSecret = try ephemeralPriv.sharedSecretFromKeyAgreement(with: recipientKey)
        try validateSharedSecret(sharedSecret)

        // 3. HKDF key derivation
        let convIdBytes = Data(conversationId.utf8)
        let aesKey = sharedSecret.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: dhSalt,
            sharedInfo: convIdBytes,
            outputByteCount: 32
        )

        // 4. AES-256-GCM
        let nonce = AES.GCM.Nonce()
        let sealedBox = try AES.GCM.seal(plaintext, using: aesKey, nonce: nonce, authenticating: convIdBytes)

        // 5. payload = nonce[12] || ciphertext || tag[16]
        let payload = Data(nonce) + sealedBox.ciphertext + sealedBox.tag

        guard payload.count <= maxPayloadSize else {
            throw ACEError.payloadTooLarge(payload.count)
        }

        return (
            ephemeralPubKey: Data(ephemeralPub.rawRepresentation),
            payload: payload
        )
    }

    // MARK: - Decrypt

    /// Decrypt a message using the recipient's X25519 private key.
    ///
    /// - Parameters:
    ///   - ephemeralPubKey: 32-byte X25519 ephemeral public key from sender
    ///   - payload: nonce[12] || ciphertext || tag[16]
    ///   - recipientPrivateKey: Recipient's X25519 private key
    ///   - conversationId: Must match the one used during encryption
    /// - Returns: Decrypted plaintext
    public static func decrypt(
        ephemeralPubKey: Data,
        payload: Data,
        recipientPrivateKey: Curve25519.KeyAgreement.PrivateKey,
        conversationId: String
    ) throws -> Data {
        // Validate
        try validatePublicKey(ephemeralPubKey)
        guard payload.count >= minPayloadLength else {
            throw ACEError.decryptionFailed("Payload too short: expected at least \(minPayloadLength) bytes, got \(payload.count)")
        }
        guard payload.count <= maxPayloadSize else {
            throw ACEError.payloadTooLarge(payload.count)
        }

        // 1. ECDH
        let ephKey = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: ephemeralPubKey)
        let sharedSecret = try recipientPrivateKey.sharedSecretFromKeyAgreement(with: ephKey)
        try validateSharedSecret(sharedSecret)

        // 2. HKDF
        let convIdBytes = Data(conversationId.utf8)
        let aesKey = sharedSecret.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: dhSalt,
            sharedInfo: convIdBytes,
            outputByteCount: 32
        )

        // 3. Parse payload: nonce[12] || ciphertext || tag[16]
        let nonce = try AES.GCM.Nonce(data: payload.prefix(12))
        let ciphertext = payload.dropFirst(12).dropLast(16)
        let tag = payload.suffix(16)
        let sealedBox = try AES.GCM.SealedBox(nonce: nonce, ciphertext: ciphertext, tag: tag)

        // 4. Decrypt
        let plaintext = try AES.GCM.open(sealedBox, using: aesKey, authenticating: convIdBytes)
        return plaintext
    }

    // MARK: - Private Helpers

    /// All 9 canonical small-order X25519 points (orders 1, 2, 4, 8) that produce
    /// all-zero or predictable shared secrets. RFC 7748 §6 + twist companions.
    /// This blocklist is defense-in-depth; the ECDH zero-check below is the root safeguard.
    private static let smallOrderPoints: [Data] = [
        // Order 1 (neutral element)
        Data([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
              0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
        // Order 1 (p)
        Data([0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
              0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
        // Order 8
        Data([0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4, 0x6a,
              0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16, 0x5f, 0x49, 0xb8, 0x00]),
        // Order 8
        Data([0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83, 0xef, 0x5b,
              0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86, 0xd8, 0x22, 0x4e, 0xdd, 0xd0, 0x9f, 0x11, 0x57]),
        // Order 2 (p - 1)
        Data([0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
              0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f]),
        // Order 4 (p)
        Data([0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
              0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f]),
        // Order 8
        Data([0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
              0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f]),
        // Order 8 (twist companion, from Wycheproof test vectors)
        Data([0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f, 0xba, 0x3c, 0x0b, 0x76, 0x0d, 0x10, 0x67, 0x0f,
              0x2a, 0x20, 0x53, 0xfa, 0x2c, 0x39, 0xcc, 0xc6, 0x4e, 0xc7, 0xfd, 0x77, 0x92, 0xac, 0x03, 0x7a]),
        // Order 8 (twist companion)
        Data([0x47, 0xcd, 0xc1, 0x24, 0x97, 0x08, 0xf9, 0xe7, 0x92, 0xf2, 0x97, 0x99, 0x0f, 0xd1, 0xd8, 0x39,
              0xce, 0x72, 0xf4, 0x01, 0x63, 0xce, 0x4f, 0x2b, 0xa7, 0x4c, 0x7b, 0x3c, 0x40, 0x16, 0x52, 0x26]),
    ]

    /// Root safeguard: reject degenerate ECDH shared secrets (all-zero).
    /// This catches any small-subgroup attack regardless of blocklist completeness.
    private static func validateSharedSecret(_ secret: SharedSecret) throws {
        let isZero = secret.withUnsafeBytes { ptr in
            ptr.allSatisfy { $0 == 0 }
        }
        if isZero {
            throw ACEError.encryptionFailed("ECDH produced degenerate shared secret")
        }
    }

    /// Validate X25519 public key: must be 32 bytes, not a known small-order point.
    private static func validatePublicKey(_ pubKey: Data) throws {
        guard pubKey.count == 32 else {
            throw ACEError.invalidKey("X25519 public key must be 32 bytes, got \(pubKey.count)")
        }
        for weakPoint in smallOrderPoints {
            if pubKey == weakPoint {
                throw ACEError.invalidKey("Refusing to use known small-order X25519 public key (produces all-zero shared secret)")
            }
        }
    }

    /// Lexicographic byte comparison. Variable-time — safe for public keys only.
    private static func compareBytes(_ a: Data, _ b: Data) -> Int {
        for i in 0..<min(a.count, b.count) {
            if a[a.startIndex + i] != b[b.startIndex + i] {
                return Int(a[a.startIndex + i]) - Int(b[b.startIndex + i])
            }
        }
        return a.count - b.count
    }
}
