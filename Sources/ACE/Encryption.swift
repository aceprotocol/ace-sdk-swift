//
//  Encryption.swift
//  ACE SDK
//
//  X-Wing hybrid KEM (X25519 + ML-KEM-768) + HKDF-SHA256 + AES-256-GCM.
//
//    (ss, kemCiphertext) = XWing.Encapsulate(recipientPublicKey)
//    aesKey  = HKDF-SHA256(ikm = ss, salt = SHA-256("ace.protocol.kem.v1"), info = conversationId, L = 32)
//    payload = nonce[12] || AES-256-GCM(aesKey, nonce, plaintext, aad = conversationId)
//
//  X-Wing (draft-connolly-cfrg-xwing-kem-11) is CryptoKit's `XWingMLKEM768X25519`.
//  This file is the single owner of X-Wing byte-length validation.
//
//  No forward secrecy on the recipient side: compromise of a recipient's static seed
//  reveals every message encrypted to that key.
//

import Foundation
import CryptoKit

public enum ACEEncryption {

    /// SHA-256("ace.protocol.kem.v1").
    static let aceKemSalt = Data(SHA256.hash(data: Data("ace.protocol.kem.v1".utf8)))
    static let nonceLength = 12
    static let tagLength = 16
    static let minPayloadBytes = 28

    // MARK: Public (seed-holding helpers for custom identities)

    /// A fresh random 32-byte X-Wing seed.
    public static func generateSeed() -> Data {
        var rng = SystemRandomNumberGenerator()
        return Data((0..<ACELimits.kemSeedSize).map { _ in UInt8.random(in: .min ... .max, using: &rng) })
    }

    /// The 1216-byte X-Wing public key of a 32-byte seed. A malformed seed is `invalid_key`.
    public static func publicKey(fromSeed seed: Data) throws -> Data {
        Data(try expandSeed(seed).publicKey.rawRepresentation)
    }

    /// `hex(SHA-256(min(pubA, pubB) || max(pubA, pubB)))` over two X-Wing public keys.
    /// A key that is not 1216 bytes is `invalid_key`.
    public static func computeConversationId(pubA: Data, pubB: Data) throws -> String {
        try validateKemPublicKey(pubA)
        try validateKemPublicKey(pubB)
        let a = [UInt8](pubA), b = [UInt8](pubB)
        let joined = a.lexicographicallyPrecedes(b) || a == b ? a + b : b + a
        return sha256Hex(Data(joined))
    }

    /// Decrypt with a borrowed 32-byte X-Wing seed (custom identities, e.g. Secure Enclave
    /// wrappers that keep the seed in the Keychain).
    ///
    /// Crypto failures are `ACEError(.decryptionFailed)`; a malformed seed is `invalid_key`;
    /// a conversationId that is not 64 lowercase hex characters is `invalid_argument`.
    public static func decrypt(kemCiphertext: Data, payload: Data, seed: Data, conversationId: String) throws -> Data {
        let key = try expandSeed(seed)
        return try decrypt(kemCiphertext: kemCiphertext, payload: payload, privateKey: key, conversationId: conversationId)
    }

    // MARK: Internal

    static func expandSeed(_ seed: Data) throws -> XWingMLKEM768X25519.PrivateKey {
        try validateKemSeed(seed)
        do {
            return try XWingMLKEM768X25519.PrivateKey(seedRepresentation: seed, publicKey: nil)
        } catch {
            throw ACEError(.invalidKey, "X-Wing seed expansion failed")
        }
    }

    static func validateKemSeed(_ seed: Data) throws {
        guard seed.count == ACELimits.kemSeedSize else {
            throw ACEError(.invalidKey, "X-Wing seed must be \(ACELimits.kemSeedSize) bytes")
        }
    }

    static func validateKemPublicKey(_ key: Data) throws {
        guard key.count == ACELimits.kemPublicKeySize else {
            throw ACEError(.invalidKey, "X-Wing public key must be \(ACELimits.kemPublicKeySize) bytes")
        }
    }

    static func validateKemCiphertext(_ ct: Data) throws {
        guard ct.count == ACELimits.kemCiphertextSize else {
            throw ACEError(.invalidEnvelope, "kemCiphertext must be \(ACELimits.kemCiphertextSize) bytes")
        }
    }

    /// Canonical Base64 of a 1216-byte key; failures are `ACEError(code)`.
    static func decodeKemPublicKey(_ text: String, code: ACEError.Code, what: String = "encryptionPublicKey") throws -> Data {
        let raw = try decodeB64(text, code: code, what: what, maxBytes: ACELimits.kemPublicKeySize + 3)
        guard raw.count == ACELimits.kemPublicKeySize else {
            throw ACEError(code, "\(what) must be \(ACELimits.kemPublicKeySize) bytes")
        }
        return raw
    }

    /// Canonical Base64 of a 1120-byte ciphertext; failures are `invalid_envelope`.
    static func decodeKemCiphertext(_ text: String) throws -> Data {
        let raw = try decodeB64(text, code: .invalidEnvelope, what: "encryption.kemCiphertext", maxBytes: ACELimits.kemCiphertextSize + 3)
        try validateKemCiphertext(raw)
        return raw
    }

    /// Returns `(kemCiphertext, payload)`. Plaintext over the limit is `limit_exceeded`.
    static func encrypt(_ plaintext: Data, recipientPublicKey: Data, conversationId: String) throws -> (kemCiphertext: Data, payload: Data) {
        guard plaintext.count <= ACELimits.maxPlaintextBytes else {
            throw ACEError(.limitExceeded, "plaintext exceeds \(ACELimits.maxPlaintextBytes) bytes")
        }
        try validateKemPublicKey(recipientPublicKey)
        let encapsulated: (sharedSecret: SymmetricKey, encapsulated: Data)
        do {
            let key = try XWingMLKEM768X25519.PublicKey(rawRepresentation: recipientPublicKey)
            let r = try key.encapsulate()
            encapsulated = (r.sharedSecret, Data(r.encapsulated))
        } catch {
            throw ACEError(.invalidKey, "X-Wing encapsulation failed")
        }
        let aad = Data(conversationId.utf8)
        let aesKey = deriveAESKey(encapsulated.sharedSecret, conversationId: aad)
        let nonce = AES.GCM.Nonce()
        do {
            let box = try AES.GCM.seal(plaintext, using: aesKey, nonce: nonce, authenticating: aad)
            return (encapsulated.encapsulated, Data(nonce) + box.ciphertext + box.tag)
        } catch {
            throw ACEError(.invalidArgument, "AES-GCM seal failed")
        }
    }

    /// Decrypt with an expanded key. Every crypto failure is `decryption_failed`.
    static func decrypt(kemCiphertext: Data, payload: Data, privateKey: XWingMLKEM768X25519.PrivateKey, conversationId: String) throws -> Data {
        guard isConversationId(conversationId) else {
            throw ACEError(.invalidArgument, "conversationId must be 64 lowercase hex characters")
        }
        guard (minPayloadBytes...ACELimits.maxPayloadBytes).contains(payload.count) else {
            throw ACEError(.decryptionFailed, "payload length out of range")
        }
        guard kemCiphertext.count == ACELimits.kemCiphertextSize else {
            throw ACEError(.decryptionFailed, "kemCiphertext must be \(ACELimits.kemCiphertextSize) bytes")
        }
        let sharedSecret: SymmetricKey
        do {
            sharedSecret = try privateKey.decapsulate(kemCiphertext)
        } catch {
            throw ACEError(.decryptionFailed, "X-Wing decapsulation failed")
        }
        let aad = Data(conversationId.utf8)
        let aesKey = deriveAESKey(sharedSecret, conversationId: aad)
        let p = Data(payload)
        do {
            let box = try AES.GCM.SealedBox(
                nonce: AES.GCM.Nonce(data: p.prefix(nonceLength)),
                ciphertext: p.dropFirst(nonceLength).dropLast(tagLength),
                tag: p.suffix(tagLength)
            )
            return try AES.GCM.open(box, using: aesKey, authenticating: aad)
        } catch {
            throw ACEError(.decryptionFailed, "AEAD authentication failed")
        }
    }

    /// Raw X-Wing decapsulation (test vectors).
    static func decapsulate(_ kemCiphertext: Data, seed: Data) throws -> Data {
        let key = try expandSeed(seed)
        let ss = try key.decapsulate(kemCiphertext)
        return ss.withUnsafeBytes { Data($0) }
    }

    private static func deriveAESKey(_ sharedSecret: SymmetricKey, conversationId: Data) -> SymmetricKey {
        HKDF<SHA256>.deriveKey(inputKeyMaterial: sharedSecret, salt: aceKemSalt, info: conversationId, outputByteCount: 32)
    }
}
