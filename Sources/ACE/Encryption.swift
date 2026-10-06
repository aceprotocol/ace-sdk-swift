//
//  Encryption.swift
//  ACE SDK
//
//  X-Wing hybrid KEM (X25519 + ML-KEM-768) + HKDF-SHA256 + AES-256-GCM.
//
//  Encryption flow:
//    1. X-Wing encapsulate to the recipient's static public key → (sharedSecret, kemCiphertext)
//    2. HKDF-SHA256(sharedSecret, salt=ACE_KEM_SALT, info=conversationId) → AES-256 key
//    3. AES-256-GCM(key, nonce=random12, plaintext, aad=conversationId) → ciphertext
//    4. Output: kemCiphertext[1120], payload = nonce[12] || ciphertext || tag[16]
//
//  X-Wing (draft-connolly-cfrg-xwing-kem-11) is provided by CryptoKit's
//  `XWingMLKEM768X25519` (macOS 26 / iOS 26). Public key = pk_M[1184] || pk_X[32],
//  ciphertext = ct_M[1088] || ct_X[32], private key = 32-byte seed.
//
//  Note: no small-order-point or all-zero shared-secret checks are needed.
//  The X-Wing combiner binds pk_X and ct_X into the shared secret, and ML-KEM
//  decapsulation uses implicit rejection.
//
//  This type is the single owner of X-Wing byte-length validation. Every other
//  layer (registration files, peer responses, message envelopes, identity import)
//  goes through `validate*` / `decode*` below rather than comparing lengths itself.
//

import Foundation
import CryptoKit

public enum ACEEncryption {

    // MARK: - Constants

    /// ACE Protocol KEM HKDF salt: SHA-256("ace.protocol.kem.v1").
    /// Shared across all implementations (TS, PY, Swift).
    public static let aceKemSalt = Data(SHA256.hash(data: Data("ace.protocol.kem.v1".utf8)))

    /// X-Wing public key size: pk_M[1184] || pk_X[32]
    public static let publicKeySize = 1216

    /// X-Wing ciphertext size: ct_M[1088] || ct_X[32]
    public static let kemCiphertextSize = 1120

    /// X-Wing private key seed size
    public static let seedSize = 32

    /// Maximum payload size (10 MB)
    public static let maxPayloadSize = 10 * 1024 * 1024

    /// Minimum payload: nonce[12] + GCM tag[16] = 28 bytes
    static let minPayloadLength = 28

    /// Maximum plaintext size
    public static let maxPlaintextSize = maxPayloadSize - minPayloadLength

    // MARK: - Key Generation

    /// Derive the X-Wing public key (1216 bytes) from a 32-byte seed.
    public static func publicKey(fromSeed seed: Data) throws -> Data {
        Data(try privateKey(fromSeed: seed).publicKey.rawRepresentation)
    }

    /// Expand a 32-byte seed into an X-Wing private key (SHAKE256 + ML-KEM-768
    /// keygen + X25519). Holders that decrypt repeatedly should keep the result
    /// and call `decrypt(kemCiphertext:payload:privateKey:conversationId:)`.
    public static func privateKey(fromSeed seed: Data) throws -> XWingMLKEM768X25519.PrivateKey {
        try validateSeed(seed)
        return try XWingMLKEM768X25519.PrivateKey(seedRepresentation: seed, publicKey: nil)
    }

    /// Generate a fresh random 32-byte X-Wing seed.
    public static func generateSeed() -> Data {
        var bytes = [UInt8](repeating: 0, count: seedSize)
        let status = SecRandomCopyBytes(kSecRandomDefault, seedSize, &bytes)
        precondition(status == errSecSuccess, "SecRandomCopyBytes failed: \(status)")
        return Data(bytes)
    }

    // MARK: - Conversation ID

    /// Compute deterministic conversation ID from two X-Wing public keys.
    /// conversationId = hex(SHA-256(sort_bytes(pubA, pubB)))
    ///
    /// Sorting ensures symmetry: A→B and B→A produce the same ID.
    /// Variable-time comparison is safe here — these are public keys, not secrets.
    public static func computeConversationId(pubA: Data, pubB: Data) throws -> String {
        try validatePublicKey(pubA)
        try validatePublicKey(pubB)
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
    ///   - recipientPublicKey: 1216-byte X-Wing public key
    ///   - conversationId: Used as HKDF info and AES-GCM AAD
    /// - Returns: Tuple of (kemCiphertext, payload) where kemCiphertext is the
    ///   1120-byte X-Wing ciphertext and payload = nonce[12] || ciphertext || tag[16]
    public static func encrypt(
        _ plaintext: Data,
        recipientPublicKey: Data,
        conversationId: String
    ) throws -> (kemCiphertext: Data, payload: Data) {
        // Validate
        try validatePublicKey(recipientPublicKey)
        guard plaintext.count <= maxPlaintextSize else {
            throw ACEError.payloadTooLarge(plaintext.count)
        }

        // 1. X-Wing encapsulate
        let recipientKey = try XWingMLKEM768X25519.PublicKey(rawRepresentation: recipientPublicKey)
        let result = try recipientKey.encapsulate()
        let kemCiphertext = Data(result.encapsulated)

        // 2. HKDF key derivation
        let convIdBytes = Data(conversationId.utf8)
        let aesKey = deriveAESKey(sharedSecret: result.sharedSecret, conversationId: convIdBytes)

        // 3. AES-256-GCM
        let nonce = AES.GCM.Nonce()
        let sealedBox = try AES.GCM.seal(plaintext, using: aesKey, nonce: nonce, authenticating: convIdBytes)

        // 4. payload = nonce[12] || ciphertext || tag[16]
        let payload = Data(nonce) + sealedBox.ciphertext + sealedBox.tag

        guard payload.count <= maxPayloadSize else {
            throw ACEError.payloadTooLarge(payload.count)
        }

        return (kemCiphertext: kemCiphertext, payload: payload)
    }

    // MARK: - Decrypt

    /// Decrypt a message using the recipient's X-Wing private key seed.
    ///
    /// - Parameters:
    ///   - kemCiphertext: 1120-byte X-Wing ciphertext from sender
    ///   - payload: nonce[12] || ciphertext || tag[16]
    ///   - seed: Recipient's 32-byte X-Wing private key seed
    ///   - conversationId: Must match the one used during encryption
    /// - Returns: Decrypted plaintext
    public static func decrypt(
        kemCiphertext: Data,
        payload: Data,
        seed: Data,
        conversationId: String
    ) throws -> Data {
        // Ciphertext length is checked before the (more expensive) key expansion.
        try validateKEMCiphertext(kemCiphertext)
        return try decrypt(
            kemCiphertext: kemCiphertext,
            payload: payload,
            privateKey: privateKey(fromSeed: seed),
            conversationId: conversationId
        )
    }

    /// Decrypt with an already-expanded X-Wing private key (see `privateKey(fromSeed:)`).
    public static func decrypt(
        kemCiphertext: Data,
        payload: Data,
        privateKey: XWingMLKEM768X25519.PrivateKey,
        conversationId: String
    ) throws -> Data {
        // Validate
        try validateKEMCiphertext(kemCiphertext)
        guard payload.count >= minPayloadLength else {
            throw ACEError.decryptionFailed("Payload too short: expected at least \(minPayloadLength) bytes, got \(payload.count)")
        }
        guard payload.count <= maxPayloadSize else {
            throw ACEError.payloadTooLarge(payload.count)
        }

        // 1. X-Wing decapsulate (implicit rejection: a bad ciphertext yields a
        //    pseudorandom secret and the AES-GCM tag check fails below)
        let sharedSecret: SymmetricKey
        do {
            sharedSecret = try privateKey.decapsulate(kemCiphertext)
        } catch {
            throw ACEError.decryptionFailed("X-Wing decapsulation failed: \(error)")
        }

        // 2. HKDF
        let convIdBytes = Data(conversationId.utf8)
        let aesKey = deriveAESKey(sharedSecret: sharedSecret, conversationId: convIdBytes)

        // 3. Parse payload: nonce[12] || ciphertext || tag[16]
        let nonce = try AES.GCM.Nonce(data: payload.prefix(12))
        let ciphertext = payload.dropFirst(12).dropLast(16)
        let tag = payload.suffix(16)
        let sealedBox = try AES.GCM.SealedBox(nonce: nonce, ciphertext: ciphertext, tag: tag)

        // 4. Decrypt
        let plaintext = try AES.GCM.open(sealedBox, using: aesKey, authenticating: convIdBytes)
        return plaintext
    }

    // MARK: - Validation

    /// Validate an X-Wing public key: must be exactly 1216 bytes.
    public static func validatePublicKey(_ pubKey: Data) throws {
        guard pubKey.count == publicKeySize else {
            throw ACEError.invalidKey("X-Wing public key must be \(publicKeySize) bytes, got \(pubKey.count)")
        }
    }

    /// Validate an X-Wing ciphertext: must be exactly 1120 bytes.
    public static func validateKEMCiphertext(_ ct: Data) throws {
        guard ct.count == kemCiphertextSize else {
            throw ACEError.invalidMessage("kemCiphertext must be \(kemCiphertextSize) bytes, got \(ct.count)")
        }
    }

    /// Validate an X-Wing private key seed: must be exactly 32 bytes.
    public static func validateSeed(_ seed: Data) throws {
        guard seed.count == seedSize else {
            throw ACEError.invalidKey("X-Wing private key seed must be \(seedSize) bytes, got \(seed.count)")
        }
    }

    // MARK: - Decoding (Base64 wire strings)

    /// Decode and validate a Base64 X-Wing public key (1216 bytes).
    /// Oversized input is refused before decoding. All failures are `ACEError.invalidKey`.
    public static func decodePublicKey(base64: String) throws -> Data {
        let key: Data
        do {
            key = try ACEBase64.decode(base64, maxLength: publicKeySize, what: "X-Wing public key")
        } catch ACEError.invalidMessage(let reason) {
            throw ACEError.invalidKey(reason)
        }
        try validatePublicKey(key)
        return key
    }

    /// Decode and validate a Base64 X-Wing ciphertext (1120 bytes).
    /// Oversized input is refused before decoding. All failures are `ACEError.invalidMessage`.
    public static func decodeKEMCiphertext(base64: String) throws -> Data {
        let ct = try ACEBase64.decode(base64, maxLength: kemCiphertextSize, what: "kemCiphertext")
        try validateKEMCiphertext(ct)
        return ct
    }

    // MARK: - Private Helpers

    /// aesKey = HKDF-SHA256(ikm = X-Wing shared secret, salt = ACE_KEM_SALT, info = conversationId, L = 32)
    private static func deriveAESKey(sharedSecret: SymmetricKey, conversationId: Data) -> SymmetricKey {
        HKDF<SHA256>.deriveKey(
            inputKeyMaterial: sharedSecret,
            salt: aceKemSalt,
            info: conversationId,
            outputByteCount: 32
        )
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
