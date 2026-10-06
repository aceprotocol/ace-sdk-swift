//
//  EncryptionTests.swift
//  ACE SDK
//
//  X-Wing (X25519 + ML-KEM-768) hybrid KEM → HKDF-SHA256 → AES-256-GCM.
//

import Testing
import Foundation
import CryptoKit
@testable import ACE

@Suite("Encryption")
struct EncryptionTests {

    // The X-Wing draft-11 KEM vector (keygen → pk, decapsulate → ss) lives in the
    // shared spec file and is exercised by InteropVectorsTests.xwingVector().

    @Test("KEM salt is SHA-256(\"ace.protocol.kem.v1\")")
    func kemSaltConstant() {
        #expect(ACEHex.encode(ACEEncryption.aceKemSalt) == "4d47944503bb761780f5214d54a2565e89d0efb29a9641df4747bd66d5821611")
    }

    // MARK: - Key generation

    @Test("expanded private key decrypts like the seed it came from")
    func expandedKeyDecrypt() throws {
        let seed = ACEEncryption.generateSeed()
        let pk = try ACEEncryption.publicKey(fromSeed: seed)
        let (ct, payload) = try ACEEncryption.encrypt(Data("hi".utf8), recipientPublicKey: pk, conversationId: "c")
        let key = try ACEEncryption.privateKey(fromSeed: seed)
        #expect(Data(key.publicKey.rawRepresentation) == pk)
        #expect(try ACEEncryption.decrypt(kemCiphertext: ct, payload: payload, privateKey: key, conversationId: "c") == Data("hi".utf8))
        #expect(try ACEEncryption.decrypt(kemCiphertext: ct, payload: payload, seed: seed, conversationId: "c") == Data("hi".utf8))
    }

    @Test("Base64 wire values must be padded")
    func base64MustBePadded() throws {
        let ct = ACEBase64.encode(Data(repeating: 7, count: ACEEncryption.kemCiphertextSize))
        #expect(throws: ACEError.self) {
            try ACEEncryption.decodeKEMCiphertext(base64: String(ct.drop(while: { _ in false }).reversed().drop(while: { $0 == "=" }).reversed()))
        }
        #expect(try ACEEncryption.decodeKEMCiphertext(base64: ct).count == ACEEncryption.kemCiphertextSize)
    }

    @Test("public key derivation from seed is deterministic")
    func deterministicPublicKey() throws {
        let seed = ACEEncryption.generateSeed()
        #expect(seed.count == 32)
        let pk1 = try ACEEncryption.publicKey(fromSeed: seed)
        let pk2 = try ACEEncryption.publicKey(fromSeed: seed)
        #expect(pk1 == pk2)
        #expect(pk1.count == 1216)
    }

    @Test("rejects off-by-one seed length", arguments: [31, 33])
    func rejectsWrongSeed(count: Int) {
        let seed = Data(repeating: 1, count: count)
        #expect(throws: ACEError.self) { try ACEEncryption.validateSeed(seed) }
        #expect(throws: ACEError.self) { _ = try ACEEncryption.publicKey(fromSeed: seed) }
    }

    // MARK: - Conversation ID

    @Test("conversationId is symmetric")
    func conversationIdSymmetric() throws {
        let pubA = try ACEEncryption.publicKey(fromSeed: ACEEncryption.generateSeed())
        let pubB = try ACEEncryption.publicKey(fromSeed: ACEEncryption.generateSeed())

        let convAB = try ACEEncryption.computeConversationId(pubA: pubA, pubB: pubB)
        let convBA = try ACEEncryption.computeConversationId(pubA: pubB, pubB: pubA)
        #expect(convAB == convBA)
        #expect(convAB.count == 64)
    }

    @Test("conversationId rejects off-by-one key lengths on either side")
    func conversationIdRejectsWrongLength() throws {
        let good = try ACEEncryption.publicKey(fromSeed: ACEEncryption.generateSeed())
        #expect(throws: ACEError.self) { _ = try ACEEncryption.computeConversationId(pubA: Data(repeating: 7, count: 1215), pubB: good) }
        #expect(throws: ACEError.self) { _ = try ACEEncryption.computeConversationId(pubA: good, pubB: Data(repeating: 7, count: 1217)) }
    }

    // MARK: - Round trip

    @Test("encrypt/decrypt roundtrip")
    func encryptDecryptRoundtrip() throws {
        let senderSeed = ACEEncryption.generateSeed()
        let receiverSeed = ACEEncryption.generateSeed()
        let senderPub = try ACEEncryption.publicKey(fromSeed: senderSeed)
        let receiverPub = try ACEEncryption.publicKey(fromSeed: receiverSeed)
        let convId = try ACEEncryption.computeConversationId(pubA: senderPub, pubB: receiverPub)

        let plaintext = Data("hello from ACE Swift SDK".utf8)
        let (kemCiphertext, payload) = try ACEEncryption.encrypt(
            plaintext,
            recipientPublicKey: receiverPub,
            conversationId: convId
        )
        #expect(kemCiphertext.count == 1120)
        #expect(payload.count == 12 + plaintext.count + 16)

        let decrypted = try ACEEncryption.decrypt(
            kemCiphertext: kemCiphertext,
            payload: payload,
            seed: receiverSeed,
            conversationId: convId
        )
        #expect(decrypted == plaintext)
    }

    @Test("every encryption produces a fresh KEM ciphertext")
    func freshCiphertext() throws {
        let receiverSeed = ACEEncryption.generateSeed()
        let receiverPub = try ACEEncryption.publicKey(fromSeed: receiverSeed)
        let a = try ACEEncryption.encrypt(Data("x".utf8), recipientPublicKey: receiverPub, conversationId: "c")
        let b = try ACEEncryption.encrypt(Data("x".utf8), recipientPublicKey: receiverPub, conversationId: "c")
        #expect(a.kemCiphertext != b.kemCiphertext)
        #expect(a.payload != b.payload)
    }

    @Test("wrong key fails decryption")
    func wrongKeyFails() throws {
        let receiverSeed = ACEEncryption.generateSeed()
        let wrongSeed = ACEEncryption.generateSeed()
        let receiverPub = try ACEEncryption.publicKey(fromSeed: receiverSeed)
        let convId = try ACEEncryption.computeConversationId(
            pubA: try ACEEncryption.publicKey(fromSeed: ACEEncryption.generateSeed()),
            pubB: receiverPub
        )

        let (kemCiphertext, payload) = try ACEEncryption.encrypt(
            Data("secret".utf8),
            recipientPublicKey: receiverPub,
            conversationId: convId
        )

        #expect(throws: (any Error).self) {
            _ = try ACEEncryption.decrypt(
                kemCiphertext: kemCiphertext,
                payload: payload,
                seed: wrongSeed,
                conversationId: convId
            )
        }
    }

    @Test("wrong conversationId fails decryption (HKDF info + AAD)")
    func wrongConversationIdFails() throws {
        let receiverSeed = ACEEncryption.generateSeed()
        let receiverPub = try ACEEncryption.publicKey(fromSeed: receiverSeed)
        let (kemCiphertext, payload) = try ACEEncryption.encrypt(
            Data("secret".utf8), recipientPublicKey: receiverPub, conversationId: "conv-a"
        )
        #expect(throws: (any Error).self) {
            _ = try ACEEncryption.decrypt(
                kemCiphertext: kemCiphertext, payload: payload, seed: receiverSeed, conversationId: "conv-b"
            )
        }
    }

    @Test("tampered KEM ciphertext fails decryption (implicit rejection → GCM tag mismatch)")
    func tamperedKEMCiphertextFails() throws {
        let receiverSeed = ACEEncryption.generateSeed()
        let receiverPub = try ACEEncryption.publicKey(fromSeed: receiverSeed)
        let (kemCiphertext, payload) = try ACEEncryption.encrypt(
            Data("secret".utf8), recipientPublicKey: receiverPub, conversationId: "conv"
        )
        var tampered = kemCiphertext
        tampered[tampered.startIndex] ^= 0x01
        #expect(throws: (any Error).self) {
            _ = try ACEEncryption.decrypt(
                kemCiphertext: tampered, payload: payload, seed: receiverSeed, conversationId: "conv"
            )
        }
    }

    // MARK: - Length validation

    @Test("public key off-by-one is rejected by validatePublicKey and encrypt", arguments: [1215, 1217])
    func encryptRejectsWrongKeyLength(count: Int) {
        let key = Data(repeating: 1, count: count)
        let err = #expect(throws: ACEError.self) { try ACEEncryption.validatePublicKey(key) }
        if case .invalidKey(let msg)? = err {
            #expect(msg.contains("1216"))
        } else {
            Issue.record("expected .invalidKey length error for count=\(count), got \(String(describing: err))")
        }
        #expect(throws: ACEError.self) {
            _ = try ACEEncryption.encrypt(Data("test".utf8), recipientPublicKey: key, conversationId: "test")
        }
    }

    @Test("kemCiphertext off-by-one is rejected by validateKEMCiphertext and decrypt", arguments: [1119, 1121])
    func decryptRejectsWrongCiphertextLength(count: Int) throws {
        let ct = Data(repeating: 1, count: count)
        let err = #expect(throws: ACEError.self) { try ACEEncryption.validateKEMCiphertext(ct) }
        if case .invalidMessage(let msg)? = err {
            #expect(msg.contains("1120"))
        } else {
            Issue.record("expected .invalidMessage length error for count=\(count), got \(String(describing: err))")
        }
        #expect(throws: ACEError.self) {
            _ = try ACEEncryption.decrypt(
                kemCiphertext: ct,
                payload: Data(repeating: 0, count: 28),
                seed: ACEEncryption.generateSeed(),
                conversationId: "test"
            )
        }
    }

    @Test("decodePublicKey / decodeKEMCiphertext: round-trip, over-long input, bad Base64")
    func decodeHelpers() throws {
        let pk = try ACEEncryption.publicKey(fromSeed: ACEEncryption.generateSeed())
        let (ct, _) = try ACEEncryption.encrypt(Data("x".utf8), recipientPublicKey: pk, conversationId: "c")
        #expect(try ACEEncryption.decodePublicKey(base64: ACEBase64.encode(pk)) == pk)
        #expect(try ACEEncryption.decodeKEMCiphertext(base64: ACEBase64.encode(ct)) == ct)

        // One character past the padded Base64 length (1624 / 1496) is rejected
        // by the string-length pre-check, before any decode.
        let longPk = String(repeating: "A", count: 1625)
        let longCt = String(repeating: "A", count: 1497)
        let longPkErr = #expect(throws: ACEError.self) { _ = try ACEEncryption.decodePublicKey(base64: longPk) }
        let longCtErr = #expect(throws: ACEError.self) { _ = try ACEEncryption.decodeKEMCiphertext(base64: longCt) }
        if case .invalidKey? = longPkErr {} else {
            Issue.record("expected .invalidKey for over-long public key input, got \(String(describing: longPkErr))")
        }
        if case .invalidMessage? = longCtErr {} else {
            Issue.record("expected .invalidMessage for over-long kemCiphertext input, got \(String(describing: longCtErr))")
        }

        // Malformed Base64 maps to the same error family as a bad length.
        let badPkErr = #expect(throws: ACEError.self) { _ = try ACEEncryption.decodePublicKey(base64: "@@@") }
        let badCtErr = #expect(throws: ACEError.self) { _ = try ACEEncryption.decodeKEMCiphertext(base64: "@@@") }
        if case .invalidKey? = badPkErr {} else {
            Issue.record("expected .invalidKey for malformed public key Base64, got \(String(describing: badPkErr))")
        }
        if case .invalidMessage? = badCtErr {} else {
            Issue.record("expected .invalidMessage for malformed kemCiphertext Base64, got \(String(describing: badCtErr))")
        }
    }

    @Test("decrypt rejects too-short payload")
    func decryptRejectsShortPayload() throws {
        let seed = ACEEncryption.generateSeed()
        #expect(throws: ACEError.self) {
            _ = try ACEEncryption.decrypt(
                kemCiphertext: Data(repeating: 1, count: 1120),
                payload: Data(repeating: 0, count: 27),
                seed: seed,
                conversationId: "test"
            )
        }
    }

    @Test("encrypt rejects oversized plaintext")
    func encryptRejectsOversizedPlaintext() throws {
        let receiverPub = try ACEEncryption.publicKey(fromSeed: ACEEncryption.generateSeed())
        let big = Data(count: ACEEncryption.maxPlaintextSize + 1)
        #expect(throws: ACEError.self) {
            _ = try ACEEncryption.encrypt(big, recipientPublicKey: receiverPub, conversationId: "test")
        }
    }
}
