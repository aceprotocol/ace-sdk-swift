//
//  EncryptionTests.swift
//  ACE SDK
//

import Testing
import Foundation
import CryptoKit
@testable import ACE

@Suite("Encryption")
struct EncryptionTests {

    @Test("DH salt matches expected value")
    func dhSaltConstant() {
        let expected = Data(SHA256.hash(data: Data("ace.protocol.dh.v1".utf8)))
        #expect(ACEEncryption.getDHSalt() == expected)
    }

    @Test("conversationId is symmetric")
    func conversationIdSymmetric() throws {
        let keyA = Curve25519.KeyAgreement.PrivateKey()
        let keyB = Curve25519.KeyAgreement.PrivateKey()
        let pubA = Data(keyA.publicKey.rawRepresentation)
        let pubB = Data(keyB.publicKey.rawRepresentation)

        let convAB = try ACEEncryption.computeConversationId(pubA: pubA, pubB: pubB)
        let convBA = try ACEEncryption.computeConversationId(pubA: pubB, pubB: pubA)
        #expect(convAB == convBA)
    }

    @Test("encrypt/decrypt roundtrip")
    func encryptDecryptRoundtrip() throws {
        let sender = Curve25519.KeyAgreement.PrivateKey()
        let receiver = Curve25519.KeyAgreement.PrivateKey()
        let convId = try ACEEncryption.computeConversationId(
            pubA: Data(sender.publicKey.rawRepresentation),
            pubB: Data(receiver.publicKey.rawRepresentation)
        )

        let plaintext = Data("hello from ACE Swift SDK".utf8)
        let (ephPub, payload) = try ACEEncryption.encrypt(
            plaintext: plaintext,
            recipientPublicKey: Data(receiver.publicKey.rawRepresentation),
            conversationId: convId
        )

        let decrypted = try ACEEncryption.decrypt(
            ephemeralPubKey: ephPub,
            payload: payload,
            recipientPrivateKey: receiver,
            conversationId: convId
        )

        #expect(decrypted == plaintext)
    }

    @Test("wrong key fails decryption")
    func wrongKeyFails() throws {
        let sender = Curve25519.KeyAgreement.PrivateKey()
        let receiver = Curve25519.KeyAgreement.PrivateKey()
        let wrongReceiver = Curve25519.KeyAgreement.PrivateKey()
        let convId = try ACEEncryption.computeConversationId(
            pubA: Data(sender.publicKey.rawRepresentation),
            pubB: Data(receiver.publicKey.rawRepresentation)
        )

        let plaintext = Data("secret".utf8)
        let (ephPub, payload) = try ACEEncryption.encrypt(
            plaintext: plaintext,
            recipientPublicKey: Data(receiver.publicKey.rawRepresentation),
            conversationId: convId
        )

        #expect(throws: (any Error).self) {
            _ = try ACEEncryption.decrypt(
                ephemeralPubKey: ephPub,
                payload: payload,
                recipientPrivateKey: wrongReceiver,
                conversationId: convId
            )
        }
    }

    @Test("rejects all-zero public key")
    func rejectsZeroKey() {
        let zeroKey = Data(repeating: 0, count: 32)
        #expect(throws: ACEError.self) {
            _ = try ACEEncryption.encrypt(
                plaintext: Data("test".utf8),
                recipientPublicKey: zeroKey,
                conversationId: "test"
            )
        }
    }
}
