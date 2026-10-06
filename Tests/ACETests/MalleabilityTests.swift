//
//  MalleabilityTests.swift
//  ACE SDK
//
//  secp256k1 signature malleability must be rejected (canonical low-S only),
//  and the signed message payload must bind the X-Wing kemCiphertext.
//

import Testing
import Foundation
@testable import ACE

@Suite("secp256k1 signature malleability")
struct MalleabilityTests {

    static let orderBE: [UInt8] = [
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
        0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41,
    ]
    static let halfOrderBE: [UInt8] = [
        0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0x5D, 0x57, 0x6E, 0x73, 0x57, 0xA4, 0x50, 0x1D, 0xDF, 0xE9, 0x2F, 0x46, 0x68, 0x1B, 0x20, 0xA0,
    ]

    func subtractBE(_ a: [UInt8], _ b: [UInt8]) -> [UInt8] {
        var result = [UInt8](repeating: 0, count: 32)
        var borrow = 0
        for i in stride(from: 31, through: 0, by: -1) {
            let diff = Int(a[i]) - Int(b[i]) - borrow
            if diff < 0 { result[i] = UInt8(diff + 256); borrow = 1 } else { result[i] = UInt8(diff); borrow = 0 }
        }
        return result
    }

    func cmpBE(_ a: [UInt8], _ b: [UInt8]) -> Int {
        for i in 0..<32 where a[i] != b[i] { return a[i] < b[i] ? -1 : 1 }
        return 0
    }

    /// (r, s, v) -> (r, N - s, v ^ 1): the canonical ECDSA malleability transform.
    func malleate(_ sig: Data) -> Data {
        let b = [UInt8](sig)
        let r = Array(b[0..<32]); let s = Array(b[32..<64]); let v = b[64]
        return Data(r + subtractBE(Self.orderBE, s) + [v ^ 1])
    }

    func signData(_ id: SoftwareIdentity) -> Data {
        ACESigning.buildSignData(
            action: "message", aceId: id.getACEId(), timestamp: 1741000000,
            payload: ACESigning.encodePayload([.string("text"), .data(Data([1]))])
        )
    }

    @Test("signs low-S and verifies")
    func lowS() throws {
        let id = try SoftwareIdentity.generate(scheme: .secp256k1)
        let sd = signData(id)
        let (sig, scheme) = try id.sign(sd)
        #expect(ACESigning.verifySignature(signData: sd, signature: sig, scheme: scheme, signingPublicKey: id.getSigningPublicKey()))
        #expect(cmpBE(Array([UInt8](sig)[32..<64]), Self.halfOrderBE) <= 0)
    }

    @Test("rejects the high-S malleated twin (same key, different bytes)")
    func highSRejected() throws {
        let id = try SoftwareIdentity.generate(scheme: .secp256k1)
        let sd = signData(id)
        let (sig, scheme) = try id.sign(sd)
        #expect(ACESigning.verifySignature(signData: sd, signature: sig, scheme: scheme, signingPublicKey: id.getSigningPublicKey()))

        let mal = malleate(sig)
        // Twin differs only in s (→ N - s, now high-S) and v; a valid signature for
        // the same key, but must be rejected as non-canonical.
        #expect(cmpBE(Array([UInt8](mal)[32..<64]), Self.halfOrderBE) > 0)
        #expect(ACESigning.verifySignature(signData: sd, signature: mal, scheme: scheme, signingPublicKey: id.getSigningPublicKey()) == false)
    }

    @Test("rejects an invalid recovery id")
    func badRecoveryId() throws {
        let id = try SoftwareIdentity.generate(scheme: .secp256k1)
        let sd = ACESigning.buildSignData(action: "message", aceId: id.getACEId(), timestamp: 1741000000)
        let (sig, _) = try id.sign(sd)
        var bad = [UInt8](sig); bad[64] = 2
        #expect(ACESigning.verifySignature(signData: sd, signature: Data(bad), scheme: .secp256k1, signingPublicKey: id.getSigningPublicKey()) == false)
    }
}

@Suite("kemCiphertext is bound by the message signature")
struct KEMCiphertextBindingTests {

    @Test("swapping kemCiphertext fails SIGNATURE verification (not just decryption)",
          arguments: [SigningScheme.ed25519, SigningScheme.secp256k1])
    func swappedKEMCiphertextFailsSignature(scheme: SigningScheme) throws {
        let alice = try SoftwareIdentity.generate(scheme: scheme)
        let bob = try SoftwareIdentity.generate(scheme: .ed25519)

        let msg = try createMessage(CreateMessageOptions(
            sender: alice,
            recipientPubKey: bob.getEncryptionPublicKey(),
            recipientACEId: bob.getACEId(),
            type: .text,
            body: ["message": "hello"],
            stateMachine: ThreadStateMachine()
        ))

        // A relay encapsulates to bob itself and swaps in its own valid 1120-byte ciphertext.
        let (foreignCt, _) = try ACEEncryption.encrypt(
            Data("x".utf8), recipientPublicKey: bob.getEncryptionPublicKey(), conversationId: msg.conversationId
        )
        #expect(foreignCt.count == 1120)
        let swapped = ACEMessage(
            ace: msg.ace, messageId: msg.messageId, from: msg.from, to: msg.to,
            conversationId: msg.conversationId, type: msg.type, threadId: msg.threadId, timestamp: msg.timestamp,
            encryption: EncryptionEnvelope(kemCiphertext: ACEBase64.encode(foreignCt), payload: msg.encryption.payload),
            signature: msg.signature
        )

        let err = #expect(throws: ACEError.self) {
            try parseMessage(
                swapped, receiver: bob, senderSigningPubKey: alice.getSigningPublicKey(),
                opts: ParseMessageOptions(stateMachine: ThreadStateMachine(), replayDetector: ReplayDetector())
            )
        }
        guard case .signatureVerificationFailed? = err else {
            Issue.record("expected signatureVerificationFailed, got \(String(describing: err))")
            return
        }
    }

    @Test("single-bit flip in kemCiphertext fails SIGNATURE verification")
    func flippedKEMCiphertextFailsSignature() throws {
        let alice = try SoftwareIdentity.generate(scheme: .ed25519)
        let bob = try SoftwareIdentity.generate(scheme: .ed25519)
        let msg = try createMessage(CreateMessageOptions(
            sender: alice, recipientPubKey: bob.getEncryptionPublicKey(), recipientACEId: bob.getACEId(),
            type: .text, body: ["message": "hello"], stateMachine: ThreadStateMachine()
        ))
        var ct = try ACEBase64.decode(msg.encryption.kemCiphertext)
        ct[ct.startIndex + 1100] ^= 0x80
        let tampered = ACEMessage(
            ace: msg.ace, messageId: msg.messageId, from: msg.from, to: msg.to,
            conversationId: msg.conversationId, type: msg.type, threadId: msg.threadId, timestamp: msg.timestamp,
            encryption: EncryptionEnvelope(kemCiphertext: ACEBase64.encode(ct), payload: msg.encryption.payload),
            signature: msg.signature
        )
        let err = #expect(throws: ACEError.self) {
            try parseMessage(
                tampered, receiver: bob, senderSigningPubKey: alice.getSigningPublicKey(),
                opts: ParseMessageOptions(stateMachine: ThreadStateMachine(), replayDetector: ReplayDetector())
            )
        }
        guard case .signatureVerificationFailed? = err else {
            Issue.record("expected signatureVerificationFailed, got \(String(describing: err))")
            return
        }
    }
}
