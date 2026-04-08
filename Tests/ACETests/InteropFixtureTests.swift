//
//  InteropFixtureTests.swift
//  ACE SDK
//
//  Cross-language interoperability tests using shared V1 test vectors.
//  These vectors are generated from deterministic seed keys and shared
//  across all SDKs (TypeScript, Python, Swift).
//

import Testing
import Foundation
@testable import ACE

@Suite("Interop Fixtures (V1)")
struct InteropFixtureTests {

    private struct Vectors: Decodable {
        let agents: [String: AgentVectors]
        let vectors: VectorData
    }

    private struct AgentVectors: Decodable {
        let scheme: String
        let signingPrivateKey: String
        let encryptionPrivateKey: String
        let signingPublicKey: String
        let encryptionPublicKey: String
        let address: String
        let aceId: String
    }

    private struct VectorData: Decodable {
        let aceDhSalt: String
        let conversationId: String
        let signData: SignDataVector
        let signature: SignatureVector
    }

    private struct SignDataVector: Decodable {
        let action: String
        let aceId: String
        let timestamp: Int
        let messagePayload: MessagePayloadVector
        let signDataHex: String
    }

    private struct MessagePayloadVector: Decodable {
        let type: String
        let to: String
        let conversationId: String
        let messageId: String
        let threadId: String
        let ciphertext: String
    }

    private struct SignatureVector: Decodable {
        let scheme: String
        let signDataHex: String
        let signatureValue: String
    }

    private func loadVectors() throws -> Vectors {
        let vectorsPath = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()  // ACETests/
            .deletingLastPathComponent()  // Tests/
            .deletingLastPathComponent()  // sdk-swift/
            .deletingLastPathComponent()  // ace-protocol/
            .appendingPathComponent("spec/test-vectors.json")

        let data = try Data(contentsOf: vectorsPath)
        return try JSONDecoder().decode(Vectors.self, from: data)
    }

    private func makeIdentity(_ agent: AgentVectors) throws -> SoftwareIdentity {
        let scheme: SigningScheme = agent.scheme == "ed25519" ? .ed25519 : .secp256k1
        let export = SoftwareIdentityExport(
            scheme: scheme,
            signingPrivateKey: agent.signingPrivateKey,
            encryptionPrivateKey: agent.encryptionPrivateKey
        )
        return try SoftwareIdentity.fromExport(export)
    }

    @Test("ACE DH salt matches cross-language vector")
    func aceDhSalt() throws {
        let v = try loadVectors()
        let salt = ACEEncryption.getDHSalt()
        #expect(ACEHex.encode(salt) == v.vectors.aceDhSalt)
    }

    @Test("Alice (ed25519) identity derivation")
    func aliceIdentity() throws {
        let v = try loadVectors()
        let a = v.agents["alice"]!
        let alice = try makeIdentity(a)

        #expect(alice.getACEId() == a.aceId)
        #expect(alice.getAddress() == a.address)
        #expect(ACEBase64.encode(alice.getSigningPublicKey()) == a.signingPublicKey)
        #expect(ACEBase64.encode(alice.getEncryptionPublicKey()) == a.encryptionPublicKey)
    }

    @Test("Bob (secp256k1) identity derivation")
    func bobIdentity() throws {
        let v = try loadVectors()
        let b = v.agents["bob"]!
        let bob = try makeIdentity(b)

        #expect(bob.getACEId() == b.aceId)
        #expect(bob.getAddress() == b.address)
        #expect(ACEBase64.encode(bob.getSigningPublicKey()) == b.signingPublicKey)
        #expect(ACEBase64.encode(bob.getEncryptionPublicKey()) == b.encryptionPublicKey)
    }

    @Test("conversationId matches cross-language vector")
    func conversationId() throws {
        let v = try loadVectors()
        let aliceEnc = try ACEBase64.decode(v.agents["alice"]!.encryptionPublicKey)
        let bobEnc = try ACEBase64.decode(v.agents["bob"]!.encryptionPublicKey)

        let convId = try ACEEncryption.computeConversationId(pubA: aliceEnc, pubB: bobEnc)
        #expect(convId == v.vectors.conversationId)

        // Symmetric
        let convIdReverse = try ACEEncryption.computeConversationId(pubA: bobEnc, pubB: aliceEnc)
        #expect(convIdReverse == v.vectors.conversationId)
    }

    @Test("signData matches cross-language vector")
    func signData() throws {
        let v = try loadVectors()
        let sd = v.vectors.signData
        let mp = sd.messagePayload

        let ciphertext = try ACEBase64.decode(mp.ciphertext)
        let messagePayload = ACESigning.encodePayload([
            .string(mp.type), .string(mp.to), .string(mp.conversationId), .string(mp.messageId), .string(mp.threadId), .data(ciphertext)
        ])
        let signData = ACESigning.buildSignData(
            action: sd.action,
            aceId: sd.aceId,
            timestamp: sd.timestamp,
            payload: messagePayload
        )
        #expect(ACEHex.encode(signData) == sd.signDataHex)
    }

    @Test("ed25519 signature verification against cross-language vector")
    func ed25519SignatureVerification() throws {
        let v = try loadVectors()
        let sigV = v.vectors.signature
        let alice = v.agents["alice"]!

        let signData = try ACEHex.decode(sigV.signDataHex)
        let sigBytes = try ACESigning.decodeSignature(sigV.signatureValue, scheme: .ed25519)
        let pubKey = try ACEBase64.decode(alice.signingPublicKey)

        let valid = ACESigning.verifySignature(
            signData: signData,
            signature: sigBytes,
            scheme: .ed25519,
            signingPublicKey: pubKey
        )
        #expect(valid)
    }

    @Test("Alice signs and Swift-produced signature verifies")
    func crossSignAndVerify() throws {
        // Note: Apple CryptoKit adds synthetic randomness to Ed25519 signatures
        // for fault injection protection, so we can't compare exact signature bytes.
        // Instead, verify that Swift-produced signatures are valid.
        let v = try loadVectors()
        let a = v.agents["alice"]!
        let alice = try makeIdentity(a)

        let signData = try ACEHex.decode(v.vectors.signData.signDataHex)
        let (sig, scheme) = try alice.sign(signData)
        #expect(scheme == .ed25519)

        // Verify Swift-produced signature is valid
        let pubKey = try ACEBase64.decode(a.signingPublicKey)
        let valid = ACESigning.verifySignature(
            signData: signData,
            signature: sig,
            scheme: .ed25519,
            signingPublicKey: pubKey
        )
        #expect(valid)
    }
}
