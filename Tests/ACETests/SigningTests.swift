//
//  SigningTests.swift
//  ACE SDK
//

import Testing
import Foundation
@testable import ACE

@Suite("Signing")
struct SigningTests {

    @Test("signData is deterministic")
    func signDataDeterministic() {
        let payload = ACESigning.encodePayload([.string("rfq"), .string("ace:sha256:receiver"), .string("conv"), .string("550e8400-e29b-41d4-a716-446655440000"), .string("thread-1"), .data(Data([0xDE, 0xAD]))])
        let hash1 = ACESigning.buildSignData(action: "message", aceId: "ace:sha256:sender", timestamp: 1700000000, payload: payload)
        let hash2 = ACESigning.buildSignData(action: "message", aceId: "ace:sha256:sender", timestamp: 1700000000, payload: payload)
        #expect(hash1 == hash2)
    }

    @Test("different actions produce different signData")
    func domainSeparation() {
        let hash1 = ACESigning.buildSignData(action: "message", aceId: "a", timestamp: 1)
        let hash2 = ACESigning.buildSignData(action: "register", aceId: "a", timestamp: 1)
        #expect(hash1 != hash2)
    }

    @Test("ed25519 sign and verify roundtrip")
    func ed25519Roundtrip() throws {
        let identity = try SoftwareIdentity.generate(scheme: .ed25519)
        let msgPayload = ACESigning.encodePayload([.string("text"), .string("ace:sha256:other"), .string("conv"), .string("550e8400-e29b-41d4-a716-446655440000"), .string(""), .data(Data("hello".utf8))])
        let signData = ACESigning.buildSignData(
            action: "message", aceId: identity.getACEId(), timestamp: 1700000000, payload: msgPayload
        )

        let (sig, scheme) = try identity.sign(signData)
        #expect(scheme == .ed25519)
        #expect(sig.count == 64)

        let valid = ACESigning.verifySignature(
            signData: signData,
            signature: sig,
            scheme: .ed25519,
            signingPublicKey: identity.getSigningPublicKey()
        )
        #expect(valid)
    }

    @Test("secp256k1 sign and verify roundtrip")
    func secp256k1Roundtrip() throws {
        let identity = try SoftwareIdentity.generate(scheme: .secp256k1)
        let msgPayload = ACESigning.encodePayload([.string("offer"), .string("ace:sha256:other"), .string("conv"), .string("550e8400-e29b-41d4-a716-446655440000"), .string("thread-1"), .data(Data("test".utf8))])
        let signData = ACESigning.buildSignData(
            action: "message", aceId: identity.getACEId(), timestamp: 1700000000, payload: msgPayload
        )

        let (sig, scheme) = try identity.sign(signData)
        #expect(scheme == .secp256k1)
        #expect(sig.count == 65)

        let valid = ACESigning.verifySignature(
            signData: signData,
            signature: sig,
            scheme: .secp256k1,
            signingPublicKey: identity.getSigningPublicKey()
        )
        #expect(valid)
    }

    @Test("tampered data fails verification")
    func tamperedDataFails() throws {
        let identity = try SoftwareIdentity.generate(scheme: .ed25519)
        let signData = ACESigning.buildSignData(
            action: "message", aceId: identity.getACEId(), timestamp: 1
        )
        let (sig, _) = try identity.sign(signData)

        // Tamper: change one byte
        var tampered = signData
        tampered[0] ^= 0xFF

        let valid = ACESigning.verifySignature(
            signData: tampered,
            signature: sig,
            scheme: .ed25519,
            signingPublicKey: identity.getSigningPublicKey()
        )
        #expect(!valid)
    }

    @Test("different actions have different domain separation")
    func actionDomainSeparation() {
        let regPayload = ACESigning.encodePayload([.string("encPub"), .string("sigPub")])
        let regData = ACESigning.buildSignData(
            action: "register", aceId: "ace:sha256:aaa", timestamp: 1, payload: regPayload
        )
        let listenData = ACESigning.buildSignData(
            action: "listen", aceId: "ace:sha256:aaa", timestamp: 1, payload: ACESigning.encodePayload([.string("-")])
        )
        #expect(regData != listenData)
    }

    @Test("signature encoding roundtrip — ed25519")
    func signatureEncodingEd25519() throws {
        let sig = Data((0..<64).map { UInt8($0) })
        let encoded = ACESigning.encodeSignature(sig, scheme: .ed25519)
        let decoded = try ACESigning.decodeSignature(encoded, scheme: .ed25519)
        #expect(decoded == sig)
    }

    @Test("signature encoding roundtrip — secp256k1")
    func signatureEncodingSecp256k1() throws {
        let sig = Data((0..<65).map { UInt8($0) })
        let encoded = ACESigning.encodeSignature(sig, scheme: .secp256k1)
        #expect(encoded.hasPrefix("0x"))
        let decoded = try ACESigning.decodeSignature(encoded, scheme: .secp256k1)
        #expect(decoded == sig)
    }
}
