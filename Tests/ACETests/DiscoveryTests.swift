//
//  DiscoveryTests.swift
//  ACE SDK
//
//  Tests for ACE ID validation, registration file validation, and key extraction.
//

import Testing
import Foundation
@testable import ACE

@Suite("Discovery")
struct DiscoveryTests {

    // ============================================================
    // validateACEId
    // ============================================================

    @Suite("validateACEId")
    struct ValidateACEIdTests {

        @Test("accepts valid ACE ID format")
        func validFormat() {
            let validId = "ace:sha256:" + String(repeating: "a", count: 64)
            #expect(validateACEId(validId))
        }

        @Test("accepts ACE ID with mixed hex chars")
        func validMixedHex() {
            let validId = "ace:sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            #expect(validateACEId(validId))
        }

        @Test("rejects missing prefix")
        func noPrefix() {
            let invalidId = "sha256:" + String(repeating: "a", count: 64)
            #expect(!validateACEId(invalidId))
        }

        @Test("rejects wrong hash length (too short)")
        func tooShortHash() {
            let invalidId = "ace:sha256:" + String(repeating: "a", count: 63)
            #expect(!validateACEId(invalidId))
        }

        @Test("rejects wrong hash length (too long)")
        func tooLongHash() {
            let invalidId = "ace:sha256:" + String(repeating: "a", count: 65)
            #expect(!validateACEId(invalidId))
        }

        @Test("rejects uppercase hex characters")
        func uppercaseHex() {
            let invalidId = "ace:sha256:" + String(repeating: "A", count: 64)
            #expect(!validateACEId(invalidId))
        }

        @Test("rejects empty string")
        func emptyString() {
            #expect(!validateACEId(""))
        }

        @Test("rejects random string")
        func randomString() {
            #expect(!validateACEId("not-an-ace-id"))
        }

        @Test("validates a real computed ACE ID")
        func realComputedId() throws {
            let identity = try SoftwareIdentity.generate(scheme: .ed25519)
            #expect(validateACEId(identity.getACEId()))
        }
    }

    // ============================================================
    // validateRegistrationFile
    // ============================================================

    @Suite("validateRegistrationFile")
    struct ValidateRegistrationFileTests {

        @Test("validates a valid registration file")
        func validFile() throws {
            let identity = try SoftwareIdentity.generate(scheme: .ed25519)
            let reg = identity.toRegistrationFile(
                name: "Test Agent",
                endpoint: "https://agent.example.com"
            )
            try validateRegistrationFile(reg)
        }

        @Test("rejects invalid ACE version")
        func invalidVersion() throws {
            let identity = try SoftwareIdentity.generate(scheme: .ed25519)
            let reg = identity.toRegistrationFile(
                name: "Test Agent",
                endpoint: "https://agent.example.com"
            )

            // Construct a new RegistrationFile with wrong version
            let badReg = RegistrationFile(
                ace: "2.0",
                id: reg.id,
                name: reg.name,
                endpoint: reg.endpoint,
                tier: reg.tier,
                signing: reg.signing
            )

            #expect(throws: ACEError.self) {
                try validateRegistrationFile(badReg)
            }
        }

        @Test("rejects empty name")
        func emptyName() throws {
            let identity = try SoftwareIdentity.generate(scheme: .ed25519)
            let reg = identity.toRegistrationFile(
                name: "Test Agent",
                endpoint: "https://agent.example.com"
            )

            let badReg = RegistrationFile(
                ace: "1.0",
                id: reg.id,
                name: "",
                endpoint: reg.endpoint,
                tier: reg.tier,
                signing: reg.signing
            )

            #expect(throws: ACEError.self) {
                try validateRegistrationFile(badReg)
            }
        }

        @Test("rejects empty endpoint")
        func emptyEndpoint() throws {
            let identity = try SoftwareIdentity.generate(scheme: .ed25519)
            let reg = identity.toRegistrationFile(
                name: "Test Agent",
                endpoint: "https://agent.example.com"
            )

            let badReg = RegistrationFile(
                ace: "1.0",
                id: reg.id,
                name: reg.name,
                endpoint: "",
                tier: reg.tier,
                signing: reg.signing
            )

            #expect(throws: ACEError.self) {
                try validateRegistrationFile(badReg)
            }
        }

        @Test("rejects missing signing address")
        func missingSigningAddress() throws {
            let identity = try SoftwareIdentity.generate(scheme: .ed25519)
            let reg = identity.toRegistrationFile(
                name: "Test Agent",
                endpoint: "https://agent.example.com"
            )

            let badSigning = SigningConfig(
                scheme: .ed25519,
                address: "",
                encryptionPublicKey: reg.signing.encryptionPublicKey
            )

            let badReg = RegistrationFile(
                ace: "1.0",
                id: reg.id,
                name: reg.name,
                endpoint: reg.endpoint,
                tier: reg.tier,
                signing: badSigning
            )

            #expect(throws: ACEError.self) {
                try validateRegistrationFile(badReg)
            }
        }

        @Test("rejects missing encryption public key")
        func missingEncryptionKey() throws {
            let identity = try SoftwareIdentity.generate(scheme: .ed25519)
            let reg = identity.toRegistrationFile(
                name: "Test Agent",
                endpoint: "https://agent.example.com"
            )

            let badSigning = SigningConfig(
                scheme: .ed25519,
                address: reg.signing.address,
                encryptionPublicKey: ""
            )

            let badReg = RegistrationFile(
                ace: "1.0",
                id: reg.id,
                name: reg.name,
                endpoint: reg.endpoint,
                tier: reg.tier,
                signing: badSigning
            )

            #expect(throws: ACEError.self) {
                try validateRegistrationFile(badReg)
            }
        }
    }

    // ============================================================
    // verifyRegistrationId
    // ============================================================

    @Suite("verifyRegistrationId")
    struct VerifyRegistrationIdTests {

        @Test("returns true when ID matches signing key")
        func idMatches() throws {
            let identity = try SoftwareIdentity.generate(scheme: .ed25519)
            let reg = identity.toRegistrationFile(
                name: "Test Agent",
                endpoint: "https://agent.example.com"
            )
            #expect(try verifyRegistrationId(reg))
        }

        @Test("returns false when ID does not match")
        func idDoesNotMatch() throws {
            let identity = try SoftwareIdentity.generate(scheme: .ed25519)
            let reg = identity.toRegistrationFile(
                name: "Test Agent",
                endpoint: "https://agent.example.com"
            )

            let badReg = RegistrationFile(
                ace: "1.0",
                id: "ace:sha256:" + String(repeating: "0", count: 64),
                name: reg.name,
                endpoint: reg.endpoint,
                tier: reg.tier,
                signing: reg.signing
            )

            #expect(try !verifyRegistrationId(badReg))
        }

        @Test("works with secp256k1")
        func secp256k1IdMatches() throws {
            let identity = try SoftwareIdentity.generate(scheme: .secp256k1)
            let reg = identity.toRegistrationFile(
                name: "Test Agent",
                endpoint: "https://agent.example.com"
            )
            #expect(try verifyRegistrationId(reg))
        }
    }

    // ============================================================
    // getRegistrationSigningPublicKey
    // ============================================================

    @Suite("getRegistrationSigningPublicKey")
    struct GetSigningPubKeyTests {

        @Test("ed25519: extracts from address")
        func ed25519FromAddress() throws {
            let identity = try SoftwareIdentity.generate(scheme: .ed25519)
            let reg = identity.toRegistrationFile(
                name: "Test Agent",
                endpoint: "https://agent.example.com"
            )

            let pubKey = try getRegistrationSigningPublicKey(reg)
            #expect(pubKey == identity.getSigningPublicKey())
        }

        @Test("secp256k1: extracts from signingPublicKey field")
        func secp256k1FromField() throws {
            let identity = try SoftwareIdentity.generate(scheme: .secp256k1)
            let reg = identity.toRegistrationFile(
                name: "Test Agent",
                endpoint: "https://agent.example.com"
            )

            let pubKey = try getRegistrationSigningPublicKey(reg)
            #expect(pubKey == identity.getSigningPublicKey())
        }
    }

    // ============================================================
    // getRegistrationEncryptionPublicKey
    // ============================================================

    @Suite("getRegistrationEncryptionPublicKey")
    struct GetEncryptionPubKeyTests {

        @Test("extracts valid encryption public key")
        func validExtraction() throws {
            let identity = try SoftwareIdentity.generate(scheme: .ed25519)
            let reg = identity.toRegistrationFile(
                name: "Test Agent",
                endpoint: "https://agent.example.com"
            )

            let encKey = try getRegistrationEncryptionPublicKey(reg)
            #expect(encKey == identity.getEncryptionPublicKey())
            #expect(encKey.count == 32)
        }

        @Test("works with secp256k1 identity")
        func secp256k1Extraction() throws {
            let identity = try SoftwareIdentity.generate(scheme: .secp256k1)
            let reg = identity.toRegistrationFile(
                name: "Test Agent",
                endpoint: "https://agent.example.com"
            )

            let encKey = try getRegistrationEncryptionPublicKey(reg)
            #expect(encKey == identity.getEncryptionPublicKey())
            #expect(encKey.count == 32)
        }
    }
}
