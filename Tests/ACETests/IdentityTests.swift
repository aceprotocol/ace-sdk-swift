//
//  IdentityTests.swift
//  ACE SDK
//

import Testing
import Foundation
@testable import ACE

@Suite("Identity")
struct IdentityTests {

    @Test("ed25519 identity generation")
    func ed25519Generation() throws {
        let identity = try SoftwareIdentity.generate(scheme: .ed25519)
        #expect(identity.getSigningScheme() == .ed25519)
        #expect(identity.getTier() == .keyOnly)
        #expect(identity.getSigningPublicKey().count == 32)
        #expect(identity.getEncryptionPublicKey().count == 32)
        #expect(identity.getACEId().hasPrefix("ace:sha256:"))
        #expect(identity.getACEId().count == 11 + 64) // "ace:sha256:" + 64 hex
    }

    @Test("secp256k1 identity generation")
    func secp256k1Generation() throws {
        let identity = try SoftwareIdentity.generate(scheme: .secp256k1)
        #expect(identity.getSigningScheme() == .secp256k1)
        #expect(identity.getSigningPublicKey().count == 33) // compressed
        #expect(identity.getEncryptionPublicKey().count == 32)
        #expect(identity.getAddress().hasPrefix("0x"))
        #expect(identity.getAddress().count == 42) // 0x + 40 hex
    }

    @Test("ed25519 address is Base58")
    func ed25519Address() throws {
        let identity = try SoftwareIdentity.generate(scheme: .ed25519)
        let address = identity.getAddress()
        // Should be decodable as Base58
        let decoded = try Base58.decode(address)
        #expect(decoded.count == 32) // Ed25519 public key
    }

    @Test("export/import roundtrip — ed25519")
    func exportImportEd25519() throws {
        let original = try SoftwareIdentity.generate(scheme: .ed25519)
        let exported = original.exportPrivateKey()
        let restored = try SoftwareIdentity.fromExport(exported)
        #expect(restored.getACEId() == original.getACEId())
        #expect(restored.getAddress() == original.getAddress())
        #expect(restored.getSigningPublicKey() == original.getSigningPublicKey())
        #expect(restored.getEncryptionPublicKey() == original.getEncryptionPublicKey())
    }

    @Test("export/import roundtrip — secp256k1")
    func exportImportSecp256k1() throws {
        let original = try SoftwareIdentity.generate(scheme: .secp256k1)
        let exported = original.exportPrivateKey()
        let restored = try SoftwareIdentity.fromExport(exported)
        #expect(restored.getACEId() == original.getACEId())
        #expect(restored.getAddress() == original.getAddress())
        #expect(restored.getSigningPublicKey() == original.getSigningPublicKey())
    }

    @Test("ACE ID matches signing public key")
    func aceIdFromPublicKey() throws {
        let identity = try SoftwareIdentity.generate(scheme: .ed25519)
        let expected = computeACEId(identity.getSigningPublicKey())
        #expect(identity.getACEId() == expected)
    }

    @Test("registration file generation — ed25519")
    func registrationFileEd25519() throws {
        let identity = try SoftwareIdentity.generate(scheme: .ed25519)
        let reg = identity.toRegistrationFile(name: "TestAgent", endpoint: "https://test.example.com/ace")
        #expect(reg.ace == "1.0")
        #expect(reg.id == identity.getACEId())
        #expect(reg.name == "TestAgent")
        #expect(reg.signing.scheme == .ed25519)
        #expect(reg.signing.signingPublicKey == nil) // ed25519 doesn't need it
    }

    @Test("registration file generation — secp256k1")
    func registrationFileSecp256k1() throws {
        let identity = try SoftwareIdentity.generate(scheme: .secp256k1)
        let reg = identity.toRegistrationFile(name: "EVMAgent", endpoint: "https://evm.example.com/ace")
        #expect(reg.signing.scheme == .secp256k1)
        #expect(reg.signing.signingPublicKey != nil) // secp256k1 requires it
        // Validate the registration file
        try validateRegistrationFile(reg)
        let valid = try verifyRegistrationId(reg)
        #expect(valid)
    }

    @Test("ed25519 registration rejects mismatched signingPublicKey")
    func registrationFileRejectsMismatchedEd25519SigningKey() throws {
        let identity = try SoftwareIdentity.generate(scheme: .ed25519)
        let otherIdentity = try SoftwareIdentity.generate(scheme: .ed25519)
        var reg = identity.toRegistrationFile(name: "TestAgent", endpoint: "https://test.example.com/ace")
        reg.signing.signingPublicKey = ACEBase64.encode(otherIdentity.getSigningPublicKey())

        #expect(throws: ACEError.self) {
            try validateRegistrationFile(reg)
        }
        #expect(throws: ACEError.self) {
            _ = try getRegistrationSigningPublicKey(reg)
        }
    }
}
