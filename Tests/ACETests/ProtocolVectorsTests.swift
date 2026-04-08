//
//  ProtocolVectorsTests.swift
//  ACE SDK
//
//  Golden vectors shared across TS, PY, and Swift implementations.
//  These tests ensure cross-language interoperability.
//

import Testing
import Foundation
@testable import ACE

@Suite("Protocol Vectors")
struct ProtocolVectorsTests {

    @Test("ACE ID golden vector")
    func aceIdGoldenVector() {
        // bytes 0..32 (33 bytes total)
        let signingPub = Data((0..<33).map { UInt8($0) })
        let aceId = computeACEId(signingPub)
        #expect(aceId == "ace:sha256:5d8fcfefa9aeeb711fb8ed1e4b7d5c8a9bafa46e8e76e68aa18adce5a10df6ab")
    }

    @Test("conversationId golden vector")
    func conversationIdGoldenVector() throws {
        let pubA = Data((1...32).map { UInt8($0) })
        let pubB = Data((0..<32).map { UInt8(255 - $0) })
        let convId = try ACEEncryption.computeConversationId(pubA: pubA, pubB: pubB)
        #expect(convId == "fcdad8d0e1cbe6726f86938e504f6a7290c6d458181ced3e199cd25bf694cb40")
    }

    @Test("signData golden vector (unified V1)")
    func signDataGoldenVector() {
        let payload = Data([1, 2, 3, 4, 5, 6])
        // Build a message signData using unified API
        let messagePayload = ACESigning.encodePayload([.string("offer"), .string("ace:sha256:bbb"), .string("conv123"), .string("550e8400-e29b-41d4-a716-446655440000"), .string("thread-1"), .data(payload)])
        let signData = ACESigning.buildSignData(
            action: "message",
            aceId: "ace:sha256:aaa",
            timestamp: 1741000000,
            payload: messagePayload
        )
        // The hash will differ from old format — this is the new golden vector
        let hex = ACEHex.encode(signData)
        #expect(hex.count == 64, "signData should be 32 bytes (64 hex chars)")
        #expect(hex == "34bc0519278ebfd7ed8c97cbb348eac253a016c97710d69c8feb01afa2405c47")
    }

    @Test("secp256k1 address golden vector")
    func secp256k1AddressGoldenVector() throws {
        let compressedPub = try ACEHex.decode("0284bf7562262bbd6940085748f3be6afa52ae317155181ece31b66351ccffa4b0")
        let address = try secp256k1Address(compressedPub)
        #expect(address == "0x6370eF2f4Db3611D657b90667De398a2Cc2a370C")
    }
}
