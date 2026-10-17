import CryptoKit
import Foundation
import Testing
@testable import ACE

@Suite struct SigningTests {
    let aceId = "ace:sha256:" + String(repeating: "ab", count: 32)

    @Test func messageLayout() throws {
        let m = try ACESigning.message(aceId: aceId, timestamp: 0x0102030405, seq: 7, payload: Data([9, 8]))
        #expect(m == ACESigning.encodePayload([.string("ace.v1"), .string(aceId), .string("4328719365"), .string("7"), .data(Data([9, 8]))]))
        let kel = try ACESigning.message(aceId: aceId, timestamp: maxSafeInteger, seq: nil, payload: Data())
        #expect(kel == ACESigning.encodePayload("ace.v1", aceId, "9007199254740991", "", ""))
    }

    /// A 256-byte UTF-8 action exceeds ML-DSA's 255-byte context: `false`, never a trap or throw. No signature under a
    /// 256-byte context can exist (ML-DSA caps ctx at 255 bytes), so the length handling is isolated with the closest
    /// one: a valid signature under the action's 255-byte prefix, which an implementation that truncated the context
    /// would accept. The control verifies it under the prefix itself.
    @Test func overlongActionIsFalse() throws {
        let key = try MLDSA65.PrivateKey(), pk = key.publicKey.rawRepresentation
        let body = Data("b".utf8)
        let prefix = String(repeating: "a", count: 255), action = prefix + "a"
        let sig = try key.signature(for: body, context: Data(prefix.utf8))
        #expect(ACESigning.verifySignature(message: body, action: prefix, signature: sig, publicKey: pk))
        #expect(!ACESigning.verifySignature(message: body, action: action, signature: sig, publicKey: pk))
        let multibyte = String(repeating: "é", count: 128)  // 256 bytes; its 255-byte prefix splits the last character
        #expect(multibyte.utf8.count == 256)
        let prefixSig = try key.signature(for: body, context: Data(multibyte.utf8.prefix(255)))
        #expect(!ACESigning.verifySignature(message: body, action: multibyte, signature: prefixSig, publicKey: pk))
    }

    @Test(arguments: [-1, maxSafeInteger + 1])
    func messageRejectsNonWireIntegers(_ n: Int) {
        expectCode(.invalidArgument) { try ACESigning.message(aceId: aceId, timestamp: n, seq: nil, payload: Data()) }
        expectCode(.invalidArgument) { try ACESigning.message(aceId: aceId, timestamp: 0, seq: n, payload: Data()) }
    }

    @Test func verifyUsesTheActionAsContext() throws {
        let key = try MLDSA65.PrivateKey()
        let body = try ACESigning.message(aceId: aceId, timestamp: 1, seq: 1, payload: Data("p".utf8))
        let sig = try key.signature(for: body, context: Data("packet".utf8))
        let pk = key.publicKey.rawRepresentation
        #expect(ACESigning.verifySignature(message: body, action: "packet", signature: sig, publicKey: pk))
        #expect(!ACESigning.verifySignature(message: body, action: "inbox", signature: sig, publicKey: pk))
        #expect(!ACESigning.verifySignature(message: body + Data([0]), action: "packet", signature: sig, publicKey: pk))
    }

    @Test func malformedInputIsFalseNotAThrow() throws {
        let key = try MLDSA65.PrivateKey()
        let body = Data("b".utf8)
        let sig = try key.signature(for: body, context: Data("kel".utf8))
        let pk = key.publicKey.rawRepresentation
        #expect(ACESigning.verifySignature(message: body, action: "kel", signature: sig, publicKey: pk))
        #expect(!ACESigning.verifySignature(message: body, action: "kel", signature: sig.dropLast(), publicKey: pk))
        #expect(!ACESigning.verifySignature(message: body, action: "kel", signature: sig, publicKey: Data(count: 32)))
        #expect(!ACESigning.verifySignature(message: body, action: "kel", signature: sig, publicKey: Data(count: 1952)))
    }

    @Test func publicKeySizes() {
        #expect(ACESigning.isValidSigningPublicKey("ml-dsa-65", Data(count: 1952)))
        #expect(!ACESigning.isValidSigningPublicKey("ml-dsa-65", Data(count: 2592)))
        #expect(!ACESigning.isValidSigningPublicKey("ml-dsa-87", Data(count: 2592)))
        #expect(!ACESigning.isValidSigningPublicKey("x-wing", Data(count: 1216)))
    }

    /// Review Focus 1: the same integers Python's `wire_int` accepts.
    @Test func wireIntAgreesWithPython() throws {
        let accepted: [(String, Int)] = [("0", 0), ("1", 1), ("1.0", 1), ("1e0", 1), ("9007199254740991", maxSafeInteger)]
        for (text, value) in accepted {
            #expect(wireInt(try JSONValue(json: Data(text.utf8))) == value, "\(text)")
        }
        for text in ["true", "-1", "-0.5", "1.5", "9007199254740992", "\"1\"", "null", "[]"] {
            #expect(wireInt(try JSONValue(json: Data(text.utf8))) == nil, "\(text)")
        }
        #expect(wireInt(nil) == nil)
    }

    @Test func decodeB64BoundIsDecodedBytes() throws {
        let text = Data(count: 16384).base64EncodedString()
        #expect(try decodeB64(text, code: .invalidBody, what: "e", maxBytes: 16384).count == 16384)
        expectCode(.invalidBody) {
            try decodeB64(Data(count: 16385).base64EncodedString(), code: .invalidBody, what: "e", maxBytes: 16384)
        }
    }

    @Test func mlDsaSignatureCodec() throws {
        let raw = Data(count: 3309)
        #expect(try decodeSignature(ACEBase64.encode(raw), code: .invalidPacket) == raw)
        expectCode(.invalidPacket) { try decodeSignature(ACEBase64.encode(Data(count: 3308)), code: .invalidPacket) }
        expectCode(.invalidPacket) { try decodeSignature(ACEBase64.encode(Data(count: 4627)), code: .invalidPacket) }
    }

    @Test func schemesAndHelpers() {
        #expect(SigningScheme.allCases == [.mlDsa65])
        #expect(ACESigning.seedSize == 32 && ACESigning.signatureSize == 3309 && ACESigning.publicKeySize == 1952)
        #expect(ACESigning.encodePayload("a", "") == Data([0, 0, 0, 1, 0x61, 0, 0, 0, 0]))
        #expect(ACESigning.encodePayload([.data(Data([1])), .string("é")]) == Data([0, 0, 0, 1, 1, 0, 0, 0, 2, 0xc3, 0xa9]))
        #expect(isSHA256Hex(String(repeating: "0a", count: 32)) && !isSHA256Hex(String(repeating: "0A", count: 32)))
        #expect(decimal(0) == "0" && decimal(maxSafeInteger) == "9007199254740991")
        expectCode(.invalidArgument) { try checkWireInt(.bool(true), "seq") }
        #expect((try? checkWireInt(.number(3), "seq")) == 3)
    }
}
