//
//  Keccak256Tests.swift
//  ACE SDK
//
//  Test vectors verified via pycryptodome (Crypto.Hash.keccak, digest_bits=256).
//  Keccak-256 uses padding byte 0x01, NOT NIST SHA-3-256 (0x06).
//

import Testing
import Foundation
@testable import ACE

@Suite("Keccak-256")
struct Keccak256Tests {

    // MARK: - Helpers

    private func hex(_ data: Data) -> String {
        data.map { String(format: "%02x", $0) }.joined()
    }

    // MARK: - Standard Test Vectors (cross-validated with pycryptodome)

    @Test("empty input")
    func emptyInput() {
        let result = Keccak256.hash(Data())
        #expect(hex(result) == "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")
    }

    @Test("single byte 0xcc")
    func singleByte0xCC() {
        let result = Keccak256.hash(Data([0xcc]))
        #expect(hex(result) == "eead6dbfc7340a56caedc044696a168870549a6a7f6f56961e84a54bd9970b8a")
    }

    @Test("single byte 0x41 ('A')")
    func singleByteA() {
        let result = Keccak256.hash(Data([0x41]))
        #expect(hex(result) == "03783fac2efed8fbc9ad443e592ee30e61d65f471140c10ca155e937b435b760")
    }

    @Test("two bytes 'AB'")
    func twoBytes() {
        let result = Keccak256.hash(Data("AB".utf8))
        #expect(hex(result) == "21faab852d29e39c56dc14d20d71ba15c1ea83a26f45b658b5e8d0f8d61f3bbd")
    }

    @Test("short string 'abc'")
    func abc() {
        let result = Keccak256.hash(Data("abc".utf8))
        #expect(hex(result) == "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45")
    }

    @Test("string 'testing'")
    func testing() {
        let result = Keccak256.hash(Data("testing".utf8))
        #expect(hex(result) == "5f16f4c7f149ac4f9510d9cf8cf384038ad348b3bcdc01915f95de12df9d1b02")
    }

    @Test("string 'Hello World'")
    func helloWorld() {
        let result = Keccak256.hash(Data("Hello World".utf8))
        #expect(hex(result) == "592fa743889fc7f92ac2a37bb1f5ba1daf2a5c84741ca0e0061d243a2e6707ba")
    }

    // MARK: - Block Boundary Tests (rate = 136 bytes)

    @Test("135 bytes — just under one block")
    func underOneBlock() {
        let result = Keccak256.hash(Data(repeating: 0x61, count: 135))
        #expect(hex(result) == "34367dc248bbd832f4e3e69dfaac2f92638bd0bbd18f2912ba4ef454919cf446")
    }

    @Test("136 bytes — exactly one block")
    func exactlyOneBlock() {
        let result = Keccak256.hash(Data(repeating: 0x61, count: 136))
        #expect(hex(result) == "a6c4d403279fe3e0af03729caada8374b5ca54d8065329a3ebcaeb4b60aa386e")
    }

    @Test("137 bytes — one block + 1 byte overflow")
    func oneByteOverBlock() {
        let result = Keccak256.hash(Data(repeating: 0x61, count: 137))
        #expect(hex(result) == "d869f639c7046b4929fc92a4d988a8b22c55fbadb802c0c66ebcd484f1915f39")
    }

    // MARK: - Properties

    @Test("output is always 32 bytes")
    func outputLength() {
        for len in [0, 1, 31, 32, 33, 64, 135, 136, 137, 256, 1000] {
            let result = Keccak256.hash(Data(repeating: 0xAB, count: len))
            #expect(result.count == 32, "Expected 32 bytes for input length \(len)")
        }
    }

    @Test("deterministic — same input produces same hash")
    func deterministic() {
        let input = Data("ace-protocol".utf8)
        let h1 = Keccak256.hash(input)
        let h2 = Keccak256.hash(input)
        #expect(h1 == h2)
        #expect(hex(h1) == "c429a9d3d75ff45c86aad288f0b45dc68bfcd02a6d3963554d068b6b2a7a6c2d")
    }

    @Test("different inputs produce different hashes")
    func noCollision() {
        let h1 = Keccak256.hash(Data([0x00]))
        let h2 = Keccak256.hash(Data([0x01]))
        #expect(h1 != h2)
    }

    @Test("NOT SHA-3-256 — padding byte difference")
    func notSHA3() {
        // SHA-3-256("")  = a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a
        // Keccak-256("") = c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470
        let result = Keccak256.hash(Data())
        #expect(hex(result) != "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a",
                "Output matches SHA-3-256 — wrong padding byte used!")
    }
}
