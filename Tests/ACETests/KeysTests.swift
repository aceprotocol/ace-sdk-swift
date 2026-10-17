// Tests/ACETests/KeysTests.swift
import CryptoKit
import Foundation
import Testing
@testable import ACE

@Suite struct KeysTests {
    let body = Data("body".utf8)

    @Test func keyDigestLayout() {
        let pk = Data(repeating: 7, count: 1952)
        var m = Data("ml-dsa-65".utf8); m.append(0); m += pk
        #expect(keyDigest(publicKey: pk) == Data(SHA256.hash(data: m)))
    }

    @Test func softwareKeyFromSeedMatchesCryptoKit() throws {
        let seed = Data((0..<32).map { UInt8($0) })
        let a = try SoftwareKey(seed: seed), b = try SoftwareKey(seed: seed)
        #expect(a.publicKey() == b.publicKey())
        #expect(a.publicKey() == (try MLDSA65.PrivateKey(seedRepresentation: seed, publicKey: nil)).publicKey.rawRepresentation)
        #expect(a.publicKey().count == ACESigning.publicKeySize)
        let sig = try a.sign(body, action: "kel")
        #expect(sig.count == ACESigning.signatureSize)
        #expect(ACESigning.verifySignature(message: body, action: "kel", signature: sig, publicKey: a.publicKey()))
    }

    /// Same seed, same public key as Python `SoftwareKey("ml-dsa-65", bytes(range(32)))`.
    @Test func softwareKeyMatchesPythonSeedExpansion() throws {
        let k = try SoftwareKey(seed: Data((0..<32).map { UInt8($0) }))
        #expect(hexEncode(SHA256.hash(data: k.publicKey())) == "d666806e11cee19a7c989f7445f90dd419cf4d2d51db8c0fdb4c0f0a542238c9")
    }

    @Test func softwareKeyRejectsBadInput() throws {
        expectCode(.invalidArgument) { try SoftwareKey(seed: Data(count: 31)) }
        let k = SoftwareKey.generate()
        expectCode(.invalidArgument) { try k.sign(body, action: String(repeating: "a", count: 256)) }
        #expect(try k.sign(body, action: String(repeating: "a", count: 255)).count == 3309)
        expectCode(.invalidArgument) { try k.sign(body, action: String(repeating: "é", count: 128)) }
        #expect(try k.sign(body, action: String(repeating: "é", count: 127) + "a").count == 3309)
    }

    @Test func softwareKeyNeverShowsItsSeed() throws {
        let k = try SoftwareKey(seed: Data(repeating: 0xab, count: 32))
        var dumped = ""
        dump(k, to: &dumped)
        for text in [String(describing: k), String(reflecting: k), "\(k)"] {
            #expect(!text.contains("abab") && text.contains("<redacted>"), "\(text)")
        }
        #expect(!dumped.contains("- seed") && !dumped.contains("bytes"), "\(dumped)")
        #expect(!Mirror(reflecting: k).children.contains { $0.label == "seed" })
    }

    // MARK: Secure Enclave blob reader (pure; no Secure Enclave, no CryptoKit)

    static func tlv(_ tag: UInt8, _ v: [UInt8]) -> [UInt8] {
        let n = v.count
        let len: [UInt8] = n < 0x80 ? [UInt8(n)] : n < 0x100 ? [0x81, UInt8(n)] : [0x82, UInt8(n >> 8), UInt8(n & 0xff)]
        return [tag] + len + v
    }

    static func attr(_ name: String, _ value: [UInt8]) -> [UInt8] { attr(bytes: Array(name.utf8), value) }

    static func attr(bytes name: [UInt8], _ value: [UInt8]) -> [UInt8] { tlv(0x30, tlv(0x0c, name) + value) }

    static func acl(dacl: UInt8 = 0x01) -> [UInt8] {
        attr("ed", tlv(0x31, attr("acl", tlv(0x31, attr("dacl", tlv(0x01, [dacl]))))))
    }

    static func blob(_ attrs: [[UInt8]], ed: [UInt8] = acl()) -> Data {
        Data(tlv(0x04, tlv(0x31, attr("rk", tlv(0x31, attrs.flatMap { $0 })) + ed)))
    }

    static func pub(_ n: Int, name: String = "pub") -> [UInt8] { attr(name, tlv(0x04, [UInt8](repeating: 9, count: n))) }

    static let kt: [UInt8] = attr("kt", tlv(0x02, [0x0f]))

    @Test func secureEnclaveBlobReaderAcceptsTheKnownShape() {
        let bid = Self.attr("bid", Self.tlv(0x04, [1, 2, 3, 4]))
        #expect(SecureEnclaveBlob.publicKeyLength(Self.blob([bid, Self.pub(1952), Self.kt])) == 1952)
        #expect(SecureEnclaveBlob.publicKeyLength(Self.blob([Self.pub(2592)])) == 2592)
    }

    @Test func secureEnclaveBlobReaderFailsClosed() {
        let good = Self.blob([Self.pub(1952), Self.kt])
        // A decoy: the real attribute renamed, the `pub` byte pattern planted inside another value.
        let planted: [UInt8] = [0x0c, 0x03, 0x70, 0x75, 0x62, 0x04, 0x82, 0x07, 0xa0] + [UInt8](repeating: 9, count: 1952)
        // An 0x83 length form for the pub value.
        let long: [UInt8] = Self.tlv(0x30, Self.tlv(0x0c, Array("pub".utf8)) + [0x04, 0x83, 0x00, 0x07, 0xa0]
                                     + [UInt8](repeating: 9, count: 1952))
        let twoRk = Self.attr("rk", Self.tlv(0x31, Self.pub(1952))) + Self.attr("rk", Self.tlv(0x31, [])) + Self.acl()
        let pubValue = Self.tlv(0x04, [UInt8](repeating: 9, count: 1952))
        let threeParts = Self.tlv(0x30, Self.tlv(0x0c, Array("pub".utf8)) + Self.tlv(0x04, [1]) + Self.tlv(0x04, [2]))
        // A non-minimal 0x81 length for a short value.
        let nonMinimal: [UInt8] = Self.tlv(0x30, Self.tlv(0x0c, Array("kt".utf8)) + [0x02, 0x81, 0x01, 0x0f])
        let cases: [(String, Data)] = [
            ("renamed pub", Self.blob([Self.pub(1952, name: "qub"), Self.kt])),
            ("decoy", Self.blob([Self.pub(1952, name: "qub"), Self.attr("wk", Self.tlv(0x04, planted))])),
            ("0x83 length", Self.blob([long, Self.kt])),
            ("non-minimal length", Self.blob([Self.pub(1952), nonMinimal])),
            ("truncated", good.dropLast()),
            ("trailing bytes", good + Data([0])),
            ("duplicate pub", Self.blob([Self.pub(1952), Self.pub(1952)])),
            ("duplicate rk", Data(Self.tlv(0x04, Self.tlv(0x31, twoRk)))),
            ("pub not an OCTET STRING", Self.blob([Self.attr("pub", Self.tlv(0x02, [UInt8](repeating: 9, count: 1952)))])),
            ("attribute with a third element", Self.blob([threeParts])),
            ("no rk", Data(Self.tlv(0x04, Self.tlv(0x31, Self.attr("rq", Self.tlv(0x31, Self.pub(1952))) + Self.acl())))),
            ("no ed", Self.blob([Self.pub(1952)], ed: [])),
            ("access control other than the default", Self.blob([Self.pub(1952)], ed: Self.acl(dacl: 0x00))),
            ("extra top-level item", Self.blob([Self.pub(1952)], ed: Self.acl() + Self.attr("xx", Self.tlv(0x31, [])))),
            ("two outer sets", Data(Self.tlv(0x04, Self.tlv(0x31, []) + Self.tlv(0x31, [])))),
            ("BOM + pub", Self.blob([Self.attr(bytes: [0xef, 0xbb, 0xbf] + Array("pub".utf8), pubValue), Self.kt])),
            ("BOM + rk", Data(Self.tlv(0x04, Self.tlv(0x31, Self.attr(bytes: [0xef, 0xbb, 0xbf, 0x72, 0x6b], Self.tlv(0x31, Self.pub(1952)))
                                                       + Self.acl())))),
            ("non-UTF-8 pub name", Self.blob([Self.attr(bytes: [0x70, 0x75, 0x62, 0xff], pubValue), Self.kt])),
            ("pub name with a trailing NUL", Self.blob([Self.attr(bytes: Array("pub".utf8) + [0], pubValue), Self.kt])),
            ("pub name with a leading NUL", Self.blob([Self.attr(bytes: [0] + Array("pub".utf8), pubValue), Self.kt])),
            ("empty", Data()),
            ("garbage", Data(repeating: 1, count: 64)),
        ]
        for (label, data) in cases {
            #expect(SecureEnclaveBlob.publicKeyLength(data) == nil, "\(label)")
        }
    }

    /// Every single-bit flip of the non-key bytes of a real blob is either rejected by the
    /// reader or still reports the true public-key length (so CryptoKit is never handed a blob
    /// whose `pub` attribute it cannot find), and every flip of the access-control item is rejected.
    @Test(.enabled(if: SecureEnclaveKey.isAvailable))
    func secureEnclaveBlobReaderFuzzedFlips() throws {
        let blob = try SecureEnclaveKey.generate().dataRepresentation
        let size = ACESigning.publicKeySize
        #expect(SecureEnclaveBlob.publicKeyLength(blob) == size)
        let pkEnd = 46 + size
        #expect(blob.subdata(in: 46..<pkEnd).count == size)
        var accepted = 0
        for offset in Array(0..<46) + Array(pkEnd..<blob.count) {
            for bit in 0..<8 {
                var x = blob
                x[offset] ^= UInt8(1 << bit)
                let n = SecureEnclaveBlob.publicKeyLength(x)
                #expect(n == nil || n == size, "offset \(offset) bit \(bit)")
                #expect(n == nil || offset < blob.count - 28, "access control accepted at offset \(offset) bit \(bit)")
                if n != nil { accepted += 1 }
            }
        }
        #expect(accepted > 0)
    }

    @Test(.enabled(if: SecureEnclaveKey.isAvailable))
    func secureEnclaveKeySignsAndRestores() throws {
        let k = try SecureEnclaveKey.generate()
        let sig = try k.sign(body, action: "packet")
        #expect(ACESigning.verifySignature(message: body, action: "packet", signature: sig, publicKey: k.publicKey()))
        let r = try SecureEnclaveKey(dataRepresentation: k.dataRepresentation)
        #expect(r.publicKey() == k.publicKey())
        #expect(ACESigning.verifySignature(message: body, action: "packet", signature: try r.sign(body, action: "packet"), publicKey: k.publicKey()))
        expectCode(.invalidArgument) { try k.sign(body, action: String(repeating: "a", count: 256)) }
        expectCode(.invalidArgument) { try k.sign(body, action: String(repeating: "é", count: 128)) }
    }

    /// CryptoKit traps on a blob of another ML-DSA parameter set and restores an altered blob without error; both must be
    /// `invalid_argument` at restore.
    @Test(.enabled(if: SecureEnclaveKey.isAvailable))
    func secureEnclaveKeyRejectsForeignAndAlteredBlobs() throws {
        expectCode(.invalidArgument) { try SecureEnclaveKey(dataRepresentation: Data(repeating: 1, count: 64)) }
        let k65 = try SecureEnclaveKey.generate()
        let k87 = try SecureEnclaveGate.run { try SecureEnclave.MLDSA87.PrivateKey() }  // no longer an ACE scheme
        #expect(SecureEnclaveBlob.publicKeyLength(k65.dataRepresentation) == 1952)
        #expect(SecureEnclaveBlob.publicKeyLength(k87.dataRepresentation) == 2592)
        expectCode(.invalidArgument) { try SecureEnclaveKey(dataRepresentation: k87.dataRepresentation) }
        let blob = k65.dataRepresentation
        var pkFlip = blob; pkFlip[blob.startIndex + 100] ^= 1
        var tailFlip = blob; tailFlip[blob.endIndex - 5] ^= 1
        for altered in [pkFlip, tailFlip, blob.dropLast(10)] {
            expectCode(.invalidArgument) { try SecureEnclaveKey(dataRepresentation: Data(altered)) }
        }
        expectCode(.invalidArgument) { try SecureEnclaveKey(dataRepresentation: Data()) }
    }
}
