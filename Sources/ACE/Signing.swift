//
//  Signing.swift
//  ACE SDK
//
//  signData construction and strict ed25519 / secp256k1 verification. Internal.
//
//  signData = SHA-256("ace.v1" || lp(action) || lp(aceId) || ts[8 BE] || lp(payload))
//

import Foundation
import CryptoKit
import P256K

enum ACESigning {

    enum Field {
        case string(String)
        case data(Data)
    }

    /// `len(4 BE) || bytes` per field; strings are UTF-8.
    static func encodePayload(_ fields: [Field]) -> Data {
        var out = Data()
        for f in fields {
            switch f {
            case .string(let s): appendPrefixed(Data(s.utf8), to: &out)
            case .data(let d): appendPrefixed(d, to: &out)
            }
        }
        return out
    }

    static func encodePayload(_ strings: String...) -> Data {
        encodePayload(strings.map { .string($0) })
    }

    static func buildSignData(action: String, aceId: String, timestamp: Int, payload: Data = Data()) throws -> Data {
        guard isWireInt(timestamp) else {
            throw ACEError(.invalidArgument, "timestamp must be an integer in [0, 2^53-1]")
        }
        var buf = Data("ace.v1".utf8)
        appendPrefixed(Data(action.utf8), to: &buf)
        appendPrefixed(Data(aceId.utf8), to: &buf)
        var ts = UInt64(timestamp).bigEndian
        withUnsafeBytes(of: &ts) { buf.append(contentsOf: $0) }
        appendPrefixed(payload, to: &buf)
        return Data(SHA256.hash(data: buf))
    }

    private static func appendPrefixed(_ d: Data, to buf: inout Data) {
        var len = UInt32(d.count).bigEndian
        withUnsafeBytes(of: &len) { buf.append(contentsOf: $0) }
        buf.append(d)
    }

    // MARK: Keys

    /// ed25519: 32 bytes. secp256k1: a 33-byte compressed point on the curve.
    static func isValidSigningPublicKey(_ scheme: SigningScheme, _ key: Data) -> Bool {
        switch scheme {
        case .ed25519:
            return key.count == 32
        case .secp256k1:
            guard key.count == 33, key.first == 0x02 || key.first == 0x03 else { return false }
            return (try? P256K.Signing.PublicKey(dataRepresentation: key, format: .compressed)) != nil
        }
    }

    // MARK: Verification

    static func verify(signData: Data, signature: Data, scheme: SigningScheme, publicKey: Data) -> Bool {
        switch scheme {
        case .ed25519: return verifyEd25519(signData: signData, signature: signature, publicKey: publicKey)
        case .secp256k1: return verifySecp256k1(signData: signData, signature: signature, publicKey: publicKey)
        }
    }

    /// L = 2^252 + 27742317777372353535851937790883648493, little-endian.
    private static let ed25519L: [UInt8] = [
        0xED, 0xD3, 0xF5, 0x5C, 0x1A, 0x63, 0x12, 0x58, 0xD6, 0x9C, 0xF7, 0xA2, 0xDE, 0xF9, 0xDE, 0x14,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
    ]

    private static let smallOrder: Set<Data> = Set([
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0100000000000000000000000000000000000000000000000000000000000000",
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    ].map { hexDecode($0)! })

    /// Little-endian `a < b` for 32-byte values.
    private static func lessLE(_ a: [UInt8], _ b: [UInt8]) -> Bool {
        for i in stride(from: 31, through: 0, by: -1) where a[i] != b[i] {
            return a[i] < b[i]
        }
        return false
    }

    /// Canonical (y < p) and not one of the small-order encodings.
    private static func ed25519PointOK(_ enc: [UInt8]) -> Bool {
        var b = enc
        b[31] &= 0x7F
        if b[31] == 0x7F, b[1...30].allSatisfy({ $0 == 0xFF }), b[0] >= 0xED { return false }
        return !smallOrder.contains(Data(b))
    }

    /// Strict ed25519 (signing-schemes/ed25519.md): steps 1–4 here, then CryptoKit.
    static func verifyEd25519(signData: Data, signature: Data, publicKey: Data) -> Bool {
        guard signature.count == 64, publicKey.count == 32 else { return false }
        let sig = [UInt8](signature), pk = [UInt8](publicKey)
        guard lessLE(Array(sig[32..<64]), ed25519L) else { return false }
        guard ed25519PointOK(pk), ed25519PointOK(Array(sig[0..<32])) else { return false }
        guard let key = try? Curve25519.Signing.PublicKey(rawRepresentation: publicKey) else { return false }
        return key.isValidSignature(signature, for: signData)
    }

    private static let secpN: [UInt8] = [
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
        0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41,
    ]
    private static let secpHalfN: [UInt8] = [
        0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0x5D, 0x57, 0x6E, 0x73, 0x57, 0xA4, 0x50, 0x1D, 0xDF, 0xE9, 0x2F, 0x46, 0x68, 0x1B, 0x20, 0xA0,
    ]

    /// Big-endian comparison of equal-length byte strings (-1 / 0 / 1).
    private static func compareBE(_ a: [UInt8], _ b: [UInt8]) -> Int {
        for i in 0..<a.count where a[i] != b[i] { return a[i] < b[i] ? -1 : 1 }
        return 0
    }

    /// Strict secp256k1: r ∈ [1, n−1], s ∈ [1, n/2], v ∈ {0, 1}; recover and compare the
    /// 33-byte compressed key in constant time.
    static func verifySecp256k1(signData: Data, signature: Data, publicKey: Data) -> Bool {
        guard signature.count == 65, signData.count == 32, isValidSigningPublicKey(.secp256k1, publicKey) else { return false }
        let sig = [UInt8](signature)
        let r = Array(sig[0..<32]), s = Array(sig[32..<64]), v = sig[64]
        guard v <= 1 else { return false }
        guard r.contains(where: { $0 != 0 }), compareBE(r, secpN) < 0 else { return false }
        guard s.contains(where: { $0 != 0 }), compareBE(s, secpHalfN) <= 0 else { return false }
        do {
            // Plain verification under the expected key first: P256K's recovery initializer
            // traps (fatalError) when `r` is not the x-coordinate of a curve point, so a forged
            // signature must never reach it. A signature valid here always recovers.
            let digest = HashDigest([UInt8](signData))
            let expected = try P256K.Signing.PublicKey(dataRepresentation: publicKey, format: .compressed)
            guard expected.isValidSignature(try P256K.Signing.ECDSASignature(compactRepresentation: r + s), for: digest) else {
                return false
            }
            let rs = try P256K.Recovery.ECDSASignature(compactRepresentation: r + s, recoveryId: Int32(v))
            let recovered = P256K.Recovery.PublicKey(digest, signature: rs)
            return constantTimeEqual(Data(recovered.dataRepresentation), publicKey)
        } catch {
            return false
        }
    }
}
