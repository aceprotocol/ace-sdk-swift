//
//  Utils.swift
//  ACE SDK
//
//  Base58, EIP-55, secp256k1 addresses, ACE IDs and constant-time comparison.
//

import Foundation
import CryptoKit
import P256K

// MARK: - Base58 (Bitcoin alphabet)

enum Base58 {
    private static let alphabet = Array("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".utf8)

    private static let decodeTable: [Int8] = {
        var table = [Int8](repeating: -1, count: 128)
        for (i, ch) in alphabet.enumerated() { table[Int(ch)] = Int8(i) }
        return table
    }()

    /// Inputs longer than this are refused (decoding is O(n²)).
    static let maxDecodeLength = 128

    static func encode(_ data: Data) -> String {
        let bytes = [UInt8](data)
        guard !bytes.isEmpty else { return "" }
        let leadingZeros = bytes.prefix(while: { $0 == 0 }).count
        var digits: [UInt8] = [0]
        for byte in bytes {
            var carry = Int(byte)
            for j in 0..<digits.count {
                carry += Int(digits[j]) << 8
                digits[j] = UInt8(carry % 58)
                carry /= 58
            }
            while carry > 0 {
                digits.append(UInt8(carry % 58))
                carry /= 58
            }
        }
        while digits.count > 1 && digits.last == 0 { digits.removeLast() }
        var out = [UInt8](repeating: alphabet[0], count: leadingZeros)
        if leadingZeros < bytes.count {
            out.append(contentsOf: digits.reversed().map { alphabet[Int($0)] })
        }
        return String(decoding: out, as: UTF8.self)
    }

    static func decode(_ string: String) -> Data? {
        let chars = Array(string.utf8)
        guard !chars.isEmpty, chars.count <= maxDecodeLength else { return chars.isEmpty ? Data() : nil }
        let leadingOnes = chars.prefix(while: { $0 == alphabet[0] }).count
        var bytes: [UInt8] = [0]
        for ch in chars {
            guard ch < 128, decodeTable[Int(ch)] >= 0 else { return nil }
            var carry = Int(decodeTable[Int(ch)])
            for j in 0..<bytes.count {
                carry += Int(bytes[j]) * 58
                bytes[j] = UInt8(carry & 0xFF)
                carry >>= 8
            }
            while carry > 0 {
                bytes.append(UInt8(carry & 0xFF))
                carry >>= 8
            }
        }
        while bytes.count > 1 && bytes.last == 0 { bytes.removeLast() }
        if leadingOnes == chars.count { return Data(repeating: 0, count: leadingOnes) }
        return Data(repeating: 0, count: leadingOnes) + Data(bytes.reversed())
    }
}

// MARK: - EIP-55 / secp256k1 address

func eip55(_ addressHex40: String) -> String {
    let addr = addressHex40.lowercased()
    let hash = hexEncode(Keccak256.hash(Data(addr.utf8)))
    var out = "0x"
    for (c, h) in zip(addr, hash) {
        if let v = h.hexDigitValue, v >= 8 { out += c.uppercased() } else { out.append(c) }
    }
    return out
}

/// EIP-55 address of a 33-byte compressed secp256k1 public key.
func secp256k1Address(_ compressedPublicKey: Data) throws -> String {
    guard compressedPublicKey.count == 33 else {
        throw ACEError(.invalidKey, "secp256k1 public key must be 33 bytes")
    }
    let key: P256K.Signing.PublicKey
    do {
        key = try P256K.Signing.PublicKey(dataRepresentation: compressedPublicKey, format: .compressed)
    } catch {
        throw ACEError(.invalidKey, "secp256k1 public key is not on the curve")
    }
    let uncompressed = key.uncompressedRepresentation
    return eip55(hexEncode(Keccak256.hash(Data(uncompressed.dropFirst())).suffix(20)))
}

/// ed25519: Base58 of the key. secp256k1: EIP-55 address of the compressed key.
func signingAddress(scheme: SigningScheme, signingPublicKey: Data) -> String {
    switch scheme {
    case .ed25519: return Base58.encode(signingPublicKey)
    case .secp256k1: return (try? secp256k1Address(signingPublicKey)) ?? ""
    }
}

// MARK: - ACE ID

/// `ace:sha256:` + hex(SHA-256(signingPublicKey)).
public func computeACEId(_ signingPublicKey: Data) -> String {
    "ace:sha256:" + sha256Hex(signingPublicKey)
}

// MARK: - Constant-time comparison

func constantTimeEqual(_ a: Data, _ b: Data) -> Bool {
    guard a.count == b.count else { return false }
    guard !a.isEmpty else { return true }
    return a.withUnsafeBytes { ap in
        b.withUnsafeBytes { bp in timingsafe_bcmp(ap.baseAddress!, bp.baseAddress!, a.count) == 0 }
    }
}
