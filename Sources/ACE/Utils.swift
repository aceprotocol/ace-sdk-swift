//
//  Utils.swift
//  ACE SDK
//
//  Shared utility functions: Base64, hex, Base58, EIP-55, constant-time comparison.
//

import Foundation
import CryptoKit
import P256K

// MARK: - Base64

public enum ACEBase64 {
    public static func encode(_ data: Data) -> String {
        data.base64EncodedString()
    }

    public static func decode(_ string: String) throws -> Data {
        guard let data = Data(base64Encoded: string) else {
            throw ACEError.invalidMessage("Invalid Base64 string")
        }
        return data
    }
}

// MARK: - Hex

public enum ACEHex {
    private static let hexChars: [UInt8] = Array("0123456789abcdef".utf8)

    public static func encode(_ data: Data) -> String {
        var result = [UInt8](repeating: 0, count: data.count * 2)
        for (i, byte) in data.enumerated() {
            result[i * 2] = hexChars[Int(byte >> 4)]
            result[i * 2 + 1] = hexChars[Int(byte & 0x0F)]
        }
        return String(bytes: result, encoding: .ascii)!
    }

    public static func decode(_ string: String) throws -> Data {
        var hex = string
        if hex.hasPrefix("0x") || hex.hasPrefix("0X") {
            hex = String(hex.dropFirst(2))
        }
        guard hex.count % 2 == 0 else {
            throw ACEError.invalidMessage("Hex string must have even length")
        }
        var data = Data(capacity: hex.count / 2)
        var chars = hex.makeIterator()
        while let hi = chars.next(), let lo = chars.next() {
            guard let hNib = hexVal(hi), let lNib = hexVal(lo) else {
                throw ACEError.invalidMessage("Invalid hex character")
            }
            data.append(hNib << 4 | lNib)
        }
        return data
    }

    private static func hexVal(_ c: Character) -> UInt8? {
        switch c {
        case "0"..."9": return UInt8(c.asciiValue! - Character("0").asciiValue!)
        case "a"..."f": return UInt8(c.asciiValue! - Character("a").asciiValue!) + 10
        case "A"..."F": return UInt8(c.asciiValue! - Character("A").asciiValue!) + 10
        default: return nil
        }
    }
}

// MARK: - Base58 (Bitcoin alphabet)

public enum Base58: Sendable {

    private static let alphabet = Array("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")

    /// Reverse lookup table: ASCII value → alphabet index (0–57), or -1 for invalid.
    private static let decodeTable: [Int8] = {
        var table = [Int8](repeating: -1, count: 128)
        for (i, ch) in alphabet.enumerated() {
            table[Int(ch.asciiValue!)] = Int8(i)
        }
        return table
    }()

    /// Encode raw bytes to a Base58 string.
    public static func encode(_ data: Data) -> String {
        guard !data.isEmpty else { return "" }

        let bytes = [UInt8](data)

        // Count leading zeros → leading '1's
        var leadingZeros = 0
        for b in bytes {
            if b == 0 { leadingZeros += 1 } else { break }
        }

        // Base conversion: big-endian bytes → base-58 digits
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

        // Strip trailing zeros in digits (= leading zeros in big-endian output).
        while digits.count > 1 && digits.last == 0 {
            digits.removeLast()
        }
        var result = String(repeating: "1", count: leadingZeros)
        if leadingZeros < data.count {
            for d in digits.reversed() {
                result.append(alphabet[Int(d)])
            }
        }
        return result
    }

    /// Maximum Base58 input length. ed25519 keys (32 bytes) encode to ~44 chars.
    /// 128 chars is generous enough for any key format while blocking DoS via O(n²) decode.
    public static let maxDecodeLength = 128

    /// Decode a Base58 string to raw bytes.
    /// - Throws: `ACEError.invalidMessage` on illegal characters or oversized input.
    public static func decode(_ string: String) throws -> Data {
        guard !string.isEmpty else { return Data() }
        guard string.count <= maxDecodeLength else {
            throw ACEError.invalidMessage("Base58 input too long: \(string.count) chars exceeds max \(maxDecodeLength)")
        }

        // Count leading '1's → leading zero bytes
        var leadingOnes = 0
        for ch in string {
            if ch == "1" { leadingOnes += 1 } else { break }
        }

        // Base conversion: base-58 digits → big-endian bytes (O(1) lookup per char)
        var bytes: [UInt8] = [0]
        for ch in string {
            guard let ascii = ch.asciiValue, ascii < 128 else {
                throw ACEError.invalidMessage("Invalid Base58 character: \(ch)")
            }
            let value = decodeTable[Int(ascii)]
            guard value >= 0 else {
                throw ACEError.invalidMessage("Invalid Base58 character: \(ch)")
            }
            var carry = Int(value)
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

        // Strip trailing zeros (= leading zeros in big-endian)
        while bytes.count > 1 && bytes.last == 0 {
            bytes.removeLast()
        }

        let leadingZeros = Data(repeating: 0, count: leadingOnes)
        // If all chars were leading '1's, bytes is just [0] — already covered by leadingZeros
        if leadingOnes == string.count {
            return leadingZeros
        }
        return leadingZeros + Data(bytes.reversed())
    }
}

// MARK: - EIP-55 Checksum Address

enum EIP55 {
    static func checksum(_ address: String) -> String {
        let addr = address.lowercased().replacingOccurrences(of: "0x", with: "")
        precondition(addr.count <= 64, "EIP55.checksum: address exceeds 64 hex chars")
        let hash = ACEHex.encode(Data(Keccak256.hash(Data(addr.utf8))))
        var result = "0x"
        for (i, c) in addr.enumerated() {
            let hashChar = hash[hash.index(hash.startIndex, offsetBy: i)]
            if let v = hashChar.hexDigitValue, v >= 8 {
                result.append(c.uppercased().first!)
            } else {
                result.append(c)
            }
        }
        return result
    }
}

// MARK: - secp256k1 Address Derivation

/// Derive Ethereum-style address from a secp256k1 compressed public key (33 bytes).
/// keccak256(uncompressed[1:]) → last 20 bytes → EIP-55 hex
public func secp256k1Address(_ compressedPubKey: Data) throws -> String {
    guard compressedPubKey.count == 33 else {
        throw ACEError.invalidKey("secp256k1 compressed public key must be 33 bytes, got \(compressedPubKey.count)")
    }
    // Decompress using P256K.Signing.PublicKey (has uncompressedRepresentation)
    let pubKey = try P256K.Signing.PublicKey(dataRepresentation: compressedPubKey, format: .compressed)
    let uncompressed = pubKey.uncompressedRepresentation
    guard uncompressed.count == 65, uncompressed[0] == 0x04 else {
        throw ACEError.invalidKey("Failed to decompress secp256k1 public key")
    }
    // keccak256(uncompressed[1:]) → last 20 bytes
    let hash = Keccak256.hash(uncompressed.dropFirst())
    let addr = "0x" + ACEHex.encode(hash.suffix(20))
    return EIP55.checksum(addr)
}

// MARK: - ACE ID

/// Compute ACE ID from a signing public key.
/// aceId = "ace:sha256:" + hex(SHA-256(signingPublicKeyBytes))
public func computeACEId(_ signingPublicKey: Data) -> String {
    let hash = Data(SHA256.hash(data: signingPublicKey))
    return "ace:sha256:" + ACEHex.encode(hash)
}

// MARK: - Constant-Time Comparison

/// Constant-time byte comparison using system-level timingsafe_bcmp.
/// Immune to Swift compiler optimizations that could break timing guarantees.
func constantTimeEqual(_ a: Data, _ b: Data) -> Bool {
    guard a.count == b.count else { return false }
    return a.withUnsafeBytes { aPtr in
        b.withUnsafeBytes { bPtr in
            timingsafe_bcmp(aPtr.baseAddress!, bPtr.baseAddress!, a.count) == 0
        }
    }
}
