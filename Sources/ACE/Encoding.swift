//
//  Encoding.swift
//  ACE SDK
//
//  Strict wire encodings shared by every module (design §0).
//

import Foundation
import CryptoKit

// MARK: - Predicates

private func isLowerHex(_ b: UInt8) -> Bool { (b >= 0x30 && b <= 0x39) || (b >= 0x61 && b <= 0x66) }

/// `ace:sha256:<64 lowercase hex>`.
public func isACEId(_ value: String) -> Bool {
    let u = Array(value.utf8)
    guard u.count == 75, value.hasPrefix("ace:sha256:") else { return false }
    return u[11...].allSatisfy(isLowerHex)
}

/// Lowercase UUIDv4: `^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`.
public func isMessageId(_ value: String) -> Bool {
    let u = Array(value.utf8)
    guard u.count == 36 else { return false }
    for (n, b) in u.enumerated() {
        switch n {
        case 8, 13, 18, 23:
            guard b == UInt8(ascii: "-") else { return false }
        case 14:
            guard b == UInt8(ascii: "4") else { return false }
        case 19:
            guard b == UInt8(ascii: "8") || b == UInt8(ascii: "9") || b == UInt8(ascii: "a") || b == UInt8(ascii: "b") else { return false }
        default:
            guard isLowerHex(b) else { return false }
        }
    }
    return true
}

/// 64 lowercase hex characters.
public func isConversationId(_ value: String) -> Bool {
    let u = Array(value.utf8)
    return u.count == 64 && u.allSatisfy(isLowerHex)
}

/// 1..256 Unicode code points with no U+0000–U+001F or U+007F.
public func isThreadId(_ value: String) -> Bool {
    let scalars = value.unicodeScalars
    var count = 0
    for s in scalars {
        if isControlScalar(s) { return false }
        count += 1
        if count > ACELimits.maxThreadIdLength { return false }
    }
    return count >= 1
}

func isControlScalar(_ s: Unicode.Scalar) -> Bool { s.value < 0x20 || s.value == 0x7F }

func hasControlCharacter(_ value: String) -> Bool {
    value.unicodeScalars.contains(where: isControlScalar)
}

// MARK: - HTTPS URL grammar

private let urlLabel = "[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
private let httpsURLRegex = try! NSRegularExpression(
    pattern: "^https://(" + urlLabel + "(?:\\." + urlLabel + ")*)(?::([0-9]{1,5}))?"
        + "(?:[/?#][A-Za-z0-9\\-._~:/?#\\[\\]@!$&'()*+,;=%]*)?$"
)

/// The ACE HTTPS URL grammar (regex plus length / host / port checks). Never the platform URL parser.
func isHTTPSURL(_ value: String) -> Bool {
    guard value.utf8.count <= 2048, !value.contains("\n") else { return false }
    let ns = value as NSString
    let full = NSRange(location: 0, length: ns.length)
    guard let m = httpsURLRegex.firstMatch(in: value, range: full), m.range == full else { return false }
    let host = m.range(at: 1)
    guard host.location != NSNotFound, host.length <= 253 else { return false }
    let port = m.range(at: 2)
    if port.location != NSNotFound {
        guard let p = Int(ns.substring(with: port)), (1...65535).contains(p) else { return false }
    }
    return true
}

// MARK: - Base64

/// Padded standard RFC 4648 Base64. Decoding is canonical-only.
public enum ACEBase64 {
    public static func encode(_ data: Data) -> String {
        data.base64EncodedString()
    }

    /// Decode canonical padded standard Base64; `invalid_argument` otherwise.
    public static func decode(_ text: String) throws -> Data {
        try decodeB64(text, code: .invalidArgument, what: "value")
    }
}

private func isB64Char(_ b: UInt8) -> Bool {
    (b >= 0x41 && b <= 0x5A) || (b >= 0x61 && b <= 0x7A) || (b >= 0x30 && b <= 0x39) || b == 0x2B || b == 0x2F
}

/// Canonical padded standard Base64 or `ACEError(code)`. `maxBytes` refuses oversized text before decoding.
func decodeB64(_ text: String, code: ACEError.Code, what: String, maxBytes: Int? = nil) throws -> Data {
    let u = Array(text.utf8)
    if let maxBytes, u.count > 4 * ((maxBytes + 2) / 3) {
        throw ACEError(code, "\(what) is too large")
    }
    guard u.count % 4 == 0 else { throw ACEError(code, "\(what) is not padded standard Base64") }
    var pad = 0
    if let last = u.last, last == UInt8(ascii: "=") { pad += 1 }
    if u.count >= 2, u[u.count - 2] == UInt8(ascii: "=") { pad += 1 }
    for (n, b) in u.enumerated() where n < u.count - pad {
        guard isB64Char(b) else { throw ACEError(code, "\(what) is not padded standard Base64") }
    }
    guard let raw = Data(base64Encoded: text), raw.base64EncodedString() == text else {
        throw ACEError(code, "\(what) is not canonical Base64")
    }
    return raw
}

// MARK: - Hex

func hexEncode(_ data: some Sequence<UInt8>) -> String {
    let digits = Array("0123456789abcdef".utf8)
    var out: [UInt8] = []
    for b in data {
        out.append(digits[Int(b >> 4)])
        out.append(digits[Int(b & 0x0F)])
    }
    return String(decoding: out, as: UTF8.self)
}

/// Strict lowercase/uppercase hex without prefix (internal test / vector helper).
func hexDecode(_ text: String) -> Data? {
    let u = Array(text.utf8)
    guard u.count % 2 == 0 else { return nil }
    var out = Data(capacity: u.count / 2)
    func nib(_ b: UInt8) -> UInt8? {
        switch b {
        case 0x30...0x39: return b - 0x30
        case 0x61...0x66: return b - 0x61 + 10
        case 0x41...0x46: return b - 0x41 + 10
        default: return nil
        }
    }
    var n = 0
    while n < u.count {
        guard let h = nib(u[n]), let l = nib(u[n + 1]) else { return nil }
        out.append(h << 4 | l)
        n += 2
    }
    return out
}

func sha256Hex(_ data: Data) -> String {
    hexEncode(SHA256.hash(data: data))
}

/// `sha256(a ‖ 0x00 ‖ b)` over UTF-8 strings (Appendix A key derivation).
func sha256Hex(_ a: String, _ b: String) -> String {
    var d = Data(a.utf8)
    d.append(0)
    d.append(contentsOf: Array(b.utf8))
    return sha256Hex(d)
}

// MARK: - Signatures

/// ed25519: Base64 of 64 bytes. secp256k1: `0x` + 130 lowercase hex.
func encodeSignature(_ sig: Data, scheme: SigningScheme) -> String {
    switch scheme {
    case .ed25519: return ACEBase64.encode(sig)
    case .secp256k1: return "0x" + hexEncode(sig)
    }
}

/// Strict decoding: ed25519 canonical Base64 of exactly 64 bytes; secp256k1 `^0x[0-9a-f]{130}$`.
func decodeSignature(_ text: String, scheme: SigningScheme, code: ACEError.Code) throws -> Data {
    switch scheme {
    case .ed25519:
        let raw = try decodeB64(text, code: code, what: "ed25519 signature", maxBytes: 64)
        guard raw.count == 64 else { throw ACEError(code, "ed25519 signature must be 64 bytes") }
        return raw
    case .secp256k1:
        let u = Array(text.utf8)
        guard u.count == 132, u[0] == UInt8(ascii: "0"), u[1] == UInt8(ascii: "x"),
              u[2...].allSatisfy(isLowerHex), let raw = hexDecode(String(text.dropFirst(2))) else {
            throw ACEError(code, "secp256k1 signature must match ^0x[0-9a-f]{130}$")
        }
        return raw
    }
}
