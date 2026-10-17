//
//  Encoding.swift
//  ACE SDK
//
//  Strict wire encodings shared by every module (02).
//

import Foundation
import CryptoKit

// MARK: - Predicates

package func isLowerHex(_ b: UInt8) -> Bool { (b >= 0x30 && b <= 0x39) || (b >= 0x61 && b <= 0x66) }

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

/// 64 lowercase hex characters: a SHA-256 digest (schema digests, prekey IDs, nonces).
package func isSHA256Hex(_ value: String) -> Bool {
    let u = Array(value.utf8)
    return u.count == 64 && u.allSatisfy(isLowerHex)
}

/// The local conversation key of two ACE IDs: `hex(SHA-256(min(a, b) ‖ 0x00 ‖ max(a, b)))` over their UTF-8 bytes.
/// Never on the wire.
public func conversationKey(_ a: String, _ b: String) -> String {
    let (lo, hi) = a.utf8.lexicographicallyPrecedes(b.utf8) ? (a, b) : (b, a)
    return pairDigest(lo, hi)
}

/// `hex(SHA-256(a ‖ 0x00 ‖ b))` over the UTF-8 bytes, in the given order: the local store key of a pair.
package func pairDigest(_ a: String, _ b: String) -> String {
    var d = Data(a.utf8)
    d.append(0)
    d.append(contentsOf: Array(b.utf8))
    return sha256Hex(d)
}

/// The namespaced-identifier grammar of profile IDs and message types, at most 256 bytes.
private let namespacedIdRegex = try! NSRegularExpression(pattern: "^[a-z][a-z0-9+.-]*:[A-Za-z0-9._~:/?#\\[\\]@!$&'()*+,;=%-]+$")

/// True when `value` is a namespaced identifier (`ace:text:1`, `urn:example:x:1`) of at most 256 bytes.
public func isNamespacedIdentifier(_ value: String) -> Bool {
    value.utf8.count <= 256 && regexFullMatch(namespacedIdRegex, value)
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

private let caip10Regex = try! NSRegularExpression(pattern: #"\A[-a-z0-9]{3,8}:[-_a-zA-Z0-9]{1,32}:[-.%a-zA-Z0-9]{1,128}\z"#)

/// A CAIP-10 account ID (`^[-a-z0-9]{3,8}:[-_a-zA-Z0-9]{1,32}:[-.%a-zA-Z0-9]{1,128}$`).
public func isCAIP10(_ value: String) -> Bool { regexFullMatch(caip10Regex, value) }

private let caip19Regex = try! NSRegularExpression(
    pattern: #"\A[-a-z0-9]{3,8}:[-_a-zA-Z0-9]{1,32}/[-a-z0-9]{3,8}:[-.%a-zA-Z0-9]{1,128}\z"#)

/// A CAIP-19 asset ID without token ID (`eip155:8453/erc20:0x…`), as profiles/commerce.md requires.
public func isCAIP19(_ value: String) -> Bool { regexFullMatch(caip19Regex, value) }

package func isControlScalar(_ s: Unicode.Scalar) -> Bool { s.value < 0x20 || s.value == 0x7F }

package func hasControlCharacter(_ value: String) -> Bool {
    value.unicodeScalars.contains(where: isControlScalar)
}

// MARK: - Integers

/// The JSON wire-integer rule: an exact integer in [0, 2^53−1] (`1.0` is 1; booleans and strings
/// are not integers). Mirrors `_encoding.wire_int`; the rule itself is `JSONValue.wireInt`.
package func wireInt(_ v: JSONValue?) -> Int? { v?.wireInt }

/// `wireInt(v)` or `invalid_argument`.
package func checkWireInt(_ v: JSONValue?, _ what: String) throws -> Int {
    guard let n = wireInt(v) else { throw ACEError(.invalidArgument, "\(what) must be an integer in [0, 2^53-1]") }
    return n
}

/// Base-10 ASCII of a wire integer (`decimal(n)` of 02 § Wire integers).
package func decimal(_ n: Int) -> String { String(n) }

// MARK: - HTTPS URL grammar

private let urlLabel = "[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
private let httpsURLRegex = try! NSRegularExpression(
    pattern: "^https://(" + urlLabel + "(?:\\." + urlLabel + ")*)(?::([0-9]{1,5}))?"
        + "(?:[/?#][A-Za-z0-9\\-._~:/?#\\[\\]@!$&'()*+,;=%]*)?$"
)

/// The ACE HTTPS URL grammar (regex plus length / host / port checks). Never the platform URL parser.
public func isHTTPSURL(_ value: String) -> Bool {
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

/// The 6-bit value of a standard Base64 symbol.
private func b64Value(_ b: UInt8) -> UInt8? {
    switch b {
    case 0x41...0x5A: return b - 0x41
    case 0x61...0x7A: return b - 0x61 + 26
    case 0x30...0x39: return b - 0x30 + 52
    case 0x2B: return 62
    case 0x2F: return 63
    default: return nil
    }
}

private func isB64Char(_ b: UInt8) -> Bool {
    (b >= 0x41 && b <= 0x5A) || (b >= 0x61 && b <= 0x7A) || (b >= 0x30 && b <= 0x39) || b == 0x2B || b == 0x2F
}

/// Canonical padded standard Base64 or `ACEError(code)`; at most `maxBytes` decoded bytes (oversized text is
/// refused before decoding).
package func decodeB64(_ text: String, code: ACEError.Code, what: String, maxBytes: Int? = nil) throws -> Data {
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
    // Alphabet, length and padding are checked, so the text is canonical exactly when the bits the padding leaves unused
    // in the last symbol are zero.
    if pad > 0, let v = b64Value(u[u.count - pad - 1]), v & (pad == 2 ? 0x0F : 0x03) != 0 {
        throw ACEError(code, "\(what) is not canonical Base64")
    }
    guard let raw = Data(base64Encoded: text) else { throw ACEError(code, "\(what) is not canonical Base64") }
    // The text pre-check above admits up to 2 extra bytes; maxBytes bounds the decoded bytes.
    if let maxBytes, raw.count > maxBytes { throw ACEError(code, "\(what) is too large") }
    return raw
}

/// True when `re` matches all of `s` (no partial or trailing-newline matches).
package func regexFullMatch(_ re: NSRegularExpression, _ s: String) -> Bool {
    guard !s.contains("\n") else { return false }
    let r = NSRange(location: 0, length: (s as NSString).length)
    return re.firstMatch(in: s, range: r)?.range == r
}

// MARK: - Hex

/// `count` bytes from the system CSPRNG.
package func randomBytes(_ count: Int) -> [UInt8] {
    var rng = SystemRandomNumberGenerator()
    return (0..<count).map { _ in UInt8.random(in: .min ... .max, using: &rng) }
}

/// `bytes` random bytes as lowercase hex.
package func randomHex(_ bytes: Int) -> String { hexEncode(randomBytes(bytes)) }

package func hexEncode(_ data: some Sequence<UInt8>) -> String {
    let digits = Array("0123456789abcdef".utf8)
    var out: [UInt8] = []
    for b in data {
        out.append(digits[Int(b >> 4)])
        out.append(digits[Int(b & 0x0F)])
    }
    return String(decoding: out, as: UTF8.self)
}

/// Strict lowercase/uppercase hex without prefix (internal test / vector helper).
package func hexDecode(_ text: String) -> Data? {
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

/// Lowercase hex SHA-256: the one digest helper of the SDK.
package func sha256Hex(_ data: Data) -> String {
    hexEncode(SHA256.hash(data: data))
}

// MARK: - Signatures

/// Strict decoding of an ML-DSA-65 signature: canonical Base64 of exactly 3309 bytes; `code` otherwise.
package func decodeSignature(_ text: String, code: ACEError.Code) throws -> Data {
    let raw = try decodeB64(text, code: code, what: "signature", maxBytes: ACESigning.signatureSize)
    guard raw.count == ACESigning.signatureSize else { throw ACEError(code, "signature must be \(ACESigning.signatureSize) bytes") }
    return raw
}

// MARK: - Blocked addresses (07 § Blocked addresses)

private let blockedV4: [(UInt32, Int)] = [
    ("0.0.0.0", 8), ("10.0.0.0", 8), ("100.64.0.0", 10), ("127.0.0.0", 8), ("169.254.0.0", 16), ("172.16.0.0", 12),
    ("192.0.0.0", 24), ("192.0.2.0", 24), ("192.168.0.0", 16), ("198.18.0.0", 15), ("198.51.100.0", 24), ("203.0.113.0", 24),
    ("224.0.0.0", 4), ("240.0.0.0", 4),
].map { (parseIPv4($0.0)!, $0.1) }

private let blockedV6: [([UInt8], Int)] = [
    ("::", 96), ("::ffff:0:0:0", 96), ("64:ff9b:1::", 48), ("100::", 64), ("2001::", 23), ("2001:db8::", 32), ("2002::", 16),
    ("3fff::", 20), ("5f00::", 16), ("fc00::", 7), ("fe80::", 10), ("fec0::", 10), ("ff00::", 8),
].map { (parseIPv6($0.0)!, $0.1) }

private func parseIPv4(_ s: String) -> UInt32? {
    let parts = s.split(separator: ".", omittingEmptySubsequences: false)
    guard parts.count == 4 else { return nil }
    var out: UInt32 = 0
    for p in parts {
        guard (1...3).contains(p.count), p.allSatisfy({ $0.isASCII && $0.isNumber }), p.count == 1 || p.first != "0",
              let n = UInt32(p), n <= 255 else { return nil }
        out = out << 8 | n
    }
    return out
}

private func parseIPv6(_ s: String) -> [UInt8]? {
    var a = in6_addr()
    guard s.allSatisfy({ $0.isHexDigit || $0 == ":" || $0 == "." }), inet_pton(AF_INET6, s, &a) == 1 else { return nil }
    return withUnsafeBytes(of: &a) { Array($0) }
}

private func inPrefix(_ addr: [UInt8], _ net: [UInt8], _ bits: Int) -> Bool {
    for i in 0..<bits where (addr[i / 8] >> (7 - i % 8)) & 1 != (net[i / 8] >> (7 - i % 8)) & 1 { return false }
    return true
}

/// True for an address a client must never connect to: private, loopback, link-local, multicast, documentation, other
/// non-public ranges and IPv4-embedding IPv6 ranges (IPv4-mapped and NAT64 `64:ff9b::/96` are judged by the embedded IPv4
/// address). Anything that is not an IP literal is blocked (fail closed); an IPv6 zone is ignored, an IPv4 one is not.
public func isBlockedAddress(_ address: String) -> Bool {
    func v4Blocked(_ v: UInt32) -> Bool { blockedV4.contains { v >> (32 - $0.1) == $0.0 >> (32 - $0.1) } }
    if address.contains(":") {
        let bare = String(address.split(separator: "%", maxSplits: 1, omittingEmptySubsequences: false)[0])
        guard let b = parseIPv6(bare) else { return true }
        if (b[0..<10].allSatisfy({ $0 == 0 }) && b[10] == 0xff && b[11] == 0xff) || Array(b[0..<12]) == [0, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0] {
            return v4Blocked(UInt32(b[12]) << 24 | UInt32(b[13]) << 16 | UInt32(b[14]) << 8 | UInt32(b[15]))
        }
        return blockedV6.contains { inPrefix(b, $0.0, $0.1) }
    }
    guard let v = parseIPv4(address) else { return true }
    return v4Blocked(v)
}
