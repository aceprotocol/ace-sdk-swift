//
//  JSON.swift
//  ACE SDK
//
//  The JSON value of the SDK and its strict parser and canonical writer. Foundation's JSONSerialization is never used
//  for acceptance: UTF-8 is validated fatally, duplicate keys and non-finite numbers (`1e400`) are rejected and nesting
//  is bounded: received JSON at `MAX_JSON_DEPTH` (02 § JSON values), the SDK's own records one level deeper. Numbers are IEEE 754 doubles, which is exactly what canonical JSON writes (02 § Canonical JSON); every
//  integer lexeme above 2^53 - 1 rounds to at least 2^53, so the wire-integer rule stays exact.
//

import Foundation

/// A JSON value. Message bodies are `[String: JSONValue]`.
///
/// **Numbers** are `Double` (the JSON / JavaScript number model, as in sdk-ts). Every
/// integer in `[-(2^53-1), 2^53-1]` is exact and round-trips: it is written in integer
/// form (`60`, never `60.0`). Other values are written in the ECMAScript form of
/// canonical JSON (`0.1`, `1e+300`). Integer literals beyond 2^53 lose precision on decode, as
/// they do in JavaScript; send such values as strings. Non-finite values cannot be
/// encoded (`invalid_body` in a body, `invalid_argument` from `jsonData()`).
///
/// Wire-integer fields (`expiresAt`) accept any number whose value is an integer in
/// `[0, 2^53-1]`, regardless of lexical form (`60`, `60.0`, `6e1`).
///
/// Literals build values directly:
///
///     let body: [String: JSONValue] = ["need": "translate", "expiresAt": 1760140800, "tags": ["a", "b"]]
public enum JSONValue: Sendable, Hashable {
    case null
    case bool(Bool)
    case number(Double)
    case string(String)
    case array([JSONValue])
    case object([String: JSONValue])

    // MARK: Accessors

    /// The member `key` of an object; nil otherwise.
    public subscript(key: String) -> JSONValue? {
        if case .object(let o) = self { return o[key] }
        return nil
    }

    /// The element at `index` of an array; nil otherwise or out of range.
    public subscript(index: Int) -> JSONValue? {
        if case .array(let a) = self, a.indices.contains(index) { return a[index] }
        return nil
    }

    public var stringValue: String? {
        if case .string(let s) = self { return s }
        return nil
    }

    public var boolValue: Bool? {
        if case .bool(let b) = self { return b }
        return nil
    }

    public var doubleValue: Double? {
        if case .number(let d) = self { return d }
        return nil
    }

    /// The number as an exact integer: integral and within `±(2^53-1)`; nil otherwise.
    public var intValue: Int? {
        guard case .number(let d) = self, d.isFinite, d.rounded(.towardZero) == d,
              abs(d) <= Double(maxSafeInteger) else { return nil }
        return Int(d)
    }

    public var arrayValue: [JSONValue]? {
        if case .array(let a) = self { return a }
        return nil
    }

    public var objectValue: [String: JSONValue]? {
        if case .object(let o) = self { return o }
        return nil
    }

    public var isNull: Bool {
        if case .null = self { return true }
        return false
    }

    // MARK: Text

    /// Parse received JSON text strictly (02 § JSON values: RFC 8259, fatal UTF-8, depth ≤ `MAX_JSON_DEPTH` with the
    /// top-level value at depth 0). Malformed text, a non-finite number or deeper nesting is `invalid_argument`.
    public init(json data: Data) throws {
        do { self = try JSONParser.parse(data) } catch {
            throw ACEError(.invalidArgument, "invalid JSON: \(error.reason)")
        }
    }

    /// Parse one of the SDK's own stored records, which wraps received JSON or private content one level down
    /// (depth ≤ `MAX_JSON_DEPTH + 1`). Nil when it does not parse.
    package init?(stored data: Data) {
        guard let v = try? JSONParser.parse(data, maxDepth: ACELimits.maxJSONDepth + 1) else { return nil }
        self = v
    }

    /// The canonical JSON (`canonical(x)` of the protocol): compact UTF-8, keys sorted by code point, non-ASCII and
    /// `/` unescaped, numbers in ECMAScript form. A non-finite number is `invalid_argument`.
    public func jsonData() throws -> Data {
        guard let data = JSONWriter.serialize(self) else { throw ACEError(.invalidArgument, "JSON cannot represent a non-finite number") }
        return data
    }
}

// MARK: - Literals

extension JSONValue: ExpressibleByNilLiteral, ExpressibleByBooleanLiteral, ExpressibleByIntegerLiteral,
    ExpressibleByFloatLiteral, ExpressibleByStringLiteral, ExpressibleByStringInterpolation, ExpressibleByArrayLiteral,
    ExpressibleByDictionaryLiteral {
    public init(nilLiteral: ()) { self = .null }
    public init(booleanLiteral value: Bool) { self = .bool(value) }
    public init(integerLiteral value: Int) { self = .number(Double(value)) }
    public init(floatLiteral value: Double) { self = .number(value) }
    public init(stringLiteral value: String) { self = .string(value) }
    public init(arrayLiteral elements: JSONValue...) { self = .array(elements) }
    public init(dictionaryLiteral elements: (String, JSONValue)...) {
        self = .object(Dictionary(elements, uniquingKeysWith: { $1 }))
    }
}

extension JSONValue: CustomStringConvertible {
    /// The compact JSON text (non-finite numbers print as `NaN` / `inf`, which is not JSON).
    public var description: String {
        switch self {
        case .number(let d) where !d.isFinite: return "\(d)"
        default:
            return (try? jsonData()).map { String(decoding: $0, as: UTF8.self) } ?? "<invalid JSON>"
        }
    }
}

extension JSONValue {
    /// The JSON wire-integer rule: an integral value in [0, 2^53-1].
    package var wireInt: Int? {
        guard let i = intValue, i >= 0 else { return nil }
        return i
    }
}

/// The ECMAScript `Number::toString` form of a finite value (RFC 8785 § 3.2.2.3), as sdk-py and sdk-ts write it:
/// the shortest round-trip digits, positional while the decimal exponent is in (−7, 21], else `d[.ddd]e±n`
/// (`1`, `0`, `0.00001`, `1e-7`, `10000000000000000`, `1e+21`).
package func jsonNumberLexeme(_ d: Double) -> String {
    if d.rounded(.towardZero) == d, abs(d) <= Double(maxSafeInteger) { return String(Int64(d)) }  // -0.0 is "0"
    // Swift's description carries the shortest round-trip digits ("1e-05", "1.5e+16", "123.456"); only the layout
    // differs from ECMAScript.
    let text = "\(abs(d))"
    let parts = text.split(separator: "e", maxSplits: 1)
    let mantissa = parts[0], exponent = parts.count > 1 ? Int(parts[1])! : 0
    let point = mantissa.firstIndex(of: ".")
    let whole = point.map { mantissa[..<$0] } ?? mantissa[...]
    let fraction = point.map { mantissa[mantissa.index(after: $0)...] } ?? ""
    var digits = Array(whole + fraction)
    // value = 0.digits × 10^n
    var n = whole.count + exponent
    while digits.first == "0" { digits.removeFirst(); n -= 1 }
    while digits.last == "0" { digits.removeLast() }
    let k = digits.count, s = String(digits)
    let body: String
    if k <= n && n <= 21 {
        body = s + String(repeating: "0", count: n - k)
    } else if 0 < n && n <= 21 {
        body = String(s.prefix(n)) + "." + String(s.dropFirst(n))
    } else if -6 < n && n <= 0 {
        body = "0." + String(repeating: "0", count: -n) + s
    } else {
        let e = n - 1
        body = String(s.prefix(1)) + (k > 1 ? "." + String(s.dropFirst()) : "") + (e < 0 ? "e-" : "e+") + String(abs(e))
    }
    return d < 0 ? "-" + body : body
}


package struct JSONParseError: Error {
    package let reason: String
}

/// Strict RFC 8259 parser. `maxDepth` counts containers: the top-level container is
/// depth 0 and a container at depth `maxDepth + 1` is rejected.
package struct JSONParser {
    private let bytes: [UInt8]
    private var i = 0
    private let maxDepth: Int

    /// The bound keeps the recursion shallow enough for any thread's stack (a cooperative-pool task included).
    package static func parse(_ data: Data, maxDepth: Int = ACELimits.maxJSONDepth) throws(JSONParseError) -> JSONValue {
        var p = JSONParser(bytes: [UInt8](data), maxDepth: maxDepth)
        p.skipWS()
        let v = try p.value(depth: 0)
        p.skipWS()
        guard p.i == p.bytes.count else { throw JSONParseError(reason: "trailing characters") }
        return v
    }

    private init(bytes: [UInt8], maxDepth: Int) {
        self.bytes = bytes
        self.maxDepth = maxDepth
    }

    private mutating func skipWS() {
        while i < bytes.count, bytes[i] == 0x20 || bytes[i] == 0x09 || bytes[i] == 0x0A || bytes[i] == 0x0D {
            i += 1
        }
    }

    private mutating func value(depth: Int) throws(JSONParseError) -> JSONValue {
        guard i < bytes.count else { throw JSONParseError(reason: "unexpected end") }
        switch bytes[i] {
        case UInt8(ascii: "{"):
            guard depth <= maxDepth else { throw JSONParseError(reason: "nesting exceeds depth \(maxDepth)") }
            return try object(depth: depth)
        case UInt8(ascii: "["):
            guard depth <= maxDepth else { throw JSONParseError(reason: "nesting exceeds depth \(maxDepth)") }
            return try array(depth: depth)
        case UInt8(ascii: "\""):
            return .string(try string())
        case UInt8(ascii: "t"):
            try literal("true")
            return .bool(true)
        case UInt8(ascii: "f"):
            try literal("false")
            return .bool(false)
        case UInt8(ascii: "n"):
            try literal("null")
            return .null
        default:
            guard let d = Double(try number()), d.isFinite else { throw JSONParseError(reason: "non-finite number") }
            return .number(d)
        }
    }

    private mutating func literal(_ word: String) throws(JSONParseError) {
        for b in word.utf8 {
            guard i < bytes.count, bytes[i] == b else { throw JSONParseError(reason: "invalid literal") }
            i += 1
        }
    }

    private mutating func object(depth: Int) throws(JSONParseError) -> JSONValue {
        i += 1
        var out: [String: JSONValue] = [:]
        skipWS()
        if i < bytes.count, bytes[i] == UInt8(ascii: "}") {
            i += 1
            return .object(out)
        }
        while true {
            skipWS()
            guard i < bytes.count, bytes[i] == UInt8(ascii: "\"") else { throw JSONParseError(reason: "expected key") }
            let key = try string()
            skipWS()
            guard i < bytes.count, bytes[i] == UInt8(ascii: ":") else { throw JSONParseError(reason: "expected ':'") }
            i += 1
            skipWS()
            guard out[key] == nil else { throw JSONParseError(reason: "duplicate object key") }
            out[key] = try value(depth: depth + 1)
            skipWS()
            guard i < bytes.count else { throw JSONParseError(reason: "unexpected end") }
            if bytes[i] == UInt8(ascii: ",") { i += 1; continue }
            if bytes[i] == UInt8(ascii: "}") { i += 1; return .object(out) }
            throw JSONParseError(reason: "expected ',' or '}'")
        }
    }

    private mutating func array(depth: Int) throws(JSONParseError) -> JSONValue {
        i += 1
        var out: [JSONValue] = []
        skipWS()
        if i < bytes.count, bytes[i] == UInt8(ascii: "]") {
            i += 1
            return .array(out)
        }
        while true {
            skipWS()
            out.append(try value(depth: depth + 1))
            skipWS()
            guard i < bytes.count else { throw JSONParseError(reason: "unexpected end") }
            if bytes[i] == UInt8(ascii: ",") { i += 1; continue }
            if bytes[i] == UInt8(ascii: "]") { i += 1; return .array(out) }
            throw JSONParseError(reason: "expected ',' or ']'")
        }
    }

    private mutating func number() throws(JSONParseError) -> String {
        let start = i
        if i < bytes.count, bytes[i] == UInt8(ascii: "-") { i += 1 }
        guard i < bytes.count, isDigit(bytes[i]) else { throw JSONParseError(reason: "invalid number") }
        if bytes[i] == UInt8(ascii: "0") {
            i += 1
        } else {
            while i < bytes.count, isDigit(bytes[i]) { i += 1 }
        }
        if i < bytes.count, bytes[i] == UInt8(ascii: ".") {
            i += 1
            guard i < bytes.count, isDigit(bytes[i]) else { throw JSONParseError(reason: "invalid number") }
            while i < bytes.count, isDigit(bytes[i]) { i += 1 }
        }
        if i < bytes.count, bytes[i] == UInt8(ascii: "e") || bytes[i] == UInt8(ascii: "E") {
            i += 1
            if i < bytes.count, bytes[i] == UInt8(ascii: "+") || bytes[i] == UInt8(ascii: "-") { i += 1 }
            guard i < bytes.count, isDigit(bytes[i]) else { throw JSONParseError(reason: "invalid number") }
            while i < bytes.count, isDigit(bytes[i]) { i += 1 }
        }
        return String(decoding: bytes[start..<i], as: UTF8.self)
    }

    private func isDigit(_ b: UInt8) -> Bool { b >= 0x30 && b <= 0x39 }

    private mutating func string() throws(JSONParseError) -> String {
        i += 1
        var out: [UInt8] = []
        while true {
            guard i < bytes.count else { throw JSONParseError(reason: "unterminated string") }
            let b = bytes[i]
            if b == UInt8(ascii: "\"") {
                i += 1
                break
            }
            if b < 0x20 { throw JSONParseError(reason: "control character in string") }
            if b != UInt8(ascii: "\\") {
                out.append(b)
                i += 1
                continue
            }
            i += 1
            guard i < bytes.count else { throw JSONParseError(reason: "unterminated escape") }
            let e = bytes[i]
            i += 1
            switch e {
            case UInt8(ascii: "\""): out.append(0x22)
            case UInt8(ascii: "\\"): out.append(0x5C)
            case UInt8(ascii: "/"): out.append(0x2F)
            case UInt8(ascii: "b"): out.append(0x08)
            case UInt8(ascii: "f"): out.append(0x0C)
            case UInt8(ascii: "n"): out.append(0x0A)
            case UInt8(ascii: "r"): out.append(0x0D)
            case UInt8(ascii: "t"): out.append(0x09)
            case UInt8(ascii: "u"):
                var cp = try hex4()
                if (0xD800...0xDBFF).contains(cp) {
                    guard i + 1 < bytes.count, bytes[i] == UInt8(ascii: "\\"), bytes[i + 1] == UInt8(ascii: "u") else {
                        throw JSONParseError(reason: "lone surrogate")
                    }
                    i += 2
                    let lo = try hex4()
                    guard (0xDC00...0xDFFF).contains(lo) else { throw JSONParseError(reason: "lone surrogate") }
                    cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00)
                } else if (0xDC00...0xDFFF).contains(cp) {
                    throw JSONParseError(reason: "lone surrogate")
                }
                guard let scalar = Unicode.Scalar(cp) else { throw JSONParseError(reason: "invalid code point") }
                out.append(contentsOf: Array(String(Character(scalar)).utf8))
            default:
                throw JSONParseError(reason: "invalid escape")
            }
        }
        guard let s = String(validating: out, as: UTF8.self) else {
            throw JSONParseError(reason: "invalid UTF-8")
        }
        return s
    }

    private mutating func hex4() throws(JSONParseError) -> UInt32 {
        guard i + 4 <= bytes.count else { throw JSONParseError(reason: "invalid \\u escape") }
        var v: UInt32 = 0
        for _ in 0..<4 {
            let b = bytes[i]
            let d: UInt32
            switch b {
            case 0x30...0x39: d = UInt32(b - 0x30)
            case 0x61...0x66: d = UInt32(b - 0x61 + 10)
            case 0x41...0x46: d = UInt32(b - 0x41 + 10)
            default: throw JSONParseError(reason: "invalid \\u escape")
            }
            v = v << 4 | d
            i += 1
        }
        return v
    }
}

// MARK: - Writing

package enum JSONWriter {
    /// The one canonical JSON form of the SDK: compact UTF-8, object keys sorted by Unicode code point (= UTF-8 byte
    /// order, Python `sort_keys`), numbers in ECMAScript form, `/` and non-ASCII raw. Nil for a non-finite number.
    package static func serialize(_ v: JSONValue) -> Data? {
        var out: [UInt8] = []
        guard write(v, into: &out) else { return nil }
        return Data(out)
    }

    private static func write(_ v: JSONValue, into out: inout [UInt8]) -> Bool {
        switch v {
        case .null: out.append(contentsOf: "null".utf8)
        case .bool(let b): out.append(contentsOf: (b ? "true" : "false").utf8)
        case .number(let d):
            guard d.isFinite else { return false }
            out.append(contentsOf: jsonNumberLexeme(d).utf8)
        case .string(let s): writeString(s, into: &out)
        case .array(let a):
            out.append(UInt8(ascii: "["))
            for (n, e) in a.enumerated() {
                if n > 0 { out.append(UInt8(ascii: ",")) }
                guard write(e, into: &out) else { return false }
            }
            out.append(UInt8(ascii: "]"))
        case .object(let o):
            out.append(UInt8(ascii: "{"))
            for (n, k) in o.keys.sorted(by: codePointLess).enumerated() {
                if n > 0 { out.append(UInt8(ascii: ",")) }
                writeString(k, into: &out)
                out.append(UInt8(ascii: ":"))
                guard write(o[k]!, into: &out) else { return false }
            }
            out.append(UInt8(ascii: "}"))
        }
        return true
    }

    /// RFC 8785 string form: escapes `"`, `\` and controls only (`\b \f \n \r \t`, others
    /// `\u00xx`). Escaping per UTF-8 byte matches escaping per scalar: multi-byte sequences
    /// are all >= 0x80.
    private static func writeString(_ s: String, into out: inout [UInt8]) {
        out.append(UInt8(ascii: "\""))
        for b in s.utf8 {
            switch b {
            case UInt8(ascii: "\""): out.append(contentsOf: [92, 34])
            case UInt8(ascii: "\\"): out.append(contentsOf: [92, 92])
            case 0x08: out.append(contentsOf: [92, UInt8(ascii: "b")])
            case 0x0C: out.append(contentsOf: [92, UInt8(ascii: "f")])
            case 0x0A: out.append(contentsOf: [92, UInt8(ascii: "n")])
            case 0x0D: out.append(contentsOf: [92, UInt8(ascii: "r")])
            case 0x09: out.append(contentsOf: [92, UInt8(ascii: "t")])
            case ..<0x20: out.append(contentsOf: [92, UInt8(ascii: "u"), 48, 48, hexDigit(b >> 4), hexDigit(b & 0xF)])
            default: out.append(b)
            }
        }
        out.append(UInt8(ascii: "\""))
    }

    private static func hexDigit(_ n: UInt8) -> UInt8 { n < 10 ? 48 + n : 87 + n }
}

/// Key order by Unicode code points (= UTF-8 byte order; Python `sort_keys`).
package func codePointLess(_ a: String, _ b: String) -> Bool {
    a.utf8.lexicographicallyPrecedes(b.utf8)
}
