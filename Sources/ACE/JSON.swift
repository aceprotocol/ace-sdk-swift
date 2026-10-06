//
//  JSON.swift
//  ACE SDK
//
//  A small strict JSON parser and writer (internal). The SDK does not rely on
//  JSONSerialization for acceptance: number lexemes are preserved so the wire-integer
//  and non-finite rules are exact, UTF-8 is validated fatally and nesting is bounded.
//

import Foundation

/// A parsed JSON value. Numbers keep their lexeme.
indirect enum JValue: Sendable, Equatable {
    case null
    case bool(Bool)
    case number(String)
    case string(String)
    case array([JValue])
    case object([String: JValue])

    subscript(key: String) -> JValue? {
        if case .object(let o) = self { return o[key] }
        return nil
    }

    var objectValue: [String: JValue]? {
        if case .object(let o) = self { return o }
        return nil
    }

    var arrayValue: [JValue]? {
        if case .array(let a) = self { return a }
        return nil
    }

    var stringValue: String? {
        if case .string(let s) = self { return s }
        return nil
    }

    var isNull: Bool {
        if case .null = self { return true }
        return false
    }

    /// The JSON wire-integer rule: an integral value in [0, 2^53-1]; booleans and
    /// non-finite values are rejected. The lexical form does not matter.
    var wireInt: Int? {
        guard case .number(let lex) = self else { return nil }
        return wireIntFromLexeme(lex)
    }

    /// True for a number whose double value is finite.
    var isFiniteNumber: Bool {
        guard case .number(let lex) = self else { return false }
        return Double(lex)?.isFinite ?? false
    }
}

func wireIntFromLexeme(_ lex: String) -> Int? {
    let isIntegerForm = !lex.contains(where: { $0 == "." || $0 == "e" || $0 == "E" })
    if isIntegerForm {
        guard let v = Int64(lex) else { return nil }
        return (0...Int64(maxSafeInteger)).contains(v) ? Int(v) : nil
    }
    guard let d = Double(lex), d.isFinite, d.rounded(.towardZero) == d,
          d >= 0, d <= Double(maxSafeInteger) else { return nil }
    return Int(d)
}

struct JSONParseError: Error {
    let reason: String
}

/// Strict RFC 8259 parser. `maxDepth` counts containers: the top-level container is
/// depth 0 and a container at depth `maxDepth + 1` is rejected.
struct JSONParser {
    private let bytes: [UInt8]
    private var i = 0
    private let maxDepth: Int

    static func parse(_ data: Data, maxDepth: Int = 512) throws(JSONParseError) -> JValue {
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

    private mutating func value(depth: Int) throws(JSONParseError) -> JValue {
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
            return .number(try number())
        }
    }

    private mutating func literal(_ word: String) throws(JSONParseError) {
        for b in word.utf8 {
            guard i < bytes.count, bytes[i] == b else { throw JSONParseError(reason: "invalid literal") }
            i += 1
        }
    }

    private mutating func object(depth: Int) throws(JSONParseError) -> JValue {
        i += 1
        var out: [String: JValue] = [:]
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
            out[key] = try value(depth: depth + 1)
            skipWS()
            guard i < bytes.count else { throw JSONParseError(reason: "unexpected end") }
            if bytes[i] == UInt8(ascii: ",") { i += 1; continue }
            if bytes[i] == UInt8(ascii: "}") { i += 1; return .object(out) }
            throw JSONParseError(reason: "expected ',' or '}'")
        }
    }

    private mutating func array(depth: Int) throws(JSONParseError) -> JValue {
        i += 1
        var out: [JValue] = []
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

enum JSONWriter {
    /// Compact JSON; object keys sorted; number lexemes preserved; `/` and non-ASCII raw.
    static func serialize(_ v: JValue) -> Data {
        var out: [UInt8] = []
        write(v, into: &out)
        return Data(out)
    }

    private static func write(_ v: JValue, into out: inout [UInt8]) {
        switch v {
        case .null: out.append(contentsOf: Array("null".utf8))
        case .bool(let b): out.append(contentsOf: Array((b ? "true" : "false").utf8))
        case .number(let lex): out.append(contentsOf: Array(lex.utf8))
        case .string(let s): out.append(contentsOf: Array(jsonString(s).utf8))
        case .array(let a):
            out.append(UInt8(ascii: "["))
            for (n, e) in a.enumerated() {
                if n > 0 { out.append(UInt8(ascii: ",")) }
                write(e, into: &out)
            }
            out.append(UInt8(ascii: "]"))
        case .object(let o):
            out.append(UInt8(ascii: "{"))
            for (n, k) in o.keys.sorted(by: utf16Less).enumerated() {
                if n > 0 { out.append(UInt8(ascii: ",")) }
                out.append(contentsOf: Array(jsonString(k).utf8))
                out.append(UInt8(ascii: ":"))
                write(o[k]!, into: &out)
            }
            out.append(UInt8(ascii: "}"))
        }
    }
}

/// RFC 8785 string form: escapes `"`, `\` and controls only (`\b \f \n \r \t`, others `\u00xx`).
func jsonString(_ s: String) -> String {
    var out = "\""
    for scalar in s.unicodeScalars {
        switch scalar {
        case "\"": out += "\\\""
        case "\\": out += "\\\\"
        case "\u{08}": out += "\\b"
        case "\u{0C}": out += "\\f"
        case "\n": out += "\\n"
        case "\r": out += "\\r"
        case "\t": out += "\\t"
        default:
            if scalar.value < 0x20 {
                out += String(format: "\\u%04x", scalar.value)
            } else {
                out.unicodeScalars.append(scalar)
            }
        }
    }
    out += "\""
    return out
}

/// Key order by UTF-16 code units (RFC 8785); identical to code-point order for ASCII keys.
func utf16Less(_ a: String, _ b: String) -> Bool {
    a.utf16.lexicographicallyPrecedes(b.utf16)
}
