//
//  JSONValue.swift
//  ACE SDK
//
//  The public, Sendable JSON value used for message bodies.
//

import Foundation

/// A JSON value. Message bodies are `[String: JSONValue]`.
///
/// **Numbers** are `Double` (the JSON / JavaScript number model, as in sdk-ts). Every
/// integer in `[-(2^53-1), 2^53-1]` is exact and round-trips: it is written in integer
/// form (`60`, never `60.0`). Other values are written in Swift's shortest round-trip
/// form (`0.1`, `1e+300`). Integer literals beyond 2^53 lose precision on decode, as
/// they do in JavaScript; send such values as strings. Non-finite values cannot be
/// encoded (`invalid_body` in a body, `invalid_argument` from `jsonData()`).
///
/// Wire-integer fields (`ttl`) accept any number whose value is an integer in
/// `[0, 2^53-1]`, regardless of lexical form (`60`, `60.0`, `6e1`).
///
/// Literals build values directly:
///
///     let body: [String: JSONValue] = ["need": "translate", "ttl": 60, "tags": ["a", "b"]]
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

    /// Parse JSON text strictly (RFC 8259, fatal UTF-8, depth ≤ 512). Malformed text or a
    /// non-finite number is `invalid_argument`.
    public init(json data: Data) throws {
        let v: JValue
        do { v = try JSONParser.parse(data) } catch {
            throw ACEError(.invalidArgument, "invalid JSON: \(error.reason)")
        }
        guard let value = JSONValue(v) else { throw ACEError(.invalidArgument, "invalid JSON: non-finite number") }
        self = value
    }

    /// Compact UTF-8 JSON with object keys sorted (UTF-16 order) and `/` unescaped.
    /// A non-finite number is `invalid_argument`.
    public func jsonData() throws -> Data {
        guard let v = jvalue else { throw ACEError(.invalidArgument, "JSON cannot represent a non-finite number") }
        return JSONWriter.serialize(v)
    }
}

// MARK: - Literals

extension JSONValue: ExpressibleByNilLiteral, ExpressibleByBooleanLiteral, ExpressibleByIntegerLiteral,
    ExpressibleByFloatLiteral, ExpressibleByStringLiteral, ExpressibleByStringInterpolation, ExpressibleByArrayLiteral, ExpressibleByDictionaryLiteral {
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

// MARK: - Codable

extension JSONValue: Codable {
    public init(from decoder: any Decoder) throws {
        let c = try decoder.singleValueContainer()
        if c.decodeNil() {
            self = .null
        } else if let b = try? c.decode(Bool.self) {
            self = .bool(b)
        } else if let d = try? c.decode(Double.self) {
            self = .number(d)
        } else if let s = try? c.decode(String.self) {
            self = .string(s)
        } else if let a = try? c.decode([JSONValue].self) {
            self = .array(a)
        } else if let o = try? c.decode([String: JSONValue].self) {
            self = .object(o)
        } else {
            throw DecodingError.dataCorruptedError(in: c, debugDescription: "not a JSON value")
        }
    }

    public func encode(to encoder: any Encoder) throws {
        var c = encoder.singleValueContainer()
        switch self {
        case .null: try c.encodeNil()
        case .bool(let b): try c.encode(b)
        case .number(let d):
            if let i = intValue { try c.encode(Int64(i)) } else { try c.encode(d) }
        case .string(let s): try c.encode(s)
        case .array(let a): try c.encode(a)
        case .object(let o): try c.encode(o)
        }
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

// MARK: - Internal bridging

extension JSONValue {
    /// From a parsed value; nil when a number is not finite.
    init?(_ v: JValue) {
        switch v {
        case .null: self = .null
        case .bool(let b): self = .bool(b)
        case .number(let lex):
            guard let d = Double(lex), d.isFinite else { return nil }
            self = .number(d)
        case .string(let s): self = .string(s)
        case .array(let a):
            var out: [JSONValue] = []
            out.reserveCapacity(a.count)
            for e in a {
                guard let j = JSONValue(e) else { return nil }
                out.append(j)
            }
            self = .array(out)
        case .object(let o):
            var out: [String: JSONValue] = [:]
            out.reserveCapacity(o.count)
            for (k, e) in o {
                guard let j = JSONValue(e) else { return nil }
                out[k] = j
            }
            self = .object(out)
        }
    }

    /// The writer form; nil when a number is not finite.
    var jvalue: JValue? {
        switch self {
        case .null: return .null
        case .bool(let b): return .bool(b)
        case .number(let d):
            guard d.isFinite else { return nil }
            return .number(jsonNumberLexeme(d))
        case .string(let s): return .string(s)
        case .array(let a):
            var out: [JValue] = []
            out.reserveCapacity(a.count)
            for e in a {
                guard let j = e.jvalue else { return nil }
                out.append(j)
            }
            return .array(out)
        case .object(let o):
            var out: [String: JValue] = [:]
            out.reserveCapacity(o.count)
            for (k, e) in o {
                guard let j = e.jvalue else { return nil }
                out[k] = j
            }
            return .object(out)
        }
    }

    /// The JSON wire-integer rule: an integral value in [0, 2^53-1].
    var wireInt: Int? {
        guard let i = intValue, i >= 0 else { return nil }
        return i
    }
}

/// Integer form for integral values within ±(2^53-1); else Swift's shortest round-trip
/// form, which is valid JSON for finite values (`0.1`, `1e-07`, `1e+300`).
func jsonNumberLexeme(_ d: Double) -> String {
    if d.rounded(.towardZero) == d, abs(d) <= Double(maxSafeInteger) { return String(Int64(d)) }
    return "\(d)"
}
