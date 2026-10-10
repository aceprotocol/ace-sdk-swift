import Foundation

/// Cross-SDK operation identity. Compare binary64 values, not platform JSON number spellings.
func intentDigest(_ value: JSONValue) throws -> String {
    func tree(_ v: JSONValue) throws -> JValue {
        switch v {
        case .null: return .array([.string("null")])
        case .bool(let b): return .array([.string("boolean"), .string(b ? "true" : "false")])
        case .string(let s): return .array([.string("string"), .string(s)])
        case .number(let n):
            guard n.isFinite else { throw ACEError(.invalidBody, "non-finite number") }
            let bits = (n == 0 ? 0.0 : n).bitPattern
            let hex = String(bits, radix: 16)
            return .array([.string("number"), .string(String(repeating: "0", count: 16 - hex.count) + hex)])
        case .array(let a): return .array([.string("array")] + (try a.map(tree)))
        case .object(let o):
            let keys = o.keys.sorted { $0.utf8.lexicographicallyPrecedes($1.utf8) }
            return .array([.string("object")] + (try keys.map { .array([.string($0), try tree(o[$0]!)]) }))
        }
    }
    return sha256Hex(Data("ace.intent.v1\0".utf8) + JSONWriter.serialize(try tree(value)))
}
