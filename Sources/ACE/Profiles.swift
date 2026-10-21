//
//  Profiles.swift
//  ACE SDK
//
//  Profile manifests (one digest algorithm), the installed set and the profile rules hook.
//
//    profile digest = SHA-256(canonical(manifest))
//    message digest = SHA-256(canonical({type, schema}))
//
//  The official manifests are the SwiftPM resources Profiles/{core,text,commerce}.json, byte-identical to
//  ace-spec/profiles (ace-spec/scripts/check-sdk-artifacts.py checks the bytes).
//
//  A manifest is data only: no remote references, code or execution authority.
//

import Foundation

/// `{id, digest}`: one entry of a descriptor's `profiles` (the profile digest of the manifest).
public struct ProfileRef: Sendable, Hashable {
    public let id: String
    public let digest: String

    public init(id: String, digest: String) {
        self.id = id
        self.digest = digest
    }

    public var jsonValue: JSONValue { ["id": .string(id), "digest": .string(digest)] }

    package init?(_ v: JSONValue?) {
        guard let o = v?.objectValue, Set(o.keys) == ["id", "digest"], let id = o["id"]?.stringValue, isNamespacedIdentifier(id),
              let digest = o["digest"]?.stringValue, isSHA256Hex(digest) else { return nil }
        self.init(id: id, digest: digest)
    }
}

/// `SHA-256(canonical({type, schema}))`: the `schemaDigest` a message of `type` carries.
public func messageDigest(type: String, schema: JSONValue) throws -> String {
    sha256Hex(try JSONValue.object(["type": .string(type), "schema": schema]).jsonData())
}

/// A validated profile manifest `{id, messages: [{type, schema}]}`.
public struct ProfileManifest: Sendable {
    public struct Message: Sendable {
        public let type: String
        public let schema: JSONValue
        public let schemaDigest: String
    }

    public let id: String
    public let value: JSONValue
    /// The profile digest, `SHA-256(canonical(manifest))`.
    public let digest: String
    public let messages: [Message]

    /// The official manifests (ace-spec/profiles). `core` (`ace:receipt:1`, `ace:contact:1`) is always installed and
    /// never listed in a descriptor's `profiles`.
    public static let core = official("core")
    public static let text = official("text")
    public static let commerce = official("commerce")

    /// The exact bytes of the bundled resource `Profiles/<name>.json`.
    package static func officialBytes(_ name: String) -> Data {
        try! Data(contentsOf: Bundle.module.url(forResource: name, withExtension: "json", subdirectory: "Profiles")!)
    }

    /// A missing or altered resource is a broken build: it traps.
    private static func official(_ name: String) -> ProfileManifest { try! ProfileManifest(json: officialBytes(name)) }

    /// The normative profile digests of the official manifests (08 § Official manifests).
    public static let officialDigests: [String: String] = [
        "ace:core:1": "66f46d4b8951b75f98abae24a72ceffa173c4e27748d09be78b8d6382ddc8222",
        "ace:text:1": "48619350eaea46b2d60f7ce71fe55867e00c8dd081796b408fb6a95692b8b307",
        "ace:commerce:1": "30583f0a1acd86ac5a217d706df1c27dc7caea5d4f2deed6112807679afab053",
    ]

    private static func bad(_ message: String) -> ACEError { ACEError(.invalidArgument, message) }

    public init(json: Data) throws {
        let v: JSONValue
        do { v = try JSONValue(json: json) } catch { throw Self.bad("manifest is not JSON") }
        try self.init(v)
    }

    /// `invalid_argument` unless `value` is a closed manifest: namespaced `id` and message types (the `ace:` prefix only in
    /// the exact official manifests), 1–32 messages with
    /// unique types, canonical JSON ≤ 65536 bytes, schemas in the supported subset (`type` object / array / string /
    /// integer / boolean / null; `properties`, `required`, `additionalProperties`, `items`, `maxItems`, `maxLength`,
    /// `minimum`, `maximum`, `enum`), each message schema an object.
    public init(_ value: JSONValue) throws {
        guard let v = value.objectValue, Set(v.keys) == ["id", "messages"],
              let id = v["id"]?.stringValue, isNamespacedIdentifier(id), let list = v["messages"]?.arrayValue,
              (1...32).contains(list.count), case let canonical = try value.jsonData(),
              canonical.count <= ACELimits.maxManifestBytes else { throw Self.bad("invalid profile manifest") }
        var seen = Set<String>(), messages: [Message] = []
        for m in list {
            guard let o = m.objectValue, Set(o.keys) == ["type", "schema"], let type = o["type"]?.stringValue, isNamespacedIdentifier(type),
                  seen.insert(type).inserted, let schema = o["schema"] else { throw Self.bad("invalid or duplicate profile message type") }
            try Self.check(schema)
            guard schema["type"] == "object" else { throw Self.bad("message schema must describe an object") }
            messages.append(Message(type: type, schema: schema, schemaDigest: try messageDigest(type: type, schema: schema)))
        }
        let digest = sha256Hex(canonical)
        if id.hasPrefix("ace:") || messages.contains(where: { $0.type.hasPrefix("ace:") }) {
            guard Self.officialDigests[id] == digest else { throw Self.bad("the ace: prefix is reserved") }
        }
        self.id = id
        self.value = value
        self.digest = digest
        self.messages = messages
    }

    /// The descriptor entry `{id, digest}`.
    public var ref: ProfileRef { ProfileRef(id: id, digest: digest) }

    public func message(_ type: String) -> Message? { messages.first { $0.type == type } }

    // MARK: Schema subset

    private static func integer(_ v: JSONValue?) -> Double? {
        guard let n = v?.doubleValue, n.isFinite, abs(n) <= Double(maxSafeInteger), n.rounded() == n else { return nil }
        return n
    }

    private static func check(_ value: JSONValue, depth: Int = 0) throws {
        guard let s = value.objectValue, depth <= 8, let type = s["type"]?.stringValue,
              ["object", "array", "string", "integer", "boolean", "null"].contains(type) else { throw bad("unsupported profile schema") }
        let special: [String: Set<String>] = ["object": ["properties", "required", "additionalProperties"], "array": ["items", "maxItems"],
                                              "string": ["maxLength"], "integer": ["minimum", "maximum"]]
        guard Set(s.keys).isSubset(of: Set(["type", "enum"]).union(special[type] ?? [])) else { throw bad("unsupported profile schema keyword") }
        if type == "object" {
            guard let p = s["properties"]?.objectValue, p.count <= 64, let r = s["required"]?.arrayValue, Set(r).count == r.count,
                  r.allSatisfy({ $0.stringValue.map { p[$0] != nil } ?? false }), s["additionalProperties"]?.boolValue != nil else {
                throw bad("object schema needs properties, required and additionalProperties")
            }
            for child in p.values { try check(child, depth: depth + 1) }
        }
        if type == "array" { try check(s["items"] ?? .null, depth: depth + 1) }
        for k in ["maxItems", "maxLength", "minimum", "maximum"] where s[k] != nil {
            guard let n = integer(s[k]), !["maxItems", "maxLength"].contains(k) || n >= 0 else { throw bad("invalid schema bound") }
        }
        if let min = integer(s["minimum"]), let max = integer(s["maximum"]), min > max { throw bad("inverted schema bounds") }
        if s["enum"] != nil {
            var base = s
            base.removeValue(forKey: "enum")
            guard let choices = s["enum"]?.arrayValue, (1...64).contains(choices.count), choices.allSatisfy({ matches(.object(base), $0) }) else {
                throw bad("invalid schema enum")
            }
        }
    }

    /// True when `value` matches the (checked) schema. String lengths are in Unicode code points.
    package static func matches(_ schema: JSONValue, _ value: JSONValue) -> Bool {
        let s = schema.objectValue!
        if let choices = s["enum"]?.arrayValue {
            // Swift String equality folds canonically equivalent Unicode; the wire schema compares canonical bytes.
            guard let canonical = try? value.jsonData(), choices.contains(where: { (try? $0.jsonData()) == canonical }) else { return false }
        }
        switch s["type"]!.stringValue! {
        case "object":
            guard let v = value.objectValue else { return false }
            let p = s["properties"]!.objectValue!
            return s["required"]!.arrayValue!.allSatisfy { v[$0.stringValue!] != nil }
                && v.allSatisfy { k, child in p[k].map { matches($0, child) } ?? s["additionalProperties"]!.boolValue! }
        case "array":
            guard let v = value.arrayValue else { return false }
            return Double(v.count) <= (integer(s["maxItems"]) ?? Double(maxSafeInteger)) && v.allSatisfy { matches(s["items"]!, $0) }
        case "string":
            return value.stringValue.map { Double($0.unicodeScalars.count) <= (integer(s["maxLength"]) ?? Double(maxSafeInteger)) } ?? false
        case "integer":
            return integer(value).map { $0 >= (integer(s["minimum"]) ?? -Double(maxSafeInteger)) && $0 <= (integer(s["maximum"]) ?? Double(maxSafeInteger)) } ?? false
        case "boolean": return value.boolValue != nil
        default: return value == .null
        }
    }
}

/// The installed profiles: `core` plus the host's manifests. `(type, schemaDigest)` must be installed for a message to be
/// sent or accepted.
public struct InstalledProfiles: Sendable {
    public let manifests: [ProfileManifest]
    private let schemas: [String: JSONValue]

    /// `invalid_argument` for conflicting profile IDs or message types (08 § Installation).
    public init(_ manifests: [ProfileManifest]) throws {
        var all = [ProfileManifest.core], ids: Set<String> = [ProfileManifest.core.id]
        var types = Set(ProfileManifest.core.messages.map(\.type))
        for m in manifests where m.id != ProfileManifest.core.id {
            guard ids.insert(m.id).inserted else { throw ACEError(.invalidArgument, "profile \(m.id) is installed twice") }
            for msg in m.messages where !types.insert(msg.type).inserted {
                throw ACEError(.invalidArgument, "profile \(m.id) redefines message type \(msg.type)")
            }
            all.append(m)
        }
        self.manifests = all
        var schemas: [String: JSONValue] = [:]
        for m in all { for msg in m.messages { schemas[msg.type + "\u{0}" + msg.schemaDigest] = msg.schema } }
        self.schemas = schemas
    }

    /// The descriptor `profiles` (every installed manifest but `core`).
    public var refs: [ProfileRef] { manifests.filter { $0.id != ProfileManifest.core.id }.map(\.ref) }

    public func manifest(_ id: String) -> ProfileManifest? { manifests.first { $0.id == id } }

    /// The schema digest of `type` in the first installed manifest defining it.
    public func schemaDigest(for type: String) -> String? {
        for m in manifests { if let msg = m.message(type) { return msg.schemaDigest } }
        return nil
    }

    /// `unsupported_schema` unless `(type, schemaDigest)` is installed; `invalid_body` when the body does not match it.
    public func validate(_ content: PrivateContent) throws {
        guard let schema = schemas[content.type + "\u{0}" + content.schemaDigest] else {
            throw ACEError(.unsupportedSchema, "(\(content.type), schemaDigest) is not installed")
        }
        guard ProfileManifest.matches(schema, .object(content.body)) else {
            throw ACEError(.invalidBody, "\(content.type) body does not match its schema")
        }
    }

    /// A `PrivateContent` of an installed `type` (its installed digest), validated (`unsupported_schema`, `invalid_body`).
    public func content(type: String, body: [String: JSONValue], threadId: String? = nil) throws -> PrivateContent {
        guard let digest = schemaDigest(for: type) else { throw ACEError(.unsupportedSchema, "\(type) is not installed") }
        let content = try PrivateContent(type: type, schemaDigest: digest, threadId: threadId, body: body)
        try validate(content)
        return content
    }
}

// MARK: - Profile rules

/// One message as a profile rule sees it: `{direction, from, to, messageId, timestamp, type, threadId?}`. For `send`,
/// `timestamp` is the time the Outbox entry is created.
public struct ProfileEvent: Sendable, Equatable {
    public enum Direction: String, Sendable { case send, receive }
    public let direction: Direction
    public let from: String
    public let to: String
    public let messageId: String
    public let timestamp: Int
    public let type: String
    public let threadId: String?

    public init(direction: Direction, from: String, to: String, messageId: String, timestamp: Int, type: String, threadId: String?) {
        self.direction = direction
        self.from = from
        self.to = to
        self.messageId = messageId
        self.timestamp = timestamp
        self.type = type
        self.threadId = threadId
    }

    /// The local conversation key of the two parties.
    public var conversation: String { conversationKey(from, to) }
}

/// Deterministic profile semantics beyond the schema (for example a state machine). `check` runs before encryption on
/// send and after the schema on receive and throws an `ACEError` to refuse (a permanent code becomes the `rejected`
/// receipt's code); `commit` runs inside the persistence step and must be idempotent per `(from, messageId)`. Rules never
/// grant execution, payment or shell rights.
public protocol ProfileRules: Sendable {
    var types: Set<String> { get }
    func check(_ event: ProfileEvent, body: [String: JSONValue]) throws
    func commit(_ event: ProfileEvent, body: [String: JSONValue]) throws
}

extension Array where Element == any ProfileRules {
    func check(_ event: ProfileEvent, body: [String: JSONValue]) throws {
        for r in self where r.types.contains(event.type) { try r.check(event, body: body) }
    }

    func commit(_ event: ProfileEvent, body: [String: JSONValue]) throws {
        for r in self where r.types.contains(event.type) { try r.commit(event, body: body) }
    }
}
