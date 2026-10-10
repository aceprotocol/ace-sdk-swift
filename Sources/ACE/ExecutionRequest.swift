import Foundation

/// Optional generic execution-request schema carried inside an ordinary private ACE packet.
/// Parsing proves no authority. The resource executor must validate the grant and installed action profile.
public struct ExecutionRequest: Sendable {
    public static let type = "urn:ace:execute:1"
    public static let schemaDescriptor = #"{"fields":["intent","grants"],"type":"urn:ace:execute:1","version":1}"#
    public static let schemaDigest = sha256Hex(Data(schemaDescriptor.utf8))
    public let intent: [String: JSONValue]
    public let grants: [[String: JSONValue]]
    public init(body: [String: JSONValue]) throws {
        guard Set(body.keys) == ["intent", "grants"], let intent = body["intent"]?.objectValue,
              let values = body["grants"]?.arrayValue, (1...8).contains(values.count) else { throw ACEGrants.bad() }
        let grants = values.compactMap(\.objectValue)
        guard grants.count == values.count, try JSONValue.object(body).jsonData().count <= 60_000 else { throw ACEGrants.bad() }
        _ = try ACEGrants.executionIntentDigest(intent)
        self.intent = intent; self.grants = grants
    }
    public var body: [String: JSONValue] { ["intent": .object(intent), "grants": .array(grants.map(JSONValue.object))] }
}
