// Local interop driver, never a network endpoint.
import Foundation
import ACE
import Darwin

actor Received { var ids: [String] = []; func append(_ value: String) { ids.append(value) } }
func output(_ value: [String: Any]) throws {
    print(String(decoding: try JSONSerialization.data(withJSONObject: value), as: UTF8.self)); fflush(nil)
}
func exchange(_ packet: ACEMessage, _ expected: SecureTransport.Route) async throws -> ACEMessage {
    try output(["event": "exchange", "packet": JSONSerialization.jsonObject(with: packet.jsonData()),
                "expected": ["attempt": expected.attempt, "kind": expected.kind, "expiresAt": expected.expiresAt]])
    guard let line = readLine(), let value = try JSONValue(json: Data(line.utf8))["reply"] else { throw MLSError("test_exchange_failed") }
    return try decodeEnvelope(value.jsonData())
}
let engine = try NativeMLSEngine()
var secure: SecureTransport?, inbox: Inbox?, identity: SoftwareIdentity?, peer: VerifiedPeer?
var received = Received()
while let line = readLine() {
    do {
        let command = try JSONValue(json: Data(line.utf8)), op = command["op"]!.stringValue!
        let result: Any
        switch op {
        case "new":
            try await secure?.close(); await inbox?.close()
            let who = try SoftwareIdentity(export: JSONDecoder().decode(SoftwareIdentityExport.self, from: command["identity"]!.jsonData()))
            identity = who
            let store = MemoryStore(), peers = try PeerStore(store: store, clock: { 1_800_000_000 })
            let other = try await peers.pinRegistrationFile(RegistrationFile(json: command["peer"]!.jsonData()))
            peer = other
            let rows = Received(); received = rows
            inbox = try await Inbox.open(identity: who, store: store, peers: peers, onMessage: { await rows.append($0.messageId) }, clock: { 1_800_000_000 })
            secure = SecureTransport(identity: who, engine: engine, store: store, clock: { 1_800_000_000 })
            try SecureTransport.setPeerAllowed(store: store, peer: other.aceId, allowed: true)
            result = ["ready": true]
        case "respond":
            let receiver = inbox!
            let reply = try await secure!.respond(decodeEnvelope(command["packet"]!.jsonData()), peer: peer!) { bytes in
                try SecureOutcome(await receiver.receive(bytes))
            }
            result = try JSONSerialization.jsonObject(with: reply.jsonData())
        case "send":
            let message = try createMessage(sender: identity!, recipient: peer!, type: .text, body: ["message": command["text"]!], timestamp: 1_800_000_000)
            try await secure!.deliver(message, peer: peer!, exchange: exchange)
            result = ["messageId": message.messageId]
        case "received": result = await received.ids
        default: throw MLSError("unknown_test_op")
        }
        try output(["ok": true, "result": result])
    } catch { try output(["ok": false, "error": (error as? MLSError)?.code ?? (error as? ACEError)?.code.rawValue ?? String(describing: error)]) }
}
try await secure?.close(); await inbox?.close(); engine.close()
