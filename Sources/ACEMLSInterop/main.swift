// Local interop test driver. It is not an agent/relay API and performs no network enrollment.
import Foundation
import ACE
import Darwin

let engine = try NativeMLSEngine()
let store = MemoryStore()
var sessions: [String: PairwiseMLS] = [:]
let encoder = JSONEncoder()
func object<T: Encodable>(_ value: T) throws -> Any { try JSONSerialization.jsonObject(with: encoder.encode(value)) }
while let line = readLine() {
    do {
        let command = try JSONSerialization.jsonObject(with: Data(line.utf8)) as! [String: Any]
        let op = command["op"] as! String
        let id = command["id"] as! String
        let result: Any
        if op == "new" {
            guard sessions[id] == nil else { throw MLSError("duplicate_test_id") }
            let session = try PairwiseMLS(engine: engine, store: store, local: command["local"] as! String, peer: command["peer"] as! String)
            sessions[id] = session
            result = try object(session.state)
        } else {
            guard let session = sessions[id] else { throw MLSError("unknown_test_id") }
            switch op {
            case "info": result = try object(session.state)
            case "create": result = try object(session.create(keyPackage: command["keyPackage"] as! String))
            case "join": result = try object(session.join(welcome: command["welcome"] as! String))
            case "send": result = try object(session.send(Data(base64Encoded: command["plaintext"] as! String)!))
            case "receive": result = try object(session.receive(command["message"] as! String))
            case "update": result = try object(session.update())
            case "close": try session.close(); result = ["closed": true]
            default: throw MLSError("unknown_test_op")
            }
        }
        print(String(decoding: try JSONSerialization.data(withJSONObject: ["ok": true, "result": result]), as: UTF8.self))
    } catch {
        let code = (error as? MLSError)?.code ?? (error as? ACEError)?.code.rawValue ?? "driver_failed"
        print(String(decoding: try JSONSerialization.data(withJSONObject: ["ok": false, "error": code]), as: UTF8.self))
    }
    fflush(nil)
}
engine.close()
