import Foundation
import Testing
import ACE

private let alice = "ace:sha256:" + String(repeating: "a", count: 64)
private let bob = "ace:sha256:" + String(repeating: "b", count: 64)

private final class FaultStore: ACECoordinatedStore, @unchecked Sendable {
    let data = MemoryStore()
    var failAfter = false
    var erase = false
    func coordinate<T>(_ name: String, _ body: (any ACEStoreData) throws -> T) throws -> T {
        try data.coordinate(name) { data in
            if erase { for key in try data.list(prefix: "mls/") { try data.delete(key) } }
            let result = try body(data)
            if failAfter { throw ACEError(.storageFailed, "lost commit acknowledgement") }
            return result
        }
    }
}

@Test func nativeSessionsInteroperateAndRejectReplay() throws {
    let engine = try NativeMLSEngine()
    defer { engine.close() }
    let a = try PairwiseMLS(engine: engine, store: MemoryStore(), local: alice, peer: bob)
    let b = try PairwiseMLS(engine: engine, store: MemoryStore(), local: bob, peer: alice)
    let welcome = try #require(a.create(keyPackage: b.state.keyPackage).message)
    #expect(try b.join(welcome: welcome).kind == .joined)
    let packet = try #require(a.send(Data("private".utf8)).message)
    #expect(try b.receive(packet).plaintextData() == Data("private".utf8))
    #expect(throws: MLSError("invalid_session_message")) { try b.receive(packet) }
    let commit = try #require(b.update().message)
    #expect(try a.receive(commit).kind == .commit)
    let reply = try #require(b.send(Data("after-update".utf8)).message)
    #expect(try a.receive(reply).plaintextData() == Data("after-update".utf8))
}

@Test func lostAcknowledgementNeverReleasesCiphertextOrResumes() throws {
    let engine = try NativeMLSEngine()
    defer { engine.close() }
    let store = FaultStore()
    let a = try PairwiseMLS(engine: engine, store: store, local: alice, peer: bob)
    let b = try PairwiseMLS(engine: engine, store: MemoryStore(), local: bob, peer: alice)
    let welcome = try #require(a.create(keyPackage: b.state.keyPackage).message)
    _ = try b.join(welcome: welcome)
    store.failAfter = true
    #expect(throws: ACEError.self) { try a.send(Data("not released".utf8)) }
    store.failAfter = false
    #expect(throws: MLSError("session_closed")) { try a.send(Data("retry".utf8)) }
}

@Test func missingGenerationNeverReinitializes() throws {
    let engine = try NativeMLSEngine()
    defer { engine.close() }
    let store = FaultStore()
    let a = try PairwiseMLS(engine: engine, store: store, local: alice, peer: bob)
    store.erase = true
    #expect(throws: MLSError("session_generation_mismatch")) { try a.update() }
    #expect(throws: MLSError("session_closed")) { try a.update() }
}

@Test func invalidCiphertextConsumesGenerationWithoutDestroyingValidRatchet() throws {
    let engine = try NativeMLSEngine()
    defer { engine.close() }
    let a = try PairwiseMLS(engine: engine, store: MemoryStore(), local: alice, peer: bob)
    let b = try PairwiseMLS(engine: engine, store: MemoryStore(), local: bob, peer: alice)
    let welcome = try #require(a.create(keyPackage: b.state.keyPackage).message)
    _ = try b.join(welcome: welcome)
    let packet = try #require(a.send(Data("ok".utf8)).message)
    let generation = b.state.generation
    #expect(throws: MLSError.self) { try b.receive("garbage") }
    #expect(b.state.generation == generation + 1)
    #expect(try b.receive(packet).plaintextData() == Data("ok".utf8))
}

@Test func nativeEngineCloseAndMalformedInput() throws {
    let engine = try NativeMLSEngine()
    let raw = try engine.execute(Data())
    #expect(String(decoding: raw, as: UTF8.self).contains("invalid_session_input"))
    engine.close()
    engine.close()
    #expect(throws: MLSError("engine_closed")) { try engine.execute(Data()) }
}

private final class FailingEngine: MLSEngine, Sendable {
    let core: NativeMLSEngine
    init(_ core: NativeMLSEngine) { self.core = core }
    func execute(_ command: Data) throws -> Data {
        let result = try core.execute(command)
        let op = (try JSONSerialization.jsonObject(with: command) as? [String: Any])?["op"] as? String
        return op == "send" ? Data(#"{"ok":false,"result":null,"error":"session_failed"}"#.utf8) : result
    }
}

@Test func unexpectedCoreFailureDestroysContext() throws {
    let engine = try NativeMLSEngine()
    defer { engine.close() }
    let a = try PairwiseMLS(engine: FailingEngine(engine), store: MemoryStore(), local: alice, peer: bob)
    let b = try PairwiseMLS(engine: engine, store: MemoryStore(), local: bob, peer: alice)
    _ = try b.join(welcome: #require(a.create(keyPackage: b.state.keyPackage).message))
    #expect(throws: MLSError("session_failed")) { try a.send(Data([1])) }
    #expect(throws: MLSError("session_closed")) { try a.update() }
}
