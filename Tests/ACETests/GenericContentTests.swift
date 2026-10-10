import Foundation
import Testing
@testable import ACE

@Suite("Private extensible content")
struct GenericContentTests {
    let type = MessageType(rawValue: "https://example.org/schemas/task/1")!
    let digest = String(repeating: "ab", count: 32)

    @Test func identifiersRejectTrailingLineTerminators() throws {
        let a = Fixtures.agent("alice"), b = Fixtures.agent("bob")
        for suffix in ["\n", "\r", "\u{2028}", "\u{2029}"] {
            #expect(MessageType(rawValue: type.rawValue + suffix) == nil)
            expectCode(.invalidBody) { try createMessage(sender: a, recipient: peerOf(b), type: type, body: [:], schemaDigest: digest + suffix) }
        }
    }

    @Test func missingCommerceThreadIsQuarantinedOnce() async throws {
        let a = Fixtures.agent("alice"), b = Fixtures.agent("bob"), store = MemoryStore()
        let peers = try PeerStore(store: store)
        try await peers.adopt(peerOf(a))
        let inbox = try await Inbox.open(identity: b, store: store, peers: peers, onMessage: { _ in Issue.record("invalid commerce delivered") }, commerce: true)
        let env = try createMessage(sender: a, recipient: peerOf(b), type: .rfq, body: ["need": "data"])
        #expect(code(try await inbox.receive(env.jsonData())) == .invalidEnvelope)
        if case .duplicate = try await inbox.receive(env.jsonData()) {} else { Issue.record("expected duplicate") }
        await inbox.close()
    }

    @Test func customRoundTripAndPrivateHeader() throws {
        let a = Fixtures.agent("alice"), b = Fixtures.agent("bob")
        let env = try createMessage(sender: a, recipient: peerOf(b), type: type, body: ["text": "你好"],
                                    threadId: "secret workflow", schemaDigest: digest)
        let o = try JSONValue(json: env.jsonData()).objectValue!
        #expect(Set(o.keys) == ["ace", "from", "to", "conversationId", "messageId", "timestamp", "encryption", "signature"])
        let m = try parseMessage(env, receiver: b, sender: peerOf(a), replay: ReplayDetector())
        #expect(m.type == type && m.schemaDigest == digest && m.threadId == "secret workflow" && m.body["text"] == "你好")
        #expect(knownSchemaDigest(.text) == "c82da8dde17338c28c42d2a6fad644961c3e7a8d1d008f9d2b18e8d624cf4a52")
        for field in ["type", "threadId", "schemaDigest", "body"] {
            var leaked = o
            leaked[field] = "leak"
            expectCode(.invalidEnvelope) { try decodeEnvelope(JSONValue.object(leaked).jsonData()) }
        }
        expectCode(.invalidBody) { try createMessage(sender: a, recipient: peerOf(b), type: type, body: [:]) }
        expectCode(.invalidBody) { try createMessage(sender: a, recipient: peerOf(b), type: .text, body: ["message": "hi"], schemaDigest: digest) }
    }

    @Test func installedSchemasValidateCustomBodies() async throws {
        let a = Fixtures.agent("alice"), b = Fixtures.agent("bob")
        let store = MemoryStore(), rxStore = MemoryStore()
        let schemas: [String: SchemaValidator] = [digest: { m in
            guard m.body["task"]?.stringValue != nil else { throw ACEError(.badReference, "task required") }
            if m.body["task"] == "boom" { throw NSError(domain: "host", code: 1) }
        }]
        let peers = try PeerStore(store: rxStore)
        try await peers.adopt(peerOf(a))
        // Keys must be schema digests.
        await expectCodeAsync(.invalidArgument) { try await Outbox.open(identity: a, store: store, schemas: ["nope": { _ in }]) }
        await expectCodeAsync(.invalidArgument) {
            try await Inbox.open(identity: b, store: rxStore, peers: peers, onMessage: { _ in }, schemas: [digest.uppercased(): { _ in }])
        }
        // Outbox.stage refuses an invalid custom body before anything is persisted.
        let out = try await Outbox.open(identity: a, store: store, schemas: schemas)
        await expectCodeAsync(.badReference) { try await out.stage(recipient: peerOf(b), type: type, body: ["nope": 1], requestId: "bad", schemaDigest: digest) }
        #expect(try store.list(prefix: "outbox/").isEmpty)
        let good = try await out.stage(recipient: peerOf(b), type: type, body: ["task": "x"], schemaDigest: digest)
        let text = try await out.stage(recipient: peerOf(b), type: .text, body: ["message": "hi"])  // bundled: built-in rules only
        // The receiver quarantines with the validator's permanent code, or invalid_body for any other failure.
        let invalid = try createMessage(sender: a, recipient: peerOf(b), type: type, body: ["nope": 1], schemaDigest: digest)
        let boom = try createMessage(sender: a, recipient: peerOf(b), type: type, body: ["task": "boom"], schemaDigest: digest)
        let sink = Sink()
        let inbox = try await Inbox.open(identity: b, store: rxStore, peers: peers, onMessage: sink.handler, schemas: schemas)
        #expect(code(try await inbox.receive(invalid.jsonData())) == .badReference)
        #expect(code(try await inbox.receive(boom.jsonData())) == .invalidBody)
        #expect(isDuplicate(try await inbox.receive(invalid.jsonData())))
        #expect(try rxStore.list(prefix: "quarantine/").count == 2)
        #expect(isDelivered(try await inbox.receive(good.message.jsonData())))
        #expect(isDelivered(try await inbox.receive(text.message.jsonData())))
        #expect(sink.count == 2)
        await inbox.close()
    }

    @Test func durableCustomMetadata() async throws {
        let a = Fixtures.agent("alice"), b = Fixtures.agent("bob")
        let store = MemoryStore(), rxStore = MemoryStore()
        let out = try await Outbox.open(identity: a, store: store)
        let p = try await out.stage(recipient: peerOf(b), type: type, body: ["data": 1], threadId: "private", requestId: "operation", schemaDigest: digest)
        let reopened = try await Outbox.open(identity: a, store: store)
        #expect(try await reopened.stage(recipient: peerOf(b), type: type, body: ["data": 1], threadId: "private", requestId: "operation", schemaDigest: digest) == p)
        await expectCodeAsync(.pendingSendConflict) {
            try await reopened.stage(recipient: peerOf(b), type: type, body: ["data": 1], threadId: "private", requestId: "operation", schemaDigest: String(repeating: "cd", count: 32))
        }
        let peers = try PeerStore(store: rxStore)
        try await peers.adopt(peerOf(a))
        let inbox = try await Inbox.open(identity: b, store: rxStore, peers: peers, onMessage: { m in
            #expect(m.schemaDigest == digest && m.threadId == "private")
        })
        #expect(isDelivered(try await inbox.receive(p.message.jsonData())))
        await inbox.close()
        let rx = try await Inbox.open(identity: b, store: rxStore, peers: peers, onMessage: { _ in Issue.record("duplicate delivered") })
        let result = try await rx.receive(p.message.jsonData())
        if case .duplicate = result {} else { Issue.record("expected duplicate") }
        #expect(try store.list(prefix: "threads/").isEmpty)
        await rx.close()
    }
}
