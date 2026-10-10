import Foundation
import Testing
import ACE

private actor Delivered {
    var ids: Set<String> = []
    var calls = 0
    var fail = false
    func record(_ message: ParsedMessage) throws {
        if fail { throw MLSError("injected_crash") }
        calls += 1; ids.insert(message.messageId)
    }
    func setFailure(_ value: Bool) { fail = value }
}
/// A store that remembers every key written (the sender keeps no attempt journal).
private final class RecordingStore: ACEStore, @unchecked Sendable {
    private let inner = MemoryStore()
    private let mutex = NSLock()
    private var written: [String] = []
    var writes: [String] { mutex.withLock { written } }
    func read(_ key: String) throws -> Data? { try inner.read(key) }
    func write(_ key: String, _ value: Data) throws { mutex.withLock { written.append(key) }; try inner.write(key, value) }
    func delete(_ key: String) throws { try inner.delete(key) }
    func list(prefix: String) throws -> [String] { try inner.list(prefix: prefix) }
    func lock(_ name: String, timeout: TimeInterval) throws -> any ACEStoreLock { try inner.lock(name, timeout: timeout) }
}
/// Captures the data frame and its receipt of one attempt.
private actor Frames {
    var data: ACEMessage?
    var ack: ACEMessage?
    func set(data: ACEMessage, ack: ACEMessage) { self.data = data; self.ack = ack }
}
private struct DeliveryFixture: Sendable {
    let engine: NativeMLSEngine
    let a: SoftwareIdentity
    let b: SoftwareIdentity
    let pa: VerifiedPeer
    let pb: VerifiedPeer
    let sa: RecordingStore
    let sb: MemoryStore
    let ta: SecureTransport
    let tb: SecureTransport
    let inbox: Inbox
    let outbox: Outbox
    let pending: PendingSend
    let effects: Delivered
    static func make(schemas: [String: SchemaValidator] = [:]) async throws -> Self {
        let engine = try NativeMLSEngine(), a = try SoftwareIdentity.generate(scheme: .ed25519), b = try SoftwareIdentity.generate(scheme: .secp256k1)
        let pa = try verifyRegistrationFile(createRegistrationFile(for: a, name: "A", endpoint: "https://a.example", timestamp: 1))
        let pb = try verifyRegistrationFile(createRegistrationFile(for: b, name: "B", endpoint: "https://b.example", timestamp: 1))
        let sa = RecordingStore(), sb = MemoryStore(), peers = try PeerStore(store: sb)
        _ = try await peers.adopt(pa)
        try SecureTransport.setPeerAllowed(store: sa, peer: pb.aceId, allowed: true)
        try SecureTransport.setPeerAllowed(store: sb, peer: pa.aceId, allowed: true)
        let effects = Delivered()
        let inbox = try await Inbox.open(identity: b, store: sb, peers: peers, onMessage: { try await effects.record($0) }, schemas: schemas)
        let outbox = try await Outbox.open(identity: a, store: sa)
        let pending = try await outbox.stage(recipient: pb, type: .text, body: ["message": "秘密 hello"], requestId: "one")
        return Self(engine: engine, a: a, b: b, pa: pa, pb: pb, sa: sa, sb: sb,
            ta: SecureTransport(identity: a, engine: engine, store: sa), tb: SecureTransport(identity: b, engine: engine, store: sb),
            inbox: inbox, outbox: outbox, pending: pending, effects: effects)
    }
    func accept(_ raw: Data) async throws -> SecureOutcome {
        try SecureOutcome(await inbox.receive(raw))
    }
    func close() async throws { try await ta.close(); try await tb.close(); await inbox.close(); engine.close() }
}

@Test func secureTransportKeepsOriginalApplicationDeduplication() async throws {
    let s = try await DeliveryFixture.make()
    try await s.ta.deliver(s.pending.message, peer: s.pb) { packet, _ in try await s.tb.respond(packet, peer: s.pa, accept: s.accept) }
    try await s.outbox.deliver("one") { env in
        try await s.ta.deliver(env, peer: s.pb) { packet, _ in try await s.tb.respond(packet, peer: s.pa, accept: s.accept) }
    }
    #expect(await s.effects.calls == 1)
    #expect(try await s.outbox.pending().isEmpty)
    #expect(try s.sa.list(prefix: "mls/gates/").isEmpty)
    // The sender keeps no attempt journal.
    #expect(!s.sa.writes.contains { $0.hasPrefix("secure/out/") })
    try await s.close()
}

@Test func rejectedEnvelopeReceiptCarriesTheInboxCode() async throws {
    let digest = String(repeating: "ab", count: 32), type = MessageType(rawValue: "https://example.org/schemas/task/1")!
    let s = try await DeliveryFixture.make(schemas: [digest: { message in
        guard message.body["task"]?.stringValue != nil else { throw ACEError(.badReference, "task required") }
    }])
    let bad = try createMessage(sender: s.a, recipient: s.pb, type: type, body: ["nope": 1], schemaDigest: digest)
    let frames = Frames()
    do {
        try await s.ta.deliver(bad, peer: s.pb) { packet, route in
            let reply = try await s.tb.respond(packet, peer: s.pa, accept: s.accept)
            if route.kind == "ack" { await frames.set(data: packet, ack: reply) }
            return reply
        }
        Issue.record("rejected envelope acknowledged")
    } catch let error as ACEError {
        #expect(error.code == .deliveryRejected && error.category == .permanent && error.remoteCode == "bad_reference")
    }
    #expect(await s.effects.calls == 0)
    #expect(try s.sb.list(prefix: "quarantine/") == ["quarantine/\(envelopeFingerprint(bad)).json"])
    // The receiver journal row carries the outcome; a replayed data frame yields the same receipt
    // without a second handover.
    let rows = try s.sb.list(prefix: "secure/in/")
    #expect(rows.count == 1)
    let row = try JSONValue(json: try s.sb.read(rows[0])!)
    #expect(row["outcome"] == "rejected:bad_reference" && row["envelope"] == .null)
    let data = await frames.data, ack = await frames.ack
    let replayed = try await s.tb.respond(data!, peer: s.pa) { _ in Issue.record("handed over twice"); return .delivered }
    #expect(replayed == ack!)
    // A body the installed validator accepts is delivered.
    let good = try createMessage(sender: s.a, recipient: s.pb, type: type, body: ["task": "x"], schemaDigest: digest)
    try await s.ta.deliver(good, peer: s.pb) { packet, _ in try await s.tb.respond(packet, peer: s.pa, accept: s.accept) }
    #expect(await s.effects.calls == 1)
    try await s.close()
}

@Test func staticDowngradeAndRevokedIdentityAreRejected() async throws {
    let s = try await DeliveryFixture.make()
    await #expect(throws: MLSError("secure_delivery_required")) { try await s.tb.respond(s.pending.message, peer: s.pa, accept: s.accept) }
    try SecureTransport.setPeerAllowed(store: s.sb, peer: s.pa.aceId, allowed: false)
    await #expect(throws: MLSError("delivery_peer_disabled")) {
        try await s.ta.deliver(s.pending.message, peer: s.pb) { packet, _ in try await s.tb.respond(packet, peer: s.pa, accept: s.accept) }
    }
    #expect(await s.effects.calls == 0)
    try await s.close()
}

private actor RestartingReceiver {
    var current: SecureTransport
    let fixture: DeliveryFixture
    init(_ f: DeliveryFixture) { fixture = f; current = f.tb }
    func exchange(_ packet: ACEMessage) async throws -> ACEMessage {
        do { return try await current.respond(packet, peer: fixture.pa, accept: fixture.accept) }
        catch let error as ACEError where error.code == .handlerFailed {
            try await current.close()
            await fixture.effects.setFailure(false)
            current = SecureTransport(identity: fixture.b, engine: fixture.engine, store: fixture.sb)
            return try await current.respond(packet, peer: fixture.pa, accept: fixture.accept)
        }
    }
    func close() async throws { try await current.close() }
}
@Test func receiverRestartNeverReplaysAnUnreceiptedAttempt() async throws {
    let s = try await DeliveryFixture.make(), receiver = RestartingReceiver(s)
    await s.effects.setFailure(true)
    // The handler fails, so no receipt exists (its outcome is the Inbox's verdict). After the
    // restart the attempt's group is gone: the replayed data frame is refused, never decrypted
    // again, and the sender's attempt fails without acknowledging the operation.
    await #expect(throws: MLSError("session_closed")) {
        try await s.ta.deliver(s.pending.message, peer: s.pb, exchange: { packet, _ in try await receiver.exchange(packet) })
    }
    #expect(await s.effects.calls == 0)
    #expect(try await s.outbox.pending().count == 1)
    // A fresh attempt hands the same operation over exactly once.
    try await s.outbox.deliver("one") { env in
        try await s.ta.deliver(env, peer: s.pb) { packet, _ in try await receiver.exchange(packet) }
    }
    #expect(await s.effects.calls == 1)
    #expect(try await s.outbox.pending().isEmpty)
    try await receiver.close(); try await s.close()
}

@Test func reenablingPeerDoesNotReviveOldHandshake() async throws {
    let s = try await DeliveryFixture.make()
    await #expect(throws: MLSError("session_closed")) {
        try await s.ta.deliver(s.pending.message, peer: s.pb) { packet, _ in
            let result = try await s.tb.respond(packet, peer: s.pa, accept: s.accept)
            try SecureTransport.setPeerAllowed(store: s.sb, peer: s.pa.aceId, allowed: false)
            try SecureTransport.setPeerAllowed(store: s.sb, peer: s.pa.aceId, allowed: true)
            return result
        }
    }
    #expect(await s.effects.calls == 0)
    try await s.close()
}

@Test func controlExpiryCannotResignOriginalApplication() async throws {
    let s = try await DeliveryFixture.make()
    await #expect(throws: MLSError("delivery_expired")) {
        try await s.outbox.deliver("one") { message in
            try await s.ta.deliver(message, peer: s.pb) { _, _ in throw ACEError(.envelopeExpired) }
        }
    }
    #expect(try await s.outbox.pending().first?.status == .pending)
    let stale = try createMessage(sender: s.a, recipient: s.pb, type: .text, body: ["message": "old"],
                                 timestamp: Int(Date().timeIntervalSince1970) - 604_801)
    do {
        try await s.ta.deliver(stale, peer: s.pb) { _, _ in throw MLSError("must_not_transmit") }
        Issue.record("stale original envelope accepted")
    } catch let error as ACEError { #expect(error.code == .envelopeExpired) }
    try await s.close()
}

@Test func revocationAfterARejectedReceiptReportsThePeerDisabled() async throws {
    // 13: the sender snapshot is checked after the receipt, before its verdict is reported.
    let digest = String(repeating: "ab", count: 32), type = MessageType(rawValue: "https://example.org/schemas/task/1")!
    let s = try await DeliveryFixture.make(schemas: [digest: { _ in throw ACEError(.badReference, "task required") }])
    let bad = try createMessage(sender: s.a, recipient: s.pb, type: type, body: ["nope": 1], schemaDigest: digest)
    await #expect(throws: MLSError("delivery_peer_disabled")) {
        try await s.ta.deliver(bad, peer: s.pb) { packet, route in
            let reply = try await s.tb.respond(packet, peer: s.pa, accept: s.accept)
            if route.kind == "ack" { try SecureTransport.setPeerAllowed(store: s.sa, peer: s.pb.aceId, allowed: false) }
            return reply
        }
    }
    try await s.close()
}

/// Holds the first frame a sender produced.
private actor FirstFrame {
    var packet: ACEMessage?
    func set(_ p: ACEMessage) { if packet == nil { packet = p } }
}

@Test func pullWaitsForAnOfferItIssued() async throws {
    let s = try await DeliveryFixture.make()
    let first = FirstFrame()
    _ = try? await s.ta.deliver(s.pending.message, peer: s.pb) { packet, _ in await first.set(packet); throw MLSError("stop") }
    let hello = try #require(await first.packet)
    #expect(!(await s.tb.pendingHandshakes()))
    _ = try await s.tb.respond(hello, peer: s.pa, accept: s.accept)
    #expect(await s.tb.pendingHandshakes())

    let fake = FakeRelay()
    let relay = try makeRelay(fake.handle)
    let mailbox = try SecureMailbox.open(identity: s.b, store: s.sb, peers: try PeerStore(store: s.sb), relay: relay, secure: s.tb,
                                         inbox: s.inbox, send: { packet, _ in try await relay.send(packet); return .relay })
    let start = ContinuousClock.now
    let pulling = Task { await mailbox.pull() }
    try await Task.sleep(for: .milliseconds(1500))
    pulling.cancel()
    let result = await pulling.value
    // An empty inbox would return at once; the pending offer kept the pull polling until cancelled.
    #expect(ContinuousClock.now - start >= .milliseconds(1500))
    #expect(result.hasMore && result.blocked == nil && result.outcomes.isEmpty)
    await mailbox.close()
    try await s.close()
}
