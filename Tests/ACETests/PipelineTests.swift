import Foundation
import Testing
import CryptoKit
@testable import ACE

/// Host effect sink: idempotent by (from, messageId), counts raw calls.
final class Sink: @unchecked Sendable {
    private let lock = NSLock()
    private(set) var calls = 0
    private(set) var effects: [String: ParsedMessage] = [:]
    var failing = false

    var handler: Inbox.MessageHandler {
        { [self] m in try self.record(m) }
    }

    private func record(_ m: ParsedMessage) throws {
        lock.lock()
        defer { lock.unlock() }
        calls += 1
        if failing { throw NSError(domain: "host", code: 1) }
        effects["\(m.from)|\(m.messageId)"] = m
    }

    var count: Int { lock.lock(); defer { lock.unlock() }; return effects.count }
    func has(_ env: ACEMessage) -> Bool { lock.lock(); defer { lock.unlock() }; return effects["\(env.from)|\(env.messageId)"] != nil }
}

/// A host-provided ACEStore that can fail the Nth write.
final class FailingStore: ACEStore, @unchecked Sendable {
    let inner = MemoryStore()
    private let lock = NSLock()
    private var writes = 0
    private var failAt: Int?

    func arm(failWrite n: Int?) {
        lock.lock(); writes = 0; failAt = n; lock.unlock()
    }

    func read(_ key: String) throws -> Data? { try inner.read(key) }
    func write(_ key: String, _ value: Data) throws {
        lock.lock()
        writes += 1
        let fail = failAt == writes
        lock.unlock()
        if fail { throw NSError(domain: "disk", code: 28) }
        try inner.write(key, value)
    }
    func delete(_ key: String) throws { try inner.delete(key) }
    func list(prefix: String) throws -> [String] { try inner.list(prefix: prefix) }
    func lock(_ name: String, timeout: TimeInterval) throws -> any ACEStoreLock { try inner.lock(name, timeout: timeout) }
}

/// A Secure-Enclave-style identity: signs with its own key and borrows the X-Wing seed
/// from a "keychain" inside `decrypt`.
final class KeychainIdentity: ACEIdentity, @unchecked Sendable {
    struct KeychainUnavailable: Error {}
    private let signingKey = Curve25519.Signing.PrivateKey()
    private let seed = ACEEncryption.generateSeed()
    private let encKey: Data
    var keychainAvailable = true
    private(set) var decryptCalls = 0

    init() throws { encKey = try ACEEncryption.publicKey(fromSeed: seed) }

    func getACEId() -> String { computeACEId(getSigningPublicKey()) }
    func getSigningScheme() -> SigningScheme { .ed25519 }
    func getSigningPublicKey() -> Data { signingKey.publicKey.rawRepresentation }
    func getEncryptionPublicKey() -> Data { encKey }
    func sign(_ data: Data) throws -> Data { try signingKey.signature(for: data) }
    func decrypt(kemCiphertext: Data, payload: Data, conversationId: String) throws -> Data {
        decryptCalls += 1
        guard keychainAvailable else { throw KeychainUnavailable() }
        return try ACEEncryption.decrypt(kemCiphertext: kemCiphertext, payload: payload, seed: seed, conversationId: conversationId)
    }

}


/// Two parties with pinned registration-file peers over a shared clock.
struct Pair {
    let clock = TestClock(1741000000)
    let alice = Fixtures.agent("alice")
    let bob = Fixtures.agent("bob")
    let aliceStore: any ACEStore
    let bobStore: any ACEStore
    let alicePeers: PeerStore
    let bobPeers: PeerStore

    init(aliceStore: any ACEStore = MemoryStore(), bobStore: any ACEStore = MemoryStore()) async throws {
        self.aliceStore = aliceStore
        self.bobStore = bobStore
        alicePeers = try PeerStore(store: aliceStore, clock: clock.fn)
        bobPeers = try PeerStore(store: bobStore, clock: clock.fn)
        try await alicePeers.pinRegistrationFile(try createRegistrationFile(for: bob, name: "Bob", endpoint: "https://bob.example", timestamp: 1))
        try await bobPeers.pinRegistrationFile(try createRegistrationFile(for: alice, name: "Alice", endpoint: "https://alice.example", timestamp: 1))
    }

    func outbox(_ who: SoftwareIdentity) async throws -> Outbox {
        try await Outbox.open(identity: who, store: who.getACEId() == alice.getACEId() ? aliceStore : bobStore, clock: clock.fn, commerce: true)
    }

    func inbox(_ who: SoftwareIdentity, _ sink: Sink) async throws -> Inbox {
        let isAlice = who.getACEId() == alice.getACEId()
        return try await Inbox.open(identity: who, store: isAlice ? aliceStore : bobStore, peers: isAlice ? alicePeers : bobPeers,
                                    onMessage: sink.handler, clock: clock.fn, commerce: true)
    }
}

func isAcceptedByReplay(_ store: any ACEStore, _ env: ACEMessage) async throws -> Bool {
    let r = try ReplayDetector(state: try ReplayState(json: try store.read("replay.json")!), capacity: 100_000)
    return try r.accepts(env.messageId, from: env.from, timestamp: env.timestamp)
}

func isDelivered(_ o: ReceiveOutcome) -> Bool { if case .delivered = o { return true }; return false }
func isDuplicate(_ o: ReceiveOutcome) -> Bool { if case .duplicate = o { return true }; return false }
func code(_ o: ReceiveOutcome) -> ACEError.Code? { o.error?.code }

@Suite("Pipeline")
struct PipelineTests {

    @Test func economicFlowBothSides() async throws {
        let p = try await Pair()
        let aOut = try await p.outbox(p.alice), bOut = try await p.outbox(p.bob)
        let aSink = Sink(), bSink = Sink()
        let aIn = try await p.inbox(p.alice, aSink), bIn = try await p.inbox(p.bob, bSink)
        let bobPeer = try await p.alicePeers.get(p.bob.getACEId())!
        let alicePeer = try await p.bobPeers.get(p.alice.getACEId())!

        let rfq = try await aOut.stage(recipient: bobPeer, type: .rfq, body: ["need": "translate"], threadId: "t1", requestId: "r1")
        // Idempotent stage; a second pending send on the thread conflicts.
        await expectCodeAsync(.pendingSendConflict) { try await aOut.stage(recipient: bobPeer, type: .rfq, body: ["need": "other"], threadId: "t1", requestId: "r1") }
        #expect(try await aOut.stage(recipient: bobPeer, type: .rfq, body: ["need": "translate"], threadId: "t1", requestId: "r1") == rfq)
        await expectCodeAsync(.pendingSendConflict) {
            try await aOut.stage(recipient: bobPeer, type: .offer, body: ["price": "1", "currency": "USDC"], threadId: "t1", requestId: "r2")
        }
        let wire = Locked<[ACEMessage]>([])
        try await aOut.deliver("r1") { env in wire.mutate { $0.append(env) } }
        #expect(try await aOut.pending().isEmpty)
        #expect(isDelivered(try await bIn.receive(wire.value[0].jsonData())))
        #expect(bSink.has(rfq.message))
        #expect(isDuplicate(try await bIn.receive(wire.value[0].jsonData())))

        let offer = try await bOut.stage(recipient: alicePeer, type: .offer, body: ["price": "5", "currency": "USDC"], threadId: "t1")
        // Offer stays pending (no ack): alice's accept later proves delivery.
        #expect(isDelivered(try await aIn.receive(offer.message.jsonData())))
        let accept = try await aOut.stage(recipient: bobPeer, type: .accept, body: ["offerId": .string(offer.message.messageId)], threadId: "t1")
        #expect(isDelivered(try await bIn.receive(accept.message.jsonData())))
        #expect(try await bOut.pending().map(\.requestId) == [])  // proven by alice's accept
        #expect(try await aOut.pending().map(\.requestId) == [accept.requestId])

        let threads = try ThreadStore(store: p.bobStore, localAceId: p.bob.getACEId())
        let snap = try threads.get(conversationId: rfq.message.conversationId, threadId: "t1")!
        #expect(snap.state == .accepted && snap.history.count == 3)
        #expect(try threads.allowedTypes(conversationId: rfq.message.conversationId, threadId: "t1", senderAceId: p.bob.getACEId()) == [.invoice, .deliver])

        // Persisted thread record shape.
        let raw = String(decoding: try p.bobStore.read(ThreadStore.key(conversationId: rfq.message.conversationId, threadId: "t1"))!, as: UTF8.self)
        #expect(raw.hasPrefix("{\"conversationId\":\"\(rfq.message.conversationId)\",\"history\":[{\"from\":"))
        #expect(raw.hasSuffix("\"state\":\"accepted\",\"threadId\":\"t1\",\"version\":1}"))
        await aIn.close(); await bIn.close()
    }

    @Test func outboxOpenSkipsAckedRecordsCoveredByTheHorizon() async throws {
        let p = try await Pair()
        let bobPeer = try await p.alicePeers.get(p.bob.getACEId())!
        let rfq = try await (try await p.outbox(p.alice)).stage(recipient: bobPeer, type: .rfq, body: ["need": "x"], threadId: "gone")
        let bIn = try await p.inbox(p.bob, Sink())
        #expect(isDelivered(try await bIn.receive(rfq.message.jsonData())))
        await bIn.close()
        let threads = try ThreadStore(store: p.bobStore, localAceId: p.bob.getACEId(), clock: p.clock.fn)
        let cid = rfq.message.conversationId
        // Not yet covered: the acked record still repairs a removed thread.
        try threads.remove(conversationId: cid, threadId: "gone")
        _ = try await p.outbox(p.bob)
        #expect(try threads.get(conversationId: cid, threadId: "gone") != nil)
        // Covered by the horizon: the thread stays removed.
        try threads.remove(conversationId: cid, threadId: "gone")
        try p.bobStore.write("replay.json", ReplayState(entries: [], horizon: rfq.message.timestamp, senderHorizons: [:]).jsonData())
        _ = try await p.outbox(p.bob)
        #expect(try threads.get(conversationId: cid, threadId: "gone") == nil)
        #expect(try p.bobStore.list(prefix: "deliveries/").count == 1)
    }

    @Test func outboxExpiredResignAndAbandon() async throws {
        let p = try await Pair()
        let aOut = try await p.outbox(p.alice)
        let bobPeer = try await p.alicePeers.get(p.bob.getACEId())!
        let staged = try await aOut.stage(recipient: bobPeer, type: .rfq, body: ["need": "x"], threadId: "t9", requestId: "q")
        await expectCodeAsync(.invalidArgument) { try await aOut.resign("q") }
        await expectCodeAsync(.envelopeExpired) { try await aOut.deliver("q") { _ in throw ACEError(.envelopeExpired) } }
        #expect(try await aOut.pending().first?.status == .expired)
        // An expired send is refused before any transport call.
        let called = Locked(false)
        await expectCodeAsync(.envelopeExpired) { try await aOut.deliver("q") { _ in called.mutate { $0 = true } } }
        #expect(!called.value)
        p.clock.now += 1000
        let resigned = try await aOut.resign("q")
        #expect(resigned.message.messageId == staged.message.messageId)
        #expect(resigned.message.timestamp == 1741001000 && resigned.status == .pending)
        #expect(resigned.message.encryption == staged.message.encryption)
        try verifyEnvelopeSignature(resigned.message, scheme: .ed25519, signingPublicKey: p.alice.getSigningPublicKey())
        let threads = try ThreadStore(store: p.aliceStore, localAceId: p.alice.getACEId())
        #expect(try threads.get(conversationId: staged.message.conversationId, threadId: "t9")?.history.last?.timestamp == 1741001000)
        // The receiver accepts the re-signed envelope.
        let bIn = try await p.inbox(p.bob, Sink())
        #expect(isDelivered(try await bIn.receive(resigned.message.jsonData())))
        try await aOut.abandon("q")
        try await aOut.abandon("unknown")
        #expect(try threads.get(conversationId: staged.message.conversationId, threadId: "t9") == nil)
        await expectCodeAsync(.invalidArgument) { try await aOut.deliver("unknown") { _ in } }

        // Non-economic: outbox/ file.
        let text = try await aOut.stage(recipient: bobPeer, type: .text, body: ["message": "hi"])
        #expect(try p.aliceStore.list(prefix: "outbox/").count == 1)
        try await aOut.deliver(text.requestId) { _ in }
        #expect(try p.aliceStore.list(prefix: "outbox/").isEmpty)
        await bIn.close()
    }

    @Test func outboxInstancesSharingAStoreSeeEachOthersSends() async throws {
        let p = try await Pair()
        let first = try await p.outbox(p.alice), second = try await p.outbox(p.alice)
        let bobPeer = try await p.alicePeers.get(p.bob.getACEId())!
        // Staged by `first` (which remembers its thread), found by `second` only by scanning.
        let staged = try await first.stage(recipient: bobPeer, type: .rfq, body: ["need": "x"], threadId: "t1")
        #expect(try await second.stage(recipient: bobPeer, type: .rfq, body: ["need": "x"], threadId: "t1",
                                       requestId: staged.requestId) == staged)
        // `second` clears it; `first`'s remembered thread no longer holds it.
        try await second.deliver(staged.requestId) { _ in }
        await expectCodeAsync(.invalidArgument) { try await first.deliver(staged.requestId) { _ in } }
        try await first.abandon(staged.requestId)
        #expect(try await first.pending().isEmpty)
    }

    @Test func quarantineRules() async throws {
        let p = try await Pair()
        let sink = Sink()
        let bIn = try await p.inbox(p.bob, sink)
        let bobPeer = try await p.alicePeers.get(p.bob.getACEId())!
        // Undecodable: quarantined without fingerprint, nothing persisted.
        let o1 = try await bIn.receive(Data("{}".utf8))
        if case .quarantined(let e, let fp) = o1 { #expect(e.code == .invalidEnvelope && fp == nil) } else { Issue.record("\(o1)") }
        #expect(try p.bobStore.list(prefix: "quarantine/").isEmpty)
        // Tampered signature: quarantine record written.
        let env = try createMessage(sender: p.alice, recipient: bobPeer, type: .text, body: ["message": "x"],
                                    threads: try ThreadStateMachine(localAceId: p.alice.getACEId()), timestamp: p.clock.now)
        let resignedByBob = try ACE.resign(env, sender: p.bob, timestamp: env.timestamp)
        let forged = ACEMessage(messageId: env.messageId, from: env.from, to: env.to, conversationId: env.conversationId,
                                timestamp: env.timestamp, encryption: env.encryption,
                                signature: SignatureEnvelope(scheme: .ed25519, value: ACEBase64.encode(Data(repeating: 1, count: 64))))
        _ = resignedByBob
        let o2 = try await bIn.receive(forged.jsonData())
        #expect(code(o2) == .invalidSignature)
        #expect(try p.bobStore.list(prefix: "quarantine/") == ["quarantine/\(envelopeFingerprint(forged)).json"])
        // The authentic one still delivers (quarantine is keyed by fingerprint).
        #expect(isDelivered(try await bIn.receive(env.jsonData())))
        // No ±300 s freshness check on the inner envelope (that is the MLS handshake's job):
        // inside the offline window it is simply a duplicate.
        p.clock.now += 1000
        #expect(isDuplicate(try await bIn.receive(env.jsonData())))
        #expect(try p.bobStore.list(prefix: "quarantine/").count == 1)
        // Unknown sender (no relay, no pin) is permanent → quarantined and persisted.
        let stranger = try SoftwareIdentity.generate(scheme: .ed25519)
        let s = try createMessage(sender: stranger, recipient: bobPeer, type: .text, body: ["message": "?"],
                                  threads: try ThreadStateMachine(localAceId: stranger.getACEId()), timestamp: p.clock.now)
        #expect(code(try await bIn.receive(s.jsonData())) == .unknownPeer)
        #expect(try p.bobStore.list(prefix: "quarantine/").count == 2)
        #expect(sink.count == 1)
        await bIn.close()
    }

    @Test func relayPathWithExtremeClocksIsStaleNotTrap() async throws {
        for extreme in [Int.min, Int.max] {
            let p = try await Pair()
            let sink = Sink()
            let bobPeer = try await p.alicePeers.get(p.bob.getACEId())!
            let env = try createMessage(sender: p.alice, recipient: bobPeer, type: .rfq, body: ["need": "x"],
                                        threads: try ThreadStateMachine(localAceId: p.alice.getACEId()),
                                        threadId: "t", timestamp: p.clock.now)
            // Opening on a fresh store with the extreme clock seeds the replay horizon from the clamped clock.
            p.clock.now = extreme
            let bIn = try await p.inbox(p.bob, sink)
            let o = try await bIn.receive(env.jsonData())
            #expect(code(o) == .staleTimestamp, "clock \(extreme): \(o)")
            #expect(sink.count == 0)
            await bIn.close()
        }
    }

    @Test func receiverIsExclusiveAndReplayMissingIsDetected() async throws {
        let p = try await Pair()
        let bIn = try await p.inbox(p.bob, Sink())
        await expectCodeAsync(.receiverBusy) { try await p.inbox(p.bob, Sink()) }
        await bIn.close()
        let again = try await p.inbox(p.bob, Sink())
        await again.close()
        // History without replay state is storage_failed (never a fresh start).
        let env = try createMessage(sender: p.alice, recipient: try await p.alicePeers.get(p.bob.getACEId())!, type: .rfq,
                                    body: ["need": "x"], threads: try ThreadStateMachine(localAceId: p.alice.getACEId()),
                                    threadId: "z", timestamp: p.clock.now)
        let b2 = try await p.inbox(p.bob, Sink())
        #expect(isDelivered(try await b2.receive(env.jsonData())))
        await b2.close()
        try p.bobStore.delete("replay.json")
        await expectCodeAsync(.storageFailed) { try await p.inbox(p.bob, Sink()) }
    }

    @Test func customKeychainIdentityPlugsIn() async throws {
        let clock = TestClock(1741000000)
        let se = try KeychainIdentity()
        let alice = Fixtures.agent("alice")
        let store = FailingStore()  // host-provided ACEStore
        let peers = try PeerStore(store: store, clock: clock.fn)
        try await peers.pinRegistrationFile(try createRegistrationFile(for: alice, name: "A", endpoint: "https://a.example", timestamp: 1))
        let sink = Sink()
        let inbox = try await Inbox.open(identity: se, store: store, peers: peers, onMessage: sink.handler, clock: clock.fn, commerce: true)
        let sePeer = try verifyRegistrationFile(try createRegistrationFile(for: se, name: "SE", endpoint: "https://se.example"))
        let env = try createMessage(sender: alice, recipient: sePeer, type: .rfq, body: ["need": "x"],
                                    threads: try ThreadStateMachine(localAceId: alice.getACEId()), threadId: "k", timestamp: clock.now)
        se.keychainAvailable = false
        let o = try await inbox.receive(env.jsonData())
        #expect(code(o) == .identityUnavailable)
        #expect(o.error?.isTransient == true)
        #expect(try store.read("replay.json").map { String(decoding: $0, as: UTF8.self).contains(env.messageId) } == false)
        se.keychainAvailable = true
        #expect(isDelivered(try await inbox.receive(env.jsonData())))
        #expect(sink.count == 1)

        // The SE identity can also send and stage through the Outbox.
        let out = try await Outbox.open(identity: se, store: store, clock: clock.fn)
        let alicePeer = try verifyRegistrationFile(try createRegistrationFile(for: alice, name: "A", endpoint: "https://a.example", timestamp: 1))
        let offer = try await out.stage(recipient: alicePeer, type: .offer, body: ["price": "1", "currency": "USDC"], threadId: "k")
        try verifyEnvelopeSignature(offer.message, scheme: .ed25519, signingPublicKey: se.getSigningPublicKey())
        await inbox.close()
    }

    @Test func handlerFailureRetriesWithoutFailedState() async throws {
        let p = try await Pair()
        let sink = Sink()
        sink.failing = true
        let bIn = try await p.inbox(p.bob, sink)
        let env = try createMessage(sender: p.alice, recipient: try await p.alicePeers.get(p.bob.getACEId())!, type: .text,
                                    body: ["message": "x"], threads: try ThreadStateMachine(localAceId: p.alice.getACEId()),
                                    timestamp: p.clock.now)
        #expect(code(try await bIn.receive(env.jsonData())) == .handlerFailed)
        await bIn.close()
        // Recovery during open surfaces handler_failed; the record stays pending.
        await expectCodeAsync(.handlerFailed) { try await p.inbox(p.bob, sink) }
        sink.failing = false
        let reopened = try await p.inbox(p.bob, sink)
        #expect(sink.has(env))
        #expect(isDuplicate(try await reopened.receive(env.jsonData())))
        await reopened.close()
    }

    // MARK: crash injection

    /// Fail the Nth store write of one non-economic receive (1 delivery, 2 replay, 3 ack),
    /// reopen, re-receive: no lost message and no duplicate effect.
    @Test(arguments: 1...4) func crashInjection(_ failAt: Int) async throws {
        let store = FailingStore()
        let p = try await Pair(bobStore: store)
        let bobPeer = try await p.alicePeers.get(p.bob.getACEId())!
        let message = try createMessage(sender: p.alice, recipient: bobPeer, type: .text, body: ["message": "ping"],
                                        threads: try ThreadStateMachine(localAceId: p.alice.getACEId()), timestamp: p.clock.now)
        let sink = Sink()
        var inbox = try await p.inbox(p.bob, sink)
        store.arm(failWrite: failAt)
        let first = try await inbox.receive(message.jsonData())
        store.arm(failWrite: nil)
        // Writes: 1 delivery record (commit point), 2 ack, 3 replay.json at close (journaled by the record).
        if failAt <= 2 { #expect(code(first) == .storageFailed, "failAt \(failAt): \(first)") } else { #expect(isDelivered(first)) }
        if failAt == 2 {
            // Failed state until reopened.
            #expect(code(try await inbox.receive(message.jsonData())) == .storageFailed)
        }
        await inbox.close()
        inbox = try await p.inbox(p.bob, sink)
        let retry = try await inbox.receive(message.jsonData())
        #expect(isDelivered(retry) || isDuplicate(retry), "failAt \(failAt): retry \(retry)")
        #expect(sink.has(message) && sink.count == 1)
        #expect(sink.calls <= 2)
        await inbox.close()
        #expect(!(try await isAcceptedByReplay(store, message)))
    }

    /// The delivery records journal the seen store between writes of replay.json: a crash
    /// (no close) loses no commit, and a record a horizon covers in memory only is kept until a
    /// written replay.json covers it.
    @Test func deliveryRecordsJournalTheSeenStore() async throws {
        let p = try await Pair()
        let bobPeer = try await p.alicePeers.get(p.bob.getACEId())!
        func text(_ s: String, at t: Int) throws -> ACEMessage {
            try createMessage(sender: p.alice, recipient: bobPeer, type: .text, body: ["message": .string(s)], timestamp: t)
        }
        let first = try text("one", at: p.clock.now - 1), second = try text("two", at: p.clock.now)
        let sink = Sink()
        func open() async throws -> Inbox {
            // Quota 1: the second message evicts the first and raises H[alice] over it, in memory.
            try await Inbox.open(identity: p.bob, store: p.bobStore, peers: p.bobPeers, onMessage: sink.handler, capacity: 16, clock: p.clock.fn)
        }
        var inbox: Inbox? = try await open()
        #expect(isDelivered(try await inbox!.receive(first.jsonData())))
        #expect(isDelivered(try await inbox!.receive(second.jsonData())))
        #expect(try p.bobStore.list(prefix: "deliveries/").count == 2)
        inbox = nil  // crash: replay.json was never rewritten
        #expect(try await isAcceptedByReplay(p.bobStore, first))
        inbox = try await open()
        #expect(isDuplicate(try await inbox!.receive(first.jsonData())))
        #expect(isDuplicate(try await inbox!.receive(second.jsonData())))
        #expect(sink.count == 2 && sink.calls == 2)
        await inbox!.close()
        // Written at close: the covered record of the first message is pruned, the second kept.
        #expect(!(try await isAcceptedByReplay(p.bobStore, first)))
        #expect(!(try await isAcceptedByReplay(p.bobStore, second)))
        #expect(try p.bobStore.list(prefix: "deliveries/").count == 1)
    }

    /// The same, for an economic message that is valid (seller offer → buyer).
    @Test(arguments: 1...6) func crashInjectionEconomic(_ failAt: Int) async throws {
        let aliceStore = FailingStore()
        let p = try await Pair(aliceStore: aliceStore)
        let bobPeer = try await p.alicePeers.get(p.bob.getACEId())!
        let alicePeer = try await p.bobPeers.get(p.alice.getACEId())!
        let aOut = try await p.outbox(p.alice), bOut = try await p.outbox(p.bob)
        let sink = Sink()
        var aIn = try await p.inbox(p.alice, sink)
        let bIn = try await p.inbox(p.bob, Sink())
        let rfq = try await aOut.stage(recipient: bobPeer, type: .rfq, body: ["need": "x"], threadId: "e")
        #expect(isDelivered(try await bIn.receive(rfq.message.jsonData())))
        let offer = try await bOut.stage(recipient: alicePeer, type: .offer, body: ["price": "2", "currency": "USDC"], threadId: "e")

        aliceStore.arm(failWrite: failAt)
        let first = try await aIn.receive(offer.message.jsonData())
        aliceStore.arm(failWrite: nil)
        await aIn.close()
        aIn = try await p.inbox(p.alice, sink)
        let retry = try await aIn.receive(offer.message.jsonData())
        #expect(isDelivered(retry) || isDuplicate(retry), "failAt \(failAt): first \(first), retry \(retry)")
        #expect(sink.has(offer.message) && sink.count == 1)
        #expect(sink.calls <= 2)
        let threads = try ThreadStore(store: aliceStore, localAceId: p.alice.getACEId())
        let snap = try threads.get(conversationId: rfq.message.conversationId, threadId: "e")!
        #expect(snap.state == .offered && snap.history.map(\.messageId) == [rfq.message.messageId, offer.message.messageId])
        // The rfq's pending send was proven delivered by the offer.
        #expect(try await aOut.pending().isEmpty)
        await aIn.close(); await bIn.close()
    }

    @Test func handlerCanStageReplyOnSameThread() async throws {
        let p = try await Pair()
        let alicePeer = try await p.bobPeers.get(p.alice.getACEId())!
        let bobPeer = try await p.alicePeers.get(p.bob.getACEId())!
        let bOut = try await p.outbox(p.bob)
        let replies = Locked<[PendingSend]>([])
        let bIn = try await Inbox.open(identity: p.bob, store: p.bobStore, peers: p.bobPeers, onMessage: { m in
            guard m.type == .rfq else { return }
            let r = try await bOut.stage(recipient: alicePeer, type: .offer, body: ["price": "1", "currency": "USDC"],
                                         threadId: m.threadId, requestId: "reply-\(m.messageId)")
            replies.mutate { $0.append(r) }
        }, clock: p.clock.fn, commerce: true)
        let aOut = try await p.outbox(p.alice)
        let rfq = try await aOut.stage(recipient: bobPeer, type: .rfq, body: ["need": "x"], threadId: "h")
        #expect(isDelivered(try await bIn.receive(rfq.message.jsonData())))
        #expect(replies.value.count == 1)
        await bIn.close()
    }

    @Test func failedStateHoldsThreadsLockUntilClose() async throws {
        let store = FailingStore()
        let p = try await Pair(bobStore: store)
        let bobPeer = try await p.alicePeers.get(p.bob.getACEId())!
        let rfq = try await (try await p.outbox(p.alice)).stage(recipient: bobPeer, type: .rfq, body: ["need": "x"], threadId: "f")
        let bIn = try await p.inbox(p.bob, Sink())
        store.arm(failWrite: 2)  // thread record write, after the commit point
        #expect(code(try await bIn.receive(rfq.message.jsonData())) == .storageFailed)
        store.arm(failWrite: nil)
        expectCode(.lockBusy) { try store.lock("threads", timeout: 0.1) }
        await bIn.close()
        try store.lock("threads", timeout: 0).release()
        // Outbox.open repairs the thread from the delivery record (without handing over).
        let bOut = try await p.outbox(p.bob)
        let threads = try ThreadStore(store: store, localAceId: p.bob.getACEId())
        #expect(try threads.get(conversationId: rfq.message.conversationId, threadId: "f")?.state == .rfq)
        _ = bOut
    }

}
