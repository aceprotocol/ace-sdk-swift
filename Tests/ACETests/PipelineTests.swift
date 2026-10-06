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

private let relayURL = "https://relay.example"
private let relayClient = try! RelayClient(baseURL: URL(string: relayURL)!)

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
        try await alicePeers.pinRegistrationFile(try bob.toRegistrationFile(name: "Bob", endpoint: "https://bob.example"), pinnedAt: 1)
        try await bobPeers.pinRegistrationFile(try alice.toRegistrationFile(name: "Alice", endpoint: "https://alice.example"), pinnedAt: 1)
    }

    func outbox(_ who: SoftwareIdentity) async throws -> Outbox {
        try await Outbox.open(identity: who, store: who.getACEId() == alice.getACEId() ? aliceStore : bobStore, clock: clock.fn)
    }

    func inbox(_ who: SoftwareIdentity, _ sink: Sink) async throws -> Inbox {
        let isAlice = who.getACEId() == alice.getACEId()
        return try await Inbox.open(identity: who, store: isAlice ? aliceStore : bobStore, peers: isAlice ? alicePeers : bobPeers,
                                    onMessage: sink.handler, clock: clock.fn)
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
        #expect(try await aOut.stage(recipient: bobPeer, type: .rfq, body: ["need": "other"], threadId: "t1", requestId: "r1") == rfq)
        await expectCodeAsync(.pendingSendConflict) {
            try await aOut.stage(recipient: bobPeer, type: .offer, body: ["price": "1", "currency": "USDC"], threadId: "t1", requestId: "r2")
        }
        let wire = Locked<[ACEMessage]>([])
        try await aOut.deliver("r1") { env in wire.mutate { $0.append(env) } }
        #expect(try await aOut.pending().isEmpty)
        #expect(isDelivered(await bIn.receive(wire.value[0].jsonData(), source: .relay(url: relayURL, streamId: "1-1"))))
        #expect(bSink.has(rfq.message))
        #expect(isDuplicate(await bIn.receive(wire.value[0].jsonData(), source: .relay(url: relayURL + "/", streamId: "1-1"))))
        #expect(await bIn.cursor(for: try RelayClient(baseURL: URL(string: "HTTPS://RELAY.example/")!)) == "1-1")

        let offer = try await bOut.stage(recipient: alicePeer, type: .offer, body: ["price": "5", "currency": "USDC"], threadId: "t1")
        // Offer stays pending (no ack): alice's accept later proves delivery.
        #expect(isDelivered(await aIn.receive(offer.message.jsonData(), source: .direct)))
        let accept = try await aOut.stage(recipient: bobPeer, type: .accept, body: ["offerId": .string(offer.message.messageId)], threadId: "t1")
        #expect(isDelivered(await bIn.receive(accept.message.jsonData(), source: .direct)))
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

    @Test func outboxExpiredResignAndAbandon() async throws {
        let p = try await Pair()
        let aOut = try await p.outbox(p.alice)
        let bobPeer = try await p.alicePeers.get(p.bob.getACEId())!
        let staged = try await aOut.stage(recipient: bobPeer, type: .rfq, body: ["need": "x"], threadId: "t9", requestId: "q")
        await expectCodeAsync(.invalidArgument) { try await aOut.resign("q") }
        await expectCodeAsync(.envelopeExpired) { try await aOut.deliver("q") { _ in throw ACEError(.envelopeExpired) } }
        #expect(try await aOut.pending().first?.status == .expired)
        await expectCodeAsync(.relayUnavailable) { try await aOut.deliver("q") { _ in throw ACEError(.relayUnavailable) } }
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
        #expect(isDelivered(await bIn.receive(resigned.message.jsonData(), source: .direct)))
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
        #expect(try await second.stage(recipient: bobPeer, type: .rfq, body: ["need": "y"], threadId: "t2",
                                       requestId: staged.requestId) == staged)
        // `second` clears it; `first`'s remembered thread no longer holds it.
        try await second.deliver(staged.requestId) { _ in }
        await expectCodeAsync(.invalidArgument) { try await first.deliver(staged.requestId) { _ in } }
        try await first.abandon(staged.requestId)
        #expect(try await first.pending().isEmpty)
    }

    @Test func quarantineAndDirectRules() async throws {
        let p = try await Pair()
        let sink = Sink()
        let bIn = try await p.inbox(p.bob, sink)
        let bobPeer = try await p.alicePeers.get(p.bob.getACEId())!
        // Undecodable: quarantined without fingerprint, cursor still advances.
        let o1 = await bIn.receive(Data("{}".utf8), source: .relay(url: relayURL, streamId: "1-1"))
        if case .quarantined(let e, let fp) = o1 { #expect(e.code == .invalidEnvelope && fp == nil) } else { Issue.record("\(o1)") }
        #expect(await bIn.cursor(for: relayClient) == "1-1")
        // Tampered signature from relay: quarantine record written.
        let env = try createMessage(sender: p.alice, recipient: bobPeer, type: .text, body: ["message": "x"],
                                    threads: try ThreadStateMachine(localAceId: p.alice.getACEId()), timestamp: p.clock.now)
        let resignedByBob = try ACE.resign(env, sender: p.bob, timestamp: env.timestamp)
        let forged = ACEMessage(messageId: env.messageId, from: env.from, to: env.to, conversationId: env.conversationId,
                                type: env.type, timestamp: env.timestamp, encryption: env.encryption,
                                signature: SignatureEnvelope(scheme: .ed25519, value: ACEBase64.encode(Data(repeating: 1, count: 64))))
        _ = resignedByBob
        let o2 = await bIn.receive(forged.jsonData(), source: .relay(url: relayURL, streamId: "1-2"))
        #expect(code(o2) == .invalidSignature)
        #expect(try p.bobStore.list(prefix: "quarantine/") == ["quarantine/\(envelopeFingerprint(forged)).json"])
        // The authentic one still delivers (quarantine is keyed by fingerprint).
        #expect(isDelivered(await bIn.receive(env.jsonData(), source: .relay(url: relayURL, streamId: "1-3"))))
        // Direct: stale is quarantined, nothing persisted.
        p.clock.now += 1000
        let late = await bIn.receive(env.jsonData(), source: .direct)
        #expect(code(late) == .staleTimestamp)
        #expect(try p.bobStore.list(prefix: "quarantine/").count == 1)
        // Unknown sender (no relay, no pin) is permanent → quarantined.
        let stranger = try SoftwareIdentity.generate(scheme: .ed25519)
        let s = try createMessage(sender: stranger, recipient: bobPeer, type: .text, body: ["message": "?"],
                                  threads: try ThreadStateMachine(localAceId: stranger.getACEId()), timestamp: p.clock.now)
        #expect(code(await bIn.receive(s.jsonData(), source: .direct)) == .unknownPeer)
        #expect(sink.count == 1)
        await bIn.close()
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
        #expect(isDelivered(await b2.receive(env.jsonData(), source: .direct)))
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
        try await peers.pinRegistrationFile(try alice.toRegistrationFile(name: "A", endpoint: "https://a.example"), pinnedAt: 1)
        let sink = Sink()
        let inbox = try await Inbox.open(identity: se, store: store, peers: peers, onMessage: sink.handler, clock: clock.fn)
        let sePeer = try verifyRegistrationFile(try createRegistrationFile(for: se, name: "SE", endpoint: "https://se.example"), pinnedAt: 1)
        let env = try createMessage(sender: alice, recipient: sePeer, type: .rfq, body: ["need": "x"],
                                    threads: try ThreadStateMachine(localAceId: alice.getACEId()), threadId: "k", timestamp: clock.now)
        se.keychainAvailable = false
        let o = await inbox.receive(env.jsonData(), source: .relay(url: relayURL, streamId: "2-1"))
        #expect(code(o) == .identityUnavailable)
        #expect(o.error?.isTransient == true)
        #expect(await inbox.cursor(for: relayClient) == nil)
        #expect(try store.read("replay.json").map { String(decoding: $0, as: UTF8.self).contains(env.messageId) } == false)
        se.keychainAvailable = true
        #expect(isDelivered(await inbox.receive(env.jsonData(), source: .relay(url: relayURL, streamId: "2-1"))))
        let cursorNow = await inbox.cursor(for: relayClient)
        #expect(sink.count == 1 && cursorNow == "2-1")

        // The SE identity can also send and stage through the Outbox.
        let out = try await Outbox.open(identity: se, store: store, clock: clock.fn)
        let alicePeer = try verifyRegistrationFile(try alice.toRegistrationFile(name: "A", endpoint: "https://a.example"), pinnedAt: 1)
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
        #expect(code(await bIn.receive(env.jsonData(), source: .relay(url: relayURL, streamId: "1-1"))) == .handlerFailed)
        #expect(await bIn.cursor(for: relayClient) == nil)
        await bIn.close()
        // Recovery during open surfaces handler_failed; the record stays pending.
        await expectCodeAsync(.handlerFailed) { try await p.inbox(p.bob, sink) }
        sink.failing = false
        let reopened = try await p.inbox(p.bob, sink)
        #expect(sink.has(env))
        #expect(isDuplicate(await reopened.receive(env.jsonData(), source: .relay(url: relayURL, streamId: "1-1"))))
        #expect(await reopened.cursor(for: relayClient) == "1-1")
        await reopened.close()
    }

    @Test func pullAndFollowThroughRelay() async throws {
        let p = try await Pair()
        let fake = FakeRelay()
        let relay = try makeRelay(fake.handle, clock: p.clock.fn)
        let aOut = try await p.outbox(p.alice)
        let bobPeer = try await p.alicePeers.get(p.bob.getACEId())!
        for i in 0..<5 {
            let s = try await aOut.stage(recipient: bobPeer, type: .text, body: ["message": .string("m\(i)")])
            try await aOut.deliver(s.requestId) { try await relay.send($0) }
        }
        let sink = Sink()
        let bIn = try await p.inbox(p.bob, sink)
        let r = await bIn.pull(relay, limit: 2)
        #expect(r.delivered == 5 && r.blocked == nil)
        #expect(await bIn.cursor(for: relay) == "1741000000000-5")
        let again = await bIn.pull(relay)
        #expect(again.delivered == 0 && again.duplicates == 0)
        #expect(sink.count == 5)
        await bIn.close()
    }

    // MARK: crash injection

    /// Fail the Nth store write of one non-economic receive (1 delivery, 2 replay, 3 ack,
    /// 4 cursor), reopen, re-receive: no lost message and no duplicate effect.
    @Test(arguments: 1...5) func crashInjection(_ failAt: Int) async throws {
        let store = FailingStore()
        let p = try await Pair(bobStore: store)
        let bobPeer = try await p.alicePeers.get(p.bob.getACEId())!
        let message = try createMessage(sender: p.alice, recipient: bobPeer, type: .text, body: ["message": "ping"],
                                        threads: try ThreadStateMachine(localAceId: p.alice.getACEId()), timestamp: p.clock.now)
        let sink = Sink()
        var inbox = try await p.inbox(p.bob, sink)
        store.arm(failWrite: failAt)
        let first = await inbox.receive(message.jsonData(), source: .relay(url: relayURL, streamId: "1-2"))
        store.arm(failWrite: nil)
        if failAt <= 4 { #expect(code(first) == .storageFailed, "failAt \(failAt): \(first)") } else { #expect(isDelivered(first)) }
        if failAt >= 2 && failAt <= 4 {
            // Failed state until reopened.
            #expect(code(await inbox.receive(message.jsonData(), source: .direct)) == .storageFailed)
        }
        await inbox.close()
        inbox = try await p.inbox(p.bob, sink)
        let retry = await inbox.receive(message.jsonData(), source: .relay(url: relayURL, streamId: "1-2"))
        #expect(isDelivered(retry) || isDuplicate(retry), "failAt \(failAt): retry \(retry)")
        #expect(sink.has(message) && sink.count == 1)
        #expect(sink.calls <= 2)
        #expect(await inbox.cursor(for: relayClient) == "1-2")
        #expect(!(try await isAcceptedByReplay(store, message)))
        await inbox.close()
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
        #expect(isDelivered(await bIn.receive(rfq.message.jsonData(), source: .direct)))
        let offer = try await bOut.stage(recipient: alicePeer, type: .offer, body: ["price": "2", "currency": "USDC"], threadId: "e")

        aliceStore.arm(failWrite: failAt)
        let first = await aIn.receive(offer.message.jsonData(), source: .relay(url: relayURL, streamId: "9-1"))
        aliceStore.arm(failWrite: nil)
        await aIn.close()
        aIn = try await p.inbox(p.alice, sink)
        let retry = await aIn.receive(offer.message.jsonData(), source: .relay(url: relayURL, streamId: "9-1"))
        #expect(isDelivered(retry) || isDuplicate(retry), "failAt \(failAt): first \(first), retry \(retry)")
        #expect(sink.has(offer.message) && sink.count == 1)
        #expect(sink.calls <= 2)
        let threads = try ThreadStore(store: aliceStore, localAceId: p.alice.getACEId())
        let snap = try threads.get(conversationId: rfq.message.conversationId, threadId: "e")!
        #expect(snap.state == .offered && snap.history.map(\.messageId) == [rfq.message.messageId, offer.message.messageId])
        // The rfq's pending send was proven delivered by the offer.
        #expect(try await aOut.pending().isEmpty)
        #expect(await aIn.cursor(for: relayClient) == "9-1")
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
        }, clock: p.clock.fn)
        let aOut = try await p.outbox(p.alice)
        let rfq = try await aOut.stage(recipient: bobPeer, type: .rfq, body: ["need": "x"], threadId: "h")
        #expect(isDelivered(await bIn.receive(rfq.message.jsonData(), source: .direct)))
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
        #expect(code(await bIn.receive(rfq.message.jsonData(), source: .direct)) == .storageFailed)
        store.arm(failWrite: nil)
        expectCode(.storageFailed) { try store.lock("threads", timeout: 0.1) }
        await bIn.close()
        try store.lock("threads", timeout: 0).release()
        // Outbox.open repairs the thread from the delivery record (without handing over).
        let bOut = try await p.outbox(p.bob)
        let threads = try ThreadStore(store: store, localAceId: p.bob.getACEId())
        #expect(try threads.get(conversationId: rfq.message.conversationId, threadId: "f")?.state == .rfq)
        _ = bOut
    }

    @Test func followYieldsLiveOutcomes() async throws {
        let p = try await Pair()
        let bobPeer = try await p.alicePeers.get(p.bob.getACEId())!
        let env = try createMessage(sender: p.alice, recipient: bobPeer, type: .text, body: ["message": "live"],
                                    threads: try ThreadStateMachine(localAceId: p.alice.getACEId()), timestamp: p.clock.now)
        let frame = "id: 5-1\nevent: message\ndata: \(String(decoding: env.jsonData(), as: UTF8.self))\n\n"
        let relay = try makeRelay({ req, _ in
            switch req.url!.path {
            case "/v1/inbox": return .json(200, ["messages": [], "cursor": NSNull()])
            case "/v1/listen":
                return req.url!.query?.contains("since=5-1") == true ? .error(401, "invalid_signature") : .sse([frame])
            default: return .error(404, "x")
            }
        }, clock: p.clock.fn)
        let sink = Sink()
        let bIn = try await p.inbox(p.bob, sink)
        var outcomes: [ReceiveOutcome] = []
        do {
            for try await o in bIn.follow(relay) { outcomes.append(o) }
        } catch let e as ACEError {
            #expect(e.code == .relayRejected)
        }
        #expect(outcomes.count == 1 && isDelivered(outcomes[0]) && sink.has(env))
        #expect(await bIn.cursor(for: relay) == "5-1")
        await bIn.close()
    }
}
