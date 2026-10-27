//
//  FPMinimalTests.swift
//  The fp-minimal revision: Review Focus 1–5 of the plan, the foreign-relay address policy (I2), the serialized receive
//  pipeline and the persisted Outbox lease (I8), and the client fixes shared by every SDK (I1, I3, I4, pending TTL).
//

import Foundation
import Testing
@testable import ACE

/// A second profile, installed only where a test says so.
private let fpTranslation = try! ProfileManifest(json: Data(#"{"id":"urn:example:translation:1","messages":[{"type":"urn:example:translation:request:1","schema":{"type":"object","properties":{"text":{"type":"string","maxLength":100}},"required":["text"],"additionalProperties":false}}]}"#.utf8))

/// Alice connects to Bob (public) about `ace:text:1`; Bob accepts explicitly; both pull.
private func linked(_ relay: FakeRelay, _ clock: TestClock, alice aliceConfig: NetworkConfiguration = NetworkConfiguration(contact: .open, listed: true),
                    bob bobConfig: NetworkConfiguration = NetworkConfiguration(contact: .open, listed: true)) async throws -> (NetPeer, NetPeer) {
    let alice = try await NetPeer.make(relay, clock: clock, configuration: aliceConfig)
    let bob = try await NetPeer.make(relay, clock: clock, configuration: bobConfig)
    try await alice.network.connect(bob.aceId, profile: "ace:text:1", note: "hello")
    _ = try await bob.network.pull()
    if try bob.network.admission.get(alice.aceId) == nil { try await bob.network.accept(alice.aceId) }
    _ = try await alice.network.pull()
    return (alice, bob)
}

/// A packet from `from` to `to` (its pinned descriptor) signed at `ts`.
private func textPacket(_ from: NetPeer, to: NetPeer, _ text: String, at ts: Int, messageId: String = UUID().uuidString.lowercased()) async throws -> Data {
    let agent = try #require(try await from.network.peers.agent(to.aceId))
    let c = try from.network.profiles.content(type: "ace:text:1", body: ["message": .string(text)]).with(prekey: somePrekey())
    return try createPacket(sender: from.identity, to: to.aceId, prekey: agent.descriptor.prekey, content: c, messageId: messageId, timestamp: ts).jsonData()
}

/// A transport whose `post` suspends until released, counting posts.
private final class Gate: PacketTransport, @unchecked Sendable {
    let prekeyValue: Prekey
    let posts = LockedValue(0)
    private let lock = NSLock()
    private var continuation: CheckedContinuation<Void, Never>?

    init(_ prekey: Prekey) { prekeyValue = prekey }
    func prekey(for aceId: String, refresh: Bool) async throws -> Prekey { prekeyValue }
    func post(to aceId: String, content: PrivateContent, messageId: String, prekey: Prekey, retry: Bool) async throws {
        posts.value += 1
        await withCheckedContinuation { c in lock.withLock { continuation = c } }
    }
    var waiting: Bool { lock.withLock { continuation != nil } }
    func release() { lock.withLock { continuation?.resume(); continuation = nil } }
}

/// A store on which another process acts the first time lock `admission` is requested (just before it is taken).
private final class InterleavingStore: ACEStore, @unchecked Sendable {
    let base = MemoryStore()
    let beforeAdmissionLock = LockedValue<(@Sendable (MemoryStore) -> Void)?>(nil)
    func read(_ key: String) throws -> Data? { try base.read(key) }
    func write(_ key: String, _ value: Data) throws { try base.write(key, value) }
    func delete(_ key: String) throws { try base.delete(key) }
    func list(prefix: String) throws -> [String] { try base.list(prefix: prefix) }
    func lock(_ name: String, timeout: TimeInterval) throws -> any ACEStoreLock {
        if name == "admission", let hook = beforeAdmissionLock.value {
            beforeAdmissionLock.value = nil
            hook(base)
        }
        return try base.lock(name, timeout: timeout)
    }
}

@Suite struct FPMinimalTests {
    // MARK: Review Focus 1: out-of-order arrival over two relays

    /// An older copy of a message arriving after `H[from]` passed its timestamp is dropped without a receipt; the sender's
    /// next retry, signed with a fresh timestamp, is delivered.
    @Test func beyondHorizonDroppedWithoutReceiptAndTheRetryIsDelivered() async throws {
        let clock = TestClock(systemClock()), relay = FakeRelay(clock: clock.fn)
        let alice = try await NetPeer.make(relay, clock: clock)
        let bob = try await NetPeer.make(relay, clock: clock, capacity: 16)  // sender quota 1
        try await alice.network.connect(bob.aceId, profile: "ace:text:1")
        _ = try await bob.network.pull()
        try await bob.network.accept(alice.aceId)
        _ = try await alice.network.pull()
        // The first attempt of `late` reaches a slow relay: taken off Bob's queue, replayed later.
        let late = try await alice.network.send(to: bob.aceId, type: "ace:text:1", body: ["message": "late"])
        let delayed = try #require(relay.take(bob.aceId).last)
        // Two later messages are delivered; the second evicts the first and raises H[alice] past the delayed copy.
        clock.now += 1
        _ = try await alice.network.send(to: bob.aceId, type: "ace:text:1", body: ["message": "one"])
        clock.now += 1
        _ = try await alice.network.send(to: bob.aceId, type: "ace:text:1", body: ["message": "two"])
        #expect(try await bob.network.pull().count == 2)
        let sends = relay.sendCount(to: alice.aceId)
        #expect(try await bob.network.inbox!.receive(delayed) == .dropped(.replayHorizon))
        #expect(relay.sendCount(to: alice.aceId) == sends)  // never receipted
        // The Outbox retry re-signs at the current time and is delivered.
        _ = try await alice.network.pull()  // the receipts of `one` and `two`
        clock.now += Outbox.backoff(afterAttempt: 1) + 1
        _ = try await alice.network.flush()
        let outcomes = try await bob.network.pull()
        #expect(outcomes.count == 1)
        guard case .delivered(let m)? = outcomes.first else { Issue.record("retry not delivered: \(outcomes)"); return }
        #expect(m.messageId == late.messageId)
        _ = try await alice.network.pull()
        #expect(try await alice.network.outbox.entry(late.messageId)?.status == .delivered)
    }

    // MARK: Review Focus 2: a contact request fetched hours later

    @Test func contactRequestAcceptedAfterHours() async throws {
        let clock = TestClock(systemClock()), relay = FakeRelay(clock: clock.fn)
        let alice = try await NetPeer.make(relay, clock: clock)
        let bob = try await NetPeer.make(relay, clock: clock)
        try await alice.network.connect(bob.aceId, profile: "ace:text:1", note: "hi")
        clock.now += 2 * 3600  // Bob is offline for two hours
        _ = try await bob.network.publish()
        guard case .delivered? = try await bob.network.pull().first else { Issue.record("request not held"); return }
        #expect(try await bob.network.requests().map(\.from) == [alice.aceId])
        try await bob.network.accept(alice.aceId)
        clock.now += 3600
        _ = try await alice.network.publish()
        _ = try await alice.network.pull()
        #expect(try alice.network.admission.get(bob.aceId)?.state == .admitted)
    }

    /// A5: an outgoing `pending` entry lives `OFFLINE_WINDOW_SECONDS` after its request was sent (the relay's retention:
    /// a reply can arrive that late), not `CONTACT_REQUEST_TTL_SECONDS`; then it is deleted and a later `accepted` is
    /// ignored.
    @Test func pendingEntryExpiresAndALateAcceptedIsIgnored() async throws {
        let clock = TestClock(systemClock()), relay = FakeRelay(clock: clock.fn)
        let alice = try await NetPeer.make(relay, clock: clock)
        let bob = try await NetPeer.make(relay, clock: clock)
        try await alice.network.connect(bob.aceId, profile: "ace:text:1")
        #expect(try alice.network.admission.get(bob.aceId)?.state == .pending)
        let sent = clock.now
        _ = try await bob.network.pull()
        try await bob.network.accept(alice.aceId)  // the reply waits on the relay, still inside the offline window below
        clock.now += ACELimits.contactRequestTTLSeconds + 60
        #expect(try alice.network.admission.get(bob.aceId)?.state == .pending)  // the incoming-request TTL does not apply
        clock.now = sent + ACELimits.offlineWindowSeconds + 30  // Alice reads the accepted after her pending entry expired
        #expect(try alice.network.admission.get(bob.aceId) == nil)
        _ = try await alice.network.publish()
        _ = try await alice.network.pull()
        #expect(try alice.network.admission.get(bob.aceId) == nil)
    }

    // MARK: Review Focus 3: a back-dated packet after notAfter

    @Test func backdatedAfterNotAfterIsDropped() async throws {
        let clock = TestClock(systemClock()), relay = FakeRelay(clock: clock.fn)
        let (alice, bob) = try await linked(relay, clock)
        let t = clock.now
        try alice.identity.delegate(now: t, notAfter: t + 100)
        try await bob.network.importAgent(try await alice.network.publish().source)  // Bob pins the new delegation
        let packet = try await textPacket(alice, to: bob, "signed while live", at: t + 50)
        clock.now = t + 150  // received after the delegation's notAfter
        let sends = relay.sendCount(to: alice.aceId)
        #expect(try await bob.network.inbox!.receive(packet) == .dropped(.stalePeerBinding))
        #expect(relay.sendCount(to: alice.aceId) == sends)
    }

    // MARK: Review Focus 4: a 503 while pushing permits after a rotation

    @Test func refreshPermitsRetriedAfterATransientFailure() async throws {
        let clock = TestClock(systemClock()), relay = FakeRelay(clock: clock.fn)
        let (alice, bob) = try await linked(relay, clock, alice: NetworkConfiguration())
        try alice.identity.delegate(now: clock.now, notAfter: nil)
        relay.withLock { relay.failSend = (503, "internal_error") }
        try await alice.network.maintain()  // the permit push fails once
        #expect(relay.queued(bob.aceId).isEmpty)
        try await alice.network.maintain()  // and is retried at the next upkeep
        #expect(relay.queued(bob.aceId).count == 1)
        _ = try await bob.network.pull()
        let held = try #require(try bob.network.admission.heldPermit(alice.aceId))
        #expect(held["signature"]?["seq"]?.wireInt == (try alice.identity.getSigningSeq()))
    }

    // MARK: Review Focus 5: block() while the relay is unreachable

    @Test func blockIsLocalFirstWhenTheRelayIsDown() async throws {
        let clock = TestClock(systemClock()), relay = FakeRelay(clock: clock.fn)
        let (alice, bob) = try await linked(relay, clock)
        relay.withLock { relay.down = ["/v1/blocks"] }
        try await bob.network.block(alice.aceId)  // does not throw
        #expect(try bob.network.admission.get(alice.aceId)?.state == .blocked)
        #expect(relay.blocked(by: bob.aceId, alice.aceId) == nil)
        _ = try await alice.network.send(to: bob.aceId, type: "ace:text:1", body: ["message": "blocked?"])
        #expect(try await bob.network.pull() == [.dropped(.notPermitted)])
        relay.withLock { relay.down = [] }
        try await bob.network.maintain()
        #expect(relay.blocked(by: bob.aceId, alice.aceId) == true)
        // unblock keeps the revision increasing
        try await bob.network.unblock(alice.aceId)
        try await bob.network.block(alice.aceId)
        #expect(relay.blocked(by: bob.aceId, alice.aceId) == true)
    }

    /// block → unblock while the relay is down, then the re-sync: every retry sends exactly the revision decided locally,
    /// so a late block can never outrank the later unblock; the relay ends unblocked like the local table.
    @Test func lateBlockResyncNeverOutranksAnUnblock() async throws {
        let clock = TestClock(systemClock()), relay = FakeRelay(clock: clock.fn)
        let (alice, bob) = try await linked(relay, clock)
        relay.withLock { relay.down = ["/v1/blocks"] }
        try await bob.network.block(alice.aceId)    // revision 1, unsynced
        try await bob.network.unblock(alice.aceId)  // revision 2, unsynced
        relay.withLock { relay.down = [] }
        try await bob.network.maintain()
        #expect(relay.blocked(by: bob.aceId, alice.aceId) == false)
        // a late copy of the revision-1 block (an attempt still in flight) is stale at the relay
        await expectCodeAsync(.relayRejected) {
            try await bob.network.relay.setBlock(bob.identity, peer: alice.aceId, blocked: true, revision: 1)
        }
        try await bob.network.maintain()
        #expect(relay.blocked(by: bob.aceId, alice.aceId) == false)
        #expect(try bob.network.admission.get(alice.aceId) == nil)
        #expect(try bob.network.admission.unsyncedBlocks().isEmpty)
    }

    /// The permit push names a profile the peer's current descriptor still lists: the recorded one only while shared,
    /// else the first shared one.
    @Test func refreshPermitsUsesAProfileThePeerStillLists() async throws {
        let clock = TestClock(systemClock()), relay = FakeRelay(clock: clock.fn)
        let (alice, bob) = try await linked(relay, clock, alice: NetworkConfiguration(profiles: [fpTranslation, .text]))
        // the recorded profile is installed here, but Bob's descriptor does not list it
        try alice.network.admission.update(bob.aceId) { r in
            var r = r
            r?.profile = fpTranslation.id
            return r
        }
        try alice.identity.delegate(now: clock.now, notAfter: nil)
        #expect(try await alice.network.refreshPermits() == [bob.aceId])
        _ = try await bob.network.pull()
        #expect(try bob.network.admission.get(alice.aceId)?.profile == "ace:text:1")
        let held = try #require(try bob.network.admission.heldPermit(alice.aceId))
        #expect(held["signature"]?["seq"]?.wireInt == (try alice.identity.getSigningSeq()))
    }

    /// No profile in common with the peer's current descriptor: the peer is skipped.
    @Test func refreshPermitsSkipsAPeerSharingNoProfile() async throws {
        let clock = TestClock(systemClock()), relay = FakeRelay(clock: clock.fn)
        let (alice, bob) = try await linked(relay, clock, alice: NetworkConfiguration())
        let reopened = try await NetworkClient.open(identity: alice.identity, store: alice.store, relay: try relay.client(clock: clock.fn),
                                                    prekeys: StorePrekeyVault(store: alice.store),
                                                    configuration: NetworkConfiguration(profiles: [fpTranslation]),
                                                    receive: false, foreignRelay: { _ in throw ACEError(.blockedAddress) }, clock: clock.fn)
        try alice.identity.delegate(now: clock.now, notAfter: nil)
        let queued = relay.queued(bob.aceId).count
        #expect(try await reopened.refreshPermits().isEmpty)
        #expect(relay.queued(bob.aceId).count == queued)
    }

    // MARK: I1, I3

    @Test func publishRegistersAfterADelegation() async throws {
        let clock = TestClock(systemClock()), relay = FakeRelay(clock: clock.fn)
        let alice = try await NetPeer.make(relay, clock: clock)
        try alice.identity.delegate(now: clock.now, notAfter: nil)
        let agent = try await alice.network.publish()
        #expect(agent.state.seq == (try alice.identity.getSigningSeq()))
        #expect(relay.registered(alice.aceId)?.seq == agent.state.seq)
    }

    /// A permit counts as issued only after the packet carrying it was sent.
    @Test func permitRecordedOnlyAfterTheSendSucceeded() async throws {
        let clock = TestClock(systemClock()), relay = FakeRelay(clock: clock.fn)
        let alice = try await NetPeer.make(relay, clock: clock)
        let bob = try await NetPeer.make(relay, clock: clock)
        relay.withLock { relay.failSend = (503, "internal_error") }
        await expectCodeAsync(.relayUnavailable) { try await alice.network.connect(bob.aceId, profile: "ace:text:1") }
        #expect(try alice.network.admission.get(bob.aceId)?.issuedPermit == nil)
        try await alice.network.connect(bob.aceId, profile: "ace:text:1")
        #expect(try alice.network.admission.get(bob.aceId)?.issuedPermit != nil)
    }

    // MARK: I2: the default foreign-relay client

    @Test func foreignRelayRefusesPrivateAddress() async throws {
        let id = "ace:sha256:" + String(repeating: "a", count: 64)
        for url in ["https://10.1.2.3", "https://127.0.0.1:8443", "https://localhost", "https://169.254.169.254", "https://0.0.0.0"] {
            let client = try RelayClient.foreign(url)
            await expectCodeAsync(.blockedAddress) { try await client.descriptor(id) }
        }
        // https only; loopback http only with an explicit development configuration, and then only to loopback
        #expect(throws: ACEError(.invalidArgument)) { try RelayClient.foreign("http://relay.example") }
        #expect(throws: ACEError(.invalidArgument)) { try RelayClient.foreign("http://127.0.0.1:8080") }
        _ = try RelayClient.foreign("http://127.0.0.1:8080", allowLoopbackRelays: true)
        await expectCodeAsync(.blockedAddress) { try await RelayClient.foreign("https://10.1.2.3", allowLoopbackRelays: true).descriptor(id) }
        // the NetworkClient default: a peer descriptor naming a private address is never contacted
        let clock = TestClock(systemClock()), relay = FakeRelay(clock: clock.fn)
        let store = MemoryStore(), me = try makeIdentity(now: clock.now)
        let network = try await NetworkClient.open(identity: me, store: store, relay: try relay.client(clock: clock.fn),
                                                   prekeys: StorePrekeyVault(store: store), clock: clock.fn)
        let peer = try TestAgent(now: clock.now, relay: "https://10.9.9.9")
        try await network.importAgent(peer.agent.source)
        await expectCodeAsync(.blockedAddress) { try await network.agent(peer.aceId, refresh: true) }
        await network.close()
    }

    // MARK: I8: the receive pipeline is serialized; the Outbox lease is persisted

    @Test func concurrentPullAndReceiveHandsOverOnce() async throws {
        for _ in 0..<5 {
            let clock = TestClock(systemClock()), relay = FakeRelay(clock: clock.fn)
            // A host that takes a moment: another pass reaching the message meanwhile finds its hand-over pending.
            let slow = NetworkConfiguration(contact: .open, listed: true, onMessage: { _ in try await Task.sleep(for: .milliseconds(20)) })
            let (alice, bob) = try await linked(relay, clock, bob: slow)
            _ = try await alice.network.send(to: bob.aceId, type: "ace:text:1", body: ["message": "once"])
            let packet = try #require(relay.queued(bob.aceId).last)
            let inbox = try #require(await bob.network.inbox)
            let sends = relay.sendCount(to: alice.aceId)
            async let pulled = bob.network.pull()
            async let received = inbox.receive(packet)
            let (p, r) = try await (pulled, received)
            #expect(bob.received.value.filter { $0.type == "ace:text:1" }.count == 1, "\(p) \(r)")
            #expect((p + [r]).filter { if case .delivered = $0 { true } else { false } }.count == 1, "\(p) \(r)")
            #expect(relay.sendCount(to: alice.aceId) - sends <= 2)  // delivered once, plus at most one duplicate receipt
        }
    }

    /// Two Outbox instances over one store (two processes) never attempt one message at once: the lease is persisted.
    @Test func outboxLeaseIsPersisted() async throws {
        let store = MemoryStore(), me = try makeIdentity(now: NOW), peer = try TestAgent(now: NOW)
        let clock = TestClock(NOW)
        let a = Outbox(identity: me, store: store, profiles: try InstalledProfiles([.text]), clock: clock.fn)
        let b = Outbox(identity: me, store: store, profiles: try InstalledProfiles([.text]), clock: clock.fn)
        let e = try await a.enqueue(to: peer.aceId, type: "ace:text:1", body: ["message": "once"])
        let gate = Gate(peer.agent.descriptor.prekey)
        let first = Task { try await a.deliver(e.messageId, via: gate) }
        #expect(await settles { gate.waiting })
        #expect(try await b.deliver(e.messageId, via: gate).attempts == 0 && gate.posts.value == 1)
        clock.now += Outbox.inFlightSeconds  // an abandoned lease (a crashed process) expires
        gate.release()
        _ = try await first.value
        #expect(try await b.entry(e.messageId)?.inFlightUntil == nil)
    }

    /// A host cancelling an attempt before its post (a stream ended) is not an attempt: the lease is released and the
    /// entry is untouched. A cancellation after the post returned is recorded, since a receipt names that prekey.
    @Test func cancelledAttemptIsNotAnAttempt() async throws {
        let me = try makeIdentity(now: NOW), peer = try TestAgent(now: NOW)
        let outbox = Outbox(identity: me, store: MemoryStore(), profiles: try InstalledProfiles([.text]), clock: { NOW })
        let e = try await outbox.enqueue(to: peer.aceId, type: "ace:text:1", body: ["message": "x"])
        struct Slow: PacketTransport {
            func prekey(for aceId: String, refresh: Bool) async throws -> Prekey { try await Task.sleep(for: .seconds(60)); throw ACEError(.relayUnavailable, "late") }
            func post(to aceId: String, content: PrivateContent, messageId: String, prekey: Prekey, retry: Bool) async throws {}
        }
        let stopped = Task { try await outbox.deliver(e.messageId, via: Slow()) }
        #expect(await settles { try! await outbox.entry(e.messageId)?.inFlightUntil != nil })
        stopped.cancel()
        await #expect(throws: CancellationError.self) { _ = try await stopped.value }
        let kept = try #require(try await outbox.entry(e.messageId))
        #expect(kept.attempts == 0 && kept.lastError == nil && kept.inFlightUntil == nil && kept.firstAttemptAt == nil && kept.nextAttemptAt == e.nextAttemptAt)

        let gate = Gate(peer.agent.descriptor.prekey)
        let posted = Task { try await outbox.deliver(e.messageId, via: gate) }
        #expect(await settles { gate.waiting })
        posted.cancel()
        gate.release()
        let done = try await posted.value
        #expect(done.attempts == 1 && done.lastPrekey == peer.agent.descriptor.prekey.id && done.lastError == nil)
    }

    /// A permanent attempt error ends the entry as `rejected` instead of retrying for the offline window.
    @Test func permanentAttemptErrorIsFinal() async throws {
        let me = try makeIdentity(now: NOW), peer = try TestAgent(now: NOW)
        let outbox = Outbox(identity: me, store: MemoryStore(), profiles: try InstalledProfiles([.text]), clock: { NOW })
        let e = try await outbox.enqueue(to: peer.aceId, type: "ace:text:1", body: ["message": "x"])
        struct Bad: PacketTransport {
            func prekey(for aceId: String, refresh: Bool) async throws -> Prekey { throw ACEError(.invalidArgument, "bad prekey") }
            func post(to aceId: String, content: PrivateContent, messageId: String, prekey: Prekey, retry: Bool) async throws {}
        }
        let done = try await outbox.deliver(e.messageId, via: Bad())
        #expect(done.status == .rejected && done.code == "invalid_argument" && done.settledAt == NOW)
    }

    /// A forged packet naming a newer delegation of an admitted sender: once its pin refresh is suppressed it is retried,
    /// and like any retry it counts, so it is quarantined after `MAX_FETCH_ATTEMPTS` fetches and later entries flow.
    @Test func suppressedPinRefreshCountsTowardQuarantine() async throws {
        let clock = TestClock(systemClock()), relay = FakeRelay(clock: clock.fn)
        let (alice, bob) = try await linked(relay, clock)
        func forged() async throws -> Data {
            let p = try Packet(json: try await textPacket(alice, to: bob, "forged", at: clock.now))
            return Packet(messageId: p.messageId, from: p.from, to: p.to, timestamp: p.timestamp, prekey: p.encryption.prekey,
                          kemCiphertext: p.kemCiphertext, payload: p.payload, signature: SignatureEnvelope(value: p.signature.value, seq: 99)).jsonData()
        }
        relay.inject(to: bob.aceId, try await forged())  // refreshes the pin (still behind): dropped
        relay.inject(to: bob.aceId, try await forged())  // its refresh is suppressed: retry
        _ = try await alice.network.send(to: bob.aceId, type: "ace:text:1", body: ["message": "after"])
        #expect(try await bob.network.pull() == [.dropped(.notPermitted), .retry(.relayUnavailable)])
        #expect(try await bob.network.pull() == [.retry(.relayUnavailable)])
        let third = try await bob.network.pull()
        #expect(third.first == .dropped(.relayUnavailable) && third.count == 2, "\(third)")
        guard case .delivered? = third.last else { Issue.record("later entry not delivered: \(third)"); return }
        #expect(relay.queued(bob.aceId).isEmpty)
        #expect(try bob.store.list(prefix: "inbox/quarantine/").count == 1 && bob.store.list(prefix: "inbox/attempts/").isEmpty)
    }

    /// `hold` (no host capacity) stops consuming without counting toward the quarantine.
    @Test func holdDoesNotCountTowardQuarantine() async throws {
        let clock = TestClock(systemClock()), relay = FakeRelay(clock: clock.fn)
        let (alice, bob) = try await linked(relay, clock, bob: NetworkConfiguration(contact: .open, listed: true, onMessage: { _ in
            throw ACEError(.receiverCapacity)
        }))
        _ = try await alice.network.send(to: bob.aceId, type: "ace:text:1", body: ["message": "m"])
        for _ in 0..<(ACELimits.maxFetchAttempts + 1) { #expect(try await bob.network.pull() == [.hold]) }
        #expect(try bob.store.list(prefix: "inbox/attempts/").isEmpty && bob.store.list(prefix: "inbox/quarantine/").isEmpty)
    }

    /// A repeated request to a peer already `pending` renews the pending lifetime (05 § Flow step 4).
    @Test func connectAgainRenewsThePendingTTL() async throws {
        let clock = TestClock(systemClock()), relay = FakeRelay(clock: clock.fn)
        let alice = try await NetPeer.make(relay, clock: clock)
        let bob = try await NetPeer.make(relay, clock: clock)
        try await alice.network.connect(bob.aceId, profile: "ace:text:1")
        clock.now += ACELimits.offlineWindowSeconds - 60
        _ = try await bob.network.publish()
        try await alice.network.connect(bob.aceId, profile: "ace:text:1")
        clock.now += 120
        #expect(try alice.network.admission.get(bob.aceId)?.state == .pending)
        clock.now += ACELimits.offlineWindowSeconds
        #expect(try alice.network.admission.get(bob.aceId) == nil)
        #expect(try alice.store.list(prefix: "admission/").isEmpty)  // an expired pending row is deleted on read
    }

    /// The expiry delete of a pending row re-reads it under lock `admission`: a block another process wrote after the
    /// expired row was read survives.
    @Test func expiredPendingDeleteNeverRemovesAConcurrentBlock() throws {
        let clock = TestClock(NOW), store = InterleavingStore()
        let table = AdmissionTable(store: store, clock: clock.fn)
        let peer = "ace:sha256:" + String(repeating: "a", count: 64)
        try table.update(peer) { _ in AdmissionRecord(aceId: peer, state: .pending, updatedAt: 0) }
        clock.now += ACELimits.offlineWindowSeconds  // the pending row has expired
        let blocked = AdmissionTable(store: store.base, clock: clock.fn)
        store.beforeAdmissionLock.value = { _ in
            _ = try? blocked.update(peer) { _ in AdmissionRecord(aceId: peer, state: .blocked, updatedAt: 0) }  // the other process
        }
        #expect(try table.get(peer)?.state == .blocked)
        #expect(try table.get(peer)?.state == .blocked)
    }

    /// A request held, then the peer blocked: an explicit accept is refused and the block stays.
    @Test func acceptAfterBlockIsRefused() async throws {
        let clock = TestClock(systemClock()), relay = FakeRelay(clock: clock.fn)
        let alice = try await NetPeer.make(relay, clock: clock)
        let bob = try await NetPeer.make(relay, clock: clock)
        try await alice.network.connect(bob.aceId, profile: "ace:text:1")
        _ = try await bob.network.pull()
        #expect(try await bob.network.requests().map(\.from) == [alice.aceId])
        try await bob.network.block(alice.aceId)
        await expectCodeAsync(.invalidArgument) { try await bob.network.accept(alice.aceId) }  // block() drops the held request
        // An old residual request beside a block is still refused; current putRequest cannot recreate one.
        let residual = ContactRequest(from: alice.aceId, profile: "ace:text:1", note: "",
                                      source: try await alice.network.publish().source,
                                      permit: try createPermit(identity: alice.identity, subject: bob.aceId, now: clock.now),
                                      receivedAt: clock.now)
        try bob.store.write("requests/\(sha256Hex(Data(residual.from.utf8))).json", try residual.jsonValue.jsonData())
        await expectCodeAsync(.notPermitted) { try await bob.network.accept(alice.aceId) }
        #expect(try bob.network.admission.get(alice.aceId)?.state == .blocked)
        #expect(relay.blocked(by: bob.aceId, alice.aceId) == true)
    }

    /// Settled entries stay for the offline window after they settled (controller ruling), then `prune` deletes them.
    @Test func pruneKeepsSettledEntriesForTheOfflineWindow() async throws {
        let clock = TestClock(NOW)
        let me = try makeIdentity(now: NOW), peer = try TestAgent(now: NOW)
        let outbox = Outbox(identity: me, store: MemoryStore(), profiles: try InstalledProfiles([.text]), clock: clock.fn)
        let e = try await outbox.enqueue(to: peer.aceId, type: "ace:text:1", body: ["message": "x"])
        clock.now += 10
        #expect(try await outbox.handleReceipt(from: peer.aceId, body: ["messageId": .string(e.messageId), "outcome": "delivered"])?.settledAt == NOW + 10)
        clock.now = NOW + 10 + ACELimits.offlineWindowSeconds - 1
        #expect(try await outbox.prune() == 0)
        clock.now += 1
        #expect(try await outbox.prune() == 1)
        #expect(try await outbox.entry(e.messageId) == nil)
    }

    /// The poison counter is persisted (`inbox/attempts/`) and removed on any final outcome.
    @Test func fetchAttemptsArePersistedAndClearedOnAFinalOutcome() async throws {
        let clock = TestClock(systemClock()), relay = FakeRelay(clock: clock.fn)
        let failing = LockedValue(true)
        let (alice, bob) = try await linked(relay, clock, bob: NetworkConfiguration(contact: .open, listed: true, onMessage: { _ in
            if failing.value { throw ACEError(.storageFailed, "host down") }
        }))
        _ = try await alice.network.send(to: bob.aceId, type: "ace:text:1", body: ["message": "m"])
        #expect(try await bob.network.pull() == [.retry(.storageFailed)])
        #expect(try bob.store.list(prefix: "inbox/attempts/").count == 1)
        failing.value = false
        #expect(try await bob.network.pull() == [.duplicate])  // the pending hand-over is finished
        #expect(try bob.store.list(prefix: "inbox/attempts/").isEmpty && bob.received.value.count == 1)
    }

    // MARK: A12: lookup by handle, onReceipt

    @Test func lookupByHandleAndOnReceipt() async throws {
        let clock = TestClock(systemClock()), relay = FakeRelay(clock: clock.fn)
        let receipts = LockedValue<[String]>([])
        let alice = try await NetPeer.make(relay, clock: clock, configuration: NetworkConfiguration(contact: .open, listed: true, onReceipt: { from, body, entry in
            receipts.value.append("\(body["outcome"]?.stringValue ?? "?"):\(entry?.status.rawValue ?? "none")")
        }))
        let bob = try await NetPeer.make(relay, clock: clock, configuration: NetworkConfiguration(handle: "bob", contact: .open, listed: true))
        let host = String(relay.url.dropFirst("https://".count))
        #expect(try await alice.network.lookup("@bob@\(host)").aceId == bob.aceId)
        try await alice.network.connect("@bob@\(host)", profile: "ace:text:1")
        _ = try await bob.network.pull()
        try await bob.network.accept(alice.aceId)
        _ = try await alice.network.pull()
        _ = try await alice.network.send(to: bob.aceId, type: "ace:text:1", body: ["message": "hello"])
        _ = try await bob.network.pull()
        _ = try await alice.network.pull()
        #expect(receipts.value == ["delivered:delivered"])
    }

    // MARK: Final review wave (F2, F3, F5, F6, F10, F13)

    /// Every upkeep step runs even when an earlier one fails (an unreachable home relay must not stop Outbox retries);
    /// the first failure is thrown at the end.
    @Test func maintainRunsEveryStepAndThrowsTheFirstFailure() async throws {
        let clock = TestClock(systemClock()), relay = FakeRelay(clock: clock.fn)
        let (alice, bob) = try await linked(relay, clock)
        relay.withLock { relay.failSend = (503, "internal_error") }
        let sent = try await alice.network.send(to: bob.aceId, type: "ace:text:1", body: ["message": "hi"])
        #expect(sent.status == .pending && sent.attempts == 1)
        clock.now += 86_400  // the prekey is due: publish must post
        try await bob.network.publish()
        relay.withLock { relay.down = ["/v1/descriptor"] }
        await expectCodeAsync(.relayUnavailable) { try await alice.network.maintain() }
        #expect(try await alice.network.outbox.entry(sent.messageId)?.attempts == 2)  // the flush still ran
        relay.withLock { relay.down = [] }
        let out = try await bob.network.pull()
        guard case .delivered? = out.first else { Issue.record("not delivered: \(out)"); return }
    }

    /// 06 § Outbox: without a permit from the peer valid under its current pin, `send` fails with `not_permitted` and
    /// stores nothing (a doomed retry would only spend the stranger allowance).
    @Test func sendWithoutAPermitFromThePeerIsNotPermittedAndStoresNothing() async throws {
        let clock = TestClock(systemClock()), relay = FakeRelay(clock: clock.fn)
        let alice = try await NetPeer.make(relay, clock: clock), bob = try await NetPeer.make(relay, clock: clock)
        try await alice.network.connect(bob.aceId, profile: "ace:text:1")  // pending: bob issued alice nothing yet
        await expectCodeAsync(.notPermitted) {
            try await alice.network.send(to: bob.aceId, type: "ace:text:1", body: ["message": "early"])
        }
        #expect(try await alice.network.outbox.entries().isEmpty)
        _ = try await bob.network.pull()
        try await bob.network.accept(alice.aceId)
        _ = try await alice.network.pull()
        #expect(try await alice.network.send(to: bob.aceId, type: "ace:text:1", body: ["message": "now"]).status == .pending)
    }

    /// 06 § Error codes: a host failure is `storage_failed`, the quarantine reports the failure that ended it, and a held
    /// `receive` lock is `lock_busy`.
    @Test func hostFailuresUseSpecCodes() async throws {
        struct HostBug: Error {}
        let clock = TestClock(systemClock()), relay = FakeRelay(clock: clock.fn)
        let (alice, bob) = try await linked(relay, clock, bob: NetworkConfiguration(contact: .open, listed: true, onMessage: { _ in throw HostBug() }))
        _ = try await alice.network.send(to: bob.aceId, type: "ace:text:1", body: ["message": "m"])
        #expect(try await bob.network.pull() == [.retry(.storageFailed)])
        #expect(try await bob.network.pull() == [.retry(.storageFailed)])
        #expect(try await bob.network.pull() == [.dropped(.storageFailed)])
        let store = MemoryStore()
        let held = try store.lock("receive", timeout: 0)
        defer { held.release() }
        expectCode(.lockBusy) { try store.lock("receive", timeout: 0) }
    }

    /// `limit_exceeded` cannot arise from the transport as a local refusal: it never ends the message.
    @Test func aTransportLimitExceededIsNotFinal() async throws {
        let me = try makeIdentity(now: NOW), peer = try TestAgent(now: NOW)
        let outbox = Outbox(identity: me, store: MemoryStore(), profiles: try InstalledProfiles([.text]), clock: { NOW })
        let e = try await outbox.enqueue(to: peer.aceId, type: "ace:text:1", body: ["message": "x"])
        struct Capped: PacketTransport {
            func prekey(for aceId: String, refresh: Bool) async throws -> Prekey { throw ACEError(.limitExceeded, "relay cap") }
            func post(to aceId: String, content: PrivateContent, messageId: String, prekey: Prekey, retry: Bool) async throws {}
        }
        let done = try await outbox.deliver(e.messageId, via: Capped())
        #expect(done.status == .pending && done.lastError?.contains("limit_exceeded") == true, "\(done)")
    }

    /// A receipt-carried permit is held for any non-blocked record (here `pending`), as in sdk-ts and sdk-py.
    @Test func aReceiptPermitIsHeldForAPendingPeer() async throws {
        let clock = TestClock(systemClock()), relay = FakeRelay(clock: clock.fn)
        let (alice, bob) = try await linked(relay, clock)
        _ = try alice.network.admission.update(bob.aceId) { r in r.map { var r = $0; r.state = .pending; return r } }
        clock.now += 10
        let permit = try createPermit(identity: bob.identity, subject: alice.aceId, now: clock.now)
        let body: [String: JSONValue] = ["messageId": .string(UUID().uuidString.lowercased()), "outcome": "delivered", "permit": permit]
        let agent = try #require(try await bob.network.peers.agent(alice.aceId))
        let c = try bob.network.profiles.content(type: CoreTypes.receipt, body: body).with(prekey: somePrekey())
        relay.inject(to: alice.aceId, try createPacket(sender: bob.identity, to: alice.aceId, prekey: agent.descriptor.prekey, content: c,
                                                       timestamp: clock.now).jsonData())
        _ = try await alice.network.pull()
        #expect(try alice.network.admission.heldPermit(bob.aceId) == permit)
    }

    /// The client advertises only its home relay (the multi-relay option is gone; 04 still allows 1–4 routes).
    @Test func theClientAdvertisesOnlyItsHomeRelay() async throws {
        let clock = TestClock(systemClock()), relay = FakeRelay(clock: clock.fn)
        let alice = try await NetPeer.make(relay, clock: clock)
        #expect(try await alice.network.publish(force: true).descriptor.relays == [relay.url])
    }
}
