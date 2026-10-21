import Foundation
import Testing
@testable import ACE

private let translation = try! ProfileManifest(json: Data(#"{"id":"urn:example:translation:1","messages":[{"type":"urn:example:translation:request:1","schema":{"type":"object","properties":{"text":{"type":"string","maxLength":100}},"required":["text"],"additionalProperties":false}}]}"#.utf8))

/// Alice connects to Bob (public) about `ace:text:1`; Bob accepts explicitly; both pulls done.
private func connected(_ relay: FakeRelay, _ clock: TestClock, alice aliceConfig: NetworkConfiguration = NetworkConfiguration(contact: .open, listed: true),
                       bob bobConfig: NetworkConfiguration = NetworkConfiguration(contact: .open, listed: true)) async throws -> (NetPeer, NetPeer) {
    let alice = try await NetPeer.make(relay, clock: clock, configuration: aliceConfig)
    let bob = try await NetPeer.make(relay, clock: clock, configuration: bobConfig)
    try await alice.network.connect(bob.aceId, profile: "ace:text:1", note: "hello")
    _ = try await bob.network.pull()
    if try bob.network.admission.get(alice.aceId) == nil { try await bob.network.accept(alice.aceId) }
    _ = try await alice.network.pull()
    return (alice, bob)
}

@Suite struct NetworkTests {
    @Test func contactFlowTextAndReceipts() async throws {
        let clock = TestClock(systemClock()), relay = FakeRelay(clock: clock.fn)
        let alice = try await NetPeer.make(relay, clock: clock)
        let bob = try await NetPeer.make(relay, clock: clock)
        try await alice.network.connect(bob.aceId, profile: "ace:text:1", note: "hi Bob")
        #expect(try alice.network.admission.get(bob.aceId)?.state == .pending)
        let outcomes = try await bob.network.pull()
        guard case .delivered(let contact)? = outcomes.first else { Issue.record("contact not delivered: \(outcomes)"); return }
        #expect(contact.type == CoreTypes.contact)
        // a request changes no admission state by itself and pins nothing
        let pinnedAlice = try await bob.network.peers.pinned(alice.aceId)
        #expect(try bob.network.admission.get(alice.aceId) == nil)
        #expect(pinnedAlice == nil)
        let invitations = try await bob.network.requests()
        #expect(invitations.map(\.from) == [alice.aceId] && invitations.first?.note == "hi Bob")
        #expect(relay.queued(bob.aceId).isEmpty)  // acknowledged

        try await bob.network.accept(alice.aceId)
        #expect(try bob.network.admission.get(alice.aceId)?.state == .admitted)
        _ = try await alice.network.pull()
        let rec = try #require(try alice.network.admission.get(bob.aceId))
        let held = try alice.network.admission.heldPermit(bob.aceId)
        #expect(rec.state == .admitted && held?["issuer"]?.stringValue == bob.aceId)

        let entry = try await alice.network.send(to: bob.aceId, type: "ace:text:1", body: ["message": "hello"])
        #expect(entry.status == .pending && entry.attempts == 1)
        let got = try await bob.network.pull()
        guard case .delivered(let m)? = got.first else { Issue.record("not delivered: \(got)"); return }
        #expect(m.body["message"] == "hello" && bob.received.value.count == 1)
        _ = try await alice.network.pull()  // the receipt
        #expect(try await alice.network.outbox.entry(entry.messageId)?.status == .delivered)
        // receipts are not receipted
        #expect(relay.queued(bob.aceId).isEmpty && relay.queued(alice.aceId).isEmpty)
    }

    /// `maxPages` bounds one pass (a notification extension's budget): the rest stays queued, unacknowledged.
    @Test func pullStopsAtMaxPages() async throws {
        let clock = TestClock(systemClock()), relay = FakeRelay(clock: clock.fn)
        let (alice, bob) = try await connected(relay, clock)
        for i in 0..<3 { _ = try await alice.network.send(to: bob.aceId, type: "ace:text:1", body: ["message": .string("m\(i)")]) }
        let first = try await bob.network.pull(limit: 1, maxPages: 2)
        #expect(first.count == 2 && relay.queued(bob.aceId).count == 1)
        let rest = try await bob.network.pull()
        #expect(rest.count == 1 && relay.queued(bob.aceId).isEmpty && bob.received.value.count == 3)
        await expectCodeAsync(.invalidArgument) { try await bob.network.pull(maxPages: 0) }
    }

    @Test func acceptProfilesAutoAccepts() async throws {
        let clock = TestClock(systemClock()), relay = FakeRelay(clock: clock.fn)
        let alice = try await NetPeer.make(relay, clock: clock)
        let bob = try await NetPeer.make(relay, clock: clock, configuration: NetworkConfiguration(acceptProfiles: ["ace:text:1"], contact: .open, listed: true))
        try await alice.network.connect(bob.aceId, profile: "ace:text:1")
        _ = try await bob.network.pull()
        let held = try await bob.network.requests()
        #expect(try bob.network.admission.get(alice.aceId)?.state == .admitted)
        #expect(held.isEmpty)
        _ = try await alice.network.pull()
        #expect(try alice.network.admission.get(bob.aceId)?.state == .admitted)
    }

    /// Admission runs before any lookup: a stranger's packet to a private agent is dropped with no network call and no pin.
    @Test func admissionBeforeLookup() async throws {
        let clock = TestClock(systemClock()), relay = FakeRelay(clock: clock.fn)
        let carol = try await NetPeer.make(relay, clock: clock, configuration: NetworkConfiguration())
        let mallory = try TestAgent(now: clock.now)
        let carolAgent = try await carol.network.publish()
        let content = try carol.network.profiles.content(type: "ace:text:1", body: ["message": "spam"])
        let packet = try createPacket(sender: mallory.identity, to: carol.aceId, prekey: carolAgent.descriptor.prekey, content: content, timestamp: clock.now)
        let before = relay.requestCount
        #expect(await carol.network.inbox!.receive(packet.jsonData()) == .dropped(.notPermitted))
        let carolPin = try await carol.network.peers.pinned(mallory.aceId)
        #expect(relay.requestCount == before && carolPin == nil)
        // a public agent drops a stranger's non-contact packet the same way (after decrypting it as a contact candidate)
        let dave = try await NetPeer.make(relay, clock: clock)
        let daveAgent = try await dave.network.publish()
        let p2 = try createPacket(sender: mallory.identity, to: dave.aceId, prekey: daveAgent.descriptor.prekey, content: content, timestamp: clock.now)
        let before2 = relay.requestCount
        #expect(await dave.network.inbox!.receive(p2.jsonData()) == .dropped(.notPermitted))
        let davePin = try await dave.network.peers.pinned(mallory.aceId)
        #expect(relay.requestCount == before2 && davePin == nil && dave.received.value.isEmpty)
    }

    @Test func unknownSchemaIsRejectedWithAReceipt() async throws {
        let clock = TestClock(systemClock()), relay = FakeRelay(clock: clock.fn)
        let (alice, bob) = try await connected(relay, clock, alice: NetworkConfiguration(profiles: [.text, translation], contact: .open, listed: true))
        let entry = try await alice.network.send(to: bob.aceId, type: "urn:example:translation:request:1", body: ["text": "bonjour"])
        #expect(try await bob.network.pull() == [.rejected("unsupported_schema")])
        #expect(bob.received.value.isEmpty)
        _ = try await alice.network.pull()
        let e = try #require(try await alice.network.outbox.entry(entry.messageId))
        #expect(e.status == .rejected && e.code == "unsupported_schema")
    }

    @Test func unknownPrekeyRefreshesAndRetries() async throws {
        let clock = TestClock(systemClock()), relay = FakeRelay(clock: clock.fn)
        let (alice, bob) = try await connected(relay, clock)
        let old = try #require(try bob.network.prekeys.current()).prekey
        try bob.network.prekeys.rotate(now: clock.now)
        _ = try await bob.network.publish(force: true)
        try bob.network.prekeys.prune(now: clock.now + ACELimits.offlineWindowSeconds)  // the old seed is gone
        #expect(try bob.network.prekeys.open(old.id, now: clock.now) == nil)
        let entry = try await alice.network.send(to: bob.aceId, type: "ace:text:1", body: ["message": "to the old prekey"])
        #expect(entry.lastPrekey == old.id)
        #expect(try await bob.network.pull() == [.rejected("unknown_prekey")])
        _ = try await alice.network.pull()
        let pending = try #require(try await alice.network.outbox.entry(entry.messageId))
        #expect(pending.status == .pending && pending.refreshPrekey)
        let retried = try await alice.network.flush()
        #expect(retried.first?.lastPrekey != old.id)
        guard case .delivered? = try await bob.network.pull().first else { Issue.record("retry not delivered"); return }
        _ = try await alice.network.pull()
        #expect(try await alice.network.outbox.entry(entry.messageId)?.status == .delivered)
    }

    @Test func attemptRetriesAPendingMessageNow() async throws {
        let clock = TestClock(systemClock()), relay = FakeRelay(clock: clock.fn)
        let (alice, bob) = try await connected(relay, clock)
        let entry = try await alice.network.send(to: bob.aceId, type: "ace:text:1", body: ["message": "hi"])
        let again = try #require(try await alice.network.attempt(entry.messageId))  // pending (no receipt yet), not due: attempted now
        #expect(again.status == .pending && again.attempts == entry.attempts + 1)
        #expect(try await alice.network.attempt(UUID().uuidString.lowercased()) == nil)
        try await alice.network.outbox.abandon(entry.messageId)
        let final = try #require(try await alice.network.attempt(entry.messageId))
        #expect(final.status == .expired && final.attempts == again.attempts)  // final: as is
    }

    @Test func duplicatesAreReceiptedAndBeyondTheHorizonIsDropped() async throws {
        let clock = TestClock(systemClock()), relay = FakeRelay(clock: clock.fn)
        let (alice, bob) = try await connected(relay, clock)
        await bob.network.close()
        let small = try await Inbox.open(network: bob.network, onMessage: { _ in }, capacity: 16, clock: clock.fn)  // quota 1 per sender
        let bobAgent = try #require(try await alice.network.peers.agent(bob.aceId))
        func packet(_ ts: Int, id: String = UUID().uuidString.lowercased()) throws -> Data {
            let c = try alice.network.profiles.content(type: "ace:text:1", body: ["message": .string("m\(ts)")])
            return try createPacket(sender: alice.identity, to: bob.aceId, prekey: bobAgent.descriptor.prekey, content: c, messageId: id, timestamp: ts).jsonData()
        }
        let first = UUID().uuidString.lowercased()
        guard case .delivered = await small.receive(try packet(clock.now + 1, id: first)) else { Issue.record("first"); return }
        let dup = await small.receive(try packet(clock.now + 2, id: first))
        #expect(dup == .duplicate, "\(dup)")  // a retry: re-signed, same messageId
        guard case .delivered = await small.receive(try packet(clock.now + 3)) else { Issue.record("second"); return }  // evicts the first
        #expect(await small.receive(try packet(clock.now + 1)) == .dropped(.replayHorizon))  // 06 step 9: no receipt
        #expect(relay.queued(alice.aceId).count == 3)  // delivered, delivered (duplicate), delivered
        await small.close()
    }

    @Test func receiptsRenewPermits() async throws {
        let clock = TestClock(systemClock()), relay = FakeRelay(clock: clock.fn)
        let (alice, bob) = try await connected(relay, clock)
        let before = try #require(try alice.network.admission.heldPermit(bob.aceId))
        clock.now += 16 * 86_400  // under 15 days left on Bob's permit
        _ = try await bob.network.publish()
        _ = try await alice.network.publish()
        _ = try await alice.network.send(to: bob.aceId, type: "ace:text:1", body: ["message": "later"])
        guard case .delivered? = try await bob.network.pull().first else { Issue.record("not delivered"); return }
        _ = try await alice.network.pull()
        let after = try #require(try alice.network.admission.heldPermit(bob.aceId))
        #expect(after["issuedAt"] != before["issuedAt"] && (after["expiresAt"]?.wireInt ?? 0) == clock.now + ACELimits.maxPermitSeconds)
    }

    @Test func blockStopsDelivery() async throws {
        let clock = TestClock(systemClock()), relay = FakeRelay(clock: clock.fn)
        let (alice, bob) = try await connected(relay, clock)
        try await bob.network.block(alice.aceId)
        let entry = try await alice.network.send(to: bob.aceId, type: "ace:text:1", body: ["message": "blocked?"])
        #expect(entry.lastError?.contains("not_permitted") == true && relay.queued(bob.aceId).isEmpty)
        let agent = try #require(try await alice.network.peers.agent(bob.aceId))
        let c = try alice.network.profiles.content(type: "ace:text:1", body: ["message": "direct"])
        let p = try createPacket(sender: alice.identity, to: bob.aceId, prekey: agent.descriptor.prekey, content: c, timestamp: clock.now)
        #expect(await bob.network.inbox!.receive(p.jsonData()) == .dropped(.notPermitted))
        // the relay refuses the blocked sender's contact request too
        await expectCodeAsync(.notPermitted) { try await alice.network.connect(agent.aceId, profile: "ace:text:1") }
        #expect(relay.queued(bob.aceId).isEmpty)
    }
}

/// A transport whose `post` suspends until released, counting posts.
private final class GateTransport: PacketTransport, @unchecked Sendable {
    let prekeyValue: Prekey
    let posts = LockedValue(0)
    let started = LockedValue(false)
    private let lock = NSLock()
    private var continuation: CheckedContinuation<Void, Never>?

    init(_ prekey: Prekey) { prekeyValue = prekey }

    func prekey(for aceId: String, refresh: Bool) async throws -> Prekey { prekeyValue }

    func post(to aceId: String, content: PrivateContent, messageId: String, prekey: Prekey) async throws {
        posts.value += 1
        await withCheckedContinuation { c in
            lock.withLock { continuation = c }
            started.value = true
        }
    }

    func release() { lock.withLock { continuation?.resume(); continuation = nil } }
}

@Suite struct OutboxTests {
    @Test func concurrentDeliverSendsOnce() async throws {
        let me = try makeIdentity(now: systemClock()), peer = try TestAgent(now: systemClock())
        let outbox = Outbox(identity: me, store: MemoryStore(), profiles: try InstalledProfiles([.text]))
        let e = try await outbox.enqueue(to: peer.aceId, type: "ace:text:1", body: ["message": "once"])
        let transport = GateTransport(peer.agent.descriptor.prekey)
        let first = Task { try await outbox.deliver(e.messageId, via: transport) }
        let deadline = ContinuousClock.now + .seconds(hangGuardSeconds)
        while !transport.started.value && ContinuousClock.now < deadline { try await Task.sleep(for: .milliseconds(5)) }
        let second = try await outbox.deliver(e.messageId, via: transport)  // in flight: returns without sending
        #expect(second.attempts == 0 && transport.posts.value == 1)
        transport.release()
        let done = try await first.value
        #expect(done.attempts == 1 && transport.posts.value == 1 && done.nextAttemptAt - (done.firstAttemptAt ?? 0) >= 60)
        // a receipt ends it; a receipt from someone else is ignored
        #expect(try await outbox.handleReceipt(from: me.getACEId(), body: ["messageId": .string(e.messageId), "outcome": "delivered"]) == nil)
        #expect(try await outbox.handleReceipt(from: peer.aceId, body: ["messageId": .string(e.messageId), "outcome": "delivered"])?.status == .delivered)
        let again = try await outbox.deliver(e.messageId, via: transport)
        #expect(again.status == .delivered && transport.posts.value == 1)
    }

    @Test func backoffAndExpiry() async throws {
        #expect([1, 2, 3, 6, 7, 20].map { Outbox.backoff(afterAttempt: $0) } == [60, 120, 240, 1920, 3600, 3600])
        let clock = TestClock(NOW)
        let me = try makeIdentity(now: NOW), peer = try TestAgent(now: NOW)
        let outbox = Outbox(identity: me, store: MemoryStore(), profiles: try InstalledProfiles([.text]), clock: clock.fn)
        let e = try await outbox.enqueue(to: peer.aceId, type: "ace:text:1", body: ["message": "x"])
        struct Down: PacketTransport {
            func prekey(for aceId: String, refresh: Bool) async throws -> Prekey { throw ACEError(.relayUnavailable) }
            func post(to aceId: String, content: PrivateContent, messageId: String, prekey: Prekey) async throws {}
        }
        #expect(try await outbox.deliver(e.messageId, via: Down()).nextAttemptAt == NOW + 60)
        #expect(try await outbox.flush(via: Down()).isEmpty)  // not due yet
        clock.now += ACELimits.offlineWindowSeconds + 1
        #expect(try await outbox.flush(via: Down()).first?.status == .expired)
        await expectCodeAsync(.invalidArgument) { try await outbox.enqueue(to: peer.aceId, type: CoreTypes.receipt, body: [:]) }
        await expectCodeAsync(.unsupportedSchema) { try await outbox.enqueue(to: peer.aceId, type: "urn:x:y:1", body: [:]) }
    }

    @Test func commerceRulesRunOnSend() async throws {
        let me = try makeIdentity(now: NOW), peer = try TestAgent(now: NOW)
        let store = MemoryStore()
        let outbox = Outbox(identity: me, store: store, profiles: try InstalledProfiles([.commerce]),
                            rules: [commerceRules(store: store, localAceId: me.getACEId())], clock: { NOW })
        await expectCodeAsync(.invalidBody) { try await outbox.enqueue(to: peer.aceId, type: CommerceType.rfq, body: ["need": "x"]) }  // no threadId
        let rfq = try await outbox.enqueue(to: peer.aceId, type: CommerceType.rfq, body: ["need": "x"], threadId: "deal")
        let threads = ThreadStore(store: store)
        // the sender's state advances on the `delivered` receipt, not at enqueue; the thread is busy until then
        #expect(try threads.thread(between: me.getACEId(), and: peer.aceId, threadId: "deal") == nil)
        await expectCodeAsync(.threadBusy) {
            try await outbox.enqueue(to: peer.aceId, type: CommerceType.offer, body: ["price": "1", "currency": "USDC"], threadId: "deal")
        }
        _ = try await outbox.enqueue(to: peer.aceId, type: CommerceType.rfq, body: ["need": "y"], threadId: "other")  // other threads are free
        try await outbox.handleReceipt(from: peer.aceId, body: ["messageId": .string(rfq.messageId), "outcome": "delivered"])
        #expect(try threads.thread(between: me.getACEId(), and: peer.aceId, threadId: "deal")?.state == .requested)
        await expectCodeAsync(.wrongRole) {
            try await outbox.enqueue(to: peer.aceId, type: CommerceType.offer, body: ["price": "1", "currency": "USDC"], threadId: "deal")
        }
        // a `rejected` receipt leaves the state unchanged and frees the thread
        let second = try #require(try await outbox.entries().first { $0.content.threadId == "other" })
        try await outbox.handleReceipt(from: peer.aceId, body: ["messageId": .string(second.messageId), "outcome": "rejected", "code": "busy"])
        #expect(try threads.thread(between: me.getACEId(), and: peer.aceId, threadId: "other") == nil)
        _ = try await outbox.enqueue(to: peer.aceId, type: CommerceType.rfq, body: ["need": "z"], threadId: "other")
    }

    /// M1: `connect` never lifts a block (a prompt-injected caller cannot re-admit a blocked peer); only `unblock` does.
    @Test func connectNeverClearsABlockOnlyUnblockDoes() async throws {
        let clock = TestClock(systemClock()), relay = FakeRelay(clock: clock.fn)
        let (alice, bob) = try await connected(relay, clock)
        try await alice.network.block(bob.aceId)
        let target = try await alice.network.agent(bob.aceId)
        await expectCodeAsync(.notPermitted) { try await alice.network.connect(target.aceId, profile: "ace:text:1") }
        #expect(try alice.network.admission.get(bob.aceId)?.state == .blocked)
        try await alice.network.unblock(bob.aceId)
        #expect(try alice.network.admission.get(bob.aceId) == nil)
        try await alice.network.connect(target.aceId, profile: "ace:text:1")
        #expect(try alice.network.admission.get(bob.aceId)?.state == .pending)
    }

    /// M3: one held request per sender (replaced), a TTL, and the oldest evicted when full.
    @Test func pendingRequestsOneSlotPerSenderTTLAndOldestEvicted() throws {
        let t0 = 1_800_000_000
        let clock = TestClock(t0)
        let table = AdmissionTable(store: MemoryStore(), clock: clock.fn)
        func put(_ i: Int, at t: Int, note: String = "") throws {
            try table.putRequest(ContactRequest(from: "ace:sha256:" + String(format: "%064x", i), profile: "ace:text:1",
                                                note: note, source: ["kel": []], permit: ["issuer": "x"], receivedAt: t))
        }
        let n = ACELimits.maxPendingContactRequests
        for i in 1...n { try put(i, at: t0 + i) }
        try put(1, at: t0 + n + 1, note: "again")  // replaced, now the newest
        clock.now = t0 + n + 1
        #expect(try table.requests().count == n)
        try put(n + 1, at: t0 + n + 2)  // full: the oldest (sender 2) is evicted
        clock.now = t0 + n + 2
        let held = try table.requests()
        #expect(held.count == n && !held.contains { $0.from.hasSuffix("02") } && held[n - 2].note == "again")
        let ttl = ACELimits.contactRequestTTLSeconds
        clock.now = t0 + 4 + ttl
        #expect(try table.requests().count < n)  // the oldest have expired
        clock.now = t0 + n + 2 + ttl
        #expect(try table.request(held.last!.from) == nil)
        #expect(try table.requests().isEmpty)
    }

    /// (b) After a signing-key change a private agent re-sends a request with a fresh permit to admitted peers, which
    /// accept it automatically (through the contact-candidate path, since its old permits no longer resolve it).
    @Test func signingKeyChangePushesFreshPermits() async throws {
        let clock = TestClock(systemClock()), relay = FakeRelay(clock: clock.fn)
        let (alice, bob) = try await connected(relay, clock, alice: NetworkConfiguration())
        let before = try #require(try bob.network.admission.heldPermit(alice.aceId)?["signature"]?["seq"]?.wireInt)
        try alice.identity.delegate(now: clock.now, notAfter: nil)
        try await alice.network.maintain()
        _ = try await bob.network.pull()
        let after = try #require(try bob.network.admission.heldPermit(alice.aceId)?["signature"]?["seq"]?.wireInt)
        #expect(after == (try alice.identity.getSigningSeq()) && after != before)
        _ = try await alice.network.pull()  // bob's `accepted` only refreshes alice's held permit
        #expect(try alice.network.admission.get(bob.aceId)?.state == .admitted)
        let e = try await bob.network.send(to: alice.aceId, type: "ace:text:1", body: ["message": "still reachable"])
        guard case .delivered? = try await alice.network.pull().first else { Issue.record("not delivered"); return }
        _ = try await bob.network.pull()
        #expect(try await bob.network.outbox.entry(e.messageId)?.status == .delivered)
        #expect(try await alice.network.refreshPermits().isEmpty)  // once per delegation
    }

    /// M2: a delegation entry carrying an older issuer KEL, signed by a delegation the pin superseded, is invalid.
    @Test func delegationIssuerIsReconciledWithItsPin() async throws {
        let now = systemClock()
        let alice = try TestAgent(now: now - 10), dave = try makeIdentity(now: now - 10)
        let stale = try createDelegation(issuer: dave, subject: alice.aceId, now: now - 5)
        try dave.delegate(now: now - 4, notAfter: nil)
        let claims = DescriptorClaims(relays: ["https://relay.example"], prekey: alice.agent.descriptor.prekey, delegations: [stale])
        let src = try createPublishedAgent(identity: alice.identity, claims: claims, now: now - 3)
        #expect(src.descriptor.delegations.map(\.issuer) == [dave.getACEId()])  // standalone: passes
        let peers = PeerStore(store: MemoryStore())
        try await peers.pin(kel: try dave.getKel())
        await expectCodeAsync(.invalidAuthorization) { try await peers.adopt(source: src.source) }
        var fresh = claims
        fresh.delegations = [try createDelegation(issuer: dave, subject: alice.aceId, now: now - 2)]
        let ok = try createPublishedAgent(identity: alice.identity, claims: fresh, now: now - 1)
        #expect(try await peers.adopt(source: ok.source).descriptor.delegations.map(\.issuer) == [dave.getACEId()])
    }

    /// Bob, on `relay`, reaching any other relay as `relayB`.
    private func routedPeer(_ relay: FakeRelay, _ relayB: FakeRelay, _ clock: TestClock) async throws -> NetworkClient {
        let store = MemoryStore()
        return try await NetworkClient.open(identity: try makeIdentity(now: clock.now), store: store, relay: try relay.client(clock: clock.fn),
                                            prekeys: StorePrekeyVault(store: store), receive: false,
                                            foreignRelay: { _ in try relayB.client(clock: clock.fn) }, clock: clock.fn)
    }

    /// Every route is tried: one replaying an older descriptor (`stale_peer_binding`, a permanent code) never blocks a
    /// lookup the next route serves.
    @Test func aRouteReplayingAnOlderDescriptorDoesNotBlockTheNext() async throws {
        let clock = TestClock(systemClock()), relay = FakeRelay(clock: clock.fn), relayB = FakeRelay(clock: clock.fn)
        let alice = try await NetPeer.make(relay, clock: clock)
        let prekey = try #require(relay.publishedAgent(alice.aceId)).descriptor.prekey
        func descriptor(_ relays: [String], lifetime: Int = ACELimits.defaultDescriptorSeconds) throws -> VerifiedAgent {
            clock.now += 1
            return try createPublishedAgent(identity: alice.identity, claims: DescriptorClaims(
                relays: relays, prekey: prekey, profiles: [ProfileManifest.text.ref]), now: clock.now, lifetime: lifetime)
        }
        // Relay B keeps serving an older revision; the home relay serves the newest.
        let old = try descriptor([relayB.url, relay.url])
        try await relayB.client(clock: clock.fn).register(alice.identity)
        try await relayB.client(clock: clock.fn).publish(old)
        let held = try descriptor([relayB.url, relay.url], lifetime: 60)
        let newest = try descriptor([relay.url])
        try await relay.client(clock: clock.fn).publish(newest)
        let bob = try await routedPeer(relay, relayB, clock)
        try await bob.importAgent(held.source)
        clock.now += 120  // the held one expired: refreshed from its routes, relay B first
        #expect(try await bob.lookup(alice.aceId).source == newest.source)
        await bob.close()
    }

    /// A cached descriptor no longer bound to the current pins (here a delegation issuer's pin advanced past the key that
    /// signed its entry) is refreshed from its relays and the home relay; a bound one from its relays alone.
    @Test func aStaleCachedDescriptorIsRefreshedFromItsRelaysAndTheHomeRelay() async throws {
        let clock = TestClock(systemClock()), relay = FakeRelay(clock: clock.fn), relayB = FakeRelay(clock: clock.fn)
        let alice = try await NetPeer.make(relay, clock: clock)  // the home relay holds an older revision only
        let dave = try makeIdentity(now: clock.now)
        let prekey = try #require(relay.publishedAgent(alice.aceId)).descriptor.prekey
        clock.now += 1
        let delegated = try createPublishedAgent(identity: alice.identity, claims: DescriptorClaims(
            relays: [relayB.url], prekey: prekey, profiles: [ProfileManifest.text.ref],
            delegations: [try createDelegation(issuer: dave, subject: alice.aceId, now: clock.now)]), now: clock.now)
        let bob = try await routedPeer(relay, relayB, clock)
        try await bob.peers.pin(kel: try dave.getKel())
        try await bob.importAgent(delegated.source)
        clock.now += 1
        try dave.delegate(now: clock.now, notAfter: nil)
        try await bob.peers.pin(kel: try dave.getKel())
        #expect(try await bob.peers.agent(alice.aceId) == nil)  // stale
        clock.now += 1
        let current = try createPublishedAgent(identity: alice.identity, claims: DescriptorClaims(
            relays: [relayB.url], prekey: prekey, profiles: [ProfileManifest.text.ref]), now: clock.now)
        try await relayB.client(clock: clock.fn).register(alice.identity)
        try await relayB.client(clock: clock.fn).publish(current)
        let homeAsked = relay.requestCount
        #expect(try await bob.agent(alice.aceId).source == current.source)  // relay B, the cached route, first
        // Bound now: a refresh asks its relays alone, never the home relay.
        #expect(try await bob.agent(alice.aceId, refresh: true).source == current.source)
        #expect(relay.withLock { relay.requests[homeAsked...].filter { $0.hasPrefix("GET /v1/descriptor/") } }.isEmpty)
        relayB.withLock { relayB.down = ["/v1/descriptor/\(alice.aceId)"] }
        await expectCodeAsync(.relayUnavailable) { try await bob.agent(alice.aceId, refresh: true) }
        #expect(relay.withLock { relay.requests[homeAsked...].filter { $0.hasPrefix("GET /v1/descriptor/") } }.isEmpty)
        await bob.close()
    }

    /// The pin advancing past a cached descriptor's KEL (a new `dlg`, a rotation) unbinds it: it is never used again (not
    /// returned, its prekey never encrypted to), and the refresh asks its relays, then the home relay; the new descriptor
    /// replaces it only once it verifies under the current pin.
    @Test(arguments: ["dlg", "rotation"])
    func aPinAdvancedPastTheCachedDescriptorRefreshesFromItsRelaysAndTheHomeRelay(_ advance: String) async throws {
        let clock = TestClock(systemClock()), relay = FakeRelay(clock: clock.fn), relayB = FakeRelay(clock: clock.fn)
        let alice = try await NetPeer.make(relay, clock: clock)  // the home relay holds a descriptor under the old KEL only
        let prekey = try #require(relay.publishedAgent(alice.aceId)).descriptor.prekey
        clock.now += 1
        let cached = try createPublishedAgent(identity: alice.identity, claims: DescriptorClaims(
            relays: [relayB.url], prekey: prekey, profiles: [ProfileManifest.text.ref]), now: clock.now)
        let bob = try await routedPeer(relay, relayB, clock)
        try await bob.importAgent(cached.source)
        clock.now += 1
        if advance == "dlg" { try alice.identity.delegate(now: clock.now, notAfter: nil) } else { try rotate(alice.identity, now: clock.now) }
        try await bob.peers.pin(kel: try alice.identity.getKel())
        // Unbound: never returned, its prekey never used, even unexpired.
        #expect(try await bob.peers.agent(alice.aceId) == nil)
        #expect(try await bob.peers.usableAgent(alice.aceId) == nil)
        #expect(try await bob.peers.heldRelays(alice.aceId) == [relayB.url])
        await expectCodeAsync(.stalePeerBinding) { try await bob.prekey(for: alice.aceId, refresh: false) }  // relay B has none: home's is stale
        // Kept across reopening.
        let reopened = PeerStore(store: bob.store, clock: clock.fn)
        #expect(try await reopened.heldRelays(alice.aceId) == [relayB.url])
        // Relay B serves the descriptor under the new KEL: asked first, it replaces the stale one.
        clock.now += 1
        let fresh = try StorePrekeyVault(store: MemoryStore()).rotate(now: clock.now).prekey
        let current = try createPublishedAgent(identity: alice.identity, claims: DescriptorClaims(
            relays: [relayB.url], prekey: fresh, profiles: [ProfileManifest.text.ref]), now: clock.now)
        try await relayB.client(clock: clock.fn).register(alice.identity)
        try await relayB.client(clock: clock.fn).publish(current)
        #expect(try await bob.prekey(for: alice.aceId, refresh: false) == fresh)
        #expect(try await bob.agent(alice.aceId).source == current.source)
        #expect(relayB.withLock { relayB.requests.filter { $0.hasPrefix("GET /v1/descriptor/") }.count } == 2)
        await bob.close()
    }
}
