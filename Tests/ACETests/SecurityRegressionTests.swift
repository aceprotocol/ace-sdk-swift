import Foundation
import Testing
@testable import ACE

/// Regression tests for the adversarial review of 2026-10-13.

/// Rejects a message whose `(from, messageId)` it already committed (a non-idempotent profile check).
private final class OnceRule: ProfileRules, @unchecked Sendable {
    let types: Set<String> = ["ace:text:1"]
    let applied = LockedValue<Set<String>>([])
    func check(_ event: ProfileEvent, body: [String: JSONValue]) throws {
        if applied.value.contains(event.messageId) { throw ACEError(.invalidBody, "already applied") }
    }
    func commit(_ event: ProfileEvent, body: [String: JSONValue]) throws { applied.value.insert(event.messageId) }
}

/// A transport that posts at once.
private struct InstantTransport: PacketTransport {
    let prekeyValue: Prekey
    func prekey(for aceId: String, refresh: Bool) async throws -> Prekey { prekeyValue }
    func post(to aceId: String, content: PrivateContent, messageId: String, prekey: Prekey, retry: Bool) async throws {}
}

/// A transport whose `post` suspends until released.
private final class HeldTransport: PacketTransport, @unchecked Sendable {
    let prekeyValue: Prekey
    let started = LockedValue(false)
    private let lock = NSLock()
    private var continuation: CheckedContinuation<Void, Never>?

    init(_ prekey: Prekey) { prekeyValue = prekey }
    func prekey(for aceId: String, refresh: Bool) async throws -> Prekey { prekeyValue }
    func post(to aceId: String, content: PrivateContent, messageId: String, prekey: Prekey, retry: Bool) async throws {
        await withCheckedContinuation { c in
            lock.withLock { continuation = c }
            started.value = true
        }
    }
    func release() { lock.withLock { continuation?.resume(); continuation = nil } }
}

private func link(_ alice: NetPeer, _ bob: NetPeer) async throws {
    try await alice.network.connect(bob.aceId, profile: "ace:text:1")
    _ = try await bob.network.pull()
    if try bob.network.admission.get(alice.aceId) == nil { try await bob.network.accept(alice.aceId) }
    _ = try await alice.network.pull()
}

@Suite struct SecurityRegressionTests {
    /// A descriptor signed under a superseded signing delegation (its KEL a strict prefix of the pin) must not replace the
    /// pinned descriptor: otherwise a holder of the replaced key substitutes the prekey.
    @Test func pinRefusesDescriptorUnderSupersededKel() async throws {
        let identity = try makeIdentity(now: NOW)
        let stale = try reload(identity, now: NOW)  // still holds the old signing key and KEL
        let honest = try StorePrekeyVault(store: MemoryStore()).rotate(now: NOW).prekey
        let evil = try StorePrekeyVault(store: MemoryStore()).rotate(now: NOW).prekey
        try identity.delegate(now: NOW + 1, notAfter: nil)
        let current = try createPublishedAgent(identity: identity, claims: DescriptorClaims(relays: ["https://relay.example"], prekey: honest), now: NOW + 2)
        let peers = PeerStore(store: MemoryStore(), clock: { NOW + 10 })
        try await peers.adopt(current)
        let forged = try createPublishedAgent(identity: stale, claims: DescriptorClaims(relays: ["https://relay.example"], prekey: evil), now: NOW + 5)
        await expectCodeAsync(.stalePeerBinding) { try await peers.adopt(forged) }
        #expect(try await peers.agent(identity.getACEId())?.descriptor.prekey == honest)
    }

    /// Deduplication runs before profile rules: a retried, already committed message is a duplicate, never rejected.
    @Test func dedupeRunsBeforeProfileRules() async throws {
        let clock = TestClock(systemClock()), relay = FakeRelay(clock: clock.fn)
        let rule = OnceRule()
        let alice = try await NetPeer.make(relay, clock: clock)
        let bob = try await NetPeer.make(relay, clock: clock, rules: { _, _ in [rule] })
        try await link(alice, bob)
        let bobAgent = try #require(try await alice.network.peers.agent(bob.aceId))
        let id = UUID().uuidString.lowercased()
        func packet(_ ts: Int) throws -> Data {
            let c = try alice.network.profiles.content(type: "ace:text:1", body: ["message": "pay once"])
            return try createPacket(sender: alice.identity, to: bob.aceId, prekey: bobAgent.descriptor.prekey, content: c, messageId: id, timestamp: ts).jsonData()
        }
        guard case .delivered = await bob.network.inbox!.receive(try packet(clock.now)) else { Issue.record("first not delivered"); return }
        let retry = await bob.network.inbox!.receive(try packet(clock.now + 1))
        #expect(retry == .duplicate, "\(retry)")
    }

    /// An automatic accept (acceptProfiles) never clears a block registered while the request was in flight, and an
    /// `accepted` reply from a peer never contacted pins nothing.
    @Test func automaticAcceptNeverOverridesBlock() async throws {
        let clock = TestClock(systemClock()), relay = FakeRelay(clock: clock.fn)
        let alice = try await NetPeer.make(relay, clock: clock)
        let bob = try await NetPeer.make(relay, clock: clock, configuration: NetworkConfiguration(acceptProfiles: ["ace:text:1"], contact: .open, listed: true))
        let aliceAgent = try await alice.network.publish()
        try await bob.network.block(alice.aceId)
        let permit = try createPermit(identity: alice.identity, subject: bob.aceId, now: clock.now)
        try await bob.network.receivedContact(from: alice.aceId, body: ["kind": "request", "profile": "ace:text:1", "note": "",
                                                                        "source": aliceAgent.source, "permit": permit], source: aliceAgent)
        #expect(try bob.network.admission.get(alice.aceId)?.state == .blocked)
        #expect(try await bob.network.requests().isEmpty)

        let carol = try await NetPeer.make(relay, clock: clock)
        let carolAgent = try await carol.network.publish()
        let carolPermit = try createPermit(identity: carol.identity, subject: bob.aceId, now: clock.now)
        try await bob.network.receivedContact(from: carol.aceId, body: ["kind": "accepted", "profile": "ace:text:1", "note": "",
                                                                        "source": carolAgent.source, "permit": carolPermit], source: carolAgent)
        #expect(try bob.network.admission.get(carol.aceId) == nil)
        #expect(try await bob.network.peers.pinned(carol.aceId) == nil)
    }

    /// 05 § Blocks: blocking discards the held request; a residual one from a blocked peer is `not_permitted` on accept,
    /// and the relay block stays as registered.
    @Test func acceptNeverClearsABlock() async throws {
        let clock = TestClock(systemClock()), relay = FakeRelay(clock: clock.fn)
        let alice = try await NetPeer.make(relay, clock: clock)
        let bob = try await NetPeer.make(relay, clock: clock, configuration: NetworkConfiguration(contact: .open, listed: true))
        let aliceAgent = try await alice.network.publish()
        let permit = try createPermit(identity: alice.identity, subject: bob.aceId, now: clock.now)
        try await bob.network.receivedContact(from: alice.aceId, body: ["kind": "request", "profile": "ace:text:1", "note": "",
                                                                        "source": aliceAgent.source, "permit": permit], source: aliceAgent)
        let held = try #require(try await bob.network.requests().first)
        try await bob.network.block(alice.aceId)
        #expect(try await bob.network.requests().isEmpty)
        // Simulate an old residual record directly: current putRequest refuses to recreate one for a blocked peer.
        try bob.store.write("requests/\(sha256Hex(Data(held.from.utf8))).json", try held.jsonValue.jsonData())
        await expectCodeAsync(.notPermitted) { try await bob.network.accept(alice.aceId) }
        #expect(try bob.network.admission.get(alice.aceId)?.state == .blocked)
        #expect(relay.blocked(by: bob.aceId, alice.aceId) == true)
        #expect(try bob.network.admission.blockRecord(alice.aceId)?.revision == clock.now)  // max(previous + 1, now)
        // the block decision itself discards the held request, in the same `admission` lock section
        _ = try bob.network.admission.decideBlock(alice.aceId, blocked: true) { $0 }
        #expect(try bob.network.admission.request(alice.aceId) == nil)
    }

    /// A concurrent block and accept never end admitted.
    @Test(arguments: [false, true]) func concurrentBlockAndAcceptNeverEndAdmitted(blockFirst: Bool) async throws {
        let clock = TestClock(systemClock()), relay = FakeRelay(clock: clock.fn)
        let alice = try await NetPeer.make(relay, clock: clock)
        let bob = try await NetPeer.make(relay, clock: clock, configuration: NetworkConfiguration(contact: .open, listed: true))
        let aliceAgent = try await alice.network.publish()
        let permit = try createPermit(identity: alice.identity, subject: bob.aceId, now: clock.now)
        try await bob.network.receivedContact(from: alice.aceId, body: ["kind": "request", "profile": "ace:text:1", "note": "",
                                                                        "source": aliceAgent.source, "permit": permit], source: aliceAgent)
        let network = bob.network, peer = alice.aceId
        await withTaskGroup(of: Void.self) { group in
            let ops: [@Sendable () async -> Void] = [{ try? await network.accept(peer) }, { try? await network.block(peer) }]
            for op in blockFirst ? ops.reversed() : ops { group.addTask { await op() } }
        }
        #expect(try bob.network.admission.get(alice.aceId)?.state == .blocked)
        #expect(relay.blocked(by: bob.aceId, alice.aceId) == true)
    }

    /// After `unregister`, a re-registration is signed above the unregister barrier even within the same second.
    @Test func reregisterAfterUnregisterExceedsBarrier() async throws {
        let registered = LockedValue<[Int]>([]), unregistered = LockedValue<[Int]>([])
        let identity = try makeIdentity(now: NOW)
        let relay = try makeRelay({ req, body in
            switch req.url!.path {
            case "/v1/register":
                registered.value.append((try? JSONValue(json: body))?["timestamp"]?.wireInt ?? -1)
                return .json(200, ["ok": true, "status": "registered"] as JSONValue)
            default:
                unregistered.value.append(Int(req.value(forHTTPHeaderField: "X-ACE-Timestamp") ?? "") ?? -1)
                return .json(200, ["ok": true] as JSONValue)
            }
        }, clock: { NOW })
        try await relay.register(identity)
        try await relay.unregister(identity)
        try await relay.register(identity)
        let r = registered.value, u = unregistered.value
        #expect(r.count == 2 && u.count == 1 && r[0] < u[0] && u[0] < r[1], "register \(r), unregister \(u)")
    }

    /// A refresh never presents a permit (descriptors are served to anyone; the resolve endpoint is gone).
    @Test func refreshWithoutPinPresentsNoPermit() async throws {
        let clock = TestClock(systemClock()), relay = FakeRelay(clock: clock.fn)
        let alice = try await NetPeer.make(relay, clock: clock)
        let bob = try await NetPeer.make(relay, clock: clock)
        try await link(alice, bob)
        #expect(try alice.network.admission.heldPermit(bob.aceId) != nil)
        try alice.store.delete("peers/\(sha256Hex(Data(bob.aceId.utf8))).json")  // the pin is forgotten
        let before = relay.withLock { relay.requests.count }
        _ = try await alice.network.agent(bob.aceId, refresh: true)
        let made = relay.withLock { Array(relay.requests.dropFirst(before)) }
        #expect(!made.contains("POST /v1/descriptor/resolve"), "\(made)")
    }

    /// `@name@host` uses an own route only when its authority is exactly `host`.
    @Test func handleHostIsMatchedExactly() async throws {
        let clock = TestClock(systemClock()), relay = FakeRelay(clock: clock.fn)
        let alice = try await NetPeer.make(relay, clock: clock)
        let bob = try await NetPeer.make(relay, clock: clock, configuration: NetworkConfiguration(handle: "bobby", contact: .open, listed: true))
        #expect(try await alice.network.lookup("@bobby@\(relay.host)").aceId == bob.aceId)
        // A typed address: the leading @ optional, any ASCII case; never Unicode case folding (U+212A KELVIN SIGN).
        #expect(try await alice.network.lookup("BoBby@\(relay.host.uppercased())").aceId == bob.aceId)
        await expectCodeAsync(.invalidArgument) { try await alice.network.lookup("@bob\u{212A}y@\(relay.host)") }
        let prefix = String(relay.host.dropLast(".test".count))
        await expectCodeAsync(.blockedAddress) { try await alice.network.lookup("@bobby@\(prefix)") }
    }

    /// A `rejected:unknown_prekey` receipt that lands while an attempt is in flight keeps its refresh request.
    @Test func refreshRequestSurvivesInFlightAttempt() async throws {
        let me = try makeIdentity(now: systemClock()), peer = try TestAgent(now: systemClock())
        let store = MemoryStore()
        let outbox = Outbox(identity: me, store: store, profiles: try InstalledProfiles([.text]))
        let e = try await outbox.enqueue(to: peer.aceId, type: "ace:text:1", body: ["message": "x"])
        let used = peer.agent.descriptor.prekey
        _ = try await outbox.deliver(e.messageId, via: InstantTransport(prekeyValue: used))  // attempt 1 posted with `used`
        let transport = HeldTransport(used)
        let attempt = Task { try await outbox.deliver(e.messageId, via: transport) }
        #expect(await settles { transport.started.value })
        let receipt: [String: JSONValue] = ["messageId": .string(e.messageId), "outcome": "rejected", "code": "unknown_prekey"]
        // L1: a receipt naming no prekey, or another attempt's, is ignored
        #expect(try await outbox.handleReceipt(from: peer.aceId, body: receipt) == nil)
        #expect(try await outbox.handleReceipt(from: peer.aceId, body: receipt.merging(["prekey": .string(String(repeating: "0", count: 64))]) { $1 }) == nil)
        #expect(try await outbox.handleReceipt(from: peer.aceId, body: receipt.merging(["prekey": .string(used.id)]) { $1 })?.refreshPrekey == true)
        // applied once
        #expect(try await outbox.handleReceipt(from: peer.aceId, body: receipt.merging(["prekey": .string(used.id)]) { $1 }) == nil)
        transport.release()
        let done = try await attempt.value
        #expect(done.refreshPrekey && done.attempts == 2 && done.status == .pending && done.lastPrekey == used.id)
        #expect(try await outbox.entry(e.messageId)?.refreshPrekey == true)
        // a corrupt entry is a storage failure, not silently skipped
        try store.checkedWrite("outbox/\(UUID().uuidString.lowercased()).json", Data("{".utf8))
        await expectCodeAsync(.storageFailed) { try await outbox.entries() }
    }

    /// `GET /v1/cards`: the relay filters by `tag` and (a hint) `profile`; an invalid `tag` is never sent.
    @Test func directoryFiltersByTagAndProfile() async throws {
        let clock = TestClock(systemClock()), relay = FakeRelay(clock: clock.fn)
        let alice = try await NetPeer.make(relay, clock: clock, configuration: NetworkConfiguration(card: AgentCard(tags: ["nlp"]),
                                                                                                    contact: .open, listed: true))
        let bob = try await NetPeer.make(relay, clock: clock, configuration: NetworkConfiguration(contact: .open, listed: false))
        #expect(try await bob.network.discover().cards.map(\.aceId) == [alice.aceId])
        #expect(try await bob.network.discover(tag: "nlp").cards.map(\.aceId) == [alice.aceId])
        #expect(try await bob.network.discover(tag: "nope").cards.isEmpty)
        #expect(try await bob.network.discover(profile: "ace:text:1").cards.map(\.aceId) == [alice.aceId])
        #expect(try await bob.network.discover(profile: "urn:example:none:1").cards.isEmpty)
        await expectCodeAsync(.invalidArgument) { try await bob.network.discover(tag: "NLP") }
    }

    /// Each directory entry is verified on its own: one failing verification, not listed at this relay or not carrying
    /// the requested tag is skipped and the rest of the page kept; `profile` is not checked client-side.
    @Test func directorySkipsEntriesFailingVerificationOrTheQuery() async throws {
        let page = LockedValue<JSONValue>(.null)
        let relay = try makeRelay { _, _ in .json(200, page.value) }
        let home = relay.baseURLString, now = systemClock()
        let alice = try makeIdentity(now: now), bob = try makeIdentity(now: now), carol = try makeIdentity(now: now)
        let good = try createCardRecord(identity: alice, home: home, card: AgentCard(tags: ["nlp"]), contact: .open, listed: true, now: now)
        var record = try #require(good["card"]?.objectValue)
        record["card"] = ["description": "Mallory"]  // changed after signing
        let forged: JSONValue = ["kel": try #require(good["kel"]), "card": .object(record)]
        let unlisted = try createCardRecord(identity: bob, home: home, contact: .open, listed: false, now: now)
        let elsewhere = try createCardRecord(identity: carol, home: "https://other.example", contact: .open, listed: true, now: now)
        page.value = ["cards": [forged, unlisted, elsewhere, good], "cursor": .null]
        let all = try await relay.directory()
        #expect(all.cards.map(\.aceId) == [alice.getACEId()] && all.rejected == 3)
        #expect(try await relay.directory(tag: "absent").cards.isEmpty)  // not carrying the tag
        #expect(try await relay.directory(profile: "urn:example:none:1").cards.count == 1)  // the relay's hint only
    }
}
