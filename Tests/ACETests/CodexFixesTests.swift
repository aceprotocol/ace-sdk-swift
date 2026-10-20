import Foundation
import Testing
@testable import ACE

/// Regression tests for the codex review of 2026-10-16 (docs/superpowers/plans/2026-10-16-codex-fixes.md).

/// A store that "dies" (every later mutation fails) once `crashAfter` matches a written key or `crashed` is set.
private final class CrashStore: ACEStore, @unchecked Sendable {
    let base = MemoryStore()
    let crashAfter = LockedValue<String?>(nil)
    let crashed = LockedValue(false)

    private func alive() throws { if crashed.value { throw ACEError(.storageFailed, "process died") } }
    func read(_ key: String) throws -> Data? { try base.read(key) }
    func write(_ key: String, _ value: Data) throws {
        try alive()
        try base.write(key, value)
        if let p = crashAfter.value, key.hasPrefix(p) { crashAfter.value = nil; crashed.value = true }
    }
    func delete(_ key: String) throws { try alive(); try base.delete(key) }
    func list(prefix: String) throws -> [String] { try base.list(prefix: prefix) }
    func lock(_ name: String, timeout: TimeInterval) throws -> any ACEStoreLock { try base.lock(name, timeout: timeout) }
}

private func connectedText(_ relay: FakeRelay, _ clock: TestClock) async throws -> (NetPeer, NetPeer) {
    let alice = try await NetPeer.make(relay, clock: clock)
    let bob = try await NetPeer.make(relay, clock: clock)
    try await alice.network.connect(bob.aceId, profile: "ace:text:1")
    _ = try await bob.network.pull()
    try await bob.network.accept(alice.aceId)
    _ = try await alice.network.pull()
    return (alice, bob)
}

/// Stage and attempt a message without `send`'s permit gate (these tests exercise the transport after a key change, when
/// the peer's earlier permit no longer verifies under its new pin). The attempt carries a permit the peer renewed under its
/// new key, as every Outbox attempt must (06 § Outbox step 3).
private func queue(_ from: NetPeer, to peer: NetPeer, _ text: String) async throws -> OutboxEntry {
    let now = from.network.clock()
    let renewed = try createPermit(identity: peer.identity, subject: from.aceId, now: now)
    try from.network.admission.holdPermit(try verifyPermit(renewed, issuer: try checkUsable(peer.identity, now: now), subject: from.aceId, now: now))
    let e = try await from.network.outbox.enqueue(to: peer.aceId, type: "ace:text:1", body: ["message": .string(text)])
    return try await from.network.outbox.deliver(e.messageId, via: from.network)
}

private let commerceConfig = NetworkConfiguration(profiles: [.text, .commerce], acceptProfiles: [ProfileManifest.commerce.id], contact: .open, listed: true)

/// A commerce seller on `store`, admitted by `buyer` (auto-accept); `open` starts (or restarts) its process.
private struct Seller {
    let identity: any ACEManagedIdentity
    let store: any ACEStore
    let relay: FakeRelay
    let clock: TestClock

    var aceId: String { identity.getACEId() }

    func open(onMessage: (@Sendable (ReceivedMessage) async throws -> Void)? = nil) async throws -> NetworkClient {
        var config = commerceConfig
        config.rules = [commerceRules(store: store, localAceId: identity.getACEId())]
        config.onMessage = onMessage
        let network = try await NetworkClient.open(identity: identity, store: store, relay: try relay.client(clock: clock.fn),
                                                   prekeys: StorePrekeyVault(store: store), configuration: config,
                                                   foreignRelay: { _ in throw ACEError(.blockedAddress) }, clock: clock.fn)
        try await network.publish()
        return network
    }
}

private func seller(_ relay: FakeRelay, _ clock: TestClock, store: any ACEStore) throws -> Seller {
    Seller(identity: try makeIdentity(now: clock.now), store: store, relay: relay, clock: clock)
}

private func buyer(_ relay: FakeRelay, _ clock: TestClock) async throws -> NetPeer {
    try await NetPeer.make(relay, clock: clock, configuration: commerceConfig) { id, store in [commerceRules(store: store, localAceId: id)] }
}

@Suite struct CodexFixesTests {
    // MARK: A. cached descriptors are bound to the current pins

    /// A descriptor the old signing key signed with `issuedAt` at the top of the skew window never outlives a rotation.
    @Test func rotatedHolderReplacesAFutureDatedDescriptor() async throws {
        let clock = TestClock(systemClock()), relay = FakeRelay(clock: clock.fn)
        let (alice, bob) = try await connectedText(relay, clock)
        let attacker = try TestAgent(now: clock.now)
        let forged = try createPublishedAgent(identity: bob.identity, claims: DescriptorClaims(
            relays: [relay.url], prekey: attacker.agent.descriptor.prekey, profiles: [ProfileManifest.text.ref]),
            now: clock.now + ACELimits.timestampWindowSeconds)
        try await alice.network.importAgent(forged.source)
        try bob.identity.delegate(now: clock.now, notAfter: nil)
        let rotated = try await bob.network.publish(force: true)
        #expect(rotated.descriptor.issuedAt < forged.descriptor.issuedAt)
        try await alice.network.importAgent(rotated.source)
        await expectCodeAsync(.notPermitted) { try await alice.network.send(to: bob.aceId, type: "ace:text:1", body: ["message": "x"]) }
        let entry = try await queue(alice, to: bob, "to the holder")
        #expect(entry.lastPrekey == rotated.descriptor.prekey.id && entry.lastPrekey != attacker.agent.descriptor.prekey.id, "\(entry)")
        guard case .delivered? = try await bob.network.pull().first else { Issue.record("not delivered"); return }
    }

    /// A newer KEL pinned through another path makes the cached descriptor stale: the next send refreshes, and a failed
    /// refresh errors instead of falling back to the old prekey.
    @Test func advancedPinRefreshesAndNeverFallsBack() async throws {
        let clock = TestClock(systemClock()), relay = FakeRelay(clock: clock.fn)
        let (alice, bob) = try await connectedText(relay, clock)
        let old = try #require(try await alice.network.peers.agent(bob.aceId)).descriptor.prekey
        try bob.identity.delegate(now: clock.now, notAfter: nil)
        try bob.network.prekeys.rotate(now: clock.now)
        let fresh = try await bob.network.publish(force: true)
        try await alice.network.peers.pin(kel: try bob.identity.getKel())
        #expect(try await alice.network.peers.agent(bob.aceId) == nil)
        let entry = try await queue(alice, to: bob, "refreshed")
        #expect(entry.lastPrekey == fresh.descriptor.prekey.id && entry.lastPrekey != old.id)

        // the relay still serves the previous descriptor: refresh fails, nothing is sent or staged
        try bob.identity.delegate(now: clock.now, notAfter: nil)
        try await alice.network.peers.pin(kel: try bob.identity.getKel())
        let staged = try await alice.network.outbox.entries().count
        await #expect(throws: ACEError.self) { try await alice.network.send(to: bob.aceId, type: "ace:text:1", body: ["message": "stale"]) }
        #expect(try await alice.network.outbox.entries().count == staged)
    }

    /// The permit (a bearer credential) goes only to relays named by a descriptor bound to the current pin: a KEL-stale
    /// descriptor's relays may be the old key holder's choice, so the refresh is anonymous at the home relay.
    @Test func kelStaleDescriptorRelaysNeverReceiveThePermit() async throws {
        let clock = TestClock(systemClock()), relay = FakeRelay(clock: clock.fn)
        let evil = uniqueHost()
        let seen = LockedValue<[String]>([])
        StubURLProtocol.register(host: evil) { req, body in
            seen.value.append("\(req.url!.path) \(String(decoding: body, as: UTF8.self))")
            return .error(404, "unknown_peer")
        }
        let store = MemoryStore()
        let identity = try makeIdentity(now: clock.now)
        let alice = try await NetworkClient.open(identity: identity, store: store, relay: try relay.client(clock: clock.fn),
                                                 prekeys: StorePrekeyVault(store: store), configuration: NetworkConfiguration(contact: .open, listed: true),
                                                 foreignRelay: { url in
            try RelayClient(baseURL: URL(string: url)!, session: stubSession(), timeout: 5, maxResponseBytes: 1 << 20, clock: clock.fn, sleeper: { _ in })
        }, clock: clock.fn)
        try await alice.publish()
        let bob = try await NetPeer.make(relay, clock: clock)
        try await alice.connect(bob.aceId, profile: "ace:text:1")
        _ = try await bob.network.pull()
        try await bob.network.accept(alice.identity.getACEId())
        _ = try await alice.pull()
        #expect(try alice.admission.heldPermit(bob.aceId) != nil)
        // the old key names the attacker's relay, then the holder rotates and the pin advances
        let current = try #require(try await alice.peers.agent(bob.aceId))
        let forged = try createPublishedAgent(identity: bob.identity, claims: DescriptorClaims(
            relays: ["https://\(evil)"], prekey: current.descriptor.prekey, profiles: [ProfileManifest.text.ref]),
            now: clock.now + 1)
        try await alice.importAgent(forged.source)
        try bob.identity.delegate(now: clock.now, notAfter: nil)
        let rotated = try await bob.network.publish(force: true)
        try await alice.peers.pin(kel: try bob.identity.getKel())
        #expect(try await alice.agent(bob.aceId, refresh: true).source == rotated.source)
        #expect(!seen.value.contains { $0.contains("permit") }, "\(seen.value)")
        await alice.close()
    }

    /// Under an unchanged KEL an expired cached descriptor is no licence to roll back: an older, longer-lived descriptor
    /// replayed by a relay never replaces the newer one.
    @Test func expiredNewerDescriptorIsNotRolledBack() async throws {
        let clock = TestClock(NOW)
        let alice = try TestAgent(now: NOW)
        let claims = DescriptorClaims(relays: ["https://relay.example"], prekey: alice.agent.descriptor.prekey, profiles: [ProfileManifest.text.ref])
        let older = try createPublishedAgent(identity: alice.identity, claims: claims, now: NOW, lifetime: ACELimits.maxDescriptorSeconds)
        let newer = try createPublishedAgent(identity: alice.identity, claims: claims, now: NOW + 10, lifetime: 60)
        let peers = PeerStore(store: MemoryStore(), clock: clock.fn)
        clock.now = NOW + 10
        try await peers.adopt(source: newer.source)
        clock.now = NOW + 100  // the newer one has expired, the older one has not
        await expectCodeAsync(.stalePeerBinding) { try await peers.adopt(source: older.source) }
        #expect(try await peers.agent(alice.aceId)?.source == newer.source)
    }

    /// An older revision refused under an unchanged KEL returns the cached one while it is usable.
    @Test func olderRevisionReturnsTheUsableCachedOne() async throws {
        let clock = TestClock(NOW)
        let alice = try TestAgent(now: NOW)
        let claims = DescriptorClaims(relays: ["https://relay.example"], prekey: alice.agent.descriptor.prekey, profiles: [ProfileManifest.text.ref])
        let older = try createPublishedAgent(identity: alice.identity, claims: claims, now: NOW)
        let newer = try createPublishedAgent(identity: alice.identity, claims: claims, now: NOW + 10)
        let peers = PeerStore(store: MemoryStore(), clock: clock.fn)
        clock.now = NOW + 10
        try await peers.adopt(source: newer.source)
        #expect(try await peers.adopt(source: older.source).source == newer.source)
        #expect(try await peers.agent(alice.aceId)?.source == newer.source)
    }

    /// A cached descriptor stops reporting a delegation once the issuer's pin advances past the key that signed it.
    @Test func advancedIssuerPinMakesTheCachedDelegationStale() async throws {
        let now = systemClock()
        let alice = try TestAgent(now: now - 10), dave = try makeIdentity(now: now - 10)
        let claims = DescriptorClaims(relays: ["https://relay.example"], prekey: alice.agent.descriptor.prekey,
                                      delegations: [try createDelegation(issuer: dave, subject: alice.aceId, now: now - 5)])
        let src = try createPublishedAgent(identity: alice.identity, claims: claims, now: now - 3)
        let peers = PeerStore(store: MemoryStore())
        try await peers.pin(kel: try dave.getKel())
        try await peers.adopt(source: src.source)
        #expect(try await peers.agent(alice.aceId)?.descriptor.delegations.map(\.issuer) == [dave.getACEId()])
        try dave.delegate(now: now - 2, notAfter: nil)
        try await peers.pin(kel: try dave.getKel())
        #expect(try await peers.agent(alice.aceId) == nil)
    }

    /// A cached descriptor never reports a delegation whose credential has expired since it was adopted.
    @Test func expiredDelegationIsDroppedFromTheCache() async throws {
        let clock = TestClock(systemClock())
        let alice = try TestAgent(now: clock.now - 10), dave = try makeIdentity(now: clock.now - 10)
        let credential = try createDelegation(issuer: dave, subject: alice.aceId, now: clock.now - 5, lifetime: 60)
        let src = try createPublishedAgent(identity: alice.identity, claims: DescriptorClaims(
            relays: ["https://relay.example"], prekey: alice.agent.descriptor.prekey, delegations: [credential]), now: clock.now - 3)
        let peers = PeerStore(store: MemoryStore(), clock: clock.fn)
        try await peers.adopt(source: src.source)
        #expect(try await peers.agent(alice.aceId)?.descriptor.delegations.map(\.issuer) == [dave.getACEId()])
        clock.now += 60
        let cached = try #require(try await peers.agent(alice.aceId))
        #expect(cached.descriptor.delegations.isEmpty && cached.source == src.source)
    }

    /// A descriptor verified elsewhere (a relay lookup, a contact target) is adopted only when each delegation whose issuer
    /// is pinned verifies under that pin: a credential the issuer's superseded key signed, carried with its older KEL, is
    /// refused (01 § Pinning: a carried KEL never rolls an issuer's pin back).
    @Test func adoptedDelegationIsReconciledWithTheIssuerPin() async throws {
        let now = systemClock()
        let alice = try TestAgent(now: now - 10), dave = try makeIdentity(now: now - 10)
        let stale = try createDelegation(issuer: dave, subject: alice.aceId, now: now - 5)
        try dave.delegate(now: now - 4, notAfter: nil)  // dave replaces the key that signed `stale`
        let peers = PeerStore(store: MemoryStore())
        try await peers.pin(kel: try dave.getKel())
        let src = try createPublishedAgent(identity: alice.identity, claims: DescriptorClaims(
            relays: ["https://relay.example"], prekey: alice.agent.descriptor.prekey, delegations: [stale]), now: now - 3)
        let unpinned = try verifyPublishedAgent(src.source, now: now)  // as a relay client verifies it
        await expectCodeAsync(.invalidAuthorization) { try await peers.adopt(unpinned) }
        await expectCodeAsync(.invalidAuthorization) { try await peers.adopt(source: src.source) }
        #expect(try await peers.agent(alice.aceId) == nil)
    }

    /// A permit (a bearer credential) signed by the issuer's superseded key is never presented once the issuer rotated,
    /// even to the relays of its current descriptor.
    @Test func permitFromASupersededKeyIsNeverPresented() async throws {
        let clock = TestClock(systemClock()), relay = FakeRelay(clock: clock.fn)
        let host = uniqueHost()
        let seen = LockedValue<[String]>([])
        StubURLProtocol.register(host: host) { req, body in
            seen.value.append("\(req.url!.path) \(String(decoding: body, as: UTF8.self))")
            return .error(404, "unknown_peer")
        }
        let store = MemoryStore()
        let identity = try makeIdentity(now: clock.now)
        let alice = try await NetworkClient.open(identity: identity, store: store, relay: try relay.client(clock: clock.fn),
                                                 prekeys: StorePrekeyVault(store: store), configuration: NetworkConfiguration(contact: .open, listed: true),
                                                 foreignRelay: { url in
            try RelayClient(baseURL: URL(string: url)!, session: stubSession(), timeout: 5, maxResponseBytes: 1 << 20, clock: clock.fn, sleeper: { _ in })
        }, clock: clock.fn)
        try await alice.publish()
        let bob = try await NetPeer.make(relay, clock: clock)
        try await alice.connect(bob.aceId, profile: "ace:text:1")
        _ = try await bob.network.pull()
        try await bob.network.accept(alice.identity.getACEId())
        _ = try await alice.pull()
        #expect(try alice.admission.heldPermit(bob.aceId) != nil)
        // bob rotates and publishes (its current key names a relay we observe); alice imports it: bound to the pin
        try bob.identity.delegate(now: clock.now, notAfter: nil)
        let current = try createPublishedAgent(identity: bob.identity, claims: DescriptorClaims(
            relays: ["https://\(host)"], prekey: try #require(try await alice.peers.agent(bob.aceId)).descriptor.prekey,
            profiles: [ProfileManifest.text.ref]), now: clock.now + 1)
        try await alice.importAgent(current.source)
        await #expect(throws: ACEError.self) { try await alice.agent(bob.aceId, refresh: true) }
        _ = try? await alice.send(to: bob.aceId, type: "ace:text:1", body: ["message": "hi"])
        #expect(!seen.value.isEmpty && !seen.value.contains { $0.contains("permit") }, "\(seen.value)")
        await alice.close()
    }

    // MARK: B. inbox crash recovery re-commits profile rules

    @Test(arguments: ["after journal write", "after commitRules", "after onMessage"])
    func crashedHandOverRecoversOnOpen(_ point: String) async throws {
        let clock = TestClock(systemClock()), relay = FakeRelay(clock: clock.fn)
        let alice = try await buyer(relay, clock)
        let store = CrashStore()
        let seller = try seller(relay, clock, store: store)
        let bobId = seller.aceId
        let host = LockedValue<Set<String>>([])  // an idempotent host keyed by messageId (06 § Deduplication)
        let crashInHost = LockedValue(false)
        let onMessage: @Sendable (ReceivedMessage) async throws -> Void = { m in
            host.value.insert(m.messageId)
            if crashInHost.value { store.crashed.value = true; throw ACEError(.storageFailed, "process died") }
        }
        var bob = try await seller.open(onMessage: onMessage)
        try await alice.network.connect(bobId, profile: ProfileManifest.commerce.id)
        _ = try await bob.pull()
        _ = try await alice.network.pull()
        let rfq = try await alice.network.send(to: bobId, type: CommerceType.rfq, body: ["need": "translate"], threadId: "deal")
        switch point {
        case "after journal write": store.crashAfter.value = "inbox/pending/"
        case "after commitRules": store.crashAfter.value = "commerce/threads/"
        default: crashInHost.value = true
        }
        #expect(try await bob.pull().first?.isFinal == false, "\(point)")
        await bob.close()
        store.crashed.value = false
        crashInHost.value = false
        bob = try await seller.open(onMessage: onMessage)  // restart: open-time recovery
        #expect(host.value == [rfq.messageId], "\(point)")
        #expect(try store.list(prefix: "inbox/pending/").isEmpty, "\(point)")
        #expect(try await bob.pull() == [.duplicate], "\(point)")  // the redelivered packet is answered `delivered`
        let thread = try ThreadStore(store: store).thread(between: alice.aceId, and: bobId, threadId: "deal")
        #expect(thread?.state == .requested && thread?.history.map(\.messageId) == [rfq.messageId], "\(point)")
        _ = try await alice.network.pull()
        #expect(try await alice.network.outbox.entry(rfq.messageId)?.status == .delivered, "\(point)")
        await bob.close()
    }

    /// The message whose journal record triggers a compaction is in the snapshot: after a crash it is still a duplicate.
    @Test func compactionKeepsTheMessageThatTriggeredIt() async throws {
        let clock = TestClock(systemClock()), relay = FakeRelay(clock: clock.fn)
        let alice = try await buyer(relay, clock)
        let store = CrashStore()
        let seller = try seller(relay, clock, store: store)
        let bobId = seller.aceId
        var bob = try await seller.open()
        try await alice.network.connect(bobId, profile: ProfileManifest.commerce.id)
        _ = try await bob.pull()
        _ = try await alice.network.pull()  // the accepted reply carries bob's permit
        var last: Data?
        for i in 0..<300 {
            _ = try await alice.network.send(to: bobId, type: "ace:text:1", body: ["message": .string("m\(i)")])
            last = relay.queued(bobId).last
            _ = try await bob.pull()
            if try store.list(prefix: "inbox/journal/").isEmpty { break }  // that message's record compacted the journal
        }
        #expect(try store.list(prefix: "inbox/journal/").isEmpty)
        store.crashed.value = true  // die before close compacts again
        await bob.close()
        store.crashed.value = false
        bob = try await seller.open()
        #expect(await bob.inbox!.receive(try #require(last)) == .duplicate)
        await bob.close()
    }

    /// The duplicate path finishes a pending entry the same way (no restart).
    @Test func duplicatePathFinishesAPendingHandOver() async throws {
        let clock = TestClock(systemClock()), relay = FakeRelay(clock: clock.fn)
        let alice = try await buyer(relay, clock)
        let store = CrashStore()
        let seller = try seller(relay, clock, store: store)
        let bobId = seller.aceId
        let host = LockedValue<Set<String>>([])
        let busy = LockedValue(false)
        let bob = try await seller.open { m in
            if busy.value { busy.value = false; throw ACEError(.storageFailed, "host unavailable") }
            host.value.insert(m.messageId)
        }
        try await alice.network.connect(bobId, profile: ProfileManifest.commerce.id)
        _ = try await bob.pull()
        _ = try await alice.network.pull()
        let rfq = try await alice.network.send(to: bobId, type: CommerceType.rfq, body: ["need": "translate"], threadId: "deal")
        busy.value = true
        #expect(try await bob.pull() == [.retry(.storageFailed)])
        #expect(try store.list(prefix: "inbox/pending/").count == 1 && host.value.isEmpty)
        #expect(try await bob.pull() == [.duplicate])
        #expect(host.value == [rfq.messageId])
        #expect(try store.list(prefix: "inbox/pending/").isEmpty)
        let thread = try ThreadStore(store: store).thread(between: alice.aceId, and: bobId, threadId: "deal")
        #expect(thread?.history.map(\.messageId) == [rfq.messageId])
        await bob.close()
    }

    /// Inbox state on disk never keeps a delivered body: the seen journal is `{messageId, from, timestamp}` and a pending
    /// entry (the only copy recovery can hand over) is removed once the host has it; dedup survives a crash.
    @Test func deliveredMessagesLeaveNoPlaintextAndStayDuplicatesAcrossACrash() async throws {
        let marker = Data("plaintext-marker-7f3a9c".utf8)
        let clock = TestClock(systemClock()), relay = FakeRelay(clock: clock.fn)
        let alice = try await buyer(relay, clock)
        let store = CrashStore()
        let seller = try seller(relay, clock, store: store)
        let bobId = seller.aceId
        let leaked = { try store.base.list(prefix: "").filter { try store.base.read($0)?.range(of: marker) != nil } }
        let host = LockedValue<[String]>([])
        let onMessage: @Sendable (ReceivedMessage) async throws -> Void = { m in host.value.append(m.messageId) }
        var bob = try await seller.open(onMessage: onMessage)
        try await alice.network.connect(bobId, profile: ProfileManifest.commerce.id)
        _ = try await bob.pull()
        _ = try await alice.network.pull()
        var packets: [Data] = []
        for i in 0..<5 {
            _ = try await alice.network.send(to: bobId, type: "ace:text:1", body: ["message": .string("plaintext-marker-7f3a9c \(i)")])
            packets.append(try #require(relay.queued(bobId).last))
        }
        #expect(try await bob.pull().count == 5 && host.value.count == 5)
        #expect(try leaked() == [])
        store.crashed.value = true  // die before close compacts the journal
        await bob.close()
        store.crashed.value = false
        bob = try await seller.open(onMessage: onMessage)
        for p in packets { #expect(await bob.inbox!.receive(p) == .duplicate) }
        #expect(host.value.count == 5)
        await bob.close()
    }

    /// A hand-over interrupted before the host returned is re-delivered on restart, then its body is gone.
    @Test func interruptedHandOverIsRedeliveredThenLeavesNoPlaintext() async throws {
        let marker = Data("plaintext-marker-7f3a9c".utf8)
        let clock = TestClock(systemClock()), relay = FakeRelay(clock: clock.fn)
        let alice = try await buyer(relay, clock)
        let store = CrashStore()
        let seller = try seller(relay, clock, store: store)
        let bobId = seller.aceId
        let leaked = { try store.base.list(prefix: "").filter { try store.base.read($0)?.range(of: marker) != nil } }
        let host = LockedValue<[String]>([])
        let crashInHost = LockedValue(false)
        let onMessage: @Sendable (ReceivedMessage) async throws -> Void = { m in
            if crashInHost.value { store.crashed.value = true; throw ACEError(.storageFailed, "process died") }
            host.value.append(m.content.body["message"]?.stringValue ?? "")
        }
        var bob = try await seller.open(onMessage: onMessage)
        try await alice.network.connect(bobId, profile: ProfileManifest.commerce.id)
        _ = try await bob.pull()
        _ = try await alice.network.pull()
        _ = try await alice.network.send(to: bobId, type: "ace:text:1", body: ["message": "plaintext-marker-7f3a9c"])
        crashInHost.value = true
        #expect(try await bob.pull().first?.isFinal == false)
        #expect(try leaked().count == 1 && (try leaked().first?.hasPrefix("inbox/pending/") ?? false))
        await bob.close()
        store.crashed.value = false
        crashInHost.value = false
        bob = try await seller.open(onMessage: onMessage)
        #expect(host.value == ["plaintext-marker-7f3a9c"])
        #expect(try leaked() == [])
        await bob.close()
    }

    // MARK: C. expired = outcome unknown; receipts settle it

    @Test func abandonedRfqSettlesOnTheLateReceiptAndTheThreadContinues() async throws {
        let clock = TestClock(systemClock()), relay = FakeRelay(clock: clock.fn)
        let alice = try await buyer(relay, clock)
        let bob = try await buyer(relay, clock)
        try await alice.network.connect(bob.aceId, profile: ProfileManifest.commerce.id)
        _ = try await bob.network.pull()
        _ = try await alice.network.pull()
        let rfq = try await alice.network.send(to: bob.aceId, type: CommerceType.rfq, body: ["need": "translate"], threadId: "deal")
        try await alice.network.outbox.abandon(rfq.messageId)
        #expect(try await alice.network.outbox.entry(rfq.messageId)?.status == .expired)
        guard case .delivered? = try await bob.network.pull().first else { Issue.record("rfq not delivered"); return }
        let offer = try await bob.network.send(to: alice.aceId, type: CommerceType.offer, body: ["price": "8", "currency": "USDC"], threadId: "deal")
        let got = try await alice.network.pull()
        #expect(got.count == 2)
        let entry = try await alice.network.outbox.entry(rfq.messageId)
        #expect(entry?.status == .delivered)
        let thread = try ThreadStore(store: alice.store).thread(between: alice.aceId, and: bob.aceId, threadId: "deal")
        #expect(thread?.state == .offered)
        _ = try await alice.network.send(to: bob.aceId, type: CommerceType.accept, body: ["offerId": .string(offer.messageId)], threadId: "deal")
    }

    @Test func lateReceiptsSettleExpiredEntriesAndPruneWaitsOutTheRetention() async throws {
        let clock = TestClock(NOW)
        let me = try makeIdentity(now: NOW), peer = try TestAgent(now: NOW)
        let outbox = Outbox(identity: me, store: MemoryStore(), profiles: try InstalledProfiles([.text]), clock: clock.fn)
        func expired() async throws -> OutboxEntry {
            let e = try await outbox.enqueue(to: peer.aceId, type: "ace:text:1", body: ["message": "x"])
            try await outbox.abandon(e.messageId)
            return try #require(try await outbox.entry(e.messageId))
        }
        let a = try await expired(), b = try await expired(), c = try await expired()
        #expect(a.status == .expired && a.expiredAt == NOW)
        #expect(try await outbox.handleReceipt(from: peer.aceId, body: ["messageId": .string(b.messageId), "outcome": "rejected", "code": "busy"])?.status == .rejected)
        let prekey = ["messageId": .string(c.messageId), "outcome": "rejected", "code": "unknown_prekey", "prekey": .string(String(repeating: "0", count: 64))] as [String: JSONValue]
        #expect(try await outbox.handleReceipt(from: peer.aceId, body: prekey) == nil)
        #expect(try await outbox.prune() == 0)  // settled and expired entries stay for the offline window
        clock.now += ACELimits.offlineWindowSeconds
        #expect(try await outbox.prune() == 3)
        #expect(try await outbox.entries().isEmpty)
    }
}
