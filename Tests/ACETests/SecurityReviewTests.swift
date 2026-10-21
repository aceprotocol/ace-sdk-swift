//
//  SecurityReviewTests.swift
//  ACE SDK
//
//  The 2026-10-21 security review decisions (docs/review-2026-10-21-security.md): C3, C4, C7–C11 and the sdk-swift items.
//

import Foundation
import Testing
@testable import ACE

@Suite struct SecurityReviewTests {
    /// An identity operation without `now` reads the system clock as any other clock: an out-of-range reading is
    /// `invalid_argument`, never a timestamp.
    @Test func identityNowValidatesTheClockReading() throws {
        expectCode(.invalidArgument) { try identityNow(nil, clock: { -1 }) }
        expectCode(.invalidArgument) { try identityNow(nil, clock: { 1 << 53 }) }
        #expect(try identityNow(nil, clock: { 42 }) == 42)
        #expect(try identityNow(7) == 7)
    }

    // MARK: C7 — verification order

    /// A tampered log: the inception's `sig` removed (`invalid_kel` when it is reached).
    private static func brokenKel(_ kel: JSONValue?) -> JSONValue {
        var events = kel?.arrayValue ?? []
        var icp = events[0].objectValue!
        icp["sig"] = nil
        events[0] = .object(icp)
        return .array(events)
    }

    /// 04 § Verification step 1: a delegation entry's closed shape is part of the descriptor's shape, checked before the KEL.
    @Test func descriptorDelegationShapeIsCheckedBeforeTheKel() throws {
        let a = try TestAgent()
        var d = a.agent.source["descriptor"]!.objectValue!
        let other = try makeIdentity()
        let malformed: JSONValue = ["kel": .array([]), "credential": [
            "issuer": .string(other.getACEId()), "subject": .string(a.aceId), "issuedAt": .number(Double(NOW)), "expiresAt": .number(Double(NOW + 60)),
            "signature": ["scheme": "ml-dsa-65", "seq": 1, "value": "AAAA"]]]
        d["delegations"] = .array([malformed])
        let source: JSONValue = ["kel": Self.brokenKel(a.agent.source["kel"]), "descriptor": .object(d)]
        expectCode(.invalidAuthorization) { try verifyPublishedAgent(source, now: NOW) }
        // the same descriptor with a well-shaped entry reaches the KEL
        var credential = malformed["credential"]!.objectValue!
        credential["signature"] = a.agent.source["descriptor"]!["signature"]
        d["delegations"] = .array([["kel": .array([]), "credential": .object(credential)]])
        expectCode(.invalidKel) { try verifyPublishedAgent(["kel": Self.brokenKel(a.agent.source["kel"]), "descriptor": .object(d)], now: NOW) }
    }

    /// 04 § Card record step 1: the record's signature shape is checked before the KEL.
    @Test func cardSignatureShapeIsCheckedBeforeTheKel() throws {
        let id = try makeIdentity()
        let bundle = try createCardRecord(identity: id, home: "https://relay.example", contact: .open, listed: true, now: NOW)
        var card = bundle["card"]!.objectValue!
        card["signature"] = ["scheme": "ml-dsa-65", "seq": 1, "value": "AAAA"]
        expectCode(.invalidAuthorization) { try verifyCardBundle(["kel": Self.brokenKel(bundle["kel"]), "card": .object(card)], now: NOW) }
        expectCode(.invalidKel) { try verifyCardBundle(["kel": Self.brokenKel(bundle["kel"]), "card": bundle["card"]!], now: NOW) }
    }

    /// 04 step 3 / 01 § Operational signatures rule 5: a signer usable under its carried KEL but not after reconciliation
    /// with the pin is `stale_peer_binding` (not `invalid_kel`), for descriptors and card records alike.
    @Test func unusableAfterReconciliationIsStalePeerBinding() throws {
        let id = try makeIdentity()
        let vault = StorePrekeyVault(store: MemoryStore())
        let agent = try createPublishedAgent(identity: id, claims: DescriptorClaims(relays: ["https://relay.example"],
                                                                                     prekey: try vault.rotate(now: NOW).prekey), now: NOW)
        let bundle = try createCardRecord(identity: id, home: "https://relay.example", contact: .open, listed: true, now: NOW)
        try id.delegate(now: NOW + 1, notAfter: NOW + 11)
        let pinned = try ACEKel.verify(try id.getKel(), now: NOW + 1)
        expectCode(.stalePeerBinding) { try verifyPublishedAgent(agent.source, now: NOW + 20, pinned: pinned) }
        expectCode(.stalePeerBinding) { try verifyCardBundle(bundle, now: NOW + 20, pinned: pinned) }
    }

    // MARK: C10 — verified-KEL cache

    @Test func kelCacheKeepsAByteBudgetAndOnlyUsableLogs() throws {
        let cache = VerifiedKelCache(capacity: 10, budget: 100)
        let state = try ACEKel.verify(try makeIdentity().getKel(), now: NOW)
        for i in 0..<4 { cache.put("k\(i)", state: state, lastTs: NOW, bytes: 30) }
        #expect(cache.usage == (3, 90))  // the oldest evicted to stay within 100 bytes
        #expect(cache.get("k0") == nil && cache.get("k3") != nil)
        cache.put("big", state: state, lastTs: NOW, bytes: 101)
        #expect(cache.get("big") == nil && cache.usage == (3, 90))

        // A log unusable at `now` (here: a `rot` revoked the signing delegation) is verified but never cached.
        let sw = try SoftwareIdentity.generate(now: NOW)
        let next = try SoftwareKey(seed: try decodeB64(sw.exportPrivateKey().nextRootSeed!, code: .invalidArgument, what: "seed"))
        let rot = try ACEKel.createRotation(state: sw.getState(), newRoot: next, nextDigest: Data(repeating: 7, count: 32), ts: NOW + 2)
        let rotated = try sw.getKel() + [rot]
        #expect(try ACEKel.verify(rotated, now: NOW + 2).signing == nil)
        #expect(VerifiedKelCache.shared.get(ACEKel.prefixKeys(rotated)!.keys.last!) == nil)
        let usable = try makeIdentity().getKel()
        _ = try ACEKel.verify(usable, now: NOW)
        #expect(VerifiedKelCache.shared.get(ACEKel.prefixKeys(usable)!.keys.last!) != nil)
    }

    // MARK: Descriptor caching (04 § Caching)

    /// An equal `issuedAt` with identical claims is the same revision even though its signature differs.
    @Test func equalIssuedAtComparesClaimsNotSignatures() async throws {
        let a = try TestAgent()
        let peers = PeerStore(store: MemoryStore(), clock: { NOW })
        try await peers.adopt(a.agent)
        let claims = DescriptorClaims(relays: a.agent.descriptor.relays, prekey: a.agent.descriptor.prekey, profiles: a.agent.descriptor.profiles)
        let resigned = try createPublishedAgent(identity: a.identity, claims: claims, now: NOW)
        try #require(resigned.source["descriptor"]?["signature"] != a.agent.source["descriptor"]?["signature"])
        try await peers.adopt(resigned)
        let other = try createPublishedAgent(identity: a.identity, claims: DescriptorClaims(relays: ["https://other.example"], prekey: claims.prekey,
                                                                                            profiles: claims.profiles), now: NOW)
        await expectCodeAsync(.stalePeerBinding) { try await peers.adopt(other) }
    }

    /// A contact `source` older than the held descriptor never replaces it, and the contact still proceeds on the held one
    /// while it is usable (`accept`, the Inbox, `receivedContact`), as `adopt(source:)` does.
    @Test func olderContactSourceFallsBackToTheHeldDescriptor() async throws {
        let clock = TestClock(systemClock()), relay = FakeRelay(clock: clock.fn)
        let alice = try await NetPeer.make(relay, clock: clock)
        let bob = try await NetPeer.make(relay, clock: clock, configuration: NetworkConfiguration())
        try await bob.network.connect(alice.aceId, profile: ProfileManifest.text.id)
        _ = try await alice.network.pull()
        let held = try #require(try await alice.network.requests().first)
        let older = try verifyPublishedAgent(held.source, now: clock.now)
        clock.now += 10
        let newer = try createPublishedAgent(identity: bob.identity, claims: DescriptorClaims(
            relays: older.descriptor.relays, prekey: older.descriptor.prekey, profiles: older.descriptor.profiles), now: clock.now)
        try await alice.network.importAgent(newer.source)
        // accept: the request's source is older than the held descriptor
        try await alice.network.accept(bob.aceId)
        _ = try await bob.network.pull()
        #expect(try bob.network.admission.get(alice.aceId)?.state == .admitted)
        #expect(try await alice.network.peers.agent(bob.aceId)?.descriptor.issuedAt == newer.descriptor.issuedAt)
        // the Inbox: an admitted peer's contact packet carrying the older source
        let permit = try createPermit(identity: bob.identity, subject: alice.aceId, now: clock.now)
        try await bob.network.sendCore(to: alice.aceId, type: CoreTypes.contact, body: [
            "kind": "request", "profile": .string(ProfileManifest.text.id), "note": "", "source": older.source, "permit": permit])
        let outcomes = try await alice.network.pull()
        #expect(outcomes.count == 1)
        if case .delivered = outcomes.first {} else { Issue.record("expected delivered, got \(outcomes)") }
        // receivedContact (`accepted`)
        try await alice.network.receivedContact(from: bob.aceId, body: ["kind": "accepted", "profile": .string(ProfileManifest.text.id),
                                                                        "permit": permit], source: older)
        #expect(try await alice.network.peers.agent(bob.aceId)?.descriptor.issuedAt == newer.descriptor.issuedAt)
        await alice.network.close()
        await bob.network.close()
    }

    // MARK: C9 — handle lookups report the pin's kelLive

    @Test func handleLookupsReportThePinsKelLive() async throws {
        let clock = TestClock(systemClock()), relay = FakeRelay(clock: clock.fn)
        let bob = try await NetPeer.make(relay, clock: clock, configuration: NetworkConfiguration(handle: "bobby", contact: .open, listed: true))
        let alice = try await NetPeer.make(relay, clock: clock)
        let served = try #require(relay.publishedAgent(bob.aceId))
        clock.now += 10
        // A newer revision pinned from an imported source (not live); the relay still serves the older one.
        let newer = try createPublishedAgent(identity: bob.identity, claims: DescriptorClaims(
            relays: served.descriptor.relays, prekey: served.descriptor.prekey, profiles: served.descriptor.profiles), now: clock.now)
        try await alice.network.importAgent(newer.source)
        let handle = "@bobby@\(relay.host)"
        #expect(try await alice.network.lookupWithCard(handle).card?.kelLive == false)
        #expect(try await alice.network.lookupCard(handle).kelLive == false)
        await alice.network.close()
        await bob.network.close()
    }
}
