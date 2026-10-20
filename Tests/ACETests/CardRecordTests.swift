//
//  CardRecordTests.swift
//  The card record (04 § Card record): verification, the relay's set-once handles, and the client's card pin (no
//  rollback, set-once handle per home), contact admission. The same scenarios as sdk-ts tests/card-record.test.ts.
//

import Foundation
import Testing
@testable import ACE

private let SOL = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp:7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU"
private let RELAY = "https://relay.test"

private func aliceCard(home: String = RELAY, handle: String? = "alice", pay: [String]? = [SOL], contact: Contact = .open,
                       now: Int = NOW) throws -> (any ACEManagedIdentity, JSONValue) {
    let id = try makeIdentity(now: NOW)
    let bundle = try createCardRecord(identity: id, home: home, handle: handle, card: AgentCard(name: "Alice"), pay: pay, contact: contact,
                                      listed: false, now: now)
    return (id, bundle)
}

/// `bundle` with record members replaced (`nil` removes one); the signature is kept.
private func withRecord(_ bundle: JSONValue, _ patch: [String: JSONValue?]) -> JSONValue {
    var r = bundle["card"]!.objectValue!
    for (k, v) in patch { r[k] = v }
    return ["kel": bundle["kel"]!, "card": .object(r)]
}

private func peer(_ relay: FakeRelay, _ clock: TestClock, contact: Contact = .closed, handle: String? = nil) async throws -> NetPeer {
    try await NetPeer.make(relay, clock: clock, configuration: NetworkConfiguration(handle: handle, contact: contact))
}

private func card(_ who: NetPeer, home: String, handle: String? = nil, pay: [String]? = nil, contact: Contact = .closed,
                  listed: Bool = false, now: Int) throws -> JSONValue {
    try createCardRecord(identity: who.identity, home: home, handle: handle, pay: pay, contact: contact, listed: listed, now: now)
}

/// Expect a relay refusal with relay code `relayCode`.
private func expectRelayCode(_ relayCode: String, sourceLocation: SourceLocation = #_sourceLocation, _ body: () async throws -> Void) async {
    do {
        try await body()
        Issue.record("expected relay code \(relayCode), got success", sourceLocation: sourceLocation)
    } catch let e as ACEError {
        #expect(e.relayCode == relayCode, "\(e)", sourceLocation: sourceLocation)
    } catch {
        Issue.record("expected ACEError, got \(error)", sourceLocation: sourceLocation)
    }
}

@Suite struct CardRecordTests {
    // MARK: verification

    @Test func roundTripsASignedCard() throws {
        let (id, bundle) = try aliceCard()
        let v = try verifyCardBundle(bundle, now: NOW)
        #expect(v.aceId == id.getACEId() && v.state.aceId == id.getACEId())
        #expect(v.record.handle == "alice" && v.record.contact == .open && v.record.pay == [SOL] && v.record.home == RELAY)
        #expect(v.record.card == AgentCard(name: "Alice") && v.bundle == bundle)
        // no expiry: a year later it still verifies
        #expect(try verifyCardBundle(bundle, now: NOW + 365 * 86_400 - 1).record.listed == false)
        expectCode(.invalidAuthorization) { try verifyCardBundle(withRecord(bundle, ["listed": true]), now: NOW) }
    }

    @Test func rejectsUnknownMember() throws {
        let (_, bundle) = try aliceCard()
        expectCode(.invalidAuthorization) { try verifyCardBundle(withRecord(bundle, ["visibility": "public"]), now: NOW) }
        var extra = bundle.objectValue!
        extra["extra"] = 1
        expectCode(.invalidAuthorization) { try verifyCardBundle(.object(extra), now: NOW) }
        expectCode(.invalidAuthorization) { try verifyCardBundle(withRecord(bundle, ["contact": "public"]), now: NOW) }
    }

    @Test func rejectsNinePayAccounts() throws {
        let (_, bundle) = try aliceCard()
        let nine = (0..<9).map { "eip155:1:0x" + String(repeating: "0", count: 39) + String($0) }
        expectCode(.invalidAuthorization) { try verifyCardBundle(withRecord(bundle, ["pay": .array(nine.map { .string($0) })]), now: NOW) }
        expectCode(.invalidAuthorization) { try aliceCard(pay: nine) }
        expectCode(.invalidAuthorization) { try aliceCard(pay: []) }
    }

    @Test func rejectsDuplicatePay() throws {
        let (_, bundle) = try aliceCard()
        expectCode(.invalidAuthorization) { try verifyCardBundle(withRecord(bundle, ["pay": [.string(SOL), .string(SOL)]]), now: NOW) }
    }

    @Test func rejectsBadCaip10() throws {
        let (_, bundle) = try aliceCard()
        #expect(isCaip10Account(SOL))
        #expect(!isCaip10Account("solana:7xKX"))
        expectCode(.invalidAuthorization) { try verifyCardBundle(withRecord(bundle, ["pay": ["solana:7xKX"]]), now: NOW) }
    }

    @Test func rejectsOversizedRecord() throws {
        let (_, bundle) = try aliceCard()
        let big = withRecord(bundle, ["card": ["name": "Alice", "description": .string(String(repeating: "x", count: ACELimits.maxCardRecordBytes))]])
        expectCode(.invalidAuthorization, messageContains: "16384") { try verifyCardBundle(big, now: NOW) }
    }

    @Test func rejectsAFutureIssuedAtABadHomeAndABadHandle() throws {
        let (_, future) = try aliceCard(now: NOW + 301)
        expectCode(.invalidAuthorization) { try verifyCardBundle(future, now: NOW) }
        expectCode(.invalidAuthorization) { try aliceCard(home: "https://Relay.test/") }
        expectCode(.invalidAuthorization) { try aliceCard(handle: "Al") }
    }

    @Test func cardSignedBySupersededKeyIsStale() throws {
        let (id, bundle) = try aliceCard()
        try id.delegate(now: NOW, notAfter: nil)
        let carried: JSONValue = ["kel": ExportJSON.kelValue(try id.getKel()), "card": bundle["card"]!]
        expectCode(.stalePeerBinding) { try verifyCardBundle(carried, now: NOW) }
    }

    // MARK: over the relay

    /// A relay serving, under `@alice@relay`, a record whose home is another relay: `unknown_peer`.
    @Test func handleLookupRejectsForeignHome() async throws {
        let clock = TestClock(systemClock()), relay = FakeRelay(clock: clock.fn)
        let alice = try await peer(relay, clock, contact: .open)
        let bob = try await peer(relay, clock)
        let foreign = try card(alice, home: "https://relay-b.test", handle: "alice", contact: .open, now: clock.now + 1)
        relay.setCard(alice.aceId, foreign)
        relay.bindHandle("alice", to: alice.aceId)
        await expectCodeAsync(.unknownPeer) { try await bob.network.lookupCard("@alice@\(relay.host)") }
        // the client check itself, against a relay that serves the foreign record
        let stub = try makeRelay({ _, _ in .json(200, foreign) }, clock: clock.fn)
        await expectCodeAsync(.unknownPeer) { try await stub.handle("alice") }
    }

    @Test func pinnedHandleMismatchIsInvalidAuthorization() async throws {
        let clock = TestClock(systemClock()), relay = FakeRelay(clock: clock.fn)
        let alice = try await peer(relay, clock, contact: .open, handle: "alice")
        let bob = try await peer(relay, clock)
        #expect(try await bob.network.lookupCard("@alice@\(relay.host)").record.handle == "alice")
        // A record of the same identity without the pinned handle (a conformant relay refuses to store it).
        relay.setCard(alice.aceId, try card(alice, home: relay.url, contact: .open, now: clock.now + 1))
        await expectCodeAsync(.invalidAuthorization) { try await bob.network.lookupCard(alice.aceId) }
    }

    @Test func handlesAreSetOnce() async throws {
        let clock = TestClock(systemClock()), relay = FakeRelay(clock: clock.fn)
        let alice = try await peer(relay, clock, handle: "alice")
        let mallory = try await peer(relay, clock)
        let client = try relay.client(clock: clock.fn)
        await expectRelayCode("invalid_argument") { try await client.publishCard(try card(alice, home: relay.url, handle: "alice2", now: clock.now + 1)) }
        await expectRelayCode("invalid_argument") { try await client.publishCard(try card(alice, home: relay.url, now: clock.now + 2)) }
        await expectRelayCode("handle_taken") { try await client.publishCard(try card(mallory, home: relay.url, handle: "alice", now: clock.now + 3)) }
        try await client.publishCard(try card(alice, home: relay.url, handle: "alice", now: clock.now + 4))
        #expect(try await client.handle("alice")["card"]?["aceId"]?.stringValue == alice.aceId)
    }

    @Test func aHandleLookupIsCheckedAgainstTheHandlePinToo() async throws {
        let clock = TestClock(systemClock()), relay = FakeRelay(clock: clock.fn)
        let alice = try await peer(relay, clock, contact: .open, handle: "alice")
        let bob = try await peer(relay, clock)
        #expect(try await bob.network.lookup("@alice@\(relay.host)").aceId == alice.aceId)  // pins alice -> "alice"
        // A relay that binds a second handle to the same identity at the same home.
        relay.setCard(alice.aceId, try card(alice, home: relay.url, handle: "alice2", contact: .open, now: clock.now + 1))
        relay.bindHandle("alice2", to: alice.aceId)
        await expectCodeAsync(.invalidAuthorization) { try await bob.network.lookup("@alice2@\(relay.host)") }
        await expectCodeAsync(.invalidAuthorization) { try await bob.network.lookupCard("@alice2@\(relay.host)") }
    }

    @Test func movingHomeKeepsTheOldBindingAndNeverReassignsIt() async throws {
        let clock = TestClock(systemClock()), relay = FakeRelay(clock: clock.fn)
        let alice = try await peer(relay, clock, handle: "alice")
        let mallory = try await peer(relay, clock)
        let client = try relay.client(clock: clock.fn)
        try await client.publishCard(try card(alice, home: "https://relay-b.test", now: clock.now + 1))
        #expect(try await client.card(alice.aceId)["card"]?["home"]?.stringValue == "https://relay-b.test")
        #expect(relay.handleOwner("alice") == alice.aceId)
        await expectCodeAsync(.unknownPeer) { try await client.handle("alice") }
        await expectRelayCode("handle_taken") { try await client.publishCard(try card(mallory, home: relay.url, handle: "alice", now: clock.now + 2)) }
        // a client that pinned alice at the old home accepts the record at the new home
        let bob = try await peer(relay, clock)
        relay.setCard(alice.aceId, try card(alice, home: relay.url, handle: "alice", now: clock.now + 3))
        _ = try await bob.network.lookupCard(alice.aceId)
        relay.setCard(alice.aceId, try card(alice, home: "https://relay-b.test", handle: "alice", now: clock.now + 4))
        #expect(try await bob.network.lookupCard(alice.aceId).record.home == "https://relay-b.test")
    }

    @Test func lookupCardPinsTheKelBeforeTrustingTheCard() async throws {
        let clock = TestClock(systemClock()), relay = FakeRelay(clock: clock.fn)
        let alice = try await NetPeer.make(relay, clock: clock, configuration: NetworkConfiguration(pay: [SOL], contact: .open))
        let old = try #require(relay.card(alice.aceId))
        // A new dlg replaces the signing key (say, stolen); the owner re-signs the card.
        clock.now += 10
        try alice.identity.delegate(now: clock.now, notAfter: nil)
        try await alice.network.maintain()
        // A relay replays the record signed under the superseded delegation, with the KEL prefix it verifies under.
        relay.setCard(alice.aceId, old)
        let bob = try await peer(relay, clock)
        #expect(try await bob.network.peers.pinned(alice.aceId) == nil)
        await expectCodeAsync(.stalePeerBinding) { try await bob.network.lookupCard(alice.aceId) }
        // The KEL was pinned from the descriptor lookup, before the card was checked.
        #expect(try await bob.network.peers.pinned(alice.aceId)?.events.count == alice.identity.getKel().count)
    }

    @Test func handleResolvingToANewAceIdIsInvalidAuthorization() async throws {
        let clock = TestClock(systemClock()), relay = FakeRelay(clock: clock.fn)
        let alice = try await peer(relay, clock, contact: .open, handle: "alice")
        let mallory = try await peer(relay, clock, contact: .open)
        let bob = try await peer(relay, clock)
        #expect(try await bob.network.lookupCard("@alice@\(relay.host)").aceId == alice.aceId)
        // The relay rebinds the handle to another identity (bindings are permanent: detectable misbehavior).
        relay.setCard(mallory.aceId, try card(mallory, home: relay.url, handle: "alice", contact: .open, now: clock.now + 1))
        relay.bindHandle("alice", to: mallory.aceId)
        await expectCodeAsync(.invalidAuthorization) { try await bob.network.lookupCard("@alice@\(relay.host)") }
        await expectCodeAsync(.invalidAuthorization) { try await bob.network.lookup("@alice@\(relay.host)") }
        // The reverse pin is durable.
        let again = try await NetworkClient.open(identity: bob.identity, store: bob.store, relay: try relay.client(clock: clock.fn),
                                                 prekeys: StorePrekeyVault(store: bob.store), receive: false, clock: clock.fn)
        await expectCodeAsync(.invalidAuthorization) { try await again.lookupCard("@alice@\(relay.host)") }
        await again.close()
    }

    @Test func refusedCardLeavesDescriptorUnpublished() async throws {
        let clock = TestClock(systemClock()), relay = FakeRelay(clock: clock.fn)
        _ = try await peer(relay, clock, handle: "alice")
        let id = try makeIdentity(now: clock.now), store = MemoryStore()
        let late = try await NetworkClient.open(identity: id, store: store, relay: try relay.client(clock: clock.fn),
                                                prekeys: StorePrekeyVault(store: store), configuration: NetworkConfiguration(handle: "alice"),
                                                receive: false, clock: clock.fn)
        await expectRelayCode("handle_taken") { try await late.publish() }
        #expect(relay.card(id.getACEId()) == nil)
        #expect(relay.publishedAgent(id.getACEId()) == nil)
        await late.close()
    }

    @Test func lookupCardFallsBackToTheBundleKelWhenNoLiveDescriptor() async throws {
        let clock = TestClock(systemClock()), relay = FakeRelay(clock: clock.fn)
        let alice = try await NetPeer.make(relay, clock: clock, configuration: NetworkConfiguration(handle: "alice", pay: [SOL], contact: .open))
        // Alice is offline past her descriptor's lifetime: the relay serves her card record but no descriptor.
        clock.now += 8 * 86_400
        await expectCodeAsync(.unknownPeer) { try await relay.client(clock: clock.fn).descriptor(alice.aceId) }
        for target in [alice.aceId, "@alice@\(relay.host)"] {
            let bob = try await peer(relay, clock)
            let v = try await bob.network.lookupCard(target)
            #expect(v.kelLive == false)
            #expect(v.aceId == alice.aceId && v.record.handle == "alice" && v.record.pay == [SOL])
            // The bundle's KEL is pinned, under the same rules as a descriptor's.
            #expect(try await bob.network.peers.pinned(alice.aceId)?.lastHash == (try ACEKel.verify(alice.identity.getKel(), now: clock.now)).lastHash)
            // The card pin still applies: a rollback is refused.
            relay.setCard(alice.aceId, try card(alice, home: relay.url, handle: "alice", contact: .closed, now: v.record.issuedAt - 1))
            await expectCodeAsync(.staleDescriptor) { try await bob.network.lookupCard(target) }
            relay.setCard(alice.aceId, v.bundle)
        }
        // Any other descriptor failure (here an unreachable relay) still fails the lookup, pinning nothing.
        let carol = try await peer(relay, clock)
        relay.withLock { relay.down = ["/v1/descriptor/\(alice.aceId)"] }
        do {
            _ = try await carol.network.lookupCard(alice.aceId)
            Issue.record("expected a failure")
        } catch let e as ACEError {
            #expect(e.code != .unknownPeer, "\(e)")
        }
        #expect(try await carol.network.peers.pinned(alice.aceId) == nil)
    }

    @Test func kelLiveIsTrueWithALiveDescriptor() async throws {
        let clock = TestClock(systemClock()), relay = FakeRelay(clock: clock.fn)
        let alice = try await peer(relay, clock, contact: .open, handle: "alice")
        let bob = try await peer(relay, clock)
        #expect(try await bob.network.lookupCard(alice.aceId).kelLive == true)
        let carol = try await peer(relay, clock)
        #expect(try await carol.network.lookupCard("@alice@\(relay.host)").kelLive == true)
    }

    @Test func unparseablePinIsStorageFailed() async throws {
        let clock = TestClock(systemClock()), relay = FakeRelay(clock: clock.fn)
        let alice = try await peer(relay, clock, contact: .open, handle: "alice")
        let bob = try await peer(relay, clock)
        _ = try await bob.network.lookupCard("@alice@\(relay.host)")
        // A damaged pin is a storage failure, never "no pin" (which would accept a rollback or a rebinding).
        let cardPin = "network/handles/\(sha256Hex(Data(alice.aceId.utf8))).json"
        let ownerPin = "network/handle-owners/\(sha256Hex(Data("\(relay.url) alice".utf8))).json"
        for key in [cardPin, ownerPin] {
            let good = try #require(try bob.store.read(key))
            for bad in ["not json", "[]", "null", "\"x\""] {
                try bob.store.checkedWrite(key, Data(bad.utf8))
                await expectCodeAsync(.storageFailed) { try await bob.network.lookupCard("@alice@\(relay.host)") }
            }
            try bob.store.checkedWrite(key, good)
        }
        #expect(try await bob.network.lookupCard("@alice@\(relay.host)").aceId == alice.aceId)
    }

    @Test func aNewDlgReSignsTheCardAtUpkeep() async throws {
        let clock = TestClock(systemClock()), relay = FakeRelay(clock: clock.fn)
        let alice = try await peer(relay, clock, contact: .open, handle: "alice")
        let bob = try await peer(relay, clock)
        let before = try await bob.network.lookupCard(alice.aceId).record.signature.seq
        clock.now += 10
        try alice.identity.delegate(now: clock.now, notAfter: nil)
        try await alice.network.maintain()
        let after = try await bob.network.lookupCard(alice.aceId)
        #expect(after.record.signature.seq > before)
        #expect(after.record.handle == "alice")
    }

    @Test func olderCardIsRejectedAfterANewerOne() async throws {
        let clock = TestClock(systemClock()), relay = FakeRelay(clock: clock.fn)
        let alice = try await peer(relay, clock, contact: .open, handle: "alice")
        let bob = try await peer(relay, clock)
        let seen = try await bob.network.lookupCard(alice.aceId)
        // A relay rolling back to an older record (contact closed) is refused on every path.
        relay.setCard(alice.aceId, try card(alice, home: relay.url, handle: "alice", pay: [SOL], now: seen.record.issuedAt - 1))
        await expectCodeAsync(.staleDescriptor) { try await bob.network.lookupCard(alice.aceId) }
        await expectCodeAsync(.staleDescriptor) { try await bob.network.lookupCard("@alice@\(relay.host)") }
        await expectCodeAsync(.staleDescriptor) { try await bob.network.lookup("@alice@\(relay.host)") }
    }

    @Test func equalIssuedAtWithDifferentClaimsIsRejected() async throws {
        let clock = TestClock(systemClock()), relay = FakeRelay(clock: clock.fn)
        let alice = try await peer(relay, clock, contact: .open, handle: "alice")
        let bob = try await peer(relay, clock)
        let seen = try await bob.network.lookupCard(alice.aceId)
        #expect(try await bob.network.lookupCard(alice.aceId).record == seen.record)  // the identical record again is fine
        relay.setCard(alice.aceId, try card(alice, home: relay.url, handle: "alice", contact: .open, listed: true, now: seen.record.issuedAt))
        await expectCodeAsync(.staleDescriptor) { try await bob.network.lookupCard(alice.aceId) }
    }

    @Test func newerCardUpdatesThePin() async throws {
        let clock = TestClock(systemClock()), relay = FakeRelay(clock: clock.fn)
        let alice = try await peer(relay, clock, contact: .open, handle: "alice")
        let bob = try await peer(relay, clock)
        let first = try #require(relay.card(alice.aceId))
        _ = try await bob.network.lookupCard(alice.aceId)
        let issued = try #require(first["card"]?["issuedAt"]?.wireInt)
        relay.setCard(alice.aceId, try card(alice, home: relay.url, handle: "alice", pay: [SOL], now: issued + 5))
        #expect(try await bob.network.lookupCard(alice.aceId).record.contact == .closed)
        // the pin moved to the newer record and persists in the store: the first one is now a rollback
        relay.setCard(alice.aceId, first)
        await expectCodeAsync(.staleDescriptor) { try await bob.network.lookupCard(alice.aceId) }
        let again = try await NetworkClient.open(identity: bob.identity, store: bob.store, relay: try relay.client(clock: clock.fn),
                                                 prekeys: StorePrekeyVault(store: bob.store), receive: false, clock: clock.fn)
        await expectCodeAsync(.staleDescriptor) { try await again.lookupCard(alice.aceId) }
        await again.close()
    }

    @Test func noCardMeansClosed() async throws {
        let clock = TestClock(systemClock()), relay = FakeRelay(clock: clock.fn)
        // Bob is configured open but has published only a descriptor, no card record.
        let bobId = try makeIdentity(now: clock.now)
        let bobStore = MemoryStore(), bobVault = StorePrekeyVault(store: bobStore)
        let bob = try await NetworkClient.open(identity: bobId, store: bobStore, relay: try relay.client(clock: clock.fn), prekeys: bobVault,
                                               configuration: NetworkConfiguration(contact: .open),
                                               foreignRelay: { _ in throw ACEError(.blockedAddress) }, clock: clock.fn)
        let prekey = try bobVault.rotate(now: clock.now).prekey
        try await bob.relay.register(bobId)
        let desc = try createPublishedAgent(identity: bobId, claims: DescriptorClaims(relays: [relay.url], prekey: prekey, profiles: bob.profiles.refs),
                                            now: clock.now)
        try await bob.relay.publish(desc)
        let alice = try await peer(relay, clock)
        try await alice.network.importAgent(desc.source)
        // connect refuses: no card record means closed
        await expectCodeAsync(.notPermitted) { try await alice.network.connect(bobId.getACEId(), profile: ProfileManifest.text.id) }
        // a stranger's contact request that reaches bob anyway is dropped by the endpoint
        let source = try await alice.network.publish()
        let content = try InstalledProfiles([.text]).content(type: CoreTypes.contact, body: [
            "kind": "request", "profile": .string(ProfileManifest.text.id), "note": "", "source": source.source,
            "permit": try createPermit(identity: alice.identity, subject: bobId.getACEId(), now: clock.now),
        ])
        let packet = try createPacket(sender: alice.identity, to: bobId.getACEId(), prekey: prekey, content: content, timestamp: clock.now)
        relay.inject(to: bobId.getACEId(), packet.jsonData())
        #expect(try await bob.pull() == [.dropped(.notPermitted)])
        #expect(try await bob.requests().isEmpty)
        await bob.close()
    }

    @Test func aClosedAgentCanStillConnectToAnOpenOwner() async throws {
        let clock = TestClock(systemClock()), relay = FakeRelay(clock: clock.fn)
        let b = try await peer(relay, clock, contact: .open)
        let a = try await peer(relay, clock)  // closed by default
        try await a.network.connect(b.aceId, profile: ProfileManifest.text.id)
        _ = try await b.network.pull()
        #expect(try await b.network.requests().map(\.from) == [a.aceId])
        // and the closed one is not reachable by strangers
        await expectCodeAsync(.notPermitted) { try await b.network.connect(a.aceId, profile: ProfileManifest.text.id) }
    }
}
