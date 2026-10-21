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
        #expect(try await client.handle("alice").aceId == alice.aceId)
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
        #expect(try await client.card(alice.aceId).record.home == "https://relay-b.test")
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
        // Hosts tell this refusal apart without parsing messages: an SDK-local reason, same wire code.
        do { _ = try await bob.network.lookupCard("@alice@\(relay.host)"); Issue.record("expected a refusal") } catch let e as ACEError {
            #expect(e.code == .invalidAuthorization && e.reason == .handleRebound)
        }
        // Other refusals carry no reason.
        #expect(ACEError(.invalidAuthorization).reason == nil)
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

    private func reopened(_ who: NetPeer, _ relay: FakeRelay, _ clock: TestClock) async throws -> NetworkClient {
        try await NetworkClient.open(identity: who.identity, store: who.store, relay: try relay.client(clock: clock.fn),
                                     prekeys: StorePrekeyVault(store: who.store), receive: false, clock: clock.fn)
    }

    @Test func fallbackPinnedKelStaysKelLiveFalseOnLaterLookups() async throws {
        let clock = TestClock(systemClock()), relay = FakeRelay(clock: clock.fn)
        let alice = try await peer(relay, clock, contact: .open, handle: "alice")
        clock.now += 8 * 86_400
        let bob = try await peer(relay, clock)
        #expect(try await bob.network.lookupCard(alice.aceId).kelLive == false)
        // The pin exists now, but no live descriptor ever confirmed it: every later lookup says so, durably.
        #expect(try await bob.network.lookupCard(alice.aceId).kelLive == false)
        #expect(try await bob.network.lookupCard("@alice@\(relay.host)").kelLive == false)
        let again = try await reopened(bob, relay, clock)
        #expect(try await again.lookupCard(alice.aceId).kelLive == false)
        await again.close()
    }

    @Test func aLaterLiveDescriptorConfirmsAFallbackPinnedKel() async throws {
        let clock = TestClock(systemClock()), relay = FakeRelay(clock: clock.fn)
        let alice = try await peer(relay, clock, contact: .open, handle: "alice")
        clock.now += 8 * 86_400
        let bob = try await peer(relay, clock)
        #expect(try await bob.network.lookupCard("@alice@\(relay.host)").kelLive == false)
        // Alice comes back online: her new descriptor reconciles with the pin and confirms it.
        try await alice.network.publish()
        #expect(try await bob.network.lookupCard("@alice@\(relay.host)").kelLive == true)
        // Confirmed for good, durably: even after she goes offline again.
        clock.now += 8 * 86_400
        #expect(try await bob.network.lookupCard(alice.aceId).kelLive == true)
        let again = try await reopened(bob, relay, clock)
        #expect(try await again.lookupCard(alice.aceId).kelLive == true)
        await again.close()
    }

    @Test func transientOnOneRoutePlusUnknownPeerOnAnotherDoesNotFallBack() async throws {
        let clock = TestClock(systemClock()), relay = FakeRelay(clock: clock.fn), relayB = FakeRelay(clock: clock.fn)
        let alice = try await peer(relay, clock, contact: .open)
        let path = "/v1/descriptor/\(alice.aceId)"
        func expectTransient(_ body: () async throws -> VerifiedCard) async {
            do {
                _ = try await body()
                Issue.record("expected a transient failure")
            } catch let e as ACEError {
                #expect(e.isTransient, "\(e)")
            } catch { Issue.record("\(error)") }
        }
        // Without a pin, an unreachable home relay is a failure, never "no live descriptor".
        let carol = try await peer(relay, clock)
        relay.withLock { relay.down = [path] }
        await expectTransient { try await carol.network.lookupCard(alice.aceId) }
        #expect(try await carol.network.peers.pinned(alice.aceId) == nil)
        relay.withLock { relay.down = [] }
        // Alice's descriptor names relay B first; her home relay has lost it, so bob pins her card's KEL.
        let own = try #require(relay.publishedAgent(alice.aceId))
        let twoRoutes = try createPublishedAgent(identity: alice.identity, claims: DescriptorClaims(
            relays: [relayB.url, relay.url], prekey: own.descriptor.prekey, profiles: [ProfileManifest.text.ref]), now: clock.now)
        relay.dropAgent(alice.aceId)
        let store = MemoryStore()
        let bob = try await NetworkClient.open(identity: try makeIdentity(now: clock.now), store: store, relay: try relay.client(clock: clock.fn),
                                               prekeys: StorePrekeyVault(store: store), receive: false,
                                               foreignRelay: { _ in try relayB.client(clock: clock.fn) }, clock: clock.fn)
        #expect(try await bob.lookupCard(alice.aceId).kelLive == false)
        _ = try await bob.importAgent(twoRoutes.source)  // shared out of band; it expires before bob looks again
        // Self-signed, not served by a relay: it does not confirm the pin.
        #expect(try await bob.peers.kelLive(alice.aceId) == false)
        // Nor does a card lookup take that cached, still usable descriptor for a live one: it asks the relays.
        #expect(try await bob.lookupCard(alice.aceId).kelLive == false)
        clock.now += 8 * 86_400
        // Relay B is unreachable and the home relay answers unknown_peer: the lookup fails instead of reporting not live.
        relayB.withLock { relayB.down = [path] }
        await expectTransient { try await bob.lookupCard(alice.aceId) }
        // Both routes answering unknown_peer: no live descriptor, still not confirmed.
        relayB.withLock { relayB.down = [] }
        #expect(try await bob.lookupCard(alice.aceId).kelLive == false)
        await bob.close()
    }

    @Test func aHandleLookupReusesTheCardRecordItResolvedThrough() async throws {
        let clock = TestClock(systemClock()), relay = FakeRelay(clock: clock.fn)
        let alice = try await peer(relay, clock, contact: .open, handle: "alice")
        let bob = try await peer(relay, clock)
        let start = relay.requestCount
        let found = try await bob.network.lookupWithCard("@alice@\(relay.host)")
        #expect(found.card?.record.contact == .open)
        #expect(found.card?.kelLive == true)
        try await bob.network.connect("@alice@\(relay.host)", profile: ProfileManifest.text.id)
        let paths = relay.withLock { Array(relay.requests[start...]) }
        #expect(paths.filter { $0.hasPrefix("GET /v1/card/") }.isEmpty)
        #expect(paths.filter { $0.hasPrefix("GET /v1/handles/") }.count == 2)
        // By ACE ID, the card record is looked up after the descriptor.
        #expect(try await bob.network.lookupWithCard(alice.aceId).card?.record.handle == "alice")
    }

    @Test func aRelayServingAnUnverifiableDocumentIsRelayProtocolErrorNeverAVerdictOnThePeer() async throws {
        let clock = TestClock(systemClock()), relay = FakeRelay(clock: clock.fn)
        let alice = try await peer(relay, clock, contact: .open, handle: "alice")
        let card = try #require(relay.card(alice.aceId))
        relay.setCard(alice.aceId, withRecord(card, ["listed": true]))  // the signature no longer verifies
        let client = try relay.client(clock: clock.fn)
        await expectCodeAsync(.relayProtocolError) { try await client.card(alice.aceId) }
        await expectCodeAsync(.relayProtocolError) { try await client.handle("alice") }
        // A tampered descriptor too, with the verifier's reason kept.
        let source = try #require(relay.publishedAgent(alice.aceId)).source
        var d = try #require(source["descriptor"]?.objectValue)
        d["expiresAt"] = .number(Double(clock.now + 3600))
        let tampered: JSONValue = ["kel": source["kel"]!, "descriptor": .object(d)]
        let stub = try makeRelay({ _, _ in .json(200, tampered) }, clock: clock.fn)
        do {
            _ = try await stub.descriptor(alice.aceId)
            Issue.record("expected relay_protocol_error")
        } catch let e as ACEError {
            #expect(e.code == .relayProtocolError && e.message.hasPrefix("relay served an invalid descriptor: "), "\(e)")
        }
    }

    @Test func acceptingARequestWhoseSourceExpiredPinsItsKelAsNotConfirmedLiveUntilADescriptorConfirmsIt() async throws {
        let clock = TestClock(systemClock()), relay = FakeRelay(clock: clock.fn)
        let alice = try await peer(relay, clock, contact: .open)
        let bob = try await peer(relay, clock)
        clock.now = try await bob.network.publish().descriptor.expiresAt - 3601
        try await bob.network.connect(alice.aceId, profile: ProfileManifest.text.id)
        _ = try await alice.network.pull()
        #expect(try await alice.network.requests().map(\.from) == [bob.aceId])
        // Bob goes offline past his descriptor's lifetime: the held request outlives its source.
        clock.now += 7200
        relay.dropAgent(bob.aceId)
        await expectCodeAsync(.unknownPeer) { try await alice.network.accept(bob.aceId) }
        #expect(try await alice.network.peers.pinned(bob.aceId) != nil)
        #expect(try await alice.network.lookupCard(bob.aceId).kelLive == false)
        // Bob republishes: the next card lookup sees a live descriptor and confirms the pin, durably.
        try await bob.network.publish()
        #expect(try await alice.network.lookupCard(bob.aceId).kelLive == true)
        relay.dropAgent(bob.aceId)
        #expect(try await alice.network.lookupCard(bob.aceId).kelLive == true)
    }

    @Test func pinMissingRequiredFieldsIsStorageFailed() async throws {
        let clock = TestClock(systemClock()), relay = FakeRelay(clock: clock.fn)
        let alice = try await peer(relay, clock, contact: .open, handle: "alice")
        let bob = try await peer(relay, clock)
        let seen = try await bob.network.lookupCard("@alice@\(relay.host)")
        let cardPin = "network/handles/\(sha256Hex(Data(alice.aceId.utf8))).json"
        let ownerPin = "network/handle-owners/\(sha256Hex(Data("\(relay.url) alice".utf8))).json"
        let full: [String: JSONValue] = ["home": .string(relay.url), "handle": "alice", "issuedAt": .number(Double(seen.record.issuedAt)), "digest": "x"]
        var cases: [(String, JSONValue)] = [(cardPin, .object([:]))]
        for missing in ["issuedAt", "digest", "home"] { cases.append((cardPin, .object(full.filter { $0.key != missing }))) }
        cases.append((ownerPin, ["home": .string(relay.url), "handle": "alice"]))
        for (key, bad) in cases {
            let good = try #require(try bob.store.read(key))
            try bob.store.checkedWrite(key, try bad.jsonData())
            await expectCodeAsync(.storageFailed) { try await bob.network.lookupCard("@alice@\(relay.host)") }
            try bob.store.checkedWrite(key, good)
        }
        // A peer pin whose `kelLive` is not a boolean.
        clock.now += 8 * 86_400
        let carol = try await peer(relay, clock)
        #expect(try await carol.network.lookupCard(alice.aceId).kelLive == false)
        let peerPin = "peers/\(sha256Hex(Data(alice.aceId.utf8))).json"
        let raw = try #require(try carol.store.read(peerPin))
        var row = try #require(JSONValue(stored: raw)?.objectValue)
        row["kelLive"] = "no"
        try carol.store.checkedWrite(peerPin, try JSONValue.object(row).jsonData())
        await expectCodeAsync(.storageFailed) { try await carol.network.lookupCard(alice.aceId) }
    }

    @Test func aRelayServedDescriptorFromAnyLookupConfirmsAFallbackPinnedKel() async throws {
        let clock = TestClock(systemClock()), relay = FakeRelay(clock: clock.fn)
        let alice = try await peer(relay, clock, contact: .open, handle: "alice")
        clock.now += 8 * 86_400
        let bob = try await peer(relay, clock)
        #expect(try await bob.network.lookupCard(alice.aceId).kelLive == false)
        // Alice is back: bob's plain descriptor lookup fetches it from her relay and confirms the pin, so the next card
        // lookup needs no descriptor request of its own (one would fail here).
        try await alice.network.publish()
        try await bob.network.agent(alice.aceId)
        #expect(try await bob.network.peers.kelLive(alice.aceId) == true)
        relay.dropAgent(alice.aceId)
        #expect(try await bob.network.lookupCard(alice.aceId).kelLive == true)
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
