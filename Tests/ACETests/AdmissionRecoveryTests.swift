import CryptoKit
import Foundation
import Testing
@testable import ACE

/// 05 § Admission recovery: an endpoint that lost its state but kept its identity recovers an admitted peer from the
/// permit that peer presents on its next retry.
@Suite struct AdmissionRecoveryTests {
    /// Alice and Bob paired and exchanged a message; Bob then lost his store (a reinstall) and came back `closed`.
    private func reinstalled(_ relay: FakeRelay, _ clock: TestClock) async throws -> (alice: NetPeer, bob: NetPeer) {
        let (alice, bob) = try await connectedText(relay, clock)
        _ = try await alice.network.send(to: bob.aceId, type: "ace:text:1", body: ["message": "before"])
        guard case .delivered? = try await bob.network.pull().first else { throw ACEError(.storageFailed, "not delivered") }
        _ = try await alice.network.pull()
        await bob.network.close()
        clock.now += 10
        let again = try await NetPeer.reopen(bob.identity, relay, clock: clock, configuration: NetworkConfiguration(contact: .closed, listed: false))
        return (alice, again)
    }

    @Test func aRetryRestoresTheLostAdmissionBothWays() async throws {
        let clock = TestClock(systemClock()), relay = FakeRelay(clock: clock.fn)
        let (alice, bob) = try await reinstalled(relay, clock)
        #expect(try bob.network.admission.get(alice.aceId) == nil)
        // The first attempt goes to the prekey Bob lost: dropped, unreceipted.
        let entry = try await alice.network.send(to: bob.aceId, type: "ace:text:1", body: ["message": "after"])
        #expect(try await bob.network.pull() == [.dropped(.unknownPrekey)])
        // The retry refreshes Bob's descriptor and carries `admission`.
        clock.now += 61
        _ = try await alice.network.flush()
        guard case .delivered(let m)? = try await bob.network.pull().first else { Issue.record("retry not delivered"); return }
        #expect(m.body["message"] == "after" && m.content.admission == nil)
        #expect(bob.received.value.map(\.content.admission) == [nil])
        #expect(try bob.network.admission.get(alice.aceId)?.state == .admitted)
        #expect(try bob.network.admission.get(alice.aceId)?.profile == nil)
        #expect(try bob.network.admission.heldPermit(alice.aceId) != nil)
        // the proof is recorded as issued: the receipt needs no renewal
        #expect(try bob.network.admission.get(alice.aceId)?.issuedPermit == alice.network.admission.heldPermit(bob.aceId))
        _ = try await alice.network.pull()
        #expect(try await alice.network.outbox.entry(entry.messageId)?.status == .delivered)
        // Bob holds Alice's reply permit: he reaches her again.
        let reply = try await bob.network.send(to: alice.aceId, type: "ace:text:1", body: ["message": "back"])
        #expect(reply.lastError == nil)
        guard case .delivered? = try await alice.network.pull().first else { Issue.record("reply not delivered"); return }
    }

    @Test func aFirstAttemptCarriesNoAdmission() async throws {
        let clock = TestClock(systemClock()), relay = FakeRelay(clock: clock.fn)
        let (alice, bob) = try await reinstalled(relay, clock)
        _ = try await alice.network.agent(bob.aceId, refresh: true)  // Bob's new prekey: the first attempt is readable
        _ = try await alice.network.send(to: bob.aceId, type: "ace:text:1", body: ["message": "first"])
        #expect(try await bob.network.pull() == [.dropped(.notPermitted)])
        #expect(try bob.network.admission.get(alice.aceId) == nil)
    }

    /// A packet carrying `admission` built by hand: `proof`, `permit` and `source` as given, signed by `signer` naming `from`.
    private func packet(from: String, signer: any ACEIdentity, to bob: NetPeer, proof: JSONValue, permit: JSONValue,
                        source: JSONValue, clock: TestClock, network: NetworkClient) async throws -> Data {
        let agent = try await network.agent(bob.aceId, refresh: true)
        let content = try network.profiles.content(type: "ace:text:1", body: ["message": "x"]).with(prekey: somePrekey())
            .with(admission: Admission(proof: proof, permit: permit, source: source))
        guard from != signer.getACEId() else {
            return try createPacket(sender: signer, to: bob.aceId, prekey: agent.descriptor.prekey, content: content, timestamp: clock.now).jsonData()
        }
        let r = try XWingMLKEM768X25519.PublicKey(rawRepresentation: agent.descriptor.prekey.publicKey).encapsulate()
        return try sealPacket(sender: signer, from: from, to: bob.aceId, messageId: UUID().uuidString.lowercased(), timestamp: clock.now,
                              prekey: agent.descriptor.prekey.id, plaintext: try content.jsonData(), sharedSecret: r.sharedSecret,
                              kemCiphertext: Data(r.encapsulated)).jsonData()
    }

    @Test func aProofBobDidNotIssueToTheSenderAdmitsNothing() async throws {
        let clock = TestClock(systemClock()), relay = FakeRelay(clock: clock.fn)
        let (alice, bob) = try await reinstalled(relay, clock)
        let mallory = try await NetPeer.make(relay, clock: clock)
        let toAlice = try #require(try alice.network.admission.heldPermit(bob.aceId))  // issued by Bob to Alice
        let reply = try createPermit(identity: mallory.identity, subject: bob.aceId, now: clock.now)
        let data = try await packet(from: mallory.aceId, signer: mallory.identity, to: bob, proof: toAlice, permit: reply,
                                    source: try await mallory.network.publish().source, clock: clock, network: mallory.network)
        #expect(await bob.network.inbox!.receive(data) == .dropped(.notPermitted))
        #expect(try bob.network.admission.get(mallory.aceId) == nil && bob.received.value.isEmpty)
    }

    @Test func aLeakedProofOnAForgedPacketAdmitsNothing() async throws {
        let clock = TestClock(systemClock()), relay = FakeRelay(clock: clock.fn)
        let (alice, bob) = try await reinstalled(relay, clock)
        let mallory = try await NetPeer.make(relay, clock: clock)
        let leaked = try #require(try alice.network.admission.heldPermit(bob.aceId))
        let reply = try createPermit(identity: alice.identity, subject: bob.aceId, now: clock.now)
        let data = try await packet(from: alice.aceId, signer: mallory.identity, to: bob, proof: leaked, permit: reply,
                                    source: try await alice.network.publish().source, clock: clock, network: mallory.network)
        #expect(await bob.network.inbox!.receive(data) == .dropped(.invalidSignature))
        #expect(try bob.network.admission.get(alice.aceId) == nil)
        #expect(try bob.network.admission.heldPermit(alice.aceId) == nil)
        // nothing is pinned, and a repeated forgery is a drop again (no lookup to rate-limit)
        #expect(try await bob.network.peers.pinned(alice.aceId) == nil)
        #expect(await bob.network.inbox!.receive(data) == .dropped(.invalidSignature))
    }

    @Test func aSourceNamingAnotherAgentAdmitsNothing() async throws {
        let clock = TestClock(systemClock()), relay = FakeRelay(clock: clock.fn)
        let (alice, bob) = try await reinstalled(relay, clock)
        let mallory = try await NetPeer.make(relay, clock: clock)
        let proof = try #require(try alice.network.admission.heldPermit(bob.aceId))
        let reply = try createPermit(identity: alice.identity, subject: bob.aceId, now: clock.now)
        let data = try await packet(from: alice.aceId, signer: alice.identity, to: bob, proof: proof, permit: reply,
                                    source: try await mallory.network.publish().source, clock: clock, network: alice.network)
        #expect(await bob.network.inbox!.receive(data) == .dropped(.invalidAuthorization))
        #expect(try bob.network.admission.get(alice.aceId) == nil)
        #expect(try await bob.network.peers.pinned(alice.aceId) == nil)
    }

    @Test func anInvalidReplyPermitAdmitsNothing() async throws {
        let clock = TestClock(systemClock()), relay = FakeRelay(clock: clock.fn)
        let (alice, bob) = try await reinstalled(relay, clock)
        let proof = try #require(try alice.network.admission.heldPermit(bob.aceId))
        let wrong = try createPermit(identity: alice.identity, subject: try makeIdentity(now: clock.now).getACEId(), now: clock.now)
        let data = try await packet(from: alice.aceId, signer: alice.identity, to: bob, proof: proof, permit: wrong,
                                    source: try await alice.network.publish().source, clock: clock, network: alice.network)
        #expect(await bob.network.inbox!.receive(data) == .dropped(.invalidAuthorization))
        #expect(try bob.network.admission.get(alice.aceId) == nil)
    }

    @Test func aBlockedSenderIsNotRecovered() async throws {
        let clock = TestClock(systemClock()), relay = FakeRelay(clock: clock.fn)
        let (alice, bob) = try await reinstalled(relay, clock)
        try await bob.network.block(alice.aceId)
        let proof = try #require(try alice.network.admission.heldPermit(bob.aceId))
        let reply = try createPermit(identity: alice.identity, subject: bob.aceId, now: clock.now)
        let data = try await packet(from: alice.aceId, signer: alice.identity, to: bob, proof: proof, permit: reply,
                                    source: try await alice.network.publish().source, clock: clock, network: alice.network)
        #expect(await bob.network.inbox!.receive(data) == .dropped(.notPermitted))
        #expect(try bob.network.admission.get(alice.aceId)?.state == .blocked)
    }

    @Test func anUninstalledTypeIsDroppedBeforeAnyLookup() async throws {
        let clock = TestClock(systemClock()), relay = FakeRelay(clock: clock.fn)
        let (alice, bob) = try await reinstalled(relay, clock)
        let proof = try #require(try alice.network.admission.heldPermit(bob.aceId))
        let reply = try createPermit(identity: alice.identity, subject: bob.aceId, now: clock.now)
        let agent = try await alice.network.agent(bob.aceId, refresh: true)
        let content = try PrivateContent(type: "urn:example:other:1", schemaDigest: String(repeating: "a", count: 64), body: [:]).with(prekey: somePrekey())
            .with(admission: Admission(proof: proof, permit: reply, source: try await alice.network.publish().source))
        let p = try createPacket(sender: alice.identity, to: bob.aceId, prekey: agent.descriptor.prekey, content: content, timestamp: clock.now)
        #expect(await bob.network.inbox!.receive(p.jsonData()) == .dropped(.unsupportedSchema))
        #expect(try await bob.network.peers.pinned(alice.aceId) == nil)
    }

    /// A receipt carrying `admission` is `invalid_body` before any state is written (03 § Private content).
    @Test func aReceiptCarryingAdmissionRecoversNothing() async throws {
        let clock = TestClock(systemClock()), relay = FakeRelay(clock: clock.fn)
        let (alice, bob) = try await reinstalled(relay, clock)
        let proof = try #require(try alice.network.admission.heldPermit(bob.aceId))
        let reply = try createPermit(identity: alice.identity, subject: bob.aceId, now: clock.now)
        let agent = try await alice.network.agent(bob.aceId, refresh: true)
        let content = try alice.network.profiles.content(type: CoreTypes.receipt, body: ["messageId": .string(UUID().uuidString.lowercased()),
                                                                                          "outcome": "delivered"]).with(prekey: somePrekey())
            .with(admission: Admission(proof: proof, permit: reply, source: try await alice.network.publish().source))
        let p = try createPacket(sender: alice.identity, to: bob.aceId, prekey: agent.descriptor.prekey, content: content, timestamp: clock.now)
        #expect(await bob.network.inbox!.receive(p.jsonData()) == .dropped(.invalidBody))
        #expect(try bob.network.admission.get(alice.aceId) == nil)
        #expect(try await bob.network.peers.pinned(alice.aceId) == nil)
    }

    @Test func receiptsAndContactsCarryNoAdmission() throws {
        let c = try PrivateContent(type: CoreTypes.receipt, schemaDigest: String(repeating: "0", count: 64),
                                   body: ["messageId": .string(UUID().uuidString.lowercased()), "outcome": "delivered"]).with(prekey: somePrekey())
        let text = try PrivateContent(type: "ace:text:1", schemaDigest: String(repeating: "0", count: 64), body: [:]).with(prekey: somePrekey())
        #expect(try PrivateContent(json: try text.with(admission: Admission(proof: ["a": 1], permit: ["b": 2], source: ["c": 3])).jsonData())
            .admission != nil)  // decoding checks the shape only; 05 checks the permits
        let raw = try c.with(admission: Admission(proof: ["a": 1], permit: ["b": 2], source: ["c": 3])).jsonData()
        #expect(throws: ACEError.self) { try PrivateContent(json: raw) }  // 03: a core packet carrying it is invalid_body
        for bad: JSONValue in [.null, ["proof": ["a": 1], "permit": ["b": 2]], ["proof": ["a": 1], "permit": ["b": 2], "source": ["c": 3], "x": [:]],
                               ["proof": "p", "permit": ["b": 2], "source": ["c": 3]]] {
            var o = try #require(text.jsonValue.objectValue)
            o["admission"] = bad
            #expect(throws: ACEError.self) { try PrivateContent(json: try JSONValue.object(o).jsonData()) }
        }
    }

    /// 05 § Blocks: a decision after the block records were lost still outranks the relay's stored revision.
    @Test func aBlockAfterAReinstallOutranksTheLostRevisions() async throws {
        let clock = TestClock(systemClock()), relay = FakeRelay(clock: clock.fn)
        let alice = try await NetPeer.make(relay, clock: clock)
        var bob = try await NetPeer.make(relay, clock: clock)
        _ = try await bob.network.lookup(alice.aceId)
        try await bob.network.block(alice.aceId)
        clock.now += 1
        try await bob.network.unblock(alice.aceId)
        #expect(relay.blocked(by: bob.aceId, alice.aceId) == false)
        await bob.network.close()
        clock.now += 10
        bob = try await NetPeer.reopen(bob.identity, relay, clock: clock)
        try await bob.network.block(alice.aceId)
        #expect(relay.blocked(by: bob.aceId, alice.aceId) == true)
        #expect(try bob.network.admission.unsyncedBlocks().isEmpty)
    }
}
