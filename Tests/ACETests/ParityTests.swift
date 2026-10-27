//
//  ParityTests.swift
//  Behaviour shared with sdk-ts / sdk-py (their security and pipeline tests) and the 2026-10-13 revision § 12 items.
//

import Foundation
import Testing
@testable import ACE

@Suite struct ParityTests {
    /// A vault configured for Secure Enclave protection never opens a seed stored in clear (no silent downgrade).
    @Test func secureEnclaveVaultFailsClosedOnPlaintextSeeds() throws {
        let store = MemoryStore()
        let planted = try StorePrekeyVault(store: store, protection: .software).rotate(now: NOW)
        let sealed = StorePrekeyVault(store: store, protection: .secureEnclave)
        expectCode(.storageFailed) { try sealed.open(planted.prekey.id, now: NOW) }
        #expect(try StorePrekeyVault(store: store).open(planted.prekey.id, now: NOW)?.count == 32)
    }

    @Test func corruptRecordsAreStorageFailures() async throws {
        let store = MemoryStore(), table = AdmissionTable(store: store)
        let peer = "ace:sha256:" + String(repeating: "a", count: 64)
        try table.update(peer) { _ in AdmissionRecord(aceId: peer, state: .admitted, updatedAt: 0) }
        let key = try #require(try store.list(prefix: "admission/").first)
        for bad: JSONValue in [
            ["version": 1, "aceId": .string(peer), "state": "admitted", "updatedAt": 0, "profile": 5],
            ["version": 1, "aceId": .string(peer), "state": "admitted", "updatedAt": 0, "theirPermit": "x"],  // a removed member
            ["version": 1, "aceId": .string(peer), "state": "admitted", "updatedAt": 0, "issuedPermit": "x"],
            ["version": 1, "aceId": .string(peer), "state": "admitted"],
            ["version": 1, "aceId": .string("ace:sha256:" + String(repeating: "b", count: 64)), "state": "admitted", "updatedAt": 0],
            ["version": 1, "aceId": .string(peer), "state": "friend", "updatedAt": 0],
        ] {
            try store.write(key, try bad.jsonData())
            expectCode(.storageFailed, "\(bad)") { try table.get(peer) }
            expectCode(.storageFailed, "\(bad)") { try table.all() }
        }
        // an outbox entry with a malformed optional member
        let me = try makeIdentity(now: NOW)
        let outbox = Outbox(identity: me, store: store, profiles: try InstalledProfiles([.text]), clock: { NOW })
        let e = try await outbox.enqueue(to: peer, type: "ace:text:1", body: ["message": "x"])
        let raw = try #require(try store.read("outbox/\(e.messageId).json"))
        guard case .object(var o) = try JSONValue(json: raw) else { Issue.record("not an object"); return }
        o["lastPrekey"] = 7
        try store.write("outbox/\(e.messageId).json", try JSONValue.object(o).jsonData())
        await expectCodeAsync(.storageFailed) { try await outbox.entry(e.messageId) }
        // a peer row whose agent is not an object
        let peers = PeerStore(store: store, clock: { NOW })
        let a = try TestAgent(now: NOW)
        try await peers.adopt(a.agent)
        let peerKey = try #require(try store.list(prefix: "peers/").first)
        guard case .object(var row) = try JSONValue(json: try #require(try store.read(peerKey))) else { return }
        row["agent"] = ["descriptor": "nope"]
        try store.write(peerKey, try JSONValue.object(row).jsonData())
        await expectCodeAsync(.storageFailed) { try await peers.agent(a.aceId) }
    }

    @Test func permitMustMatchThePacket() async throws {
        let alice = try TestAgent(now: NOW), bob = try TestAgent(now: NOW), carol = try TestAgent(now: NOW)
        let relay = try makeRelay({ _, _ in .json(200, ["ok": true] as JSONValue) }, clock: { NOW })
        let content = try InstalledProfiles([.text]).content(type: "ace:text:1", body: ["message": "x"]).with(prekey: somePrekey())
        let packet = try createPacket(sender: alice.identity, to: bob.aceId, prekey: bob.agent.descriptor.prekey, content: content, timestamp: NOW)
        let good = try createPermit(identity: bob.identity, subject: alice.aceId, now: NOW)
        try await relay.send(packet, permit: good)
        let foreign = try createPermit(identity: carol.identity, subject: alice.aceId, now: NOW)
        await expectCodeAsync(.invalidArgument) { try await relay.send(packet, permit: foreign) }
        let other = try createPermit(identity: bob.identity, subject: carol.aceId, now: NOW)
        await expectCodeAsync(.invalidArgument) { try await relay.send(packet, permit: other) }
    }

    /// `GET /v1/descriptor` serves any registered identity's descriptor (no visibility); one of another identity is
    /// `relay_protocol_error`.
    @Test func anonymousLookupsServeAnyDescriptor() async throws {
        let open = try TestAgent(now: NOW), other = try TestAgent(now: NOW)
        let relay = try makeRelay({ _, _ in .json(200, open.agent.source) }, clock: { NOW })
        #expect(try await relay.descriptor(open.aceId).aceId == open.aceId)
        await expectCodeAsync(.relayProtocolError) { try await relay.descriptor(other.aceId) }
    }

    @Test func profileRuleCodesArePermanentOutcomeCodes() {
        let e = ACEError(rule: "too_expensive", "price above budget")
        #expect(e.code == .ruleRejected && e.outcomeCode == "too_expensive" && e.category == .permanent)
        #expect(e != ACEError(rule: "other_code"))
        #expect(ACEError(rule: "wrong_role").code == .wrongRole)
        #expect(ACEError(rule: "Bad-Code").code == .invalidArgument)
        #expect(ACEError.Code.threadBusy.category == .local)
    }

    /// Registration ordering survives a new process (a second RelayClient over the same store).
    @Test func registrationTimestampsPersistAcrossClients() async throws {
        let host = uniqueHost(), seen = LockedValue<[Int]>([])
        StubURLProtocol.register(host: host) { req, body in
            if let ts = (try? JSONValue(json: body))?["timestamp"]?.intValue { seen.value.append(ts) }
            return .json(200, ["status": "registered"] as JSONValue)
        }
        let store = MemoryStore(), me = try makeIdentity(now: NOW)
        for _ in 0..<2 {
            let client = try RelayClient(baseURL: URL(string: "https://\(host)")!, session: stubSession(), timeout: 5, maxResponseBytes: 1 << 20,
                                         clock: { NOW }, sleeper: { _ in }, store: store)
            try await client.register(me)
        }
        #expect(seen.value == [NOW, NOW + 1])
    }

    /// Outbox: a peer we hold no permit from (here: unknown everywhere) fails at once (`not_permitted`) and is never staged.
    @Test func sendToAnUnresolvablePeerFailsAtOnce() async throws {
        let clock = TestClock(systemClock()), relay = FakeRelay(clock: clock.fn)
        let alice = try await NetPeer.make(relay, clock: clock)
        let ghost = "ace:sha256:" + String(repeating: "c", count: 64)
        await expectCodeAsync(.notPermitted) { try await alice.network.send(to: ghost, type: "ace:text:1", body: ["message": "x"]) }
        #expect(try await alice.network.outbox.entries().isEmpty)
    }

    /// `createInvitation` (permit + own descriptor) lets one peer reach a `closed` agent; `importInvitation` pins the
    /// inviter and holds the permit but never admits it.
    @Test func invitationsReachAClosedAgent() async throws {
        let clock = TestClock(systemClock()), relay = FakeRelay(clock: clock.fn)
        let carol = try await NetPeer.make(relay, clock: clock, configuration: NetworkConfiguration())
        let bob = try await NetPeer.make(relay, clock: clock)
        let invitation = try await carol.network.createInvitation(peer: bob.aceId)
        #expect(Set(invitation.jsonValue.objectValue!.keys) == ["agent", "permit"])
        #expect(try carol.network.admission.get(bob.aceId)?.state == .admitted)
        let inviter = try await bob.network.importInvitation(invitation)
        #expect(inviter.aceId == carol.aceId)
        #expect(try await bob.network.lookupCard(carol.aceId).record.contact == .closed)
        #expect(try bob.network.admission.get(carol.aceId) == nil)  // never admits
        #expect(try bob.network.admission.heldPermit(carol.aceId)?["subject"]?.stringValue == bob.aceId)
        await expectCodeAsync(.invalidAuthorization) {  // a permit for someone else is refused
            try await carol.network.importInvitation(try Invitation(invitation.jsonValue))
        }
        try await bob.network.connect(inviter.aceId, profile: "ace:text:1", note: "hello")
        _ = try await carol.network.pull()  // admitted: auto-accepted
        _ = try await bob.network.pull()
        #expect(try bob.network.admission.get(carol.aceId)?.state == .admitted)
        let entry = try await bob.network.send(to: carol.aceId, type: "ace:text:1", body: ["message": "hi carol"])
        _ = try await carol.network.pull()
        #expect(carol.received.value.map { $0.body["message"] } == ["hi carol"])
        _ = try await bob.network.pull()
        #expect(try await bob.network.outbox.entry(entry.messageId)?.status == .delivered)
    }
}
