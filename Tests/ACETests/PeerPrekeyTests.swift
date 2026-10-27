//
//  PeerPrekeyTests.swift
//  04 § Peer prekeys: the vault's per-peer surface, and end to end (06 § Outbox step 2, § Receipts, § Receive pipeline).
//

import CryptoKit
import Foundation
import Testing
@testable import ACE

/// Secure Enclave–sealed seeds under `ACE_KEY_PROVIDER=secure-enclave`, else software.
let testPrekeyProtection: PrekeyProtection = testKeyProvider == "secure-enclave" ? .secureEnclave : .software

private let T = 1_760_140_800
private let W = ACELimits.offlineWindowSeconds
private func peerId(_ name: String) -> String { "ace:sha256:" + sha256Hex(Data(name.utf8)) }
private let A = peerId("alice"), B = peerId("bob")
private let PIN = String(repeating: "a", count: 64), OTHER_PIN = String(repeating: "b", count: 64)

private func freshKey() throws -> Prekey { try Prekey(publicKey: somePrekey()) }

/// A valid ML-KEM-768 half followed by an all-zero X25519 half.
private func zeroX25519Key() -> Data { somePrekey().prefix(1184) + Data(count: 32) }

private func publicKey(_ seed: Data?) throws -> Data { try XWing.publicKey(fromSeed: try #require(seed)) }

@Suite struct PeerPrekeyVaultTests {
    private func vault(_ store: any ACEStore = MemoryStore()) -> StorePrekeyVault { StorePrekeyVault(store: store, protection: testPrekeyProtection) }

    @Test func offerIsStableUntilUsed() throws {
        let v = vault()
        let k1 = try v.offer(peer: A, now: T)
        #expect(try v.offer(peer: A, now: T + 1) == k1)
        try v.used(peer: A, prekeyId: k1.id)
        let k2 = try v.offer(peer: A, now: T + 3)
        #expect(k2.id != k1.id)
        #expect(try publicKey(try v.open(k1.id, sender: A, now: T + 3)) == k1.publicKey)  // in use: still opens for A
        #expect(try publicKey(try v.open(k2.id, sender: A, now: T + 3)) == k2.publicKey)
        #expect(try v.open(k1.id, sender: B, now: T + 3) == nil)  // no other sender
        #expect(try v.open(k1.id, now: T + 3) == nil)  // nor without the sender
    }

    @Test func usedDeletesThePreviousInUseSeed() throws {
        let v = vault()
        let k1 = try v.offer(peer: A, now: T)
        try v.used(peer: A, prekeyId: k1.id)
        let k2 = try v.offer(peer: A, now: T + 1)
        try v.used(peer: A, prekeyId: k2.id)
        #expect(try v.open(k1.id, sender: A, now: T + 1) == nil)
        #expect(try v.open(k2.id, sender: A, now: T + 1) != nil)
    }

    @Test func inUseIsUnchangedOnReuse() throws {
        let v = vault()
        let k1 = try v.offer(peer: A, now: T)
        try v.used(peer: A, prekeyId: k1.id)
        let k2 = try v.offer(peer: A, now: T + 1)
        try v.used(peer: A, prekeyId: k1.id)  // the in-use key again: nothing changes
        #expect(try v.open(k1.id, sender: A, now: T + 2) != nil)
        #expect(try v.offer(peer: A, now: T + 3) == k2)
        try v.used(peer: A, prekeyId: String(repeating: "0", count: 64))  // an unknown ID: nothing
        #expect(try v.offer(peer: A, now: T + 4) == k2)
    }

    @Test func seedsExpireAfterTheWindow() throws {
        let v = vault()
        let k1 = try v.offer(peer: A, now: T)
        #expect(try v.open(k1.id, sender: A, now: T + W - 1) != nil)
        #expect(try v.open(k1.id, sender: A, now: T + W) == nil)
        #expect(try v.offer(peer: A, now: T + W).id != k1.id)
        let k2 = try v.offer(peer: B, now: T)
        try v.used(peer: B, prekeyId: k2.id)  // in use keeps its offeredAt
        #expect(try v.open(k2.id, sender: B, now: T + W - 1) != nil)
        #expect(try v.open(k2.id, sender: B, now: T + W) == nil)
    }

    @Test func holdKeepsTheNewestTimestamp() throws {
        let v = vault()
        let (p100, p90, p101) = (try freshKey(), try freshKey(), try freshKey())
        try v.hold(peer: A, prekey: p100, timestamp: 100, pin: PIN)
        try v.hold(peer: A, prekey: p90, timestamp: 90, pin: PIN)
        #expect(try v.held(peer: A, pin: PIN, now: 102) == p100)
        try v.hold(peer: A, prekey: p101, timestamp: 101, pin: PIN)
        #expect(try v.held(peer: A, pin: PIN, now: 102) == p101)
        #expect(try v.held(peer: B, pin: PIN, now: 102) == nil)
    }

    @Test func heldUnderAnotherPinIsDeleted() throws {
        let v = vault()
        try v.hold(peer: A, prekey: try freshKey(), timestamp: T, pin: PIN)
        #expect(try v.held(peer: A, pin: OTHER_PIN, now: T) == nil)
        #expect(try v.held(peer: A, pin: PIN, now: T) == nil)  // deleted by the mismatch
    }

    @Test func heldExpiresAfterTheWindow() throws {
        let v = vault()
        let k = try freshKey()
        try v.hold(peer: A, prekey: k, timestamp: T, pin: PIN)
        #expect(try v.held(peer: A, pin: PIN, now: T + W - 1) == k)
        #expect(try v.held(peer: A, pin: PIN, now: T + W) == nil)
        #expect(try v.held(peer: A, pin: PIN, now: T) == nil)  // deleted
    }

    @Test func dropHeldDeletesIt() throws {
        let v = vault()
        try v.hold(peer: A, prekey: try freshKey(), timestamp: T, pin: PIN)
        try v.dropHeld(peer: A)
        #expect(try v.held(peer: A, pin: PIN, now: T) == nil)
        try v.dropHeld(peer: B)  // nothing held: no-op
    }

    @Test func pruneRemovesEmptyPeerEntries() throws {
        let store = MemoryStore(), v = vault(store)
        let published = try v.rotate(now: T)
        let k = try v.offer(peer: A, now: T)
        try v.hold(peer: B, prekey: try freshKey(), timestamp: T + 5, pin: PIN)
        try v.prune(now: T + W - 1)
        #expect(try v.open(k.id, sender: A, now: T + W - 1) != nil)
        try v.prune(now: T + W + 5)
        let doc = try #require(try store.readJSON("prekeys.json"))
        #expect(doc["version"] == 1 && doc["peers"] == .object([:]))
        #expect(try v.current()?.prekey == published.prekey)
    }

    @Test func anUnknownVersionOrShapeIsAStorageFailure() throws {
        let store = MemoryStore()
        try store.write("prekeys.json", try JSONValue.object(["version": 1, "keys": .array([])]).jsonData())
        let v = vault(store)
        expectCode(.storageFailed) { _ = try v.current() }
        expectCode(.storageFailed) { _ = try v.offer(peer: A, now: T) }
    }

    @Test func peerArgumentsAreChecked() throws {
        let v = vault()
        expectCode(.invalidArgument) { _ = try v.offer(peer: "alice", now: T) }
        expectCode(.invalidArgument) { try v.hold(peer: A, prekey: try freshKey(), timestamp: T, pin: "x") }
    }

    @Test func aFileVaultStaysPrivate() throws {
        let dir = tempDirectory()
        let v = vault(try FileStore(directory: dir))
        let k = try v.offer(peer: A, now: T)
        try v.hold(peer: A, prekey: try freshKey(), timestamp: T, pin: PIN)
        let mode = try FileManager.default.attributesOfItem(atPath: dir.appendingPathComponent("prekeys.json").path)[.posixPermissions] as? Int
        #expect(mode == 0o600)
        // another vault over the same file sees the peer state
        #expect(try vault(try FileStore(directory: dir)).open(k.id, sender: A, now: T) != nil)
    }

    /// A content `prekey` is checked for its length only: an all-zero X25519 half decodes (03 § X-Wing).
    @Test func anAllZeroX25519HalfIsAPublicKey() throws {
        let key = zeroX25519Key()
        #expect(try Prekey(publicKey: key).publicKey == key)
        let c = try PrivateContent(type: "ace:text:1", schemaDigest: String(repeating: "0", count: 64), body: [:]).with(prekey: key)
        #expect(try PrivateContent(json: try c.jsonData()).prekey == key)
    }

    @Test func aSealedPeerSeedThatFailsToOpenIsIdentityUnavailable() throws {
        let store = MemoryStore(), v = vault(store)
        let k = try v.offer(peer: A, now: T)
        var doc = try #require(try store.readJSON("prekeys.json")?.objectValue)
        doc["peers"] = .object([A: ["offered": ["prekey": k.jsonValue, "offeredAt": .number(Double(T)),
                                                "secret": ["seal": ["key": "AAAA", "encapsulatedKey": "AAAA", "ciphertext": "AAAA"]]],
                                    "inUse": .null, "held": .null]])
        try store.write("prekeys.json", try JSONValue.object(doc).jsonData())
        expectCode(.identityUnavailable) { _ = try v.open(k.id, sender: A, now: T) }
    }

    @Test(.enabled(if: testPrekeyProtection == .secureEnclave)) func peerSeedsAreSealed() throws {
        let store = MemoryStore(), v = vault(store)
        let k = try v.offer(peer: A, now: T)
        let raw = String(decoding: try #require(try store.read("prekeys.json")), as: UTF8.self)
        #expect(raw.contains("\"seal\"") && !raw.contains("\"seed\""))
        #expect(try publicKey(try v.open(k.id, sender: A, now: T)) == k.publicKey)
    }
}

/// End to end over a `FakeRelay`: assertions on the packets the relay saw and their decrypted contents.
@Suite struct PeerPrekeyScenarioTests {
    private func published(_ p: NetPeer) throws -> String { try #require(try p.network.prekeys.current()).prekey.id }

    private func pin(_ holder: NetPeer, _ peer: NetPeer) async throws -> String { try #require(try await holder.network.peers.pinned(peer.aceId)).lastHash }

    private func held(_ holder: NetPeer, _ peer: NetPeer, _ clock: TestClock) async throws -> Prekey? {
        try holder.network.prekeys.held(peer: peer.aceId, pin: try await pin(holder, peer), now: clock.now)
    }

    /// The private content of `p` as its recipient decrypts it.
    private func content(_ p: Packet, at recipient: NetPeer, _ clock: TestClock) throws -> PrivateContent {
        try PrivateContent(json: try decryptPacket(p, vault: recipient.network.prekeys, now: clock.now))
    }

    private func offered(_ p: Packet, at recipient: NetPeer, _ clock: TestClock) throws -> String {
        sha256Hex(try #require(try content(p, at: recipient, clock).prekey))
    }

    private func one(_ relay: FakeRelay, since n: Int, _ from: NetPeer, _ to: NetPeer) throws -> Packet {
        let ps = relay.posted(since: n, from: from.aceId, to: to.aceId)
        try #require(ps.count == 1, "expected one packet, got \(ps.count)")
        return ps[0]
    }

    /// m1 A→B, receipt, m2 A→B (to the key B offered in that receipt), receipt. Returns the relay mark at the start and
    /// the key B offered.
    @discardableResult
    private func ratchet(_ relay: FakeRelay, _ clock: TestClock, _ alice: NetPeer, _ bob: NetPeer) async throws -> (start: Int, offered: String) {
        let start = relay.postedCount
        let m1 = try await alice.network.send(to: bob.aceId, type: "ace:text:1", body: ["message": "m1"])
        let p1 = try one(relay, since: start, alice, bob)
        #expect(p1.encryption.prekey == (try published(bob)))  // A holds nothing yet: B's published prekey
        var n = relay.postedCount
        _ = try await bob.network.pull()
        // B holds the key m1 carried
        #expect(try await held(bob, alice, clock)?.id == (try offered(p1, at: bob, clock)))
        let r1 = try one(relay, since: n, bob, alice)
        #expect(try content(r1, at: alice, clock).type == CoreTypes.receipt)
        #expect(r1.encryption.prekey == (try published(alice)))
        let offered = try offered(r1, at: alice, clock)
        #expect(try bob.network.prekeys.offer(peer: alice.aceId, now: clock.now).id == offered)  // B's offered key, not yet used
        _ = try await alice.network.pull()
        #expect(try await alice.network.outbox.entry(m1.messageId)?.status == .delivered)
        n = relay.postedCount
        let m2 = try await alice.network.send(to: bob.aceId, type: "ace:text:1", body: ["message": "m2"])
        let p2 = try one(relay, since: n, alice, bob)
        let bobPublished = try published(bob)
        #expect(p2.encryption.prekey == offered && offered != bobPublished)
        _ = try await bob.network.pull()
        _ = try await alice.network.pull()
        #expect(try await alice.network.outbox.entry(m2.messageId)?.status == .delivered)
        #expect(bob.received.value.filter { $0.type == "ace:text:1" }.map { $0.body["message"] } == ["m1", "m2"])
        return (start, offered)
    }

    @Test func ratchetPingPong() async throws {
        let clock = TestClock(systemClock()), relay = FakeRelay(clock: clock.fn)
        let (alice, bob) = try await connectedText(relay, clock)
        let (_, offered) = try await ratchet(relay, clock, alice, bob)
        // B's vault: the offered key is now in use (opens for A only) and a new one is offered
        #expect(try bob.network.prekeys.open(offered, sender: alice.aceId, now: clock.now) != nil)
        #expect(try bob.network.prekeys.open(offered, sender: peerId("mallory"), now: clock.now) == nil)
        #expect(try bob.network.prekeys.offer(peer: alice.aceId, now: clock.now).id != offered)
    }

    @Test func everyReceiptReferencesTheRecipientsPublishedPrekey() async throws {
        let clock = TestClock(systemClock()), relay = FakeRelay(clock: clock.fn)
        let (alice, bob) = try await connectedText(relay, clock)
        let (start, _) = try await ratchet(relay, clock, alice, bob)
        let reply = try await bob.network.send(to: alice.aceId, type: "ace:text:1", body: ["message": "back"])  // B holds A's key now
        _ = try await alice.network.pull()
        _ = try await bob.network.pull()
        #expect(try await bob.network.outbox.entry(reply.messageId)?.status == .delivered)
        var receipts = 0
        for (sender, recipient) in [(alice, bob), (bob, alice)] {
            for p in relay.posted(since: start, from: sender.aceId, to: recipient.aceId) where try content(p, at: recipient, clock).type == CoreTypes.receipt {
                receipts += 1
                #expect(p.encryption.prekey == (try published(recipient)))
            }
        }
        #expect(receipts == 3)
    }

    @Test func aRetryUsesThePublishedPrekeyAndCarriesAdmission() async throws {
        let clock = TestClock(systemClock()), relay = FakeRelay(clock: clock.fn)
        let (alice, bob) = try await connectedText(relay, clock)
        try await ratchet(relay, clock, alice, bob)
        let n = relay.postedCount
        let entry = try await alice.network.send(to: bob.aceId, type: "ace:text:1", body: ["message": "m3"])  // B offline
        clock.now += 61
        _ = try await alice.network.attempt(entry.messageId)
        let ps = relay.posted(since: n, from: alice.aceId, to: bob.aceId)
        try #require(ps.count == 2)
        #expect(ps[0].encryption.prekey != (try published(bob)))  // the held key
        #expect(try content(ps[0], at: bob, clock).admission == nil)
        #expect(ps[1].encryption.prekey == (try published(bob)))
        #expect(try content(ps[1], at: bob, clock).admission != nil)
    }

    @Test func aReinstallRecoversOnTheSecondAttempt() async throws {
        let clock = TestClock(systemClock()), relay = FakeRelay(clock: clock.fn)
        let (alice, old) = try await connectedText(relay, clock)
        try await ratchet(relay, clock, alice, old)
        let lost = try #require(try await held(alice, old, clock))
        await old.network.close()
        clock.now += 5
        let bob = try await NetPeer.reopen(old.identity, relay, clock: clock)
        #expect(try bob.network.admission.get(alice.aceId) == nil)
        var n = relay.postedCount
        let entry = try await alice.network.send(to: bob.aceId, type: "ace:text:1", body: ["message": "m3"])
        #expect(try one(relay, since: n, alice, bob).encryption.prekey == lost.id)  // the key the old install offered
        n = relay.postedCount
        #expect(try await bob.network.pull() == [.dropped(.unknownPrekey)])
        #expect(relay.posted(since: n, from: bob.aceId, to: alice.aceId).isEmpty)  // no receipt
        clock.now += 61
        n = relay.postedCount
        _ = try await alice.network.flush()
        #expect(try one(relay, since: n, alice, bob).encryption.prekey == (try published(bob)))
        guard case .delivered? = try await bob.network.pull().first else { Issue.record("retry not delivered"); return }
        #expect(try bob.network.admission.get(alice.aceId)?.state == .admitted)
        #expect(try await held(bob, alice, clock) != nil)  // recorded by the recovery path
        _ = try await alice.network.pull()
        #expect(try await alice.network.outbox.entry(entry.messageId)?.status == .delivered)
    }

    @Test func reorderedPacketsKeepTheNewerHeldKey() async throws {
        let clock = TestClock(systemClock()), relay = FakeRelay(clock: clock.fn)
        let (alice, bob) = try await connectedText(relay, clock)
        let t = clock.now
        let keys = [somePrekey(), somePrekey()]
        let bobKey = try #require(try bob.network.prekeys.current()).prekey
        for (ts, key) in [(t + 10, keys[0]), (t + 5, keys[1])] {
            let c = try alice.network.profiles.content(type: "ace:text:1", body: ["message": "x"]).with(prekey: key)
            let p = try createPacket(sender: alice.identity, to: bob.aceId, prekey: bobKey, content: c, timestamp: ts)
            guard case .delivered = await bob.network.inbox!.receive(p.jsonData()) else { Issue.record("not delivered"); return }
        }
        #expect(try await held(bob, alice, clock)?.publicKey == keys[0])
    }

    @Test func unknownPrekeyOnAHeldKey() async throws {
        let clock = TestClock(systemClock()), relay = FakeRelay(clock: clock.fn)
        let (alice, bob) = try await connectedText(relay, clock)
        try await ratchet(relay, clock, alice, bob)
        let first = try #require(try await held(alice, bob, clock))
        // B loses its peer state (keeping its published prekeys, admission and pins)
        var doc = try #require(try bob.store.readJSON("prekeys.json")?.objectValue)
        doc["peers"] = .object([:])
        try bob.store.write("prekeys.json", try JSONValue.object(doc).jsonData())
        clock.now += 1
        var n = relay.postedCount
        let m3 = try await alice.network.send(to: bob.aceId, type: "ace:text:1", body: ["message": "m3"])
        #expect(try one(relay, since: n, alice, bob).encryption.prekey == first.id)
        #expect(try await bob.network.pull() == [.rejected("unknown_prekey")])
        _ = try await alice.network.pull()
        #expect(try await alice.network.outbox.entry(m3.messageId)?.refreshPrekey == true)
        // the rejection carried B's new offer, which replaced the rejected key
        #expect(try await held(alice, bob, clock).map(\.id) != first.id)
        n = relay.postedCount
        _ = try await alice.network.flush()
        #expect(try one(relay, since: n, alice, bob).encryption.prekey == (try published(bob)))
        _ = try await bob.network.pull()
        _ = try await alice.network.pull()
        #expect(try await alice.network.outbox.entry(m3.messageId)?.status == .delivered)

        // a rejection naming the key still held drops it before the retry chooses
        n = relay.postedCount
        let m4 = try await alice.network.send(to: bob.aceId, type: "ace:text:1", body: ["message": "m4"])
        let still = try #require(try await held(alice, bob, clock))
        #expect(try one(relay, since: n, alice, bob).encryption.prekey == still.id)
        try await alice.network.outbox.handleReceipt(from: bob.aceId, body: [
            "messageId": .string(m4.messageId), "outcome": "rejected", "code": "unknown_prekey", "prekey": .string(still.id),
        ])
        n = relay.postedCount
        _ = try await alice.network.flush()
        #expect(try one(relay, since: n, alice, bob).encryption.prekey == (try published(bob)))
        #expect(try await held(alice, bob, clock) == nil)
        #expect(try await alice.network.outbox.entry(m4.messageId)?.status == .pending)
    }

    @Test func aBlockDropsTheHeldKey() async throws {
        let clock = TestClock(systemClock()), relay = FakeRelay(clock: clock.fn)
        let (alice, bob) = try await connectedText(relay, clock)
        try await ratchet(relay, clock, alice, bob)
        let p = try await pin(alice, bob)
        #expect(try alice.network.prekeys.held(peer: bob.aceId, pin: p, now: clock.now) != nil)
        try await alice.network.block(bob.aceId)
        #expect(try alice.network.prekeys.held(peer: bob.aceId, pin: p, now: clock.now) == nil)
    }

    /// The one packet bob sent alice since `n`, decrypted: a `rejected` receipt for `messageId` with `code`.
    private func expectRejectedReceipt(_ relay: FakeRelay, since n: Int, _ bob: NetPeer, _ alice: NetPeer, _ clock: TestClock,
                                       messageId: String, code: String) throws {
        let r = try content(try one(relay, since: n, bob, alice), at: alice, clock)
        #expect(r.type == CoreTypes.receipt)
        #expect(r.body["messageId"]?.stringValue == messageId)
        #expect(r.body["outcome"]?.stringValue == "rejected")
        #expect(r.body["code"]?.stringValue == code)
    }

    /// 06 step 7: a malformed `prekey` (not canonical Base64) from a pinned peer is rejected `invalid_body` with a receipt.
    @Test func step7AMalformedPrekeyIsRejectedWithAReceipt() async throws {
        let clock = TestClock(systemClock()), relay = FakeRelay(clock: clock.fn)
        let (alice, bob) = try await connectedText(relay, clock)
        let d = try alice.network.profiles.content(type: "ace:text:1", body: ["message": "x"]).schemaDigest
        let plaintext = Data(#"{"body":{"message":"x"},"prekey":"not base64!","schemaDigest":"\#(d)","type":"ace:text:1"}"#.utf8)
        let p = try forged(alice, to: bob, plaintext: plaintext, clock)
        let n = relay.postedCount
        #expect(await bob.network.inbox!.receive(p.jsonData()) == .rejected("invalid_body"))
        try expectRejectedReceipt(relay, since: n, bob, alice, clock, messageId: p.messageId, code: "invalid_body")
        #expect(try await held(bob, alice, clock) == nil)
        #expect(bob.received.value.isEmpty)
    }

    /// 06 step 7: the same failure on receipt-typed content is dropped, never receipted.
    @Test func step7AMalformedCorePacketIsDroppedWithoutAReceipt() async throws {
        let clock = TestClock(systemClock()), relay = FakeRelay(clock: clock.fn)
        let (alice, bob) = try await connectedText(relay, clock)
        let c = try alice.network.profiles.content(type: CoreTypes.receipt, body: ["messageId": .string(UUID().uuidString.lowercased()),
                                                                                  "outcome": "delivered"])
        var o = try #require(c.with(prekey: somePrekey()).jsonValue.objectValue)
        o["prekey"] = "not base64!"
        let p = try forged(alice, to: bob, plaintext: try JSONValue.object(o).jsonData(), clock)
        let n = relay.postedCount
        #expect(await bob.network.inbox!.receive(p.jsonData()) == .dropped(.invalidBody))
        #expect(relay.posted(since: n, from: bob.aceId, to: alice.aceId).isEmpty)
        #expect(try await held(bob, alice, clock) == nil)
    }

    /// A correctly signed packet whose plaintext is `plaintext` verbatim (what a faulty or hostile sender can send).
    private func forged(_ alice: NetPeer, to bob: NetPeer, plaintext: Data, _ clock: TestClock) throws -> Packet {
        let prekey = try #require(try bob.network.prekeys.current()).prekey
        let r = try XWingMLKEM768X25519.PublicKey(rawRepresentation: prekey.publicKey).encapsulate()
        let messageId = UUID().uuidString.lowercased(), kem = Data(r.encapsulated)
        let header = Packet.header(from: alice.aceId, to: bob.aceId, messageId: messageId, timestamp: clock.now, prekey: prekey.id, kemCiphertext: kem)
        let payload = try Packet.seal(plaintext, sharedSecret: r.sharedSecret, header: header)
        let signature = try operationalSign(alice.identity, action: "packet", timestamp: clock.now,
                                            payload: Packet.signPayload(to: bob.aceId, messageId: messageId, prekey: prekey.id, kemCiphertext: kem,
                                                                        payload: payload))
        return Packet(messageId: messageId, from: alice.aceId, to: bob.aceId, timestamp: clock.now, prekey: prekey.id, kemCiphertext: kem,
                      payload: payload, signature: signature)
    }

    /// A vault storage failure at step 6 is a retry, never a drop or a rejection.
    @Test func aVaultStorageFailureAtStep6IsARetry() async throws {
        let clock = TestClock(systemClock()), relay = FakeRelay(clock: clock.fn)
        let (alice, bob) = try await connectedText(relay, clock)
        let c = try alice.network.profiles.content(type: "ace:text:1", body: ["message": "x"]).with(prekey: somePrekey())
        let p = try createPacket(sender: alice.identity, to: bob.aceId, prekey: try #require(try bob.network.prekeys.current()).prekey, content: c,
                                 timestamp: clock.now)
        let saved = try #require(try bob.store.read("prekeys.json"))
        try bob.store.write("prekeys.json", Data("{\"version\":1,\"keys\":[]}".utf8))
        #expect(await bob.network.inbox!.receive(p.jsonData()) == .retry(.storageFailed))
        try bob.store.write("prekeys.json", saved)
        guard case .delivered = await bob.network.inbox!.receive(p.jsonData()) else { Issue.record("not delivered once restored"); return }
    }

    /// A held key that does not encapsulate (CryptoKit refuses an all-zero X25519 half) is dropped and the same attempt
    /// goes to the published prekey.
    @Test func aHeldKeyThatDoesNotEncapsulateFallsBackToThePublishedPrekey() async throws {
        let clock = TestClock(systemClock()), relay = FakeRelay(clock: clock.fn)
        let (alice, bob) = try await connectedText(relay, clock)
        let dead = try Prekey(publicKey: zeroX25519Key())
        #expect(throws: ACEError.self) {
            _ = try createPacket(sender: alice.identity, to: bob.aceId, prekey: dead,
                                 content: try alice.network.profiles.content(type: "ace:text:1", body: [:]).with(prekey: somePrekey()), timestamp: clock.now)
        }
        try alice.network.prekeys.hold(peer: bob.aceId, prekey: dead, timestamp: clock.now, pin: try await pin(alice, bob))
        #expect(try await held(alice, bob, clock) == dead)
        let n = relay.postedCount
        let entry = try await alice.network.send(to: bob.aceId, type: "ace:text:1", body: ["message": "x"])
        #expect(try one(relay, since: n, alice, bob).encryption.prekey == (try published(bob)))
        #expect(try await held(alice, bob, clock) == nil)
        guard case .delivered? = try await bob.network.pull().first else { Issue.record("not delivered"); return }
        _ = try await alice.network.pull()
        #expect(try await alice.network.outbox.entry(entry.messageId)?.status == .delivered)
    }

    @Test func contactPacketsRecordNoHeldKey() async throws {
        let clock = TestClock(systemClock()), relay = FakeRelay(clock: clock.fn)
        let (alice, bob) = try await connectedText(relay, clock)
        #expect(try await held(alice, bob, clock) == nil)
        #expect(try await held(bob, alice, clock) == nil)
    }
}

/// Posts to the prekey given (`held` on the first attempt, as `NetworkClient` does with a held key); a forced refresh fails
/// and the cached descriptor publishes `published`.
private struct RefreshDownTransport: PacketTransport {
    let published: Prekey, held: Prekey
    func prekey(for aceId: String, refresh: Bool) async throws -> Prekey {
        if refresh { throw ACEError(.relayUnavailable, "down") }
        return published
    }
    func dropHeld(_ aceId: String, ifId prekeyId: String) async throws -> Bool { false }  // the held key was since replaced
    func post(to aceId: String, content: PrivateContent, messageId: String, prekey: Prekey, attempts: Int) async throws -> Prekey {
        attempts == 0 ? held : prekey
    }
}

@Suite struct PeerPrekeyOutboxFallbackTests {
    /// 06 § Outbox step 1: after `unknown_prekey` named a held key since replaced, a failed refresh falls back to the cached
    /// descriptor unless it publishes the rejected ID; then the retry goes to the published prekey.
    @Test(arguments: [false, true]) func refreshFailureAfterAHeldKeyRejection(cachedPublishesRejected: Bool) async throws {
        let me = try makeIdentity(now: systemClock()), peer = try TestAgent(now: systemClock())
        let outbox = Outbox(identity: me, store: MemoryStore(), profiles: try InstalledProfiles([.text]))
        let published = try freshKey(), h1 = try freshKey()
        let transport = RefreshDownTransport(published: cachedPublishesRejected ? h1 : published, held: h1)
        let e = try await outbox.enqueue(to: peer.aceId, type: "ace:text:1", body: ["message": "x"])
        #expect(try await outbox.deliver(e.messageId, via: transport).lastPrekey == h1.id)
        let receipt: [String: JSONValue] = ["messageId": .string(e.messageId), "outcome": "rejected", "code": "unknown_prekey", "prekey": .string(h1.id)]
        #expect(try await outbox.handleReceipt(from: peer.aceId, body: receipt)?.refreshPrekey == true)
        let done = try await outbox.deliver(e.messageId, via: transport)
        #expect(done.attempts == 2 && done.status == .pending)
        if cachedPublishesRejected {
            #expect(done.refreshPrekey && done.lastPrekey == h1.id && done.lastError != nil)  // failed: retried on schedule
        } else {
            #expect(!done.refreshPrekey && done.lastPrekey == published.id && done.lastError == nil)
        }
    }
}
