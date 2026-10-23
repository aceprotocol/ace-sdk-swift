import Foundation
import Testing
@testable import ACE

/// Apply a second client's decision immediately before this client acquires the shared admission lock.
private final class AuditInterleavingStore: ACEStore, @unchecked Sendable {
    let base = MemoryStore()
    let beforeAdmissionLock = LockedValue<(@Sendable (MemoryStore) throws -> Void)?>(nil)
    func read(_ key: String) throws -> Data? { try base.read(key) }
    func write(_ key: String, _ value: Data) throws { try base.write(key, value) }
    func delete(_ key: String) throws { try base.delete(key) }
    func list(prefix: String) throws -> [String] { try base.list(prefix: prefix) }
    func lock(_ name: String, timeout: TimeInterval) throws -> any ACEStoreLock {
        if name == "admission", let hook = beforeAdmissionLock.value {
            beforeAdmissionLock.value = nil
            try hook(base)
        }
        return try base.lock(name, timeout: timeout)
    }
}

@Suite struct AuditSecurityFixesTests {
    @Test func connectCannotReplaceABlockRegisteredDuringPublish() async throws {
        let clock = TestClock(systemClock()), relay = FakeRelay(clock: clock.fn)
        let peer = try await NetPeer.make(relay, clock: clock)
        let identity = try makeIdentity(now: clock.now), store = MemoryStore()
        let network = try await NetworkClient.open(identity: identity, store: store, relay: relay.client(clock: clock.fn),
                                                   prekeys: StorePrekeyVault(store: store), clock: clock.fn)
        let entered = LockedValue(false), gate = DispatchSemaphore(value: 0)
        defer { gate.signal() }
        StubURLProtocol.register(host: relay.host) { request, body in
            if request.url?.path == "/v1/card", !entered.value {
                entered.value = true
                _ = gate.wait(timeout: .now() + Double(hangGuardSeconds))
            }
            return relay.handle(request, body)
        }
        let connecting = Task { try await network.connect(peer.aceId, profile: ProfileManifest.text.id) }
        #expect(await settles { entered.value })
        let blocking = Task { try await network.block(peer.aceId) }
        #expect(await settles { (try? network.admission.get(peer.aceId)?.state) == .blocked })
        gate.signal()
        await expectCodeAsync(.notPermitted) { try await connecting.value }
        try await blocking.value
        #expect(try network.admission.get(peer.aceId)?.state == .blocked)
        #expect(relay.sendCount(to: peer.aceId) == 0)
        // Even a reply already in flight cannot turn the persisted block into admission.
        let source = try await peer.network.publish()
        let permit = try createPermit(identity: peer.identity, subject: identity.getACEId(), now: clock.now)
        try await network.receivedContact(from: peer.aceId, body: ["kind": "accepted", "profile": .string(ProfileManifest.text.id),
                                                                 "permit": permit], source: source)
        #expect(try network.admission.get(peer.aceId)?.state == .blocked)
        await network.close()
        await peer.network.close()
    }

    @Test func handleBindingsSurviveHomeMovesAndLegacyMigration() async throws {
        let clock = TestClock(systemClock()), relay = FakeRelay(clock: clock.fn)
        let subject = try await NetPeer.make(relay, clock: clock, configuration: NetworkConfiguration(handle: "alice"))
        let reader = try await NetPeer.make(relay, clock: clock)
        let key = "network/handles/\(sha256Hex(Data(subject.aceId.utf8))).json"
        #expect(try await reader.network.lookupCard(subject.aceId).record.handle == "alice")
        // Simulate the one-home format written by an earlier SDK, then restart with the same store.
        var legacy = try #require(try reader.store.readJSON(key)?.objectValue)
        legacy.removeValue(forKey: "handles")
        try reader.store.write(key, try JSONValue.object(legacy).jsonData())
        let again = try await NetworkClient.open(identity: reader.identity, store: reader.store, relay: relay.client(clock: clock.fn),
                                                 prekeys: StorePrekeyVault(store: reader.store), receive: false, clock: clock.fn)
        let secondHome = "https://second.example"
        func serve(home: String, handle: String?) throws {
            clock.now += 1
            relay.setCard(subject.aceId, try createCardRecord(identity: subject.identity, home: home, handle: handle,
                                                            contact: .closed, listed: false, now: clock.now))
        }
        try serve(home: secondHome, handle: "bob")
        #expect(try await again.lookupCard(subject.aceId).record.handle == "bob")
        for handle in [String?("evil"), nil] {
            try serve(home: relay.url, handle: handle)
            await expectCodeAsync(.invalidAuthorization) { try await again.lookupCard(subject.aceId) }
        }
        try serve(home: relay.url, handle: "alice")
        #expect(try await again.lookupCard(subject.aceId).record.handle == "alice")
        let pin = try #require(try reader.store.readJSON(key))
        #expect(pin["handles"]?[relay.url] == "alice")
        #expect(pin["handles"]?[secondHome] == "bob")
        // Moving back never forgets the second home's binding either.
        try serve(home: secondHome, handle: "other")
        await expectCodeAsync(.invalidAuthorization) { try await again.lookupCard(subject.aceId) }
        await again.close()
        await reader.network.close()
        await subject.network.close()
    }

    @Test func invitationCanLiftAnOldBlockButCannotOverrideANewerBlockWhileRegistering() async throws {
        let clock = TestClock(systemClock()), relay = FakeRelay(clock: clock.fn)
        let owner = try await NetPeer.make(relay, clock: clock), peer = try await NetPeer.make(relay, clock: clock)
        try await owner.network.block(peer.aceId)
        _ = try await owner.network.createInvitation(peer: peer.aceId)
        #expect(try owner.network.admission.get(peer.aceId)?.state == .admitted)
        #expect(relay.blocked(by: owner.aceId, peer.aceId) == false)
        try await owner.network.block(peer.aceId)
        let entered = LockedValue(false), gate = DispatchSemaphore(value: 0)
        defer { gate.signal() }
        StubURLProtocol.register(host: relay.host) { request, body in
            if request.url?.path == "/v1/blocks", let payload = try? JSONParser.parse(body), payload["blocked"]?.boolValue == false, !entered.value {
                entered.value = true
                _ = gate.wait(timeout: .now() + Double(hangGuardSeconds))
            }
            return relay.handle(request, body)
        }
        let inviting = Task { try await owner.network.createInvitation(peer: peer.aceId) }
        #expect(await settles { entered.value })
        let blocking = Task { try await owner.network.block(peer.aceId) }
        #expect(await settles { (try? owner.network.admission.get(peer.aceId)?.state) == .blocked })
        gate.signal()
        _ = try await inviting.value
        try await blocking.value
        #expect(try owner.network.admission.get(peer.aceId)?.state == .blocked)
        #expect(relay.blocked(by: owner.aceId, peer.aceId) == true)
        await owner.network.close()
        await peer.network.close()
    }

    @Test func contactRequestCannotReappearAfterAnotherClientBlocksItsSender() async throws {
        let clock = TestClock(systemClock()), relay = FakeRelay(clock: clock.fn)
        let peer = try await NetPeer.make(relay, clock: clock), store = AuditInterleavingStore()
        let identity = try makeIdentity(now: clock.now)
        let network = try await NetworkClient.open(identity: identity, store: store, relay: relay.client(clock: clock.fn),
                                                   prekeys: StorePrekeyVault(store: store), clock: clock.fn)
        let source = try await peer.network.publish(), sender = peer.aceId
        store.beforeAdmissionLock.value = { base in
            _ = try AdmissionTable(store: base, clock: clock.fn).decideBlock(sender, blocked: true) { _ in
                AdmissionRecord(aceId: sender, state: .blocked, updatedAt: clock.now)
            }
        }
        try await network.receivedContact(from: sender, body: ["kind": "request", "profile": .string(ProfileManifest.text.id),
                                                               "note": "", "permit": try createPermit(identity: peer.identity, subject: identity.getACEId(), now: clock.now)], source: source)
        #expect(try network.admission.get(sender)?.state == .blocked)
        #expect(try await network.requests().isEmpty)
        await network.close()
        await peer.network.close()
    }

    @Test func invitationClearsAnInterleavedBlockWithTheCorrespondingRelayRevision() async throws {
        let clock = TestClock(systemClock()), relay = FakeRelay(clock: clock.fn)
        let peer = try await NetPeer.make(relay, clock: clock), store = AuditInterleavingStore()
        let identity = try makeIdentity(now: clock.now)
        let network = try await NetworkClient.open(identity: identity, store: store, relay: relay.client(clock: clock.fn),
                                                   prekeys: StorePrekeyVault(store: store), clock: clock.fn)
        _ = try await network.publish()
        _ = try await network.lookup(peer.aceId)
        let sender = peer.aceId
        store.beforeAdmissionLock.value = { base in
            _ = try AdmissionTable(store: base, clock: clock.fn).decideBlock(sender, blocked: true) { _ in
                AdmissionRecord(aceId: sender, state: .blocked, updatedAt: clock.now)
            }
        }
        _ = try await network.createInvitation(peer: sender)
        #expect(try network.admission.get(sender)?.state == .admitted)
        #expect(try network.admission.blockRecord(sender)?.revision == clock.now + 1)  // above the interleaved block at `now`
        #expect(try network.admission.blockRecord(sender)?.blocked == false)
        #expect(relay.blocked(by: identity.getACEId(), sender) == false)
        await network.close()
        await peer.network.close()
    }

    @Test func malformedOrConflictingHomeMapsFailClosed() async throws {
        let clock = TestClock(systemClock()), relay = FakeRelay(clock: clock.fn)
        let subject = try await NetPeer.make(relay, clock: clock, configuration: NetworkConfiguration(handle: "alice"))
        let reader = try await NetPeer.make(relay, clock: clock)
        _ = try await reader.network.lookupCard(subject.aceId)
        let key = "network/handles/\(sha256Hex(Data(subject.aceId.utf8))).json"
        let original = try #require(try reader.store.readJSON(key)?.objectValue)
        let malformed: [JSONValue] = [[], .object([relay.url: "other"]), .object(["http://internal.example": "alice"]),
                                      .object([relay.url: "invalid handle"]), .object([relay.url: 1]),
                                      .object([relay.url: "alice", "https://home.example/path": "alice"])]
        for handles in malformed {
            var pin = original
            pin["handles"] = handles
            try reader.store.write(key, try JSONValue.object(pin).jsonData())
            await expectCodeAsync(.storageFailed) { try await reader.network.lookupCard(subject.aceId) }
        }
        var missingLegacyHandle = original
        missingLegacyHandle.removeValue(forKey: "handle")
        try reader.store.write(key, try JSONValue.object(missingLegacyHandle).jsonData())
        await expectCodeAsync(.storageFailed) { try await reader.network.lookupCard(subject.aceId) }
        await reader.network.close()
        await subject.network.close()
    }

    @Test func replayHeapCompactionPreservesDecisionsAndBoundsMemory() throws {
        let now = NOW, capacity = 16
        let replay = try ReplayDetector(capacity: capacity, horizon: now - 1_209_601, clock: { now })
        let anchor = UUID().uuidString.lowercased()
        try replay.commit(anchor, from: "anchor", timestamp: now - 600_000)
        var last = ""
        for i in 1...4000 {
            last = UUID().uuidString.lowercased()
            #expect(try replay.commit(last, from: "attacker", timestamp: now - 600_000 + i))
        }
        let state = replay.exportState()
        #expect(state.entries.count == 2)
        #expect(try !replay.accepts(anchor, from: "anchor", timestamp: now))
        #expect(try !replay.accepts(last, from: "attacker", timestamp: now))
        #expect(replay.covers(sender: "attacker", timestamp: now - 596_001))
        try checkHeapSizes(replay)
        let restored = try ReplayDetector(state: state, capacity: capacity, clock: { now })
        #expect(restored.exportState() == state)
        // Capacity evictions can leave stale entries in per-sender heaps even when the global heap stays short.
        let many = try ReplayDetector(capacity: 128, horizon: now - 1_209_601, clock: { now })
        for i in 1...4000 {
            try many.commit(UUID().uuidString.lowercased(), from: "sender-\(i % 40)", timestamp: now - 600_000 + i)
        }
        try checkHeapSizes(many)
        #expect(try ReplayDetector(state: many.exportState(), capacity: 128, clock: { now }).exportState() == many.exportState())
    }

    private func checkHeapSizes(_ replay: ReplayDetector) throws {
        let reflected = Mirror(reflecting: replay), state = replay.exportState(), live = state.entries.count
        let global = try #require(reflected.descendant("global", "items") as? [Any])
        let horizons = try #require(reflected.descendant("shHeap", "items") as? [Any])
        let senders = try #require(reflected.descendant("senderHeapSize") as? Int)
        #expect(global.count <= live + max(live, 16))
        #expect(senders <= live + max(live, 16))
        #expect(horizons.count <= state.senderHorizons.count + max(state.senderHorizons.count, 16))
    }

    @Test func profileEnumsCompareCanonicalBytesRecursively() throws {
        let schema: JSONValue = ["type": "object", "properties": ["mode": ["type": "string", "enum": ["é"]]],
                                 "required": ["mode"], "additionalProperties": false]
        let manifest = try ProfileManifest(["id": "urn:audit:unicode:1", "messages": [["type": "urn:audit:message:1", "schema": schema]]])
        let installed = try InstalledProfiles([manifest])
        _ = try installed.content(type: "urn:audit:message:1", body: ["mode": "é"])
        expectCode(.invalidBody) { try installed.content(type: "urn:audit:message:1", body: ["mode": .string("e\u{301}")]) }
        let objectEnum: JSONValue = ["type": "object", "properties": [:], "required": [], "additionalProperties": true,
                                    "enum": [["label": "é", "number": 1]]]
        #expect(ProfileManifest.matches(objectEnum, ["number": 1.0, "label": "é"]))
        #expect(!ProfileManifest.matches(objectEnum, ["number": 1, "label": .string("e\u{301}")]))
        #expect(ProfileManifest.matches(["type": "integer", "enum": [0]], .number(-0.0)))
    }

    @Test func followBackpressuresWithoutDroppingBufferedOutcomes() async throws {
        let total = 160, acknowledgements = LockedValue<[String]>([]), opened = LockedValue(false)
        let frames = (1...total).map { i in
            "id: \(i)-0\nevent: message\ndata: {\"packet\":\(i % 2 == 0 ? "{}" : "{\"ace\":\"2\"}")}\n\n"
        }
        let relay = try makeRelay({ request, _ in
            if request.url?.path == "/v1/listen" {
                if opened.value { return .error(403, "not_permitted") }
                opened.value = true
                return .sse(frames)
            }
            if request.url?.path == "/v1/inbox/ack" {
                acknowledgements.value.append(URLComponents(url: request.url!, resolvingAgainstBaseURL: false)!.queryItems!.first!.value!)
            }
            return .json(200, ["ok": true] as JSONValue)
        }, clock: { NOW })
        let store = MemoryStore()
        let network = try await NetworkClient.open(identity: makeIdentity(), store: store, relay: relay,
                                                   prekeys: StorePrekeyVault(store: store), clock: { NOW })
        let stream = network.follow()
        var iterator = stream.makeAsyncIterator()
        #expect(try await iterator.next() == .dropped(.unsupportedVersion))
        // One consumed, 64 queued and at most one processed entry waiting to be yielded.
        #expect(await settles { acknowledgements.value.count >= 66 })
        try await Task.sleep(for: .milliseconds(100))
        #expect(acknowledgements.value.count == 66)
        for i in 2...total {
            #expect(try await iterator.next() == .dropped(i % 2 == 0 ? .invalidPacket : .unsupportedVersion))
        }
        await expectCodeAsync(.notPermitted) { try await iterator.next() }
        #expect(acknowledgements.value == (1...total).map { "\($0)-0" })
        await network.close()
    }

    @Test func cancellingFollowWhileItsBufferIsFullStopsConsumption() async throws {
        let acknowledgements = LockedValue(0), consumed = LockedValue(false), opened = LockedValue(false)
        let frames = (1...300).map { "id: \($0)-0\nevent: message\ndata: {\"packet\":{}}\n\n" }
        let relay = try makeRelay({ request, _ in
            if request.url?.path == "/v1/listen" {
                if opened.value { return .suspended }
                opened.value = true
                return .sse(frames)
            }
            if request.url?.path == "/v1/inbox/ack" { acknowledgements.value += 1 }
            return .json(200, ["ok": true] as JSONValue)
        }, clock: { NOW })
        let store = MemoryStore()
        let network = try await NetworkClient.open(identity: makeIdentity(), store: store, relay: relay,
                                                   prekeys: StorePrekeyVault(store: store), clock: { NOW })
        let stream = network.follow()
        let consumer = Task {
            var iterator = stream.makeAsyncIterator()
            _ = try await iterator.next()
            consumed.value = true
            do { try await Task.sleep(for: .seconds(hangGuardSeconds)) } catch {}
            return try await iterator.next()
        }
        #expect(await settles { consumed.value && acknowledgements.value >= 66 })
        consumer.cancel()
        // AsyncThrowingStream may return one already buffered value from a cancelled next(); cancellation must
        // still terminate the producer even while the caller retains the stream itself.
        _ = try await consumer.value
        let stopped = acknowledgements.value
        try await Task.sleep(for: .milliseconds(100))
        #expect(acknowledgements.value == stopped)
        await network.close()
    }

    @Test func cancellingFollowWhileAwaitingAnEntryFinishesTheConsumer() async throws {
        let listening = LockedValue(false)
        let relay = try makeRelay({ request, _ in
            if request.url?.path == "/v1/listen" { listening.value = true; return .suspended }
            return .json(200, ["ok": true] as JSONValue)
        }, clock: { NOW })
        let store = MemoryStore()
        let network = try await NetworkClient.open(identity: makeIdentity(), store: store, relay: relay,
                                                   prekeys: StorePrekeyVault(store: store), clock: { NOW })
        let consumer = Task {
            var iterator = network.follow().makeAsyncIterator()
            return try await iterator.next()
        }
        #expect(await settles { listening.value })
        consumer.cancel()
        #expect(try await consumer.value == nil)
        await network.close()
    }
}
