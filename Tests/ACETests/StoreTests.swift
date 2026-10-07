import Foundation
import Testing
import Darwin
@testable import ACE

func tempDirectory() -> URL {
    let url = FileManager.default.temporaryDirectory.appendingPathComponent("ace-store-\(UUID().uuidString)")
    return url
}

@Suite("Stores")
struct StoreTests {
    @Test func keyGrammar() {
        for good in ["replay.json", "threads/abc.json", "a", "a/b/c-d_e.f", String(repeating: "a", count: 200)] {
            #expect(isValidStoreKey(good), "\(good)")
        }
        for bad in ["", "/a", "a/", "a//b", ".tmp", "A", "a/.b", "a b", "../x", String(repeating: "a", count: 201)] {
            #expect(!isValidStoreKey(bad), "\(bad)")
        }
    }

    private func exercise(_ store: any ACEStore) throws {
        #expect(try store.read("x.json") == nil)
        try store.write("x.json", Data("1".utf8))
        try store.write("dir/b.json", Data("2".utf8))
        try store.write("dir/a.json", Data("3".utf8))
        try store.write("dir/a.json", Data("4".utf8))
        #expect(try store.read("dir/a.json") == Data("4".utf8))
        #expect(try store.list(prefix: "dir/") == ["dir/a.json", "dir/b.json"])
        #expect(try store.list(prefix: "") == ["dir/a.json", "dir/b.json", "x.json"])
        try store.delete("dir/a.json")
        try store.delete("dir/a.json")
        #expect(try store.list(prefix: "dir/") == ["dir/b.json"])
        expectCode(.invalidArgument) { try store.write("Bad", Data()) }

        let held = try store.lock("receive", timeout: 0)
        expectCode(.receiverBusy) { try store.lock("receive", timeout: 0) }
        expectCode(.lockBusy) {
            let other = try store.lock("threads", timeout: 1)
            defer { other.release() }
            return try store.lock("threads", timeout: 0.1)
        }
        held.release()
        held.release()
        try store.lock("receive", timeout: 0).release()
        try store.lock("receive").release()  // default timeout

        // Lock names have their own grammar (no '/', no '.', at most 64 characters).
        for bad in ["", "a/b", "a.b", "A", "-a", String(repeating: "a", count: 65)] {
            expectCode(.invalidArgument) { try store.lock(bad, timeout: 0) }
        }
        try store.lock("a_b-" + String(repeating: "c", count: 60), timeout: 0).release()

        // Nothing is written that could not be read back.
        expectCode(.invalidArgument) { try store.write("big.json", Data(count: ACELimits.maxStoreValueBytes + 1)) }
        #expect(try store.read("big.json") == nil)
    }

    @Test func memoryStore() throws { try exercise(MemoryStore()) }

    @Test func fileStore() throws {
        let dir = tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let store = try FileStore(directory: dir)
        try exercise(store)
        // Permissions and layout.
        var st = stat()
        #expect(stat(dir.appendingPathComponent("x.json").path, &st) == 0 && st.st_mode & 0o777 == 0o600)
        #expect(stat(dir.appendingPathComponent("dir").path, &st) == 0 && st.st_mode & 0o777 == 0o700)
        // Locks live under locks/ and are not listed.
        let l = try store.lock("peers", timeout: 1)
        let content = try String(contentsOf: dir.appendingPathComponent("locks/peers.lock"), encoding: .utf8)
        #expect(content.hasPrefix("{\"createdAt\":") && content.contains("\"pid\":\(getpid())"))
        #expect(try !store.list(prefix: "").contains { $0.hasPrefix("locks") })
        l.release()
        #expect(!FileManager.default.fileExists(atPath: dir.appendingPathComponent("locks/peers.lock").path))
    }

    @Test func fileStoreRefusesSymlinksAndBreaksStaleLocks() throws {
        let dir = tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let store = try FileStore(directory: dir)
        try store.write("real.json", Data("x".utf8))
        symlink(dir.appendingPathComponent("real.json").path, dir.appendingPathComponent("link.json").path)
        expectCode(.storageFailed) { try store.read("link.json") }

        // A lock left by a dead process on this host is broken.
        var host = [CChar](repeating: 0, count: 256)
        gethostname(&host, 256)
        let hostname = String(decoding: host.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }, as: UTF8.self)
        try FileManager.default.createDirectory(at: dir.appendingPathComponent("locks"), withIntermediateDirectories: true)
        try Data("{\"createdAt\":1,\"host\":\"\(hostname)\",\"pid\":999999}".utf8).write(to: dir.appendingPathComponent("locks/receive.lock"))
        try store.lock("receive", timeout: 0).release()

        // A live foreign lock is respected; an unparseable fresh one too.
        try Data("{\"createdAt\":1,\"host\":\"other-host\",\"pid\":1}".utf8).write(to: dir.appendingPathComponent("locks/receive.lock"))
        expectCode(.receiverBusy) { try store.lock("receive", timeout: 0.1) }
        try Data("garbage".utf8).write(to: dir.appendingPathComponent("locks/threads.lock"))
        expectCode(.lockBusy) { try store.lock("threads", timeout: 0) }
        // ... but an unparseable one older than 60 s is broken.
        let old = Date(timeIntervalSinceNow: -120)
        try FileManager.default.setAttributes([.modificationDate: old], ofItemAtPath: dir.appendingPathComponent("locks/threads.lock").path)
        try store.lock("threads", timeout: 0).release()
    }

    @Test func fileStoreSerializesInProcessAcrossInstances() throws {
        let dir = tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let a = try FileStore(directory: dir), b = try FileStore(directory: dir)
        let l = try a.lock("receive", timeout: 0)
        expectCode(.receiverBusy) { try b.lock("receive", timeout: 0) }
        l.release()
        try b.lock("receive", timeout: 0).release()
    }
}

@Suite("PeerStore")
struct PeerStoreTests {
    let bob = Fixtures.agent("bob")
    let clock = TestClock(1741000000)

    @Test func adoptRollbackBarrier() async throws {
        let store = MemoryStore()
        let peers = try PeerStore(store: store, clock: clock.fn)
        let r1 = try verifyPeerRecord(try peerRecord(bob, registeredAt: 1740000000))
        #expect(try await peers.adopt(r1).outcome == .adopted)
        let r0 = try verifyPeerRecord(try peerRecord(bob, registeredAt: 1739000000))
        let same = try await peers.adopt(r0)
        #expect(same.outcome == .unchanged && same.peer.registeredAt == 1740000000)

        // A different key needs a strictly newer signed binding.
        let rotatedIdentity = try SoftwareIdentity(scheme: .secp256k1, signingPrivateKey: try ACEBase64.decode(Fixtures.agentInfo("bob")["signingPrivateKey"] as! String),
                                                   encryptionSeed: ACEEncryption.generateSeed())
        let older = try verifyPeerRecord(try peerRecord(rotatedIdentity, registeredAt: 1740000000))
        await expectCodeAsync(.stalePeerBinding) { try await peers.adopt(older) }
        // An unsigned (registration-file) candidate never rotates.
        let file = try createRegistrationFile(for: rotatedIdentity, name: "Bob", endpoint: "https://bob.example")
        await expectCodeAsync(.stalePeerBinding) { try await peers.pinRegistrationFile(file, pinnedAt: 1741000000) }
        let newer = try verifyPeerRecord(try peerRecord(rotatedIdentity, registeredAt: 1740000001))
        #expect(try await peers.adopt(newer).outcome == .rotated)
        #expect(try await peers.get(bob.getACEId())?.encryptionPublicKey == rotatedIdentity.getEncryptionPublicKey())
        // Future bound.
        let future = try verifyPeerRecord(try peerRecord(rotatedIdentity, registeredAt: 1741000301))
        await expectCodeAsync(.invalidPeer) { try await peers.adopt(future) }
    }

    @Test func persistedRecordFormatAndCorruption() async throws {
        let store = MemoryStore()
        let peers = try PeerStore(store: store, clock: clock.fn)
        try await peers.adopt(try verifyPeerRecord(try peerRecord(bob, registeredAt: 1740000000)))
        let key = PinnedPeer.key(bob.getACEId())
        let text = String(decoding: try store.read(key)!, as: UTF8.self)
        #expect(text.hasPrefix("{\"aceId\":\"\(bob.getACEId())\",\"encryptionPublicKey\":"))
        #expect(text.contains("\"fetchedAt\":1741000000,\"profile\":null,\"registeredAt\":1740000000,\"registrationSignature\":\"0x"))
        #expect(text.hasSuffix("\"source\":\"relay\",\"version\":1}"))
        // Tampered key → storage_failed, never overwritten.
        let tampered = text.replacingOccurrences(of: "\"registeredAt\":1740000000", with: "\"registeredAt\":1740000001")
        try store.write(key, Data(tampered.utf8))
        await expectCodeAsync(.storageFailed) { try await peers.get(bob.getACEId()) }
        await expectCodeAsync(.storageFailed) { try await peers.adopt(try verifyPeerRecord(try peerRecord(bob, registeredAt: 1740000002))) }
        #expect(String(decoding: try store.read(key)!, as: UTF8.self) == tampered)
    }

    @Test func resolveRefreshesAndFallsBack() async throws {
        let fake = FakeRelay()
        let relay = try makeRelay(fake.handle)
        let store = MemoryStore()
        let peers = try PeerStore(store: store, relay: relay, ttlSeconds: 100, clock: clock.fn)
        await expectCodeAsync(.unknownPeer) { try await peers.resolve(bob.getACEId()) }
        fake.add(try peerRecord(bob, registeredAt: 1740000000))
        #expect(try await peers.resolve(bob.getACEId()).registeredAt == 1740000000)
        // Fresh pin: no relay call.
        let before = fake.requests.count
        _ = try await peers.resolve(bob.getACEId())
        #expect(fake.requests.count == before)
        // Expired TTL, relay forgets the peer: fall back to the pin; maxAge 0 throws.
        clock.now += 1000
        fake.peers = [:]
        #expect(try await peers.resolve(bob.getACEId()).registeredAt == 1740000000)
        await expectCodeAsync(.unknownPeer) { try await peers.resolve(bob.getACEId(), maxAgeSeconds: 0) }
        // Refresh with a newer same-key binding raises registeredAt.
        fake.add(try peerRecord(bob, registeredAt: 1740000500))
        #expect(try await peers.resolve(bob.getACEId(), maxAgeSeconds: 0).registeredAt == 1740000500)
    }

    @Test func noRelay() async throws {
        let peers = try PeerStore(store: MemoryStore(), clock: clock.fn)
        await expectCodeAsync(.unknownPeer) { try await peers.resolve(bob.getACEId()) }
        let p = try await peers.pinRegistrationFile(try createRegistrationFile(for: bob, name: "Bob", endpoint: "https://bob.example"))
        #expect(p.source == .registration && p.registeredAt == 1741000000 && p.registrationSignature == nil)
        clock.now += 10_000_000
        #expect(try await peers.resolve(bob.getACEId()) == p)
        try await peers.remove(bob.getACEId())
        #expect(try await peers.get(bob.getACEId()) == nil)
    }
}
