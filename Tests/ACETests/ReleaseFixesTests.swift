import Foundation
import Testing
@testable import ACE

/// Regression tests for the pre-release review of 2026-10-17.
@Suite struct ReleaseFixesTests {
    // MARK: Constants and blocked addresses

    /// 02 § Constants names the `dlg` key lifetime `MAX_SIGNING_KEY_LIFETIME`.
    @Test func maxSigningKeyLifetimeIsTheSpecConstant() {
        #expect(ACELimits.maxSigningKeyLifetime == 31_622_400)
    }

    /// 07 § Blocked addresses: `2001::/23`, `3fff::/20`, `5f00::/16` and `fec0::/10`, each with a boundary just outside
    /// (where the neighbour is not itself blocked).
    @Test func widenedIPv6BlockedRanges() {
        let cases: [(String, Bool)] = [
            ("2001::1", true), ("2001:1ff:ffff::1", true), ("2001:200::1", false),
            ("3fff::1", true), ("3fff:fff:ffff::1", true), ("3fff:1000::1", false), ("3ffe:ffff::1", false),
            ("5f00::1", true), ("5f00:ffff::1", true), ("5f01::1", false), ("5eff:ffff::1", false),
            // fec0::/10 sits between fe80::/10 and ff00::/8, both blocked: its own ends are the boundary.
            ("fec0::1", true), ("feff:ffff::1", true),
        ]
        for (address, blocked) in cases { #expect(isBlockedAddress(address) == blocked, "\(address)") }
    }

    // MARK: Secrets never print

    /// `String(describing:)`, `String(reflecting:)` and `dump` of a software identity, its export and a Secure Enclave
    /// export never contain key material.
    @Test func identitiesAndExportsNeverPrintKeyMaterial() throws {
        let identity = try SoftwareIdentity.generate(now: NOW)
        let export = identity.exportPrivateKey()
        let seeds = [export.rootSeed, export.signingSeed] + (export.nextRootSeed.map { [$0] } ?? [])
        let secrets = seeds + (try seeds.map { hexEncode(try ACEBase64.decode($0)) })
        let blob = ACEBase64.encode(Data(repeating: 0xcd, count: 48))
        let se = SecureEnclaveIdentityExport(rootKey: blob, nextRootKey: blob, signingKey: blob, kel: export.kel)
        let subjects: [Any] = [identity, export, se, SoftwareKey.generate()]
        for subject in subjects {
            var dumped = ""
            dump(subject, to: &dumped)
            for text in [String(describing: subject), String(reflecting: subject), "\(subject)", dumped] {
                for secret in secrets + [blob] { #expect(!text.contains(secret), "\(type(of: subject)): \(text)") }
            }
        }
    }

    /// Seen-journal keys are 20 zero-padded digits for every 64-bit count (no 32-bit varargs truncation).
    @Test func journalKeysPadTheFullCount() {
        #expect(Inbox.journalKey(7) == "inbox/journal/00000000000000000007.json")
        #expect(Inbox.journalKey(1 << 40) == "inbox/journal/00000001099511627776.json")
        #expect(Inbox.journalKey(Int.max) == "inbox/journal/09223372036854775807.json")
    }

    // MARK: Received JSON depth (02 § JSON values, MAX_JSON_DEPTH)

    /// `depth` nested arrays: the outermost is depth 0, so `nested(33)` reaches depth 32 below a top-level object member.
    private static func nested(_ depth: Int) -> String { String(repeating: "[", count: depth) + String(repeating: "]", count: depth) }

    /// A relay response as a whole is within `MAX_JSON_DEPTH + 3` (its deepest wrapper, an inbox page, holds packets at
    /// depth 3); deeper is `relay_protocol_error`.
    @Test func relayResponsesAreDepthCheckedAt35() async throws {
        func relay(_ extra: String) throws -> RelayClient {
            try makeRelay { _, _ in .raw(200, #"{"status":"registered","x":"# + extra + "}", "application/json") }
        }
        let identity = try makeIdentity(now: systemClock())
        #expect(try await relay(Self.nested(35)).register(identity) == .registered)
        await expectCodeAsync(.relayProtocolError) { try await relay(Self.nested(36)).register(identity) }
    }

    /// A JSON value whose deepest container is at depth `n` (its root at 0).
    private static func nest(_ n: Int) -> JSONValue { n == 0 ? .object([:]) : ["a": nest(n - 1)] }

    /// A public PublishedAgent within depth `29 + 3`: `ext.x:deep:1` sits at depth 3 and holds `levels` more.
    private static func deepAgent(_ levels: Int, now: Int) throws -> VerifiedAgent {
        let prekey = try StorePrekeyVault(store: MemoryStore()).rotate(now: now).prekey
        return try createPublishedAgent(identity: try makeIdentity(now: now), claims: DescriptorClaims(
            relays: ["https://relay.example"], prekey: prekey, profiles: [ProfileRef(id: "x:deep:1", digest: String(repeating: "a", count: 64))],
            visibility: .public, ext: ["x:deep:1": nest(levels)]), now: now)
    }

    /// A PublishedAgent's depth counts from its own root (as sdk-ts and the relay), not from `ext`.
    @Test func publishedAgentDepthCountsFromItsRoot() throws {
        _ = try Self.deepAgent(29, now: NOW)  // depth 32
        expectCode(.invalidAuthorization) { try Self.deepAgent(30, now: NOW) }  // depth 33; ext alone only 31
    }

    /// 02 § JSON values: a PublishedAgent or packet at exactly `MAX_JSON_DEPTH` passes inside every wrapper; one level more
    /// is `relay_protocol_error` for the whole response, never a dropped entry.
    @Test func containedObjectsAtMaxJSONDepthPassInsideWrappers() async throws {
        let now = systemClock()
        let ok = try Self.deepAgent(29, now: now)
        var d = try #require(ok.source["descriptor"]?.objectValue)
        d["ext"] = ["x:deep:1": Self.nest(30)]
        let bad: JSONValue = ["kel": try #require(ok.source["kel"]), "descriptor": .object(d)]
        func relay(_ body: JSONValue) throws -> RelayClient {
            let text = String(decoding: try body.jsonData(), as: UTF8.self)
            return try makeRelay { _, _ in .raw(200, text, "application/json") }
        }
        #expect(try await relay(ok.source).descriptor(ok.aceId).aceId == ok.aceId)
        await expectCodeAsync(.relayProtocolError) { try await relay(bad).descriptor(ok.aceId) }
        #expect(try await relay(["agents": [ok.source], "cursor": .null]).directory().agents.count == 1)
        await expectCodeAsync(.relayProtocolError) { try await relay(["agents": [ok.source, bad], "cursor": .null]).directory() }

        let identity = try makeIdentity(now: now)
        let page = { (n: Int) -> JSONValue in ["messages": [["streamId": "1-0", "packet": Self.nest(n)]], "cursor": "1-0"] }
        #expect(try await relay(page(32)).fetchInbox(identity).entries.first?.packet == (try Self.nest(32).jsonData()))
        await expectCodeAsync(.relayProtocolError) { try await relay(page(33)).fetchInbox(identity) }
    }

    /// A 200 000-deep descriptor from a relay is `relay_protocol_error`, never a crash or a non-ACE error.
    @Test func aDeeplyNestedDescriptorIsARelayProtocolError() async throws {
        let id = try makeIdentity(now: systemClock()).getACEId()
        let relay = try makeRelay { _, _ in .raw(200, #"{"kel":[],"descriptor":{"card":"# + Self.nested(200_000) + "}}", "application/json") }
        await expectCodeAsync(.relayProtocolError) { try await relay.descriptor(id) }
    }

    /// An SSE `catchup` / `message` frame must be `{"packet": …}` with the packet within `MAX_JSON_DEPTH` (sdk-py):
    /// anything else ends listening with `relay_protocol_error`.
    @Test func sseFramesAreDepthCheckedAt32() async throws {
        let identity = try makeIdentity(now: systemClock())
        func listen(_ data: String) async throws -> [RelayClient.Event] {
            let relay = try makeRelay { _, _ in .sse(["event: message\nid: 1-0\ndata: \(data)\n\n"]) }
            var out: [RelayClient.Event] = []
            for try await e in relay.listen(identity) {
                out.append(e)
                break
            }
            return out
        }
        let ok = try await listen(#"{"packet":{"x":"# + Self.nested(32) + "}}")  // the packet at depth 32
        #expect(ok.count == 1 && ok[0].streamId == "1-0")
        await expectCodeAsync(.relayProtocolError) { try await listen(#"{"packet":{"x":"# + Self.nested(33) + "}}") }
        await expectCodeAsync(.relayProtocolError) { try await listen(#"{"packet":"# + Self.nested(200_000) + "}") }
        await expectCodeAsync(.relayProtocolError) { try await listen("not json") }
        await expectCodeAsync(.relayProtocolError) { try await listen(#"{"other":1}"#) }
    }

    /// The SDK's own records wrap private content one level down: a body at the full depth is staged and read back.
    @Test func storedRecordsHoldABodyAtFullDepth() async throws {
        let me = try makeIdentity(now: NOW), peer = try TestAgent(now: NOW)
        let store = MemoryStore()
        let open = try ProfileManifest(json: Data(#"{"id":"urn:example:open:1","messages":[{"type":"urn:example:open:msg:1","schema":{"type":"object","properties":{},"required":[],"additionalProperties":true}}]}"#.utf8))
        let outbox = Outbox(identity: me, store: store, profiles: try InstalledProfiles([open]), clock: { NOW })
        // content (depth 0) > body (1) > member array (2) > 30 more arrays: depth 32.
        let deep = try JSONValue(json: Data(Self.nested(31).utf8))
        let e = try await outbox.enqueue(to: peer.aceId, type: "urn:example:open:msg:1", body: ["deep": deep])
        #expect(try await outbox.entry(e.messageId)?.content.body["deep"] == deep)
        await expectCodeAsync(.invalidBody) {
            try await outbox.enqueue(to: peer.aceId, type: "urn:example:open:msg:1", body: ["deep": .array([deep])])
        }
    }

    // MARK: Foreign relay clients

    /// A foreign relay's session has a whole-request deadline (`timeoutIntervalForResource = timeout`, as sdk-ts and
    /// sdk-py), not URLSession's 7-day default, and the client owns (and so invalidates) it.
    @Test func foreignRelayRequestsHaveATotalDeadline() async throws {
        let relay = try RelayClient.foreign("https://relay.example", timeout: 7)
        let config = await relay.session.configuration
        #expect(config.timeoutIntervalForResource == 7 && config.timeoutIntervalForRequest == 7)
        #expect(await relay.ownsSession)
        let hosted = try RelayClient(baseURL: URL(string: "https://relay.example")!, session: stubSession())
        #expect(await !hosted.ownsSession)
    }

    // MARK: FileStore permissions

    private static func mode(_ path: String) -> mode_t {
        var st = stat()
        return lstat(path, &st) == 0 ? st.st_mode & 0o777 : 0
    }

    /// Fail closed: a store directory, subdirectory or file readable or writable by group or others is `storage_failed`;
    /// every directory the store creates, intermediate ones included, is 0700 and files are 0600.
    @Test func fileStoreRefusesLoosePermissions() throws {
        let base = tempDirectory()
        defer { try? FileManager.default.removeItem(at: base) }
        let root = base.appendingPathComponent("a/b/store")
        let store = try FileStore(directory: root)
        try store.write("dir/x.json", Data("1".utf8))
        for dir in [base.path, base.path + "/a", base.path + "/a/b", store.directory.path, store.directory.path + "/dir"] {
            #expect(Self.mode(dir) == 0o700, "\(dir)")
        }
        #expect(Self.mode(store.directory.path + "/dir/x.json") == 0o600)

        // the refusal names the offending path and the fix
        let real = store.directory.path
        chmod(real + "/dir/x.json", 0o644)
        expectCode(.storageFailed, messageContains: "chmod 600 \(real)/dir/x.json") { try store.read("dir/x.json") }
        chmod(real + "/dir/x.json", 0o600)
        #expect(try store.read("dir/x.json") == Data("1".utf8))

        chmod(real + "/dir", 0o750)
        expectCode(.storageFailed, messageContains: "chmod 700 \(real)/dir") { try store.write("dir/y.json", Data("2".utf8)) }
        chmod(real + "/dir", 0o700)

        try store.withLock("l") {}
        chmod(real + "/locks/l.lock", 0o644)
        expectCode(.storageFailed, messageContains: "chmod 600 \(real)/locks/l.lock") { try store.withLock("l") {} }
        chmod(real + "/locks/l.lock", 0o600)

        chmod(real, 0o755)
        expectCode(.storageFailed, messageContains: "chmod 700 \(root.standardizedFileURL.path)") { try FileStore(directory: root) }
        expectCode(.storageFailed, messageContains: "chmod 700 \(real)") { try store.read("dir/x.json") }
    }

    // MARK: Quarantine

    /// A text message from Alice queued for Bob from Alice whose host always fails on it (`storage_failed`).
    private static func quarantinedPair() async throws -> (alice: NetPeer, bob: NetPeer, messageId: String, clock: TestClock, relay: FakeRelay) {
        struct HostBug: Error, CustomStringConvertible { var description: String { String(repeating: "x", count: 2000) } }
        let clock = TestClock(systemClock()), relay = FakeRelay(clock: clock.fn)
        let alice = try await NetPeer.make(relay, clock: clock)
        let bob = try await NetPeer.make(relay, clock: clock, configuration: NetworkConfiguration(visibility: .public, onMessage: { m in
            if m.content.type == "ace:text:1" { throw HostBug() }
        }))
        try await alice.network.connect(bob.aceId, profile: "ace:text:1", note: "hello")
        _ = try await bob.network.pull()
        if try bob.network.admission.get(alice.aceId) == nil { try await bob.network.accept(alice.aceId) }
        _ = try await alice.network.pull()
        let sent = try await alice.network.send(to: bob.aceId, type: "ace:text:1", body: ["message": "m"])
        return (alice, bob, sent.messageId, clock, relay)
    }

    /// The quarantine record is `{fingerprint, code, reason ≤ 1000, quarantinedAt, packet: header}` (sdk-py, sdk-ts):
    /// the packet's scalar header fields only, never its ciphertext or signature.
    @Test func quarantineKeepsTheHeaderNotThePacket() async throws {
        let (alice, bob, messageId, clock, relay) = try await Self.quarantinedPair()
        let packet = try #require(relay.queued(bob.aceId).first)
        for _ in 0..<ACELimits.maxFetchAttempts { _ = try await bob.network.pull() }
        let keys = try bob.store.list(prefix: "inbox/quarantine/")
        #expect(keys == ["inbox/quarantine/\(sha256Hex(packet)).json"])
        let raw = try #require(try bob.store.read(keys[0]))
        let v = try JSONValue(json: raw)
        #expect(Set(v.objectValue?.keys.map { $0 } ?? []) == ["fingerprint", "code", "reason", "quarantinedAt", "packet"], "\(v)")
        #expect(v["fingerprint"]?.stringValue == sha256Hex(packet) && v["code"]?.stringValue == "storage_failed")
        #expect((v["reason"]?.stringValue?.count ?? 0) <= 1000 && v["quarantinedAt"]?.wireInt == clock.now)
        let p = try Packet(json: packet)
        #expect(v["packet"] == ["ace": "1", "from": .string(alice.aceId), "to": .string(bob.aceId), "messageId": .string(messageId),
                                "timestamp": .number(Double(p.timestamp)), "prekey": .string(p.encryption.prekey)], "\(v)")
        #expect(raw.count < 1500)
    }

    /// The header of a malformed packet keeps only well-formed scalars, strings cut to 256 characters; a non-object is null.
    @Test func quarantineHeaderOfAMalformedPacket() {
        let long = String(repeating: "é", count: 300)
        let raw = Data(#"{"ace":1.5,"from":"\#(long)","to":["x"],"timestamp":-1,"messageId":7,"encryption":{"prekey":"p","ciphertext":"c"},"signature":"s"}"#.utf8)
        #expect(Inbox.quarantineHeader(raw) == ["from": .string(String(repeating: "é", count: 256)), "messageId": 7, "prekey": "p"])
        #expect(Inbox.quarantineHeader(Data("[1]".utf8)) == .null && Inbox.quarantineHeader(Data("x".utf8)) == .null)
    }

    /// Past 1000 records the oldest by `quarantinedAt` (unreadable ones first) are deleted down to 900.
    @Test func quarantineIsCapped() async throws {
        let (_, bob, _, _, _) = try await Self.quarantinedPair()
        for n in 0..<1000 {
            let fp = String(format: "%064x", n)
            let body = n == 500 ? Data("junk".utf8) : try JSONValue.object(["fingerprint": .string(fp), "quarantinedAt": .number(Double(n))]).jsonData()
            try bob.store.write("inbox/quarantine/\(fp).json", body)
        }
        for _ in 0..<ACELimits.maxFetchAttempts { _ = try await bob.network.pull() }
        let keys = try bob.store.list(prefix: "inbox/quarantine/")
        #expect(keys.count == 900)
        let kept = Set(keys)
        #expect(!kept.contains("inbox/quarantine/\(String(format: "%064x", 500)).json"))  // unreadable: oldest
        #expect(!kept.contains("inbox/quarantine/\(String(format: "%064x", 99)).json"))
        #expect(kept.contains("inbox/quarantine/\(String(format: "%064x", 101)).json"))
    }

    // MARK: Shared state across processes (sdk-py regressions checked in Swift)

    /// Two vaults over one directory (two processes): each operation reloads under the `prekeys` flock, so neither
    /// overwrites the other's new prekey.
    @Test func prekeyVaultsSharingADirectoryKeepEachOthersPrekeys() throws {
        let dir = tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let a = StorePrekeyVault(store: try FileStore(directory: dir)), b = StorePrekeyVault(store: try FileStore(directory: dir))
        let first = try a.rotate(now: NOW)
        let second = try b.rotate(now: NOW + 1)
        #expect(try a.current() == second)
        #expect(try a.open(first.prekey.id, now: NOW + 2) != nil && b.open(second.prekey.id, now: NOW + 2) != nil)
    }

    /// A terminal Outbox state is never overwritten: a receipt that settles the entry while an attempt is in flight wins
    /// over the attempt's final failure, and a later `rejected` receipt does not downgrade `delivered`.
    @Test func outboxNeverDowngradesATerminalState() async throws {
        let me = try makeIdentity(now: NOW), peer = try TestAgent(now: NOW)
        let outbox = Outbox(identity: me, store: MemoryStore(), profiles: try InstalledProfiles([.text]), clock: { NOW })
        let e = try await outbox.enqueue(to: peer.aceId, type: "ace:text:1", body: ["message": "x"])
        // The receipt lands while the attempt is suspended in `prekey`.
        struct Settling: PacketTransport {
            let outbox: Outbox, peer: String, id: String
            func prekey(for aceId: String, refresh: Bool) async throws -> Prekey {
                _ = try await outbox.handleReceipt(from: peer, body: ["messageId": .string(id), "outcome": "delivered"])
                throw ACEError(.unknownPrekey, "refreshed descriptor refused")
            }
            func post(to aceId: String, content: PrivateContent, messageId: String, prekey: Prekey) async throws {}
        }
        let done = try await outbox.deliver(e.messageId, via: Settling(outbox: outbox, peer: peer.aceId, id: e.messageId))
        #expect(done.status == .delivered && done.code == nil, "\(done)")
        _ = try await outbox.handleReceipt(from: peer.aceId, body: ["messageId": .string(e.messageId), "outcome": "rejected", "code": "invalid_body"])
        #expect(try await outbox.entry(e.messageId)?.status == .delivered)
    }

    // MARK: Outbox attempts carry a permit (06 § Outbox step 3)

    /// Every attempt, first or retry, carries a permit valid under the peer's current pin; without one it fails
    /// `not_permitted` (not final: it waits for a renewal on the retry schedule) and nothing is posted on the stranger path.
    @Test func anOutboxAttemptWithoutAPermitIsNotPermittedAndNeverPosted() async throws {
        let clock = TestClock(systemClock()), relay = FakeRelay(clock: clock.fn)
        let alice = try await NetPeer.make(relay, clock: clock)
        let bob = try await NetPeer.make(relay, clock: clock)  // public: the relay would accept a permit-less packet
        _ = try await alice.network.agent(bob.aceId)
        let staged = try await alice.network.outbox.enqueue(to: bob.aceId, type: "ace:text:1", body: ["message": "x"])
        let first = try await alice.network.outbox.deliver(staged.messageId, via: alice.network)
        #expect(first.status == .pending && first.lastError?.contains("not_permitted") == true, "\(first)")
        clock.now = first.nextAttemptAt
        let retried = try await alice.network.flush()
        #expect(retried.count == 1 && retried[0].status == .pending && retried[0].attempts == 2)
        #expect(relay.sendCount(to: bob.aceId) == 0)
    }
}
