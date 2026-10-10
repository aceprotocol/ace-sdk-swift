import Foundation
import Testing
@testable import ACE

/// An SSE endpoint that never ends: optional initial frames, then a heartbeat every
/// 20 ms until the client cancels. Records connects and cancellations per host.
final class EndlessSSEProtocol: URLProtocol, @unchecked Sendable {
    struct Host { var frames: [String] = []; var connects = 0; var stops = 0 }
    private static let state = Locked<[String: Host]>([:])
    private var timer: DispatchSourceTimer?

    static func register(_ host: String, frames: [String] = []) { state.mutate { $0[host] = Host(frames: frames) } }
    static func info(_ host: String) -> Host { state.value[host] ?? Host() }

    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        let host = request.url!.host!
        if request.url!.path == "/v1/inbox" {
            let response = HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: "HTTP/1.1",
                                           headerFields: ["Content-Type": "application/json"])!
            client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
            client?.urlProtocol(self, didLoad: Data(#"{"messages":[],"cursor":null}"#.utf8))
            client?.urlProtocolDidFinishLoading(self)
            return
        }
        let frames = Self.state.mutate { s -> [String] in s[host, default: Host()].connects += 1; return s[host]!.frames }
        let response = HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: "HTTP/1.1",
                                       headerFields: ["Content-Type": "text/event-stream"])!
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        for f in frames { client?.urlProtocol(self, didLoad: Data(f.utf8)) }
        let t = DispatchSource.makeTimerSource(queue: .global())
        t.schedule(deadline: .now() + .milliseconds(20), repeating: .milliseconds(20))
        t.setEventHandler { [weak self] in
            guard let self else { return }
            self.client?.urlProtocol(self, didLoad: Data(": heartbeat\n\n".utf8))
        }
        timer = t
        t.resume()
    }

    override func stopLoading() {
        timer?.cancel()
        timer = nil
        let host = request.url!.host!
        Self.state.mutate { $0[host, default: Host()].stops += 1 }
    }
}

private func endlessRelay(frames: [String] = [], realSleeper: Bool = false, clock: @escaping @Sendable () -> Int = systemClock) throws -> (RelayClient, String) {
    let host = uniqueHost()
    EndlessSSEProtocol.register(host, frames: frames)
    let config = URLSessionConfiguration.ephemeral
    config.protocolClasses = [EndlessSSEProtocol.self]
    let sleeper: @Sendable (Double) async throws -> Void = { seconds in
        if realSleeper { try await Task.sleep(nanoseconds: UInt64(seconds * 1_000_000_000)) }
    }
    let relay = try RelayClient(baseURL: URL(string: "https://\(host)")!, session: URLSession(configuration: config), timeout: 5,
                                maxResponseBytes: 1 << 20, clock: clock, sleeper: sleeper)
    return (relay, host)
}

/// Poll `condition` for up to `seconds`.
private func eventually(_ seconds: Double = 2, _ condition: () -> Bool) async -> Bool {
    let deadline = Date().addingTimeInterval(seconds)
    while Date() < deadline {
        if condition() { return true }
        try? await Task.sleep(nanoseconds: 10_000_000)
    }
    return condition()
}

@Suite("Developer experience")
struct DXTests {

    // MARK: JSONValue

    @Test func jsonValueLiteralsAndAccessors() throws {
        let v: JSONValue = ["s": "x", "n": 60, "f": 0.5, "b": true, "z": nil, "a": [1, "two"], "o": ["k": "v"]]
        #expect(v["s"]?.stringValue == "x" && v["n"]?.intValue == 60 && v["f"]?.doubleValue == 0.5)
        #expect(v["b"]?.boolValue == true && v["z"]?.isNull == true && v["a"]?[1]?.stringValue == "two")
        #expect(v["o"]?["k"] == "v" && v["a"]?[5] == nil && v["f"]?.intValue == nil)
        #expect(String(decoding: try v.jsonData(), as: UTF8.self)
                == #"{"a":[1,"two"],"b":true,"f":0.5,"n":60,"o":{"k":"v"},"s":"x","z":null}"#)
    }

    @Test func jsonValueNumbersRoundTrip() throws {
        let max = 9_007_199_254_740_991
        for text in ["9007199254740991", "-9007199254740991", "0", "60", "0.1", "1e+300", "-2.5", "1e-07"] {
            let v = try JSONValue(json: Data(text.utf8))
            #expect(String(decoding: try v.jsonData(), as: UTF8.self) == text, "\(text)")
        }
        #expect(try JSONValue(json: Data("\(max)".utf8)).intValue == max)
        #expect(try JSONValue(json: Data("6e1".utf8)) == 60)
        #expect(try JSONValue(json: Data("60.0".utf8)).wireInt == 60)
        #expect(JSONValue.number(-1).wireInt == nil && JSONValue.number(Double(max) + 2).wireInt == nil)
        #expect(throws: ACEError(.invalidArgument)) { try JSONValue(json: Data("1e400".utf8)) }
        #expect(throws: ACEError(.invalidArgument)) { try JSONValue(json: Data("{".utf8)) }
        #expect(throws: ACEError(.invalidArgument)) { try JSONValue.number(.nan).jsonData() }
    }

    @Test func jsonValueCodable() throws {
        let v: JSONValue = ["n": 9_007_199_254_740_991, "x": [true, nil, "s", 1.5]]
        let data = try JSONEncoder().encode(v)
        #expect(try JSONDecoder().decode(JSONValue.self, from: data) == v)
        #expect(String(decoding: data, as: UTF8.self).contains("9007199254740991"))
    }

    @Test func bodiesRoundTripThroughDeliveryRecords() async throws {
        let p = try await Pair()
        let bobPeer = try await p.alicePeers.get(p.bob.getACEId())!
        let body: [String: JSONValue] = ["message": "x", "big": 9_007_199_254_740_991, "f": 0.25, "nested": ["a": [1, 2]]]
        let env = try createMessage(sender: p.alice, recipient: bobPeer, type: .text, body: body,
                                    threads: try ThreadStateMachine(localAceId: p.alice.getACEId()), timestamp: p.clock.now)
        let sink = Sink()
        let bIn = try await p.inbox(p.bob, sink)
        let outcome = try await bIn.receive(env.jsonData())
        #expect(outcome.message?.body == body)
        let key = DeliveryRecord.key(from: env.from, messageId: env.messageId)
        let rec = try DeliveryRecord.parse(try p.bobStore.readJSON(key)!, key: key)
        #expect(rec.message.body == body)
        // A ParsedMessage crosses actors without @unchecked.
        let crossed = await Task.detached { outcome.message }.value
        #expect(crossed == outcome.message)
        await bIn.close()
    }

    // MARK: ACEError

    @Test func errorEqualityComparesCodeOnly() {
        #expect(ACEError(.replay, "a", status: 409) == ACEError(.replay))
        #expect(ACEError(.replay) != ACEError(.invalidBody))
        #expect(throws: ACEError(.invalidBody)) { try validateBody(.text, [:]) }
    }

    // MARK: createRegistrationFile

    @Test func registrationFileForCustomIdentity() throws {
        let se = try KeychainIdentity()
        let reg = try createRegistrationFile(for: se, name: "SE", endpoint: "https://se.example", hardwareBacking: .secureEnclave)
        let peer = try verifyRegistrationFile(reg)
        #expect(peer.aceId == se.getACEId() && peer.encryptionPublicKey == se.getEncryptionPublicKey())
        let k1 = try SoftwareIdentity.generate(scheme: .secp256k1)
        #expect(try verifyRegistrationFile(createRegistrationFile(for: k1, name: "K", endpoint: "https://k.example")).scheme == .secp256k1)
    }

    // MARK: listen session and cancellation

    @Test func listenUsesItsOwnUnboundedSession() async throws {
        let config = URLSessionConfiguration.ephemeral
        config.timeoutIntervalForResource = 30
        config.timeoutIntervalForRequest = 5
        config.protocolClasses = [EndlessSSEProtocol.self]
        let relay = try RelayClient(baseURL: URL(string: "https://x.example")!, session: URLSession(configuration: config))
        let s = await relay.listenSession()
        #expect(s.configuration.timeoutIntervalForResource == .infinity)
        #expect(s.configuration.timeoutIntervalForRequest == 90)
        #expect(s.configuration.protocolClasses?.first == EndlessSSEProtocol.self)
        #expect(await relay.listenSession() === s)
    }

    @Test func cancellingTheConsumerClosesAHeartbeatOnlyStream() async throws {
        let (relay, host) = try endlessRelay()
        let alice = Fixtures.agent("alice")
        let connected = Locked(false)
        let consumer = Task {
            for try await _ in relay.listen(alice, onOpen: { connected.mutate { $0 = true } }) {}
        }
        #expect(await eventually { connected.value })
        try await Task.sleep(nanoseconds: 100_000_000)  // a few heartbeats
        consumer.cancel()
        #expect(await eventually(1) { EndlessSSEProtocol.info(host).stops == 1 })
        _ = try? await consumer.value
        #expect(EndlessSSEProtocol.info(host).connects == 1)
    }

    @Test func droppingTheStreamClosesTheConnection() async throws {
        let bob = Fixtures.agent("bob")
        let env = try createMessage(sender: Fixtures.agent("alice"), recipient: try peerOf(bob), type: .text, body: ["message": "x"],
                                    threads: try ThreadStateMachine(localAceId: Fixtures.agent("alice").getACEId()))
        let (relay, host) = try endlessRelay(frames: ["id: 1-1\ndata: \(String(decoding: env.jsonData(), as: UTF8.self))\n\n"])
        for try await event in relay.listen(bob) {
            #expect(event.streamId == "1-1")
            break  // terminates the stream
        }
        #expect(await eventually(1) { EndlessSSEProtocol.info(host).stops == 1 })
    }

    @Test func cancellationInterruptsBackoffSleep() async throws {
        let calls = Locked(0)
        let host = uniqueHost()
        StubURLProtocol.register(host: host) { _, _ in
            calls.mutate { $0 += 1 }
            return .error(503, "x")
        }
        let relay = try RelayClient(baseURL: URL(string: "https://\(host)")!, session: stubSession())  // real sleeper: 1 s backoff
        let finished = Locked(false)
        let consumer = Task {
            defer { finished.mutate { $0 = true } }
            for try await _ in relay.listen(Fixtures.agent("alice")) {}
        }
        #expect(await eventually { calls.value == 1 })
        consumer.cancel()
        #expect(await eventually(0.5) { finished.value })
        try await Task.sleep(nanoseconds: 1_300_000_000)
        #expect(calls.value == 1)  // the backoff sleep was cancelled, no reconnect
    }

    // MARK: per-peer open threads

    private func openThread(_ threads: ThreadStore, local: String, peer: String, n: Int, at ts: Int, localFirst: Bool = false) throws {
        let conversationId = sha256Hex(Data("c\(n)".utf8))
        let snap = ThreadSnapshot(conversationId: conversationId, threadId: "t\(n)", localAceId: local, peerAceId: peer, state: .rfq,
                                  history: [ThreadHistoryEntry(type: .rfq, messageId: "00000000-0000-4000-8000-\(String(format: "%012d", n))",
                                                               timestamp: ts, from: localFirst ? local : peer)])
        try threads.write(StoredThread(snapshot: snap, pending: nil))
    }

    @Test func openThreadsPerPeerAreBounded() async throws {
        let p = try await Pair()
        let local = p.bob.getACEId(), peer = p.alice.getACEId()
        let bIn = try await p.inbox(p.bob, Sink())  // inbound threads exist only beside replay state
        let threads = try ThreadStore(store: p.bobStore, localAceId: local, clock: p.clock.fn)
        for n in 0..<ACELimits.maxOpenThreadsPerPeer {
            try openThread(threads, local: local, peer: peer, n: n, at: p.clock.now - 10)
        }
        let index = try p.bobStore.readJSON(ThreadStore.indexKey(peerAceId: peer))!
        #expect(index["open"]?.arrayValue?.count == ACELimits.maxOpenThreadsPerPeer && index["version"]?.wireInt == 1)
        let firstKey = ThreadStore.key(conversationId: sha256Hex(Data("c0".utf8)), threadId: "t0")
        #expect(index["open"]?.arrayValue?.contains(.string(String(firstKey.dropLast(5)))) == true)  // "threads/<hex>"

        let bobPeer = try await p.alicePeers.get(local)!
        let alicePeer = try await p.bobPeers.get(peer)!
        let rfq = try createMessage(sender: p.alice, recipient: bobPeer, type: .rfq, body: ["need": "x"],
                                    threads: try ThreadStateMachine(localAceId: peer), threadId: "new", timestamp: p.clock.now)
        let refused = try await bIn.receive(rfq.jsonData())
        #expect(refused.error == ACEError(.limitExceeded))
        if case .quarantined = refused {} else { Issue.record("expected quarantined: \(refused)") }
        let bOut = try await p.outbox(p.bob)
        await expectCodeAsync(.limitExceeded) {
            try await bOut.stage(recipient: alicePeer, type: .rfq, body: ["need": "y"], threadId: "mine")
        }
        // A type that cannot open a thread fails on the state machine, not on the bound.
        await expectCodeAsync(.transitionNotAllowed) {
            try await bOut.stage(recipient: alicePeer, type: .offer, body: ["price": "1", "currency": "USDC"], threadId: "mine")
        }
        // Closing one thread frees a slot.
        try threads.remove(conversationId: sha256Hex(Data("c0".utf8)), threadId: "t0")
        let rfq2 = try createMessage(sender: p.alice, recipient: bobPeer, type: .rfq, body: ["need": "x"],
                                     threads: try ThreadStateMachine(localAceId: peer), threadId: "new2", timestamp: p.clock.now)
        #expect(isDelivered(try await bIn.receive(rfq2.jsonData())))
        await bIn.close()
    }

    @Test func pruningDropsStalePeerOnlyThreads() throws {
        let clock = TestClock(1741000000)
        let store = MemoryStore()
        let local = Fixtures.agent("bob").getACEId(), peer = Fixtures.agent("alice").getACEId()
        let threads = try ThreadStore(store: store, localAceId: local, clock: clock.fn)
        let old = clock.now - ThreadStore.retentionSeconds - 1
        try openThread(threads, local: local, peer: peer, n: 1, at: old)                    // peer-only, stale
        try openThread(threads, local: local, peer: peer, n: 2, at: old, localFirst: true)  // has a local entry
        clock.now += ThreadStore.pruneIntervalSeconds
        try openThread(threads, local: local, peer: peer, n: 3, at: clock.now)
        #expect(try threads.list().map(\.threadId).sorted() == ["t2", "t3"])
        let open = try store.readJSON(ThreadStore.indexKey(peerAceId: peer))!["open"]!.arrayValue!
        #expect(open.count == 2)
    }

    // MARK: bounded resources

    @Test func quarantineIsCappedWithoutListingOnEveryInsert() async throws {
        final class CountingStore: ACEStore, @unchecked Sendable {
            let inner = MemoryStore()
            let lists = Locked(0)
            func read(_ key: String) throws -> Data? { try inner.read(key) }
            func write(_ key: String, _ value: Data) throws { try inner.write(key, value) }
            func delete(_ key: String) throws { try inner.delete(key) }
            func list(prefix: String) throws -> [String] {
                if prefix == "quarantine/" { lists.mutate { $0 += 1 } }
                return try inner.list(prefix: prefix)
            }
            func lock(_ name: String, timeout: TimeInterval) throws -> any ACEStoreLock { try inner.lock(name, timeout: timeout) }
        }
        let store = CountingStore()
        let p = try await Pair(bobStore: store)
        let bobPeer = try await p.alicePeers.get(p.bob.getACEId())!
        let env = try createMessage(sender: p.alice, recipient: bobPeer, type: .text, body: ["message": "x"],
                                    threads: try ThreadStateMachine(localAceId: p.alice.getACEId()), timestamp: p.clock.now)
        let bIn = try await p.inbox(p.bob, Sink())
        for n in 0..<(Inbox.quarantineCap + 1) {
            // A fresh messageId under the old signature: invalid_signature, a new fingerprint.
            let forged = ACEMessage(messageId: "00000000-0000-4000-8000-\(String(format: "%012d", n))", from: env.from, to: env.to,
                                    conversationId: env.conversationId, timestamp: env.timestamp,
                                    encryption: env.encryption, signature: env.signature)
            let o = try await bIn.receive(forged.jsonData())
            #expect(o.error == ACEError(.invalidSignature))
        }
        #expect(try store.list(prefix: "quarantine/").count == Inbox.quarantineKeep)
        #expect(store.lists.value <= 3)  // the first insert, the trim, and this check
        await bIn.close()
    }

    @Test func onOpenErrorEndsListenWithoutRetry() async throws {
        struct HookError: Error {}
        let (relay, host) = try endlessRelay()
        do {
            for try await _ in relay.listen(Fixtures.agent("alice"), onOpen: { throw HookError() }) {}
            Issue.record("expected the hook's error")
        } catch {
            #expect(error is HookError)
        }
        #expect(EndlessSSEProtocol.info(host).connects == 1)
    }

}

@Test func jsonValueAcceptsStringInterpolation() throws {
    let name = "bob"
    let body: [String: JSONValue] = ["message": "hello \(name) ✓"]
    #expect(body["message"]?.stringValue == "hello bob ✓")
}
