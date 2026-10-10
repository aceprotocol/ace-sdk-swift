import Foundation
import Testing
@testable import ACE

@Suite("Durable execution authority")
struct ExecutionAuthorityTests {
    @Test func genericExecutionWrapper() throws {
        let op = try operation(), body: [String: JSONValue] = ["intent": .object(op.intent), "grants": .array(op.chain.map(JSONValue.object))]
        #expect(ExecutionRequest.schemaDigest == "5acd227e6886b0d327ed34be5ff2a89debbc08a1cbcd87ba582f9eed6e42cf32")
        #expect(try ExecutionRequest(body: body).body == body)
        var extra = body; extra["hiddenCondition"] = "unrecognized"
        expectCode(.invalidAuthorization) { try ExecutionRequest(body: extra) }
        extra = body; extra["grants"] = .array([])
        expectCode(.invalidAuthorization) { try ExecutionRequest(body: extra) }
    }
    private func setup(_ store: any ACECoordinatedStore, now: @escaping @Sendable () -> Int = { 150 }) throws -> ExecutionAuthority {
        let base = (Fixtures.vectors["grants"] as! [String: Any])["cases"] as! [[String: Any]]
        let intent = jsonBody(base[0]["intent"]!)
        return try ExecutionAuthority(configuration: .init(resource: intent["resource"]!.stringValue!, authority: peerOf(Fixtures.agent("alice")),
            executor: Fixtures.agent("bob").getACEId(), schemaDigest: intent["schemaDigest"]!.stringValue!, actions: [intent["action"]!.stringValue!], clock: now) { i in
                guard let d = i["details"]?.objectValue, Set(d.keys) == ["amount", "recipient"], let amount = d["amount"]?.stringValue else { throw ACEGrants.bad() }
                return ["asset:token": amount, "asset:fee": "2"]
            }, store: store)
    }
    private func operation(_ n: Int = 1, amount: String = "5") throws -> (intent: [String: JSONValue], chain: [[String: JSONValue]]) {
        let c = ((Fixtures.vectors["grants"] as! [String: Any])["cases"] as! [[String: Any]])[0]
        var intent = jsonBody(c["intent"]!), d = intent["details"]!.objectValue!
        intent["operationId"] = .string(String(format: "00000000-0000-4000-8000-%012d", n)); d["amount"] = .string(amount); intent["details"] = .object(d)
        var claims = jsonBody((c["chain"] as! [[String: Any]])[0]["claims"]!)
        claims["subject"] = .string(Fixtures.agent("bob").getACEId()); claims["delegationDepth"] = 0
        claims["intentDigest"] = .string(try ACEGrants.executionIntentDigest(intent))
        return (intent, [try ACEGrants.createExecutionGrant(signer: Fixtures.agent("alice"), claims: claims)])
    }
    private var sender: String { Fixtures.agent("bob").getACEId() }

    @Test func concurrentBudgetAndRelease() async throws {
        let store = MemoryStore(), one = try setup(store), two = try setup(store), op = try operation()
        try one.provision(epoch: 1, budget: ["asset:token": "10", "asset:fee": "2"])
        let results = try await withThrowingTaskGroup(of: ExecutionAuthority.Reservation.self) { group in
            for i in 0..<16 { group.addTask { try (i % 2 == 0 ? one : two).reserve(chain: op.chain, intent: op.intent, authenticatedSender: sender) } }
            var out: [ExecutionAuthority.Reservation] = []; for try await r in group { out.append(r) }; return out
        }
        #expect(results.filter { $0 == .reserved }.count == 1)
        #expect(try two.inspect().remaining == ["asset:token": "5", "asset:fee": "0"])
        let next = try operation(2)
        expectCode(.invalidAuthorization) { try two.reserve(chain: next.chain, intent: next.intent, authenticatedSender: sender) }
        try one.release(chain: op.chain, intent: op.intent, authenticatedSender: sender)
        expectCode(.invalidAuthorization) { try two.release(chain: op.chain, intent: op.intent, authenticatedSender: sender) }
        let changed = try operation(amount: "4")
        expectCode(.invalidAuthorization) { try two.reserve(chain: changed.chain, intent: changed.intent, authenticatedSender: sender) }
    }

    @Test(arguments: ["revoke", "epoch", "expire"])
    func lastGateChecksCurrentPolicy(change: String) throws {
        let store = MemoryStore(), a = try setup(store), op = try operation()
        try a.provision(epoch: 1, budget: ["asset:token": "10", "asset:fee": "10"])
        _ = try a.reserve(chain: op.chain, intent: op.intent, authenticatedSender: sender)
        if change == "revoke" { try a.revoke(op.chain[0]["claims"]!["grantId"]!.stringValue!) }
        if change == "epoch" { try a.advanceEpoch(2) }
        let reopened = try setup(store, now: { change == "expire" ? 1000 : 150 })
        #expect(try reopened.hasReservation(intent: op.intent, authenticatedSender: sender))
        expectCode(.invalidAuthorization) { try reopened.hasReservation(intent: op.intent, authenticatedSender: Fixtures.agent("alice").getACEId()) }
        expectCode(.invalidAuthorization) { try reopened.release(chain: op.chain, intent: op.intent, authenticatedSender: sender) }
        #expect(try reopened.inspect().remaining["asset:token"] == "5")
    }

    @Test(arguments: [1, 2, 3, 4], [false, true])
    func reservationCrashRecovery(boundary: Int, after: Bool) throws {
        let store = AuthorityFaultStore(), a = try setup(store), op = try operation()
        try a.provision(epoch: 1, budget: ["asset:token": "10", "asset:fee": "10"])
        store.arm(boundary, after: after)
        expectCode(.storageFailed) { try a.reserve(chain: op.chain, intent: op.intent, authenticatedSender: sender) }
        let recovered = try setup(store)
        let status = try recovered.reserve(chain: op.chain, intent: op.intent, authenticatedSender: sender)
        #expect(status == (boundary == 1 && !after ? .reserved : .existing))
        #expect(try recovered.inspect().remaining == ["asset:token": "5", "asset:fee": "8"])
        #expect(try recovered.inspect().reserved == 1)
    }

    @Test func lostReleaseAcknowledgementCannotReleaseTwice() throws {
        let store = AuthorityFaultStore(), a = try setup(store), op = try operation()
        try a.provision(epoch: 1, budget: ["asset:token": "10", "asset:fee": "10"])
        _ = try a.reserve(chain: op.chain, intent: op.intent, authenticatedSender: sender)
        store.arm(1, after: true)
        expectCode(.storageFailed) { try a.release(chain: op.chain, intent: op.intent, authenticatedSender: sender) }
        expectCode(.invalidAuthorization) { try setup(store).release(chain: op.chain, intent: op.intent, authenticatedSender: sender) }
    }

    @Test func deadlineCrossedDuringStorageWaitNeverReleasesAgain() throws {
        let store = ReleaseDelayStore(), a = try setup(store, now: { store.now }), op = try operation()
        try a.provision(epoch: 1, budget: ["asset:token": "10", "asset:fee": "10"])
        _ = try a.reserve(chain: op.chain, intent: op.intent, authenticatedSender: sender)
        store.arm()
        expectCode(.invalidAuthorization) { try a.release(chain: op.chain, intent: op.intent, authenticatedSender: sender) }
        expectCode(.invalidAuthorization) { try setup(store).release(chain: op.chain, intent: op.intent, authenticatedSender: sender) }
        #expect(try a.inspect().remaining == ["asset:token": "5", "asset:fee": "8"])
    }

    @Test func largeDecimalAndClosedProfile() throws {
        let store = MemoryStore(), a = try setup(store), amount = "1" + String(repeating: "0", count: 77)
        try a.provision(epoch: 1, budget: ["asset:token": amount, "asset:fee": "2"])
        let op = try operation(amount: String(repeating: "9", count: 77))
        _ = try a.reserve(chain: op.chain, intent: op.intent, authenticatedSender: sender)
        #expect(try a.inspect().remaining["asset:token"] == "1")
        var extra = op.intent; extra["units"] = "0"
        expectCode(.invalidAuthorization) { try a.reserve(chain: op.chain, intent: extra, authenticatedSender: sender) }
        try store.delete(try #require(store.list(prefix: "authority/").first { $0.hasSuffix("/head") }))
        expectCode(.storageFailed) { try a.inspect() }
        expectCode(.invalidAuthorization) { try a.provision(epoch: 1, budget: ["asset:token": "100"]) }
    }
}

private final class AuthorityFaultStore: ACEStore, @unchecked Sendable {
    private let base = MemoryStore(), guardLock = NSLock()
    private var countdown = 0, after = false
    func arm(_ count: Int, after: Bool) { guardLock.withLock { countdown = count; self.after = after } }
    private func mutate(_ body: () throws -> Void) throws {
        let fail = guardLock.withLock { () -> (Bool, Bool) in countdown -= 1; return (countdown == 0, after) }
        if fail.0 && !fail.1 { throw ACEError(.storageFailed, "injected before commit") }
        try body()
        if fail.0 { throw ACEError(.storageFailed, "injected after commit") }
    }
    func write(_ k: String, _ v: Data) throws { try mutate { try base.write(k, v) } }
    func delete(_ k: String) throws { try mutate { try base.delete(k) } }
    func read(_ k: String) throws -> Data? { try base.read(k) }
    func list(prefix: String) throws -> [String] { try base.list(prefix: prefix) }
    func lock(_ name: String, timeout: TimeInterval) throws -> any ACEStoreLock { try base.lock(name, timeout: timeout) }
}

private final class ReleaseDelayStore: ACECoordinatedStore, @unchecked Sendable {
    private let base = MemoryStore(), lock = NSLock()
    private var armed = false, time = 150
    var now: Int { lock.withLock { time } }
    func arm() { lock.withLock { armed = true } }
    func coordinate<T>(_ name: String, _ body: (any ACEStoreData) throws -> T) throws -> T {
        let result = try base.coordinate(name, body)
        lock.withLock { if armed { time = 1000 } }
        return result
    }
}
