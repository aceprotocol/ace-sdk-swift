import Foundation

/// All devices must address one authority/executor; never copy this store to another device.
/// FileStore is a single-host reference backend, without rollback or replication protection.
public final class ExecutionAuthority: Sendable {
    public typealias Usage = [String: String]
    public struct Configuration: Sendable {
        public let resource: String
        public let authority: VerifiedPeer
        public let executor: String
        public let schemaDigest: String
        public let actions: [String]
        public let validateIntent: @Sendable ([String: JSONValue]) throws -> Usage
        public let clock: @Sendable () -> Int
        public init(resource: String, authority: VerifiedPeer, executor: String, schemaDigest: String, actions: [String],
                    clock: @escaping @Sendable () -> Int = systemClock,
                    validateIntent: @escaping @Sendable ([String: JSONValue]) throws -> Usage) {
            self.resource = resource; self.authority = authority; self.executor = executor
            self.schemaDigest = schemaDigest; self.actions = actions; self.clock = clock; self.validateIntent = validateIntent
        }
    }
    public enum Reservation: Sendable, Equatable { case reserved, existing }
    public struct Snapshot: Sendable, Equatable {
        public let epoch: Int
        public let remaining: Usage
        public let reserved: Int
    }
    private struct State: Equatable {
        var epoch: Int
        var remaining: Usage
        var revoked: [String]
        var reserved: Int
        func json(_ configDigest: String) -> [String: JSONValue] {
            ["version": .number(1), "configDigest": .string(configDigest), "epoch": .number(Double(epoch)),
             "remaining": .object(remaining.mapValues(JSONValue.string)), "revoked": .array(revoked.map(JSONValue.string)),
             "reserved": .number(Double(reserved))]
        }
    }
    private struct Entry: Equatable {
        let digest: String
        let sender: String
        let charges: Usage
        var released: Bool
        var json: [String: JSONValue] {
            ["digest": .string(digest), "sender": .string(sender), "charges": .object(charges.mapValues(JSONValue.string)), "released": .bool(released)]
        }
    }
    private let config: Configuration
    private let store: any ACECoordinatedStore
    private let prefix: String
    private let configDigest: String
    private static let lockName = "execution-authority"
    private static func bad(_ s: String) -> ACEError { ACEError(.invalidAuthorization, s) }
    private static func corrupt() -> ACEError { ACEError(.storageFailed, "authority state unavailable or corrupt") }

    public init(configuration c: Configuration, store: any ACECoordinatedStore) throws {
        guard ACEGrants.name(.string(c.resource)), isACEId(c.executor), isSha256Hex(c.schemaDigest),
              (1...32).contains(c.actions.count), Set(c.actions).count == c.actions.count,
              c.actions.allSatisfy({ ACEGrants.name(.string($0)) }) else { throw Self.bad("invalid authority configuration") }
        config = c; self.store = store; prefix = "authority/\(sha256Hex(Data(c.resource.utf8)))/"
        configDigest = try intentDigest(.object([
            "resource": .string(c.resource), "authority": .string(c.authority.aceId), "executor": .string(c.executor),
            "scheme": .string(c.authority.scheme.rawValue), "publicKey": .string(c.authority.signingPublicKey.base64EncodedString()),
            "schemaDigest": .string(c.schemaDigest), "actions": .array(c.actions.sorted().map(JSONValue.string))]))
    }
    private static func usage(_ o: [String: JSONValue]?) throws -> Usage {
        guard let o, (1...32).contains(o.count) else { throw bad("invalid resource accounting") }
        var result: Usage = [:]
        for (k, v) in o {
            guard ACEGrants.name(.string(k)), let s = v.stringValue, ACEGrants.isExecutionUnits(s) else { throw bad("invalid resource accounting") }
            result[k] = s
        }
        return result
    }
    // Exact decimal subtraction, independent of machine integer size (up to 78 digits).
    private static func subtract(_ budget: Usage, _ charges: Usage) throws -> Usage {
        var next = budget
        for (key, cost) in charges {
            guard let balance = next[key], balance.count > cost.count || balance.count == cost.count && balance >= cost else {
                throw bad("insufficient resource budget")
            }
            var digits = Array(balance.utf8.reversed()), borrow = 0
            let costs = Array(cost.utf8.reversed())
            for i in digits.indices {
                var n = Int(digits[i]) - 48 - borrow - (i < costs.count ? Int(costs[i]) - 48 : 0)
                borrow = n < 0 ? 1 : 0; if n < 0 { n += 10 }; digits[i] = UInt8(n + 48)
            }
            while digits.count > 1 && digits.last == 48 { digits.removeLast() }
            next[key] = String(decoding: digits.reversed(), as: UTF8.self)
        }
        return next
    }
    private func object(_ data: Data) throws -> [String: JSONValue] {
        guard data.count <= 1_048_576, let o = try? JSONValue(json: data).objectValue else { throw Self.corrupt() }
        return o
    }
    private func state(_ o: [String: JSONValue]) throws -> State {
        guard ACEGrants.keys(o, "version,configDigest,epoch,remaining,revoked,reserved"), o["version"] == .number(1),
              o["configDigest"]?.stringValue == configDigest, let epoch = o["epoch"]?.wireInt,
              let reserved = o["reserved"]?.wireInt, let values = o["revoked"]?.arrayValue, values.count <= 10_000 else { throw Self.corrupt() }
        let revoked = values.compactMap(\.stringValue)
        guard revoked.count == values.count, revoked.allSatisfy(isMessageId), Set(revoked).count == revoked.count,
              let remaining = try? Self.usage(o["remaining"]?.objectValue) else { throw Self.corrupt() }
        return State(epoch: epoch, remaining: remaining, revoked: revoked, reserved: reserved)
    }
    private func entry(_ o: [String: JSONValue]) throws -> Entry {
        guard ACEGrants.keys(o, "digest,sender,charges,released"), let digest = o["digest"]?.stringValue, isSha256Hex(digest),
              let sender = o["sender"]?.stringValue, isACEId(sender), case .bool(let released) = o["released"],
              let charges = try? Self.usage(o["charges"]?.objectValue) else { throw Self.corrupt() }
        return Entry(digest: digest, sender: sender, charges: charges, released: released)
    }
    private func head(_ data: any ACEStoreData) throws -> State {
        guard let bytes = try data.checkedRead(prefix + "head") else { throw Self.corrupt() }
        return try state(object(bytes))
    }
    private func operation(_ data: any ACEStoreData, _ id: String) throws -> Entry? {
        try data.checkedRead(prefix + "operations/" + id).map { try entry(object($0)) }
    }
    private func put(_ data: any ACEStoreData, _ key: String, _ value: [String: JSONValue]) throws {
        try data.checkedWrite(prefix + key, JSONValue.object(value).jsonData())
    }
    private func put(_ data: any ACEStoreData, head s: State) throws { try put(data, "head", s.json(configDigest)) }
    /// Roll a journaled reservation forward: the operation row (unless present), then the head.
    private func finish(_ data: any ACEStoreData, _ id: String, _ e: Entry, after: State, writeOperation: Bool) throws {
        if writeOperation { try put(data, "operations/" + id, e.json) }
        try put(data, head: after); try data.checkedDelete(prefix + "pending")
    }
    /// Recovery of a `pending` journal left by an interrupted reservation.
    private func commit(_ data: any ACEStoreData, _ p: [String: JSONValue]) throws {
        guard ACEGrants.keys(p, "previous,next,operationId,entry"), let previous = p["previous"]?.objectValue,
              let next = p["next"]?.objectValue, let id = p["operationId"]?.stringValue, isMessageId(id),
              let value = p["entry"]?.objectValue else { throw Self.corrupt() }
        let before = try state(previous), after = try state(next), e = try entry(value)
        guard !e.released, before.reserved < maxSafeInteger,
              let remaining = try? Self.subtract(before.remaining, e.charges) else { throw Self.corrupt() }
        var expected = before; expected.remaining = remaining; expected.reserved += 1
        let h = try head(data), old = try operation(data, id)
        guard expected == after, h == before || h == after, old == nil || old == e else { throw Self.corrupt() }
        try finish(data, id, e, after: after, writeOperation: old == nil)
    }
    private func recover(_ data: any ACEStoreData) throws -> State {
        if let pending = try data.checkedRead(prefix + "pending") { try commit(data, object(pending)) }
        return try head(data)
    }
    /// Trusted local administration; no network request may provision/reset an authority.
    public func provision(epoch: Int, budget: Usage) throws {
        guard isWireInt(epoch) else { throw Self.bad("invalid initial epoch") }
        let remaining = try Self.usage(budget.mapValues(JSONValue.string))
        try store.coordinate(Self.lockName) { data in
            guard try data.checkedList(prefix).isEmpty else { throw Self.bad("authority already provisioned") }
            try put(data, head: State(epoch: epoch, remaining: remaining, revoked: [], reserved: 0))
        }
    }
    public func advanceEpoch(_ epoch: Int) throws {
        try store.coordinate(Self.lockName) { data in
            var s = try recover(data)
            guard isWireInt(epoch), epoch > s.epoch else { throw Self.bad("epoch must increase") }
            s.epoch = epoch; s.revoked = []; try put(data, head: s)
        }
    }
    public func revoke(_ grantId: String) throws {
        guard isMessageId(grantId) else { throw Self.bad("invalid grant ID") }
        try store.coordinate(Self.lockName) { data in
            var s = try recover(data)
            if s.revoked.contains(grantId) { return }
            guard s.revoked.count < 10_000 else { throw Self.bad("revocation capacity reached; advance epoch") }
            s.revoked.append(grantId); try put(data, head: s)
        }
    }
    private func verify(_ chain: [[String: JSONValue]], _ intent: [String: JSONValue], _ sender: String, _ s: State) throws -> String {
        try ACEGrants.verifyExecutionGrantChain(chain, intent: intent, sender: sender, executor: config.executor,
            policy: ResourcePolicy(resource: config.resource, authority: config.authority, epoch: s.epoch, revoked: s.revoked), now: config.clock())
    }
    /// Only `.reserved` may start preparing an effect. `.existing` requires reconciliation, never re-execution.
    public func reserve(chain: [[String: JSONValue]], intent: [String: JSONValue], authenticatedSender: String) throws -> Reservation {
        try store.coordinate(Self.lockName) { data in
            let s = try recover(data), hash = try verify(chain, intent, authenticatedSender, s)
            guard intent["schemaDigest"]?.stringValue == config.schemaDigest,
                  let action = intent["action"]?.stringValue, config.actions.contains(action) else { throw Self.bad("unsupported execution profile") }
            let charges = try Self.usage(config.validateIntent(intent).mapValues(JSONValue.string)), id = intent["operationId"]!.stringValue!
            if let old = try operation(data, id) {
                guard old.digest == hash, old.sender == authenticatedSender, old.charges == charges else { throw Self.bad("operation ID already bound") }
                return .existing
            }
            guard s.reserved < maxSafeInteger else { throw Self.bad("authority operation limit reached") }
            var next = s; next.reserved += 1; next.remaining = try Self.subtract(s.remaining, charges)
            let e = Entry(digest: hash, sender: authenticatedSender, charges: charges, released: false)
            let p: [String: JSONValue] = ["previous": .object(s.json(configDigest)), "next": .object(next.json(configDigest)),
                                          "operationId": .string(id), "entry": .object(e.json)]
            // Journal first; under this lock the head is `s` and the operation row is absent.
            try put(data, "pending", p); try finish(data, id, e, after: next, writeOperation: true)
            return .reserved
        }
    }
    /// Executor-local gate immediately before releasing a signature/effect. Never an RPC permission token.
    /// Current policy is rechecked and the release is permanently consumed before return. Lost ACKs fail closed.
    public func release(chain: [[String: JSONValue]], intent: [String: JSONValue], authenticatedSender: String) throws {
        try store.coordinate(Self.lockName) { data in
            let s = try recover(data), hash = try verify(chain, intent, authenticatedSender, s), id = intent["operationId"]!.stringValue!
            guard var old = try operation(data, id), old.digest == hash, old.sender == authenticatedSender, !old.released else {
                throw Self.bad("operation unavailable or already released")
            }
            old.released = true; try put(data, "operations/" + id, old.json)
        }
        // The quorum write/unlock can cross the deadline. Retain the consumed release, but never
        // authorize disclosure after the wait. A fresh request cannot reuse this operation.
        guard let deadline = intent["expiresAt"]?.wireInt, config.clock() < deadline else { throw Self.bad("intent expired during release") }
    }
    /// Reads a binding even after expiry/revocation. Never permission to execute or repeat an effect.
    public func hasReservation(intent: [String: JSONValue], authenticatedSender: String) throws -> Bool {
        let hash = try ACEGrants.executionIntentDigest(intent)
        guard isACEId(authenticatedSender), intent["resource"]?.stringValue == config.resource,
              intent["audience"]?.stringValue == config.executor else { throw Self.bad("invalid operation lookup") }
        return try store.coordinate(Self.lockName) { data in
            _ = try recover(data)
            guard let old = try operation(data, intent["operationId"]!.stringValue!) else { return false }
            guard old.digest == hash, old.sender == authenticatedSender else { throw Self.bad("operation ID already bound") }
            return true
        }
    }
    public func inspect() throws -> Snapshot {
        try store.coordinate(Self.lockName) { data in
            let s = try recover(data); return Snapshot(epoch: s.epoch, remaining: s.remaining, reserved: s.reserved)
        }
    }
}
