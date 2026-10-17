//
//  PeerStore.swift
//  ACE SDK
//
//  Peer pins: the verified KEL per ACE ID, extended under the fork rules, plus the newest signed descriptor adopted for
//  it (lock `peers`). Rows are re-verified on every read (cached by their exact bytes).
//

import Foundation

/// How `PeerStore.adopt` changed a pin.
public struct PeerAdoption: Sendable {
    public let state: KelState
    public let outcome: ExtendOutcome
}

/// Durable pins. `adopt` applies `ACEKel.extend` (rollback and fork protection) and keeps the newest descriptor per
/// identity: one under an advanced pin always replaces the held one; under the same pin an older `issuedAt`, or a
/// descriptor whose KEL is a strict prefix of the pin, or the same `issuedAt` with other content, is `stale_peer_binding`.
public actor PeerStore {
    private static let cacheSize = 256
    private let store: any ACEStore
    private let clock: @Sendable () -> Int
    private var cache: [String: (raw: Data, pin: Pin)] = [:]

    private struct Pin {
        let state: KelState
        let agent: VerifiedAgent?
        let fetchedAt: Int
    }

    public init(store: any ACEStore, clock: @escaping @Sendable () -> Int = systemClock) {
        self.store = store
        self.clock = clock
    }

    private static func key(_ aceId: String) -> String { "peers/\(sha256Hex(Data(aceId.utf8))).json" }

    private static func checkId(_ aceId: String) throws {
        guard isACEId(aceId) else { throw ACEError(.invalidArgument, "aceId must be an ACE ID") }
    }

    private func load(_ aceId: String) throws -> Pin? {
        let key = Self.key(aceId)
        guard let raw = try store.checkedRead(key) else { return nil }
        if let hit = cache[key], hit.raw == raw { return hit.pin }
        let pin: Pin
        do {
            guard let o = JSONValue(stored: raw)?.objectValue, o["version"] == 1, o["aceId"]?.stringValue == aceId,
                  let at = o["fetchedAt"]?.wireInt, let list = o["kel"]?.arrayValue, let source = o["agent"] else {
                throw ACEError(.storageFailed, "\(key) is malformed")
            }
            let events = try list.map { e -> KelEvent in
                guard let ev = e.objectValue else { throw ACEError(.storageFailed, "\(key) holds a malformed event") }
                return ev
            }
            let state = try ACEKel.verify(events, now: at)
            guard state.aceId == aceId else { throw ACEError(.storageFailed, "\(key) does not match its aceId") }
            var agent: VerifiedAgent?
            if !source.isNull {
                guard let issued = source["descriptor"]?["issuedAt"]?.wireInt else { throw ACEError(.storageFailed, "\(key) holds a malformed descriptor") }
                agent = try Self.reverify(source, issuedAt: issued, state: state)
            }
            pin = Pin(state: state, agent: agent, fetchedAt: at)
        } catch let e as ACEError {
            throw ACEError(.storageFailed, "\(key): \(e.message)")
        }
        if cache.count >= Self.cacheSize { cache.removeAll() }
        cache[key] = (raw, pin)
        return pin
    }

    /// A stored descriptor, verified as adopted: its claims at `issuedAt`, its signature under the pinned `state`.
    private static func reverify(_ source: JSONValue, issuedAt: Int, state: KelState) throws -> VerifiedAgent {
        let carried = try verifyPublishedAgent(["kel": ExportJSON.kelValue(state.events), "descriptor": source["descriptor"] ?? .null],
                                               now: issuedAt, allowLoopback: true, pinned: nil, kelNow: state.events.last.flatMap { wireInt($0["ts"]) })
        return VerifiedAgent(state: state, descriptor: carried.descriptor, source: source)
    }

    /// The pinned KEL state, or nil.
    public func pinned(_ aceId: String) throws -> KelState? {
        try Self.checkId(aceId)
        return try load(aceId)?.state
    }

    /// The newest adopted descriptor (possibly expired: check `descriptor.expiresAt`), or nil. Its `state` is the pinned
    /// (newest) KEL state. A descriptor is bound to the pins it was verified under: when a delegation issuer's pin has
    /// advanced since, the entry must verify again against it, else the descriptor is stale (nil: refresh it). Delegations
    /// expired at the store clock are dropped.
    public func agent(_ aceId: String) throws -> VerifiedAgent? {
        try Self.checkId(aceId)
        guard let agent = try load(aceId)?.agent else { return nil }
        for d in agent.descriptor.delegations {
            guard let pin = try load(d.issuer)?.state, pin.lastHash != d.issuerState.lastHash else { continue }
            if (try? checkDelegationEntry(d.entry, subject: aceId, now: agent.descriptor.issuedAt, pinned: pin)) == nil { return nil }
        }
        // an entry that has expired since is dropped (04 § Delegations), never reported
        let now = try unixNow(clock)
        guard agent.descriptor.delegations.contains(where: { now >= $0.expiresAt }) else { return agent }
        var d = agent.descriptor
        d.delegations.removeAll { now >= $0.expiresAt }
        return VerifiedAgent(state: agent.state, descriptor: d, source: agent.source)
    }

    /// `agent(aceId)` while its descriptor is unexpired at the store clock and the pinned identity is usable (01 § Verifier
    /// rules 5: never send to an identity whose signing delegation has passed its `notAfter`), else nil: the descriptor that
    /// may be used (04 § Caching).
    public func usableAgent(_ aceId: String) throws -> VerifiedAgent? {
        let now = try unixNow(clock)
        guard let a = try agent(aceId), now < a.descriptor.expiresAt, ACEKel.isUsable(a.state, now: now) else { return nil }
        return a
    }

    /// The pins held for the delegation issuers a PublishedAgent names (01 § Pinning): pass them as
    /// `verifyPublishedAgent(delegationPins:)` so a carried issuer KEL is reconciled with them.
    public func delegationPins(for source: JSONValue) throws -> [String: KelState] {
        try ACE.delegationPins(source) { try load($0)?.state }
    }

    /// Pin (or extend the pin to) a KEL under the fork rules, without a descriptor. A held descriptor is bound to the KEL
    /// state it was verified under: when the pin advances it is dropped (refreshed on next use).
    @discardableResult
    public func pin(kel: [KelEvent]) throws -> PeerAdoption {
        try store.withLock("peers") {
            let now = try unixNow(clock)
            let candidate = try ACEKel.verify(kel, now: now)
            let old = try load(candidate.aceId)
            let (state, outcome) = try ACEKel.extend(pinned: old?.state, verified: candidate)
            let agent = old?.state.lastHash == state.lastHash ? old?.agent : nil
            try write(state.aceId, state: state, agent: agent?.source, fetchedAt: max(now, old?.fetchedAt ?? 0))
            return PeerAdoption(state: state, outcome: outcome)
        }
    }

    /// Verify a PublishedAgent against the pin (`verifyPublishedAgent(pinned:)` at the store clock) and adopt it. An older
    /// revision refused under the same KEL never stands in for the held one: that one is returned only while usable
    /// (unexpired and bound to the current pins), else `stale_peer_binding`.
    @discardableResult
    public func adopt(source: JSONValue, allowLoopback: Bool = false) throws -> VerifiedAgent {
        guard let aceId = source["descriptor"]?["aceId"]?.stringValue, isACEId(aceId) else {
            throw ACEError(.invalidAuthorization, "published agent must be {kel, descriptor}")
        }
        let now = try unixNow(clock)
        let pinned = try load(aceId)?.state
        let agent = try verifyPublishedAgent(source, now: now, allowLoopback: allowLoopback, pinned: pinned,
                                             delegationPins: try delegationPins(for: source))
        do {
            try adopt(agent)
        } catch let e as ACEError where e.code == .stalePeerBinding {
            guard let kept = try usableAgent(aceId) else { throw e }
            return kept
        }
        return try load(aceId)?.agent ?? agent
    }

    /// Adopt a verified agent's KEL and descriptor under lock `peers`. The KEL is reconciled with the pin (fork rules) and
    /// the descriptor must verify under the resulting newest state: one signed by a delegation the pin has superseded is
    /// `stale_peer_binding` (no prekey substitution by a replaced signing key). A descriptor under an advanced pin replaces
    /// the held one unconditionally; under the same pin, an older `issuedAt`, or the same `issuedAt` with other content, is
    /// `stale_peer_binding`. Each delegation whose issuer is pinned must verify under that pin
    /// (`invalid_authorization`).
    @discardableResult
    public func adopt(_ agent: VerifiedAgent) throws -> PeerAdoption {
        try store.withLock("peers") {
            let now = try unixNow(clock)
            let old = try load(agent.aceId)
            let (state, outcome) = try ACEKel.extend(pinned: old?.state, events: agent.state.events, now: max(now, agent.descriptor.issuedAt))
            try verifyDescriptorSignature(agent.source, state: state, now: now)
            // A delegation whose issuer is pinned must verify under that pin (01 § Pinning), however the agent was verified:
            // a carried older issuer KEL never stands in for the pin.
            for entry in agent.source["descriptor"]?["delegations"]?.arrayValue ?? [] {
                guard let issuer = delegationIssuer(entry), let pin = try load(issuer)?.state else { continue }
                _ = try checkDelegationEntry(entry, subject: agent.aceId, now: now, pinned: pin)
            }
            var kept = agent.source
            if let previous = old?.agent, old?.state.lastHash == state.lastHash {
                // An older revision, or the same `issuedAt` with other claims, never replaces the held one (04 § Caching).
                if previous.descriptor.issuedAt > agent.descriptor.issuedAt {
                    throw ACEError(.stalePeerBinding, "descriptor revision rolled back")
                }
                if previous.descriptor.issuedAt == agent.descriptor.issuedAt {
                    guard try previous.source["descriptor"]?.jsonData() == agent.source["descriptor"]?.jsonData() else {
                        throw ACEError(.stalePeerBinding, "conflicting descriptor revision")
                    }
                    kept = previous.source
                }
            }
            try write(agent.aceId, state: state, agent: kept, fetchedAt: max(now, agent.descriptor.issuedAt, old?.fetchedAt ?? 0))
            return PeerAdoption(state: state, outcome: outcome)
        }
    }

    private func write(_ aceId: String, state: KelState, agent: JSONValue?, fetchedAt: Int) throws {
        let row: JSONValue = ["version": 1, "aceId": .string(aceId), "fetchedAt": .number(Double(fetchedAt)),
                              "kel": ExportJSON.kelValue(state.events), "agent": agent ?? .null]
        try store.checkedWrite(Self.key(aceId), try row.jsonData())
    }
}
