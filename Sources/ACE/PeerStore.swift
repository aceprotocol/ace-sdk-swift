//
//  PeerStore.swift
//  ACE SDK
//
//  Pinned peer bindings with the rollback barrier (02-discovery).
//

import Foundation

/// Persistent peer cache. Pins are never removed by TTL expiry; the TTL only triggers a
/// relay refresh. A corrupt record is `storage_failed` and is never overwritten.
public actor PeerStore {
    public struct AdoptResult: Sendable {
        public let peer: VerifiedPeer
        public let outcome: AdoptOutcome
    }

    private let store: any ACEStore
    private let relay: RelayClient?
    private let ttlSeconds: Int
    private let clock: @Sendable () -> Int

    public init(store: any ACEStore, relay: RelayClient? = nil, ttlSeconds: Int = 86400,
                clock: @escaping @Sendable () -> Int = systemClock) throws {
        guard ttlSeconds >= 0 else { throw ACEError(.invalidArgument, "ttlSeconds must be a non-negative integer") }
        self.store = store
        self.relay = relay
        self.ttlSeconds = ttlSeconds
        self.clock = wireClock(clock)
    }

    private func load(_ aceId: String) throws -> PinnedPeer? {
        let key = PinnedPeer.key(aceId)
        guard let v = try store.readJSON(key) else { return nil }
        return try PinnedPeer.parse(v, key: key, aceId: aceId)
    }

    /// The pin regardless of TTL, or nil.
    public func get(_ aceId: String) throws -> VerifiedPeer? {
        guard isACEId(aceId) else { throw ACEError(.invalidArgument, "aceId must be an ACE ID") }
        return try load(aceId)?.peer
    }

    /// The peer, refreshed from the relay when the pin is older than `maxAgeSeconds`
    /// (default: the TTL). Falls back to the pin on retryable (`transient` or `local`)
    /// errors, `unknown_peer` and `stale_peer_binding` while `maxAgeSeconds > 0`.
    public func resolve(_ aceId: String, maxAgeSeconds: Int? = nil) async throws -> VerifiedPeer {
        guard isACEId(aceId) else { throw ACEError(.invalidArgument, "aceId must be an ACE ID") }
        let maxAge = maxAgeSeconds ?? ttlSeconds
        guard maxAge >= 0 else { throw ACEError(.invalidArgument, "maxAgeSeconds must be non-negative") }
        let pinned = try load(aceId)
        if let pinned, clock() - pinned.fetchedAt <= maxAge { return pinned.peer }
        guard let relay else {
            if let pinned { return pinned.peer }
            throw ACEError(.unknownPeer, "no pinned binding and no relay")
        }
        let candidate: VerifiedPeer
        do {
            candidate = try await relay.lookupPeer(aceId)
        } catch let e as ACEError where e.isTransient || e.code == .unknownPeer {
            if let pinned, maxAge > 0 { return pinned.peer }
            throw e
        }
        do {
            return try adopt(candidate).peer
        } catch let e as ACEError where e.code == .stalePeerBinding {
            if maxAge > 0, let pinned { return pinned.peer }
            throw e
        }
    }

    /// Adopt a verified binding under the rollback barrier (lock `peers`).
    @discardableResult
    public func adopt(_ peer: VerifiedPeer) throws -> AdoptResult {
        try store.withLock("peers") {
            let now = clock()
            let pin = try load(peer.aceId)
            let (next, outcome) = try adoptDecision(pin: pin?.peer, candidate: peer, now: now)
            // An unsigned candidate equal to the pin leaves the record (and its fetchedAt) untouched.
            if outcome == .unchanged, peer.registrationSignature == nil, let pin {
                return AdoptResult(peer: pin.peer, outcome: outcome)
            }
            try store.checkedWrite(PinnedPeer.key(peer.aceId), PinnedPeer(peer: next, fetchedAt: now).data())
            return AdoptResult(peer: next, outcome: outcome)
        }
    }

    /// Verify a registration file (`registeredAt = pinnedAt ?? now`) and adopt it.
    @discardableResult
    public func pinRegistrationFile(_ reg: RegistrationFile, pinnedAt: Int? = nil) throws -> VerifiedPeer {
        let candidate = try verifyRegistrationFile(reg, pinnedAt: pinnedAt ?? clock(), clock: clock)
        return try adopt(candidate).peer
    }

    public func remove(_ aceId: String) throws {
        guard isACEId(aceId) else { throw ACEError(.invalidArgument, "aceId must be an ACE ID") }
        try store.withLock("peers") { try store.checkedDelete(PinnedPeer.key(aceId)) }
    }
}
