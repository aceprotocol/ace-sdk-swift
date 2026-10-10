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
    /// Horizon rows already validated: their exact bytes and record, by key. The key binds the
    /// ACE ID (so the signing key), account and signer, so equal bytes validate identically.
    private var horizons: [String: (raw: Data, record: PrincipalRecord)] = [:]
    private static let horizonsCap = 1024

    public init(store: any ACEStore, relay: RelayClient? = nil, ttlSeconds: Int = 86400,
                clock: @escaping @Sendable () -> Int = systemClock) throws {
        guard ttlSeconds >= 0 else { throw ACEError(.invalidArgument, "ttlSeconds must be a non-negative integer") }
        self.store = store
        self.relay = relay
        self.ttlSeconds = ttlSeconds
        self.clock = wireClock(clock)
    }

    private func load(_ aceId: String, enforceHorizon: Bool = true) throws -> PinnedPeer? {
        let key = PinnedPeer.key(aceId)
        guard let v = try store.readJSON(key) else { return nil }
        let result = try PinnedPeer.parse(v, key: key, aceId: aceId)
        if enforceHorizon {
            do { try checkPrincipalHorizon(result.peer, persist: false) }
            catch { throw storageError(key, "principal conflicts with durable horizon") }
        }
        return result
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

    /// Look the peer up on the relay now and adopt it under the rollback barrier; nil without a
    /// relay. Errors propagate. (`resolve(maxAgeSeconds: 0)` returns a pin fetched in the same
    /// second, so it is not a forced refresh.) Used by the Inbox's one-shot principal refresh (R-P20).
    func refresh(_ aceId: String) async throws -> VerifiedPeer? {
        guard isACEId(aceId) else { throw ACEError(.invalidArgument, "aceId must be an ACE ID") }
        guard let relay else { return nil }
        return try adopt(try await relay.lookupPeer(aceId)).peer
    }

    /// Adopt a verified binding under the rollback barrier (lock `peers`).
    @discardableResult
    public func adopt(_ peer: VerifiedPeer) throws -> AdoptResult {
        try store.withLock("peers") {
            let now = clock()
            let pin = try load(peer.aceId, enforceHorizon: false)
            let (next, outcome) = try adoptDecision(pin: pin?.peer, candidate: peer, now: now)
            try checkPrincipalHorizon(next)
            // A kept candidate replaces the cached profile and fetchedAt (02).
            try store.checkedWrite(PinnedPeer.key(peer.aceId), PinnedPeer(peer: next, fetchedAt: now).data())
            return AdoptResult(peer: next, outcome: outcome)
        }
    }

    /// Keep the authority barrier independently of the evictable key/profile cache.
    private func checkPrincipalHorizon(_ peer: VerifiedPeer, persist: Bool = true) throws {
        guard let next = peer.principal else { return }
        let domain = [peer.aceId, next.account, next.signer.scheme, next.signer.publicKey].joined(separator: "\0")
        let key = "principal-horizons/\(sha256Hex(Data(domain.utf8))).json"
        var high: PrincipalRecord?
        if let raw = try store.checkedRead(key) {
            if let cached = horizons[key], cached.raw == raw {
                high = cached.record
            } else {
                let value: JValue
                do { value = try JSONParser.parse(raw) } catch { throw ACEError(.storageFailed, "\(key) is not valid JSON") }
                do {
                    guard let o = value.objectValue, o["aceId"]?.stringValue == peer.aceId,
                          let p = o["principal"] else { throw storageError(key, "wrong record") }
                    try checkVersion(o, key)
                    let record = try PrincipalRecord.parse(p)
                    guard record.account == next.account, record.signer == next.signer else { throw storageError(key, "wrong authority") }
                    high = try validatePrincipalRecord(record, subjectSigningPublicKey: peer.signingPublicKey, now: record.issuedAt)
                } catch { throw storageError(key, "invalid principal horizon") }
                if horizons.count >= Self.horizonsCap { horizons.removeAll() }
                horizons[key] = (raw, high!)
            }
        }
        if let high, next.issuedAt < high.issuedAt || (next.issuedAt == high.issuedAt && !next.sameClaims(as: high)) {
            throw ACEError(.invalidPrincipal, "principal rolls back or conflicts with the durable horizon")
        }
        if persist && (high == nil || next.issuedAt > high!.issuedAt) {
            try store.checkedWrite(key, JSONWriter.serialize(.object([
                "aceId": .string(peer.aceId), "principal": next.jvalue, "version": num(1)
            ])))
        }
    }

    /// Verify a registration file (signed binding time) and adopt it.
    @discardableResult
    public func pinRegistrationFile(_ reg: RegistrationFile) throws -> VerifiedPeer {
        let candidate = try verifyRegistrationFile(reg, clock: clock)
        return try adopt(candidate).peer
    }

    public func remove(_ aceId: String) throws {
        guard isACEId(aceId) else { throw ACEError(.invalidArgument, "aceId must be an ACE ID") }
        try store.withLock("peers") { try store.checkedDelete(PinnedPeer.key(aceId)) }
    }
}
