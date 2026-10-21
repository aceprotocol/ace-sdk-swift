//
//  ExternalRootIdentity.swift
//  ACE SDK
//
//  An ACEIdentity whose root is supplied by the caller for each operation that needs it (in SoulPass, derived from a
//  passkey PRF and never stored) and whose signing key is an injected provider (a Secure Enclave key in production, a
//  SoftwareKey in tests). The identity holds the log and the signing key only: no root, no next root, public or private.
//  Its export never holds key material in clear: only a Secure Enclave key's device-bound reference.
//  The log steps are `KelSteps`, shared with `KelIdentityCore`.
//
//  Root keys: this type never retains a root it is handed. `SoftwareKey` cannot zero its seed (`Data` and CryptoKit's
//  private key are immutable), so the caller derives the root for one call and drops it right after.
//

import Foundation

/// The persisted part of an `ExternalRootIdentity`: the signing key reference (Base64 Secure Enclave
/// `dataRepresentation`, device-bound) and the log. Never a root, never a seed.
public struct ExternalRootIdentityExport: Sendable, Equatable {
    public let signingKey: String
    public let kel: [KelEvent]

    public init(signingKey: String, kel: [KelEvent]) {
        self.signingKey = signingKey
        self.kel = kel
    }

    /// Not an object, or a missing or non-string `signingKey` → `invalid_argument`; a bad `kel` → `invalid_kel`. Unknown
    /// members are ignored.
    public init(json: Data) throws {
        let o = try ExportJSON.object(json)
        kel = try ExportJSON.kel(o)
        signingKey = try ExportJSON.string(o, "signingKey")
    }

    /// Canonical JSON.
    public func jsonData() throws -> Data {
        try JSONValue.object(["signingKey": .string(signingKey), "kel": ExportJSON.kelValue(kel)]).jsonData()
    }
}

/// A person identity: root key(n) is held outside (the caller supplies it per operation), the signing key is injected.
/// KEL convention: inception root key(0) commits digest(key(1)); the k-th `rot` reveals key(k) and commits
/// digest(key(k+1)); the current root is key(`rotationCount`).
/// Not an `ACEManagedIdentity`: it holds no root, so it cannot delegate on its own (a new signing key comes with `recover`).
public final class ExternalRootIdentity: HeldKelIdentity, @unchecked Sendable {
    private let lock = NSLock()
    private var state: KelState
    private let signing: any ACEKeyProvider

    private init(state: KelState, signing: any ACEKeyProvider) throws {
        guard let s = state.signing else { throw ACEError(.invalidKel, "kel has no signing delegation") }
        guard s.publicKey == signing.publicKey() else { throw ACEError(.invalidArgument, "signing key does not match the kel") }
        self.state = state
        self.signing = signing
    }

    /// `icp` by `root` (key(0)) committing `nextRootDigest` (digest(key(1))) dated `inceptedAt`, then `dlg` of
    /// `signingKey` at `now`. The ACE ID hashes the inception, so a fixed `inceptedAt` makes it a function of the root
    /// chain alone (the KEL bounds `ts` only from above, 01 § Verifier rules). `inceptedAt` after `now` is `invalid_argument`.
    public static func incept(root: SoftwareKey, nextRootDigest: Data, signingKey: any ACEKeyProvider, inceptedAt: Int,
                              now: Int? = nil) throws -> ExternalRootIdentity {
        let d = try checkNextDigest(nextRootDigest)
        let ts = try identityNow(now)
        try KelSteps.checkFreshNext(d, current: root.publicKey(), events: [])
        let state = try KelSteps.incept(root: root, nextDigest: d, signingPublicKey: signingKey.publicKey(), ts: ts, inceptedAt: inceptedAt)
        return try ExternalRootIdentity(state: state, signing: signingKey)
    }

    /// Take the identity over from its log (another device's, or a relay's copy): fork at the start of the current root
    /// epoch, `rot` revealing `nextRoot` (the committed next root, else `invalid_argument`) and committing
    /// `nextRootDigest`, then `dlg` of `signingKey`, dated `max(now, ts of the epoch start)`. Every delegation of the
    /// epoch, the previous device's included, is revoked.
    public static func recover(kel: [KelEvent], revealing nextRoot: SoftwareKey, nextRootDigest: Data, signingKey: any ACEKeyProvider,
                               now: Int? = nil) throws -> ExternalRootIdentity {
        try recover(kel: kel, next: { _ in (nextRoot, nextRootDigest) }, signingKey: signingKey, now: now)
    }

    /// `recover`, with the next root and the digest to commit chosen once the log verified: `next(k)` gets the index k of
    /// the root to reveal (the epoch's `rotationCount` + 1).
    private static func recover(kel: [KelEvent], next: (Int) throws -> (root: SoftwareKey, digest: Data), signingKey: any ACEKeyProvider,
                                now: Int?) throws -> ExternalRootIdentity {
        let (state, ts, full) = try KelSteps.epochStart(kel, now: try identityNow(now))
        let (nextRoot, nextRootDigest) = try next(state.rotationCount + 1)
        let d = try checkNextDigest(nextRootDigest)
        try checkCommitted(nextRoot, state)
        // The whole verified log: a key revealed only on the dropped branch is exposed all the same.
        try KelSteps.checkFreshNext(d, current: nextRoot.publicKey(), events: full)
        let st = try KelSteps.rotate(state, revealed: nextRoot, nextDigest: d, signingPublicKey: signingKey.publicKey(), ts: ts)
        return try ExternalRootIdentity(state: st, signing: signingKey)
    }

    /// Restore from an export and the signing key the host rebuilt from `export.signingKey`. A log that does not verify at
    /// `now` is `invalid_kel`; a signing key that is not the one the log delegates is `invalid_argument`.
    public convenience init(export: ExternalRootIdentityExport, signingKey: any ACEKeyProvider, now: Int? = nil) throws {
        try self.init(state: ACEKel.verify(export.kel, now: try identityNow(now)), signing: signingKey)
    }

    /// `rot` revealing `nextRoot` (the committed next root, key(`rotationCount` + 1), else `invalid_argument`) and
    /// committing `nextRootDigest`, then `dlg` of the current signing key by the revealed root (a `rot` revokes the
    /// signing delegation). A new signing key comes with `recover` (a new device).
    public func rotate(revealing nextRoot: SoftwareKey, nextRootDigest: Data, now: Int? = nil) throws {
        let d = try checkNextDigest(nextRootDigest)
        try withLock {
            let ts = try identityNow(now)
            try checkCommitted(nextRoot, state)
            try KelSteps.checkFreshNext(d, current: nextRoot.publicKey(), events: state.events)
            state = try KelSteps.rotate(state, revealed: nextRoot, nextDigest: d, signingPublicKey: signing.publicKey(), ts: ts)
        }
    }

    /// The number of `rot` events in the log: the index n of the current root key(n).
    public var rotationCount: Int { withLock { state.rotationCount } }

    /// The signing key reference and the log (the host persists them). Never a root. Only a Secure Enclave signing key
    /// has a reference; any other key (a `SoftwareKey` would export its seed in clear) is `invalid_argument`.
    public func exportKeyReferences() throws -> ExternalRootIdentityExport {
        guard let se = signing as? SecureEnclaveKey else {
            throw ACEError(.invalidArgument, "only a Secure Enclave signing key can be exported (as its device-bound reference)")
        }
        return withLock { ExternalRootIdentityExport(signingKey: ACEBase64.encode(se.dataRepresentation), kel: state.events) }
    }

    private func withLock<T>(_ body: () throws -> T) rethrows -> T {
        lock.lock()
        defer { lock.unlock() }
        return try body()
    }

    // MARK: ACEIdentity

    public func getACEId() -> String { withLock { state.aceId } }
    public func getSigningPublicKey() -> Data { withLock { signing.publicKey() } }
    public func getSigningSeq() throws -> Int {
        guard let s = withLock({ state.signing }) else { throw ACEError(.identityUnavailable, "no signing delegation") }
        return s.seq
    }
    public func getKel() throws -> [KelEvent] { withLock { state.events } }

    /// The signing key and its `seq` are read in one lock section; the signature is made outside the lock.
    public func sign(_ message: (Int) throws -> Data, action: String) throws -> (seq: Int, signature: Data) {
        let (key, seq) = try withLock { () throws -> (any ACEKeyProvider, Int) in
            guard let seq = state.signing?.seq else { throw ACEError(.identityUnavailable, "no signing delegation") }
            return (signing, seq)
        }
        return (seq, try key.sign(try message(seq), action: action))
    }
    package var heldState: KelState { withLock { state } }

    /// The verified log state.
    public func getState() -> KelState { withLock { state } }
}

/// `print`, `dump` and string interpolation never show the signing key reference.
extension ExternalRootIdentity: CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public var description: String { "ExternalRootIdentity(\(getACEId()))" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(self, children: ["aceId": getACEId()], displayStyle: .class) }
}

/// `print`, `dump` and string interpolation never show the signing key reference.
extension ExternalRootIdentityExport: CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public var description: String { "ExternalRootIdentityExport(signingKey: <redacted>, kel: \(kel.count) events)" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(self, children: ["kelEvents": kel.count], displayStyle: .struct) }
}

// MARK: - Root chain

/// For a host whose roots form a chain key(0), key(1), … it derives on demand (e.g. from one passkey PRF): `roots(k)`
/// returns key(k), and ACE picks k from the log (the current root is key(`rotationCount`); a step reveals key(n + 1) and
/// commits digest(key(n + 2))), so the host never indexes the chain itself. Each key is dropped after the call.
extension ExternalRootIdentity {
    public typealias RootChain = (Int) throws -> SoftwareKey

    private static func digest(_ roots: RootChain, _ k: Int) throws -> Data { keyDigest(publicKey: try roots(k).publicKey()) }

    /// The ACE ID `incept(roots:signingKey:inceptedAt:)` makes, without a signing key: the hash of the inception by key(0)
    /// committing digest(key(1)) dated `inceptedAt`.
    public static func aceId(roots: RootChain, inceptedAt: Int) throws -> String {
        let icp = try ACEKel.createInception(root: roots(0), nextDigest: digest(roots, 1), ts: inceptedAt)
        return ACEKel.computeACEId(inceptionBytes: try ACEKel.eventBytes(icp))
    }

    /// `incept` by key(0) committing digest(key(1)).
    public static func incept(roots: RootChain, signingKey: any ACEKeyProvider, inceptedAt: Int, now: Int? = nil) throws -> ExternalRootIdentity {
        try incept(root: roots(0), nextRootDigest: digest(roots, 1), signingKey: signingKey, inceptedAt: inceptedAt, now: now)
    }

    /// `recover` revealing key(n + 1) and committing digest(key(n + 2)), n read off the verified log.
    public static func recover(kel: [KelEvent], roots: RootChain, signingKey: any ACEKeyProvider, now: Int? = nil) throws -> ExternalRootIdentity {
        try recover(kel: kel, next: { k in (try roots(k), try digest(roots, k + 1)) }, signingKey: signingKey, now: now)
    }

    /// `rotate` revealing key(`rotationCount` + 1) and committing digest(key(`rotationCount` + 2)).
    public func rotate(roots: RootChain, now: Int? = nil) throws {
        let n = rotationCount
        try rotate(revealing: roots(n + 1), nextRootDigest: Self.digest(roots, n + 2), now: now)
    }
}
