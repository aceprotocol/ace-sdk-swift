//
//  ExternalRootIdentity.swift
//  ACE SDK
//
//  An ACEIdentity whose root is supplied by the caller for each operation that needs it (in SoulPass, derived from a
//  passkey PRF and never stored) and whose signing key is an injected provider (a Secure Enclave key in production, a
//  SoftwareKey in tests). The identity holds the log and the signing key only: no root, no next root, public or private.
//  The log steps are `KelSteps`, shared with `KelIdentityCore`.
//
//  Root keys: this type never retains a root it is handed. `SoftwareKey` cannot zero its seed (`Data` and CryptoKit's
//  private key are immutable), so the caller derives the root for one call and drops it right after.
//

import Foundation

/// The persisted part of an `ExternalRootIdentity`: the signing key reference (Base64 Secure Enclave
/// `dataRepresentation`, device-bound; or Base64 seed of a `SoftwareKey`, tests only) and the log. Never a root.
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
public final class ExternalRootIdentity: ACEManagedIdentity, HeldKelIdentity, @unchecked Sendable {
    private let lock = NSLock()
    private var state: KelState
    private let signing: any ACEKeyProvider
    private let signingReference: String

    private init(state: KelState, signing: any ACEKeyProvider) throws {
        guard let s = state.signing else { throw ACEError(.invalidKel, "kel has no signing delegation") }
        guard s.publicKey == signing.publicKey() else { throw ACEError(.invalidArgument, "signing key does not match the kel") }
        self.state = state
        self.signing = signing
        self.signingReference = try Self.reference(of: signing)
    }

    /// The persistable reference of a signing key: a Secure Enclave key's `dataRepresentation` or a `SoftwareKey`'s
    /// seed (Base64); any other provider is `invalid_argument`.
    private static func reference(of key: any ACEKeyProvider) throws -> String {
        if let se = key as? SecureEnclaveKey { return ACEBase64.encode(se.dataRepresentation) }
        if let sw = key as? SoftwareKey { return ACEBase64.encode(sw.seed) }
        throw ACEError(.invalidArgument, "signingKey must be a SecureEnclaveKey or a SoftwareKey")
    }

    private static func digest(_ d: Data) throws -> Data {
        guard d.count == 32 else { throw ACEError(.invalidArgument, "nextRootDigest must be 32 bytes") }
        return d
    }

    /// `icp` by `root` (key(0)) committing `nextRootDigest` (digest(key(1))) dated `inceptedAt`, then `dlg` of
    /// `signingKey` at `now`. The ACE ID hashes the inception, so a fixed `inceptedAt` makes it a function of the root
    /// chain alone (the KEL bounds `ts` only from above, 01 § Verifier rules). `inceptedAt` after `now` is `invalid_argument`.
    public static func incept(root: SoftwareKey, nextRootDigest: Data, signingKey: any ACEKeyProvider, inceptedAt: Int,
                              now: Int? = nil) throws -> ExternalRootIdentity {
        let d = try digest(nextRootDigest)
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
        let d = try digest(nextRootDigest)
        let (state, ts) = try KelSteps.epochStart(kel, now: try identityNow(now))
        try checkCommitted(nextRoot, state)
        try KelSteps.checkFreshNext(d, current: nextRoot.publicKey(), events: state.events)
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
        let d = try Self.digest(nextRootDigest)
        try withLock {
            let ts = try identityNow(now)
            try checkCommitted(nextRoot, state)
            try KelSteps.checkFreshNext(d, current: nextRoot.publicKey(), events: state.events)
            state = try KelSteps.rotate(state, revealed: nextRoot, nextDigest: d, signingPublicKey: signing.publicKey(), ts: ts)
        }
    }

    /// The number of `rot` events in the log: the index n of the current root key(n).
    public var rotationCount: Int { withLock { state.events.filter { $0["t"] == .string("rot") }.count } }

    /// The signing key reference and the log (the host persists them). Never a root.
    public func exportKeyReferences() -> ExternalRootIdentityExport {
        withLock { ExternalRootIdentityExport(signingKey: signingReference, kel: state.events) }
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

    // MARK: ACEManagedIdentity

    public func getState() -> KelState { withLock { state } }

    /// Always `invalid_argument`: the root is held outside this identity; a new signing key comes with `recover`.
    public func delegate(now: Int?, notAfter: Int?) throws {
        throw ACEError(.invalidArgument, "an external-root identity delegates only with its root: recover on the new device")
    }
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
