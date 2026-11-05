// An ACEIdentity whose root is supplied by the caller for each operation that needs it (e.g. derived from a passkey
// PRF, never stored) and whose signing key is an injected provider. The identity holds the log and the signing key
// only; its export holds no key material in clear, only a Secure Enclave key's device-bound reference.
//
// This type never retains a root it is handed. `SoftwareKey` cannot zero its seed (`Data` and CryptoKit's private key
// are immutable), so the caller derives the root for one call and drops it right after.

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
/// KEL convention: inception root key(0) commits digest(key(1)); the k-th primary `rot` reveals key(k) and commits
/// digest(key(k+1)). An optional fallback root chain fb(0), fb(1), … is committed as `fallback` (see `RootChain`).
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
    /// `nextRootDigest` and the log's fallback (unless the log revealed it), then `dlg` of `signingKey`, dated
    /// `max(now, ts of the epoch start)`. Every delegation of the epoch, the previous device's included, is revoked.
    public static func recover(kel: [KelEvent], revealing nextRoot: SoftwareKey, nextRootDigest: Data, signingKey: any ACEKeyProvider,
                               now: Int? = nil) throws -> ExternalRootIdentity {
        let (state, ts, full) = try KelSteps.epochStart(kel, now: try identityNow(now))
        return try recover(state, ts: ts, full: full, revealing: nextRoot, nextRootDigest: nextRootDigest, signingKey: signingKey)
    }

    /// `rot` revealing the committed next root `nextRoot` after `state` (a verified prefix of `full`), keeping its fallback
    /// unless `full` revealed it, then `dlg` of `signingKey`, both at `ts`.
    private static func recover(_ state: KelState, ts: Int, full: [KelEvent], revealing nextRoot: SoftwareKey, nextRootDigest: Data,
                                signingKey: any ACEKeyProvider) throws -> ExternalRootIdentity {
        let d = try checkNextDigest(nextRootDigest)
        try checkCommitted(nextRoot, state)
        // The whole verified log: a key revealed only on the dropped branch is exposed all the same.
        try KelSteps.checkFreshNext(d, current: nextRoot.publicKey(), events: full)
        let fallback = try state.fallback.flatMap(hexDecode).flatMap { try KelSteps.revealedDigests(full).contains($0) ? nil : $0 }
        let st = try KelSteps.rotate(state, revealed: nextRoot, nextDigest: d, fallbackDigest: fallback,
                                     signingPublicKey: signingKey.publicKey(), ts: ts)
        return try ExternalRootIdentity(state: st, signing: signingKey)
    }

    /// Restore from an export and the signing key the host rebuilt from `export.signingKey`. A log that does not verify at
    /// `now` is `invalid_kel`; a signing key that is not the one the log delegates is `invalid_argument`.
    public convenience init(export: ExternalRootIdentityExport, signingKey: any ACEKeyProvider, now: Int? = nil) throws {
        try self.init(state: ACEKel.verify(export.kel, now: try identityNow(now)), signing: signingKey)
    }

    /// `rot` revealing `nextRoot` (the committed next root, else `invalid_argument`) and committing `nextRootDigest`,
    /// keeping the fallback, then `dlg` of the current signing key by the revealed root (a `rot` revokes the signing
    /// delegation). A new signing key comes with `recover` (a new device).
    public func rotate(revealing nextRoot: SoftwareKey, nextRootDigest: Data, now: Int? = nil) throws {
        let st = getState()
        try rotate(revealing: nextRoot, nextRootDigest: nextRootDigest, fallback: st.fallback.flatMap(hexDecode), now: now, from: st.lastHash)
    }

    /// `from`: the `lastHash` the keys were chosen for; another one (a concurrent rotation) is `invalid_argument`.
    private func rotate(revealing nextRoot: SoftwareKey, nextRootDigest: Data, fallback: Data?, now: Int?, from: String) throws {
        let d = try checkNextDigest(nextRootDigest)
        try withLock {
            guard from == state.lastHash else { throw ACEError(.invalidArgument, "the log changed during rotate") }
            let ts = try identityNow(now)
            try checkCommitted(nextRoot, state)
            for c in [d, fallback].compactMap({ $0 }) {
                try KelSteps.checkFreshNext(c, current: nextRoot.publicKey(), events: state.events)
            }
            state = try KelSteps.rotate(state, revealed: nextRoot, nextDigest: d, fallbackDigest: fallback, signingPublicKey: signing.publicKey(), ts: ts)
        }
    }

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
/// returns key(k), and ACE picks k from the log by finding which keys of the chain it reveals, so the host never indexes
/// the chain itself. Each key is dropped after the call.
///
/// A second, independent chain fb(0), fb(1), … (e.g. from a backup passkey's PRF) can be committed as the fallback root
/// (01 § Rotation and recovery): `rotate(roots:fallback: .set(fb))` commits fb(i), the first key of it the log has not
/// revealed, and `recover(kel:fallbackRoots:signingKey:)` takes the identity over with fb alone. The next root outranks the
/// fallback: `recover(kel:roots:signingKey:)` forks at the first `rot` after the chain's own last root, so it reclaims the
/// identity from any fallback recovery (a stolen backup included).
extension ExternalRootIdentity {
    public typealias RootChain = (Int) throws -> SoftwareKey

    /// What a primary `rotate(roots:fallback:)` commits as the fallback root.
    public enum FallbackChange {
        /// The log's current fallback commitment, if any.
        case keep
        /// fb(i) of this chain, i the number of its keys the log reveals.
        case set(RootChain)
        /// No fallback.
        case remove
    }

    private static func digest(_ roots: RootChain, _ k: Int) throws -> Data { keyDigest(publicKey: try roots(k).publicKey()) }

    /// How many keys of `chain` `events` reveals as roots, in order from key(0), and the index of the last event that
    /// revealed one (nil when none).
    private static func revealed(_ events: [KelEvent], _ chain: RootChain) throws -> (count: Int, last: Int?) {
        var n = 0, last: Int?, d = try digest(chain, 0)
        for (i, ev) in events.enumerated() where ev["t"] != "dlg" {
            guard keyDigest(publicKey: try ACEKel.keyBytes(ev["root"], "root").publicKey) == d else { continue }
            n += 1
            last = i
            d = try digest(chain, n)
        }
        return (n, last)
    }

    /// The ACE ID `incept(roots:signingKey:inceptedAt:)` makes, without a signing key: the hash of the inception by key(0)
    /// committing digest(key(1)) dated `inceptedAt`.
    public static func aceId(roots: RootChain, inceptedAt: Int) throws -> String {
        let icp = try ACEKel.createInception(root: roots(0), nextDigest: digest(roots, 1), ts: inceptedAt)
        return ACEKel.computeACEId(inceptionBytes: try ACEKel.eventBytes(icp))
    }

    /// `incept` by key(0) committing digest(key(1)), with no fallback (the ACE ID is a function of `roots` alone).
    public static func incept(roots: RootChain, signingKey: any ACEKeyProvider, inceptedAt: Int, now: Int? = nil) throws -> ExternalRootIdentity {
        try incept(root: roots(0), nextRootDigest: digest(roots, 1), signingKey: signingKey, inceptedAt: inceptedAt, now: now)
    }

    /// Take the identity over with the next root: the log reveals key(0) … key(n − 1) of `roots` (else `invalid_argument`);
    /// fork at the first `rot` after the last of them (a fallback `rot`, which a primary `rot` supersedes, 01 rule 6) or,
    /// when there is none, at the start of its epoch; `rot` revealing key(n), committing digest(key(n + 1)) and the
    /// fallback committed before the fork unless the log revealed it, then `dlg` of `signingKey`, dated
    /// `max(now, ts of the last kept event)`. Every delegation and commitment after the fork is revoked.
    public static func recover(kel: [KelEvent], roots: RootChain, signingKey: any ACEKeyProvider, now: Int? = nil) throws -> ExternalRootIdentity {
        let nowTs = try identityNow(now)
        let full = try ACEKel.verify(kel, now: nowTs).events
        let (n, last) = try revealed(full, roots)
        guard let last else { throw ACEError(.invalidArgument, "the roots did not incept this log") }
        let cut = full[(last + 1)...].firstIndex { $0["t"] == "rot" } ?? last + 1
        let kept = Array(full[..<cut])
        let ts = atLogTail(kept, now: nowTs)
        return try recover(try ACEKel.verify(kept, now: ts), ts: ts, full: full, revealing: roots(n), nextRootDigest: digest(roots, n + 1),
                           signingKey: signingKey)
    }

    /// Take the identity over with the fallback root: fork at the start of the current root epoch; `rot` revealing fb(i),
    /// the first key of `fallbackRoots` the log has not revealed (the committed fallback, else `invalid_argument`),
    /// carrying the committed next root and committing digest(fb(i + 1)), then `dlg` of `signingKey`, dated
    /// `max(now, ts of the epoch start)`. The holder of the next root can reclaim the identity from it at any time.
    public static func recover(kel: [KelEvent], fallbackRoots: RootChain, signingKey: any ACEKeyProvider, now: Int? = nil) throws -> ExternalRootIdentity {
        let (state, ts, full) = try KelSteps.epochStart(kel, now: try identityNow(now))
        let i = try revealed(state.events, fallbackRoots).count
        let root = try fallbackRoots(i)
        guard hexEncode(keyDigest(publicKey: root.publicKey())) == state.fallback else {
            throw ACEError(.invalidArgument, "fallbackRoots(\(i)) is not the committed fallback root")
        }
        let d = try digest(fallbackRoots, i + 1)
        try KelSteps.checkFreshNext(d, current: root.publicKey(), events: full)
        guard let next = hexDecode(state.next) else { throw ACEError(.invalidKel, "next must be 64 lowercase hex") }
        let st = try KelSteps.rotate(state, revealed: root, nextDigest: next, fallbackDigest: d,
                                     signingPublicKey: signingKey.publicKey(), ts: ts)
        return try ExternalRootIdentity(state: st, signing: signingKey)
    }

    /// `rotate` revealing key(n), the first key of `roots` the log has not revealed, committing digest(key(n + 1)) and the
    /// fallback `fallback` selects.
    public func rotate(roots: RootChain, fallback: FallbackChange = .keep, now: Int? = nil) throws {
        // `roots` runs outside the lock (host code); the log it was read at is checked again under the lock.
        let st = getState()
        let n = try Self.revealed(st.events, roots).count
        let fd: Data?
        switch fallback {
        case .keep: fd = st.fallback.flatMap(hexDecode)
        case .remove: fd = nil
        case .set(let chain): fd = try Self.digest(chain, Self.revealed(st.events, chain).count)
        }
        try rotate(revealing: roots(n), nextRootDigest: Self.digest(roots, n + 1), fallback: fd, now: now, from: st.lastHash)
    }
}
