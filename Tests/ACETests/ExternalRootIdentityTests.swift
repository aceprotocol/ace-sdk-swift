import Foundation
import Testing
@testable import ACE

/// The person identity's KEL: root key(n) is supplied per operation (derived from a passkey PRF in the host), key(0)
/// at inception committing digest(key(1)); the k-th `rot` reveals key(k) and commits digest(key(k+1)).
@Suite struct ExternalRootIdentityTests {
    /// Deterministic root chain key(n) (the host derives these from the PRF).
    static func root(_ n: Int) -> SoftwareKey { try! SoftwareKey(seed: Data(repeating: UInt8(n + 1), count: 32)) }
    static func digest(_ n: Int) -> Data { keyDigest(publicKey: root(n).publicKey()) }

    static func incept(now: Int = NOW) throws -> (ExternalRootIdentity, SoftwareKey) {
        let signing = SoftwareKey.generate()
        let id = try ExternalRootIdentity.incept(root: root(0), nextRootDigest: digest(1), signingKey: signing, inceptedAt: 0, now: now)
        return (id, signing)
    }

    static func rotCount(_ kel: [KelEvent]) -> Int { kel.filter { $0["t"] == "rot" }.count }

    @Test func inceptCommitsTheGivenNextRoot() throws {
        let (id, signing) = try Self.incept()
        let kel = try id.getKel()
        #expect(kel.count == 2 && kel[0]["t"] == "icp" && kel[1]["t"] == "dlg")
        #expect(kel[0]["next"]?.stringValue == hexEncode(Self.digest(1)))
        let st = try ACEKel.verify(kel, now: NOW)
        #expect(st.aceId == id.getACEId() && st.rootPublicKey == Self.root(0).publicKey())
        #expect(id.getSigningPublicKey() == signing.publicKey() && st.signing?.publicKey == signing.publicKey())
        #expect(try Self.rotCount(try id.getKel()) == 0)
        #expect(try checkUsable(id, now: NOW).aceId == id.getACEId())
    }

    @Test func inceptRefusesABadOrReusedNextDigest() {
        expectCode(.invalidArgument, "short") {
            try ExternalRootIdentity.incept(root: Self.root(0), nextRootDigest: Data(count: 31), signingKey: SoftwareKey.generate(),
                                            inceptedAt: 0, now: NOW)
        }
        expectCode(.invalidArgument, "root itself") {
            try ExternalRootIdentity.incept(root: Self.root(0), nextRootDigest: Self.digest(0), signingKey: SoftwareKey.generate(),
                                            inceptedAt: 0, now: NOW)
        }
        expectCode(.invalidArgument, "inception after now") {
            try ExternalRootIdentity.incept(root: Self.root(0), nextRootDigest: Self.digest(1), signingKey: SoftwareKey.generate(),
                                            inceptedAt: NOW + 1, now: NOW)
        }
    }

    /// A fixed inception time makes the ACE ID a function of the root chain: another signing key, another day, same ID.
    @Test func aFixedInceptionTimeGivesADeterministicACEId() throws {
        let (a, _) = try Self.incept(now: NOW)
        let (b, _) = try Self.incept(now: NOW + 86_400)
        #expect(a.getACEId() == b.getACEId())
        #expect(try ACEKel.verify(b.getKel(), now: NOW + 86_400).aceId == a.getACEId())
    }

    @Test func rootIsNotRetainedAfterInceptRotate() throws {
        let (id, _) = try Self.incept()
        func check(_ label: String) throws {
            // What the host persists besides the signing key reference: the log.
            let export = ExternalRootIdentityExport(signingKey: "", kel: try id.getKel())
            let data = try export.jsonData()
            let text = String(decoding: data, as: UTF8.self) + String(describing: Mirror(reflecting: id).children.map(\.value))
            for n in 0...3 {
                // Roots appear in the KEL only once revealed (icp / rot carry them by design); seeds never appear.
                #expect(!text.contains(ACEBase64.encode(Self.root(n).seed)), "\(label): seed \(n)")
            }
            let kelRoots = Set(export.kel.compactMap { $0["root"]?.objectValue?["publicKey"]?.stringValue })
            let held = ACEBase64.encode(Self.root(Self.rotCount(try id.getKel()) + 1).publicKey())
            #expect(!kelRoots.contains(held) && !text.contains(held), "\(label): next root public key")
        }
        try check("incept")
        try id.rotate(revealing: Self.root(1), nextRootDigest: Self.digest(2), now: NOW + 2)
        try check("rotate")
    }

    /// The export never holds a seed: a software signing key is refused; the host rebuilds the identity from the log and a
    /// key it holds itself.
    @Test func exportRefusesASoftwareSigningKeyAndRestoresFromTheLog() throws {
        let (id, signing) = try Self.incept()
        expectCode(.invalidArgument, "software signing key") { try id.exportKeyReferences() }
        let parsed = try ExternalRootIdentityExport(json: ExternalRootIdentityExport(signingKey: "ref", kel: try id.getKel()).jsonData())
        let restored = try ExternalRootIdentity(export: parsed, signingKey: try SoftwareKey(seed: signing.seed), now: NOW)
        #expect(try restored.getACEId() == id.getACEId() && restored.getKel() == id.getKel())
        expectCode(.invalidArgument, "wrong signing key") {
            try ExternalRootIdentity(export: parsed, signingKey: SoftwareKey.generate(), now: NOW)
        }
        expectCode(.invalidArgument, "not an object") { try ExternalRootIdentityExport(json: Data("[]".utf8)) }
        guard testKeyProvider == "secure-enclave" else { return }
        let se = try SecureEnclaveKey.generate()
        let hw = try ExternalRootIdentity.incept(root: Self.root(0), nextRootDigest: Self.digest(1), signingKey: se, inceptedAt: 0, now: NOW)
        let export = try hw.exportKeyReferences()
        #expect(export.signingKey == ACEBase64.encode(se.dataRepresentation))
        let back = try SecureEnclaveKey(dataRepresentation: try decodeB64(export.signingKey, code: .invalidArgument, what: "signingKey", maxBytes: 16384))
        #expect(try ExternalRootIdentity(export: export, signingKey: back, now: NOW).getACEId() == hw.getACEId())
    }

    /// 01 § Rotation and recovery: the signer refuses a signing key that is the current root or the committed next
    /// root, and a next root committing to a delegated signing key.
    @Test func signerRefusesKeyReuseAcrossRolesInTheLog() throws {
        let signing = SoftwareKey.generate()
        expectCode(.invalidArgument, "signing key is the root") {
            try ExternalRootIdentity.incept(root: Self.root(0), nextRootDigest: Self.digest(1), signingKey: Self.root(0), inceptedAt: 0, now: NOW)
        }
        expectCode(.invalidArgument, "signing key is the committed next root") {
            try ExternalRootIdentity.incept(root: Self.root(0), nextRootDigest: keyDigest(publicKey: signing.publicKey()),
                                            signingKey: signing, inceptedAt: 0, now: NOW)
        }
        let (id, held) = try Self.incept()
        expectCode(.invalidArgument, "next commits to the delegated key") {
            try id.rotate(revealing: Self.root(1), nextRootDigest: keyDigest(publicKey: held.publicKey()), now: NOW + 1)
        }
        expectCode(.invalidArgument, "recovered signing key is the revealed root") {
            try ExternalRootIdentity.recover(kel: try id.getKel(), revealing: Self.root(1), nextRootDigest: Self.digest(2),
                                             signingKey: Self.root(1), now: NOW + 1)
        }
        // A software identity: a next root committing to its (current or a past) signing key is refused.
        let sw = try SoftwareIdentity.generate(now: NOW)
        let first = sw.getSigningPublicKey()
        try sw.delegate(now: NOW + 1)
        for key in [first, sw.getSigningPublicKey()] {
            expectCode(.invalidArgument, "software next = signing key") { try sw.rotate(now: NOW + 2, nextRootDigest: keyDigest(publicKey: key)) }
        }
        try sw.rotate(now: NOW + 2)
    }

    @Test func recoverWithTheCommittedNextRootRotatesAndDelegates() throws {
        let (lost, _) = try Self.incept()
        let kel = try lost.getKel()
        let signing = SoftwareKey.generate()
        let r = try ExternalRootIdentity.recover(kel: kel, revealing: Self.root(1), nextRootDigest: Self.digest(2),
                                                 signingKey: signing, now: NOW + 5)
        #expect(try r.getACEId() == lost.getACEId() && Self.rotCount(try r.getKel()) == 1)
        #expect(try r.getSigningSeq() > lost.getSigningSeq())
        let st = try checkUsable(r, now: NOW + 5)
        #expect(st.signing?.publicKey == signing.publicKey() && st.rootPublicKey == Self.root(1).publicKey())
        let (seq, sig) = try r.sign({ Data("m\($0)".utf8) }, action: "test")
        #expect(seq == st.signing?.seq)
        #expect(ACESigning.verifySignature(message: Data("m\(seq)".utf8), action: "test", signature: sig, publicKey: signing.publicKey()))
        // The lost device's delegation is revoked.
        let old = try ACEKel.verify(try r.getKel(), now: NOW + 5)
        #expect(old.signing?.publicKey != lost.getSigningPublicKey())
    }

    /// The lost device's signing key, revealed only by the `dlg` the recovery drops, may not be committed.
    @Test func recoverRefusesANextRootRevealedAfterTheEpochStart() throws {
        let (lost, signing) = try Self.incept()
        expectCode(.invalidArgument) {
            try ExternalRootIdentity.recover(kel: try lost.getKel(), revealing: Self.root(1),
                                             nextRootDigest: keyDigest(publicKey: signing.publicKey()),
                                             signingKey: SoftwareKey.generate(), now: NOW + 5)
        }
    }

    @Test func recoverWithADifferentKeyIsRefused() throws {
        let (lost, _) = try Self.incept()
        expectCode(.invalidArgument) {
            try ExternalRootIdentity.recover(kel: try lost.getKel(), revealing: Self.root(2), nextRootDigest: Self.digest(3),
                                             signingKey: SoftwareKey.generate(), now: NOW + 5)
        }
    }

    @Test func rotateKeepsACEIdAndSigningKey() throws {
        let (id, signing) = try Self.incept()
        let aceId = id.getACEId()
        try id.rotate(revealing: Self.root(1), nextRootDigest: Self.digest(2), now: NOW + 1)
        #expect(try id.getACEId() == aceId && Self.rotCount(try id.getKel()) == 1)
        #expect(try checkUsable(id, now: NOW + 1).signing?.publicKey == signing.publicKey())
        expectCode(.invalidArgument, "not committed") {
            try id.rotate(revealing: Self.root(3), nextRootDigest: Self.digest(4), now: NOW + 3)
        }
        #expect(!((id as Any) is any ACEManagedIdentity))  // root-less: it cannot delegate on its own
        #expect(try checkUsable(id, now: NOW + 3).signing?.publicKey == signing.publicKey())
    }

    @Test func verifiesUnderVerifyKelAfterEveryStep() throws {
        let (id, _) = try Self.incept()
        var now = NOW
        func check() throws {
            let kel = try id.getKel()
            let st = try ACEKel.verify(kel, now: now)
            #expect(try st.aceId == id.getACEId() && Self.rotCount(kel) == Self.rotCount(try id.getKel()))
            #expect(try checkUsable(id, now: now).signing?.publicKey == id.getSigningPublicKey())
        }
        try check()
        for k in 1...3 {
            now += 1
            try id.rotate(revealing: Self.root(k), nextRootDigest: Self.digest(k + 1), now: now)
            try check()
        }
        #expect(try Self.rotCount(try id.getKel()) == 3)
        // A recovery from the full log continues the chain at key(4).
        let r = try ExternalRootIdentity.recover(kel: try id.getKel(), revealing: Self.root(4), nextRootDigest: Self.digest(5),
                                                 signingKey: SoftwareKey.generate(), now: now + 1)
        #expect(try Self.rotCount(try r.getKel()) == 4 && r.getACEId() == id.getACEId())
        _ = try ACEKel.verify(try r.getKel(), now: now + 1)
    }

    /// The root-chain forms index the chain from the verified log: the same identity and log as the explicit-key forms,
    /// and `aceId(roots:)` predicts `incept(roots:)` without a signing key.
    @Test func rootChainFormsIndexTheChainFromTheLog() throws {
        let roots: ExternalRootIdentity.RootChain = { Self.root($0) }
        let id = try ExternalRootIdentity.incept(roots: roots, signingKey: SoftwareKey.generate(), inceptedAt: 0, now: NOW)
        let (explicit, _) = try Self.incept()
        #expect(id.getACEId() == explicit.getACEId())
        #expect(try ExternalRootIdentity.aceId(roots: roots, inceptedAt: 0) == id.getACEId())
        try id.rotate(roots: roots, now: NOW + 1)
        try id.rotate(roots: roots, now: NOW + 2)
        #expect(try Self.rotCount(try id.getKel()) == 2 && Self.rotCount(id.getState().events) == 2)
        // Recovery reveals key(3) and commits digest(key(4)): the next explicit step needs key(4).
        let r = try ExternalRootIdentity.recover(kel: try id.getKel(), roots: roots, signingKey: SoftwareKey.generate(), now: NOW + 3)
        #expect(try Self.rotCount(try r.getKel()) == 3 && r.getACEId() == id.getACEId())
        try r.rotate(revealing: Self.root(4), nextRootDigest: Self.digest(5), now: NOW + 4)
        // A chain that is not this identity's fails closed.
        expectCode(.invalidArgument, "foreign chain") {
            try ExternalRootIdentity.recover(kel: try id.getKel(), roots: { Self.root($0 + 10) }, signingKey: SoftwareKey.generate(), now: NOW + 3)
        }
    }

    // MARK: Fallback root (01 § Rotation and recovery)

    /// The backup chain fb(i), independent of the main chain.
    static func backup(_ i: Int) throws -> SoftwareKey { try SoftwareKey(seed: Data(repeating: UInt8(100 + i), count: 32)) }
    static func fbDigest(_ i: Int) -> String { hexEncode(keyDigest(publicKey: try! backup(i).publicKey())) }

    /// Main incepts, then a primary rotate with main present adds the backup chain's fb(0) as the fallback.
    static func withFallback() throws -> ExternalRootIdentity {
        let id = try ExternalRootIdentity.incept(roots: root, signingKey: SoftwareKey.generate(), inceptedAt: 0, now: NOW)
        try id.rotate(roots: root, fallback: .set(backup), now: NOW + 1)
        return id
    }

    @Test func rotateSetsKeepsAndRemovesTheFallback() throws {
        let id = try Self.withFallback()
        let aceId = try ExternalRootIdentity.aceId(roots: Self.root, inceptedAt: 0)
        #expect(id.getACEId() == aceId)  // the fallback never changes the ACE ID
        #expect(id.getState().fallback == Self.fbDigest(0) && id.getState().next == hexEncode(Self.digest(2)))
        try id.rotate(roots: Self.root, now: NOW + 2)
        #expect(id.getState().fallback == Self.fbDigest(0) && id.getState().next == hexEncode(Self.digest(3)))
        try id.rotate(revealing: Self.root(3), nextRootDigest: Self.digest(4), now: NOW + 3)
        #expect(id.getState().fallback == Self.fbDigest(0))
        try id.rotate(roots: Self.root, fallback: .remove, now: NOW + 4)
        #expect(id.getState().fallback == nil)
        expectCode(.invalidArgument, "no fallback committed") {
            try ExternalRootIdentity.recover(kel: try id.getKel(), fallbackRoots: Self.backup, signingKey: SoftwareKey.generate(), now: NOW + 5)
        }
    }

    /// The backup alone takes the identity over: same ACE ID, the next root carried, fb(1) committed; peers recover it.
    @Test func theFallbackRootRecoversAlone() throws {
        let id = try Self.withFallback()
        let pinned = id.getState()
        let r = try ExternalRootIdentity.recover(kel: try id.getKel(), fallbackRoots: Self.backup, signingKey: SoftwareKey.generate(), now: NOW + 2)
        let st = r.getState()
        let fb0 = try Self.backup(0).publicKey()
        #expect(r.getACEId() == id.getACEId() && st.rootPublicKey == fb0)
        #expect(st.next == pinned.next && st.fallback == Self.fbDigest(1))
        #expect(try ACEKel.extend(pinned: pinned, events: st.events, now: NOW + 2).outcome == .recovered)
        // The backup again, on another device: it reveals fb(1) and commits fb(2).
        let r2 = try ExternalRootIdentity.recover(kel: st.events, fallbackRoots: Self.backup, signingKey: SoftwareKey.generate(), now: NOW + 3)
        #expect(r2.getState().fallback == Self.fbDigest(2) && r2.getState().next == pinned.next)
        // Main with main present afterwards: a primary rot after the backup's epoch would keep the backup's commitment,
        // so main's recovery reclaims from the first fallback rot instead.
        let m = try ExternalRootIdentity.recover(kel: try r2.getKel(), roots: Self.root, signingKey: SoftwareKey.generate(), now: NOW + 4)
        let ms = m.getState()
        #expect(m.getACEId() == id.getACEId() && ms.rootPublicKey == Self.root(2).publicKey() && ms.next == hexEncode(Self.digest(3)))
        #expect(ms.fallback == nil)  // fb(0) was revealed on the dropped branch: the host sets a fresh one with the backup
        #expect(try ACEKel.extend(pinned: r2.getState(), events: ms.events, now: NOW + 4).outcome == .recovered)
        try m.rotate(roots: Self.root, fallback: .set(Self.backup), now: NOW + 5)
        // The kept log reveals no backup key, so the backup chain starts over at fb(0) (its keys stand or fall together).
        #expect(m.getState().fallback == Self.fbDigest(0))
    }

    /// A thief holding the backup takes the identity over and commits keys of its own; main reclaims it.
    @Test func theNextRootReclaimsFromAStolenFallback() throws {
        let id = try Self.withFallback()
        let base = id.getState()
        let thiefNext = SoftwareKey.generate(), thiefFallback = SoftwareKey.generate()
        let rot = try ACEKel.createRotation(state: base, newRoot: Self.backup(0), nextDigest: keyDigest(publicKey: thiefNext.publicKey()),
                                            ts: NOW + 2, fallbackDigest: keyDigest(publicKey: thiefFallback.publicKey()))
        var stolen = try ACEKel.verify(base.events + [rot], now: NOW + 2)
        let rot2 = try ACEKel.createRotation(state: stolen, newRoot: thiefNext, nextDigest: keyDigest(publicKey: SoftwareKey.generate().publicKey()), ts: NOW + 3)
        stolen = try ACEKel.verify(stolen.events + [rot2], now: NOW + 3)
        stolen = try KelSteps.delegate(stolen, root: thiefNext, keyPublic: SoftwareKey.generate().publicKey(), ts: NOW + 3, notAfter: nil)
        let m = try ExternalRootIdentity.recover(kel: stolen.events, roots: Self.root, signingKey: SoftwareKey.generate(), now: NOW + 4)
        #expect(m.getACEId() == id.getACEId() && m.getState().seq == base.seq + 2)
        #expect(try ACEKel.extend(pinned: stolen, events: try m.getKel(), now: NOW + 4).outcome == .recovered)
        // The thief cannot take it back with the backup: its rot is fallback at the same seq.
        expectCode(.kelConflict) { try ACEKel.extend(pinned: m.getState(), events: stolen.events, now: NOW + 4) }
    }

    /// The fallback holder knows only fb(0)'s digest: the relay's fallback binding finds the log (07 § Registration).
    @Test func theFallbackHolderFindsTheLogByItsFirstCommitment() async throws {
        let clock = TestClock(systemClock()), relay = FakeRelay(clock: clock.fn)
        let id = try ExternalRootIdentity.incept(roots: Self.root, signingKey: SoftwareKey.generate(), inceptedAt: 0, now: clock.now)
        try id.rotate(roots: Self.root, fallback: .set(Self.backup), now: clock.now)
        let client = try relay.client(clock: clock.fn)
        _ = try await client.register(id)
        let found = try await client.fallbackKel(Self.fbDigest(0))
        #expect(found.aceId == id.getACEId())
        let r = try ExternalRootIdentity.recover(kel: found.events, fallbackRoots: Self.backup, signingKey: SoftwareKey.generate(), now: clock.now)
        _ = try await client.register(r)
        // fb(0) stays bound after the recovery revealed it, so the next recovery looks it up the same way.
        #expect(try await client.fallbackKel(Self.fbDigest(0)).lastHash == r.getState().lastHash)
        await expectCodeAsync(.unknownPeer) { try await client.fallbackKel(String(repeating: "ab", count: 32)) }
        await expectCodeAsync(.invalidArgument) { try await client.fallbackKel("AB") }
        relay.bindFallback(String(repeating: "cd", count: 32), to: id.getACEId())
        await expectCodeAsync(.relayProtocolError) { try await client.fallbackKel(String(repeating: "cd", count: 32)) }
    }
}
