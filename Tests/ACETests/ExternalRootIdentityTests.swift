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
        #expect(id.rotationCount == 0)
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
            let held = ACEBase64.encode(Self.root(id.rotationCount + 1).publicKey())
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

    /// 01 § Rotation and recovery (SP3): the signer refuses a signing key that is the current root or the committed next
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
        #expect(r.getACEId() == lost.getACEId() && r.rotationCount == 1)
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

    /// SP3(a): the lost device's signing key, revealed only by the `dlg` the recovery drops, may not be committed.
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
        #expect(id.getACEId() == aceId && id.rotationCount == 1)
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
            #expect(st.aceId == id.getACEId() && Self.rotCount(kel) == id.rotationCount)
            #expect(try checkUsable(id, now: now).signing?.publicKey == id.getSigningPublicKey())
        }
        try check()
        for k in 1...3 {
            now += 1
            try id.rotate(revealing: Self.root(k), nextRootDigest: Self.digest(k + 1), now: now)
            try check()
        }
        #expect(id.rotationCount == 3)
        // A recovery from the full log continues the chain at key(4).
        let r = try ExternalRootIdentity.recover(kel: try id.getKel(), revealing: Self.root(4), nextRootDigest: Self.digest(5),
                                                 signingKey: SoftwareKey.generate(), now: now + 1)
        #expect(r.rotationCount == 4 && r.getACEId() == id.getACEId())
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
        #expect(id.rotationCount == 2 && id.getState().rotationCount == 2)
        // Recovery reveals key(3) and commits digest(key(4)): the next explicit step needs key(4).
        let r = try ExternalRootIdentity.recover(kel: try id.getKel(), roots: roots, signingKey: SoftwareKey.generate(), now: NOW + 3)
        #expect(r.rotationCount == 3 && r.getACEId() == id.getACEId())
        try r.rotate(revealing: Self.root(4), nextRootDigest: Self.digest(5), now: NOW + 4)
        // A chain that is not this identity's fails closed.
        expectCode(.invalidArgument, "foreign chain") {
            try ExternalRootIdentity.recover(kel: try id.getKel(), roots: { Self.root($0 + 10) }, signingKey: SoftwareKey.generate(), now: NOW + 3)
        }
    }
}
