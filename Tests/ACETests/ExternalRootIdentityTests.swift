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
        let id = try ExternalRootIdentity.incept(root: root(0), nextRootDigest: digest(1), signingKey: signing, now: now)
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
            try ExternalRootIdentity.incept(root: Self.root(0), nextRootDigest: Data(count: 31), signingKey: SoftwareKey.generate(), now: NOW)
        }
        expectCode(.invalidArgument, "root itself") {
            try ExternalRootIdentity.incept(root: Self.root(0), nextRootDigest: Self.digest(0), signingKey: SoftwareKey.generate(), now: NOW)
        }
    }

    @Test func rootIsNotRetainedAfterInceptDelegateRotate() throws {
        let (id, _) = try Self.incept()
        func check(_ label: String) throws {
            let export = id.exportKeyReferences()
            let data = try export.jsonData()
            let o = try JSONValue(json: data).objectValue!
            #expect(Set(o.keys) == ["signingKey", "kel"], "\(label)")
            let text = String(decoding: data, as: UTF8.self)
            for n in 0...3 {
                // Roots appear in the KEL only once revealed (icp / rot carry them by design); seeds never appear.
                #expect(!text.contains(ACEBase64.encode(Self.root(n).seed)), "\(label): seed \(n)")
            }
            let kelRoots = Set(export.kel.compactMap { $0["root"]?.objectValue?["publicKey"]?.stringValue })
            let held = ACEBase64.encode(Self.root(id.rotationCount + 1).publicKey())
            #expect(!kelRoots.contains(held) && !text.contains(held), "\(label): next root public key")
        }
        try check("incept")
        try id.delegate(root: Self.root(0), signingKey: SoftwareKey.generate(), now: NOW + 1)
        try check("delegate")
        try id.rotate(revealing: Self.root(1), nextRootDigest: Self.digest(2), now: NOW + 2)
        try check("rotate")
    }

    @Test func exportRoundTrips() throws {
        let (id, signing) = try Self.incept()
        let export = id.exportKeyReferences()
        #expect(export.signingKey == ACEBase64.encode(signing.seed))
        let parsed = try ExternalRootIdentityExport(json: export.jsonData())
        #expect(parsed == export)
        let restored = try ExternalRootIdentity(export: parsed, signingKey: try SoftwareKey(seed: signing.seed), now: NOW)
        #expect(try restored.getACEId() == id.getACEId() && restored.getKel() == id.getKel())
        expectCode(.invalidArgument, "wrong signing key") {
            try ExternalRootIdentity(export: parsed, signingKey: SoftwareKey.generate(), now: NOW)
        }
        expectCode(.invalidArgument, "not an object") { try ExternalRootIdentityExport(json: Data("[]".utf8)) }
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

    @Test func recoverWithADifferentKeyIsRefused() throws {
        let (lost, _) = try Self.incept()
        expectCode(.invalidArgument) {
            try ExternalRootIdentity.recover(kel: try lost.getKel(), revealing: Self.root(2), nextRootDigest: Self.digest(3),
                                             signingKey: SoftwareKey.generate(), now: NOW + 5)
        }
    }

    @Test func rotateThenDelegateKeepsACEId() throws {
        let (id, signing) = try Self.incept()
        let aceId = id.getACEId()
        try id.rotate(revealing: Self.root(1), nextRootDigest: Self.digest(2), now: NOW + 1)
        #expect(id.getACEId() == aceId && id.rotationCount == 1)
        #expect(try checkUsable(id, now: NOW + 1).signing?.publicKey == signing.publicKey())
        let next = SoftwareKey.generate()
        try id.delegate(root: Self.root(1), signingKey: next, now: NOW + 2)
        #expect(id.getACEId() == aceId && id.getSigningPublicKey() == next.publicKey())
        #expect(try checkUsable(id, now: NOW + 2).signing?.publicKey == next.publicKey())
        expectCode(.invalidArgument, "old root") { try id.delegate(root: Self.root(0), signingKey: SoftwareKey.generate(), now: NOW + 3) }
        expectCode(.invalidArgument, "not committed") {
            try id.rotate(revealing: Self.root(3), nextRootDigest: Self.digest(4), now: NOW + 3)
        }
        expectCode(.invalidArgument, "root-less delegate") { try id.delegate(now: NOW + 3, notAfter: nil) }
        #expect(try checkUsable(id, now: NOW + 3).signing?.publicKey == next.publicKey())
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
            now += 1
            try id.delegate(root: Self.root(k), signingKey: SoftwareKey.generate(), now: now, notAfter: now + 3600)
            try check()
        }
        #expect(id.rotationCount == 3)
        // A recovery from the full log continues the chain at key(4).
        let r = try ExternalRootIdentity.recover(kel: try id.getKel(), revealing: Self.root(4), nextRootDigest: Self.digest(5),
                                                 signingKey: SoftwareKey.generate(), now: now + 1)
        #expect(r.rotationCount == 4 && r.getACEId() == id.getACEId())
        _ = try ACEKel.verify(try r.getKel(), now: now + 1)
    }
}
