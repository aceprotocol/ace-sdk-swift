import Foundation
import Testing
@testable import ACE

@Suite struct IdentityTests {
    @Test func generateDelegatesOneSigningKey() throws {
        let a = try makeIdentity(now: NOW)
        let st = try checkUsable(a, now: NOW)
        #expect(st.seq == 1 && st.signing?.seq == 1 && st.events.count == 2)
        #expect(try a.getSigningSeq() == 1 && a.getSigningPublicKey() == st.signing?.publicKey)
        #expect(isACEId(a.getACEId()) && st.aceId == a.getACEId())
    }

    /// The SDK's own identities skip re-verifying the log they hold; the result is the full verification's at every `now`.
    @Test func heldStateMatchesFullVerification() throws {
        struct Forwarding: ACEIdentity {  // a third-party identity: always verified in full
            let base: any ACEIdentity
            func getACEId() -> String { base.getACEId() }
            func getSigningPublicKey() -> Data { base.getSigningPublicKey() }
            func getSigningSeq() throws -> Int { try base.getSigningSeq() }
            func getKel() throws -> [KelEvent] { try base.getKel() }
            func sign(_ message: (Int) throws -> Data, action: String) throws -> (seq: Int, signature: Data) {
                try base.sign(message, action: action)
            }
        }
        let a = try makeIdentity(now: NOW)
        try rotate(a, now: NOW + 5)
        try a.delegate(now: NOW + 10, notAfter: NOW + 100)
        for now in [0, NOW, NOW + 10, NOW + 99, NOW + 100, NOW + 1000] {
            let held = Result { try checkUsable(a, now: now) }
            let full = Result { try checkUsable(Forwarding(base: a), now: now) }
            switch (held, full) {
            case let (.success(h), .success(f)): #expect(h == f && h.events == f.events, "\(now)")
            case let (.failure(h as ACEError), .failure(f as ACEError)): #expect(h.code == f.code, "\(now)")
            default: Issue.record("\(now): \(held) vs \(full)")
            }
        }
    }

    @Test func softwareExportHasNoEncryptionSeedAndRoundTrips() throws {
        let a = try SoftwareIdentity.generate(now: NOW)
        let e = a.exportPrivateKey()
        let obj = try JSONValue(json: try e.jsonData()).objectValue!
        #expect(Set(obj.keys) == ["rootSeed", "nextRootSeed", "signingSeed", "kel"])
        let b = try SoftwareIdentity(export: try SoftwareIdentityExport(json: try e.jsonData()), now: NOW)
        #expect(b.getACEId() == a.getACEId() && b.getSigningPublicKey() == a.getSigningPublicKey())
        // signatures of the import verify under the exported identity's KEL
        let state = try checkUsable(a, now: NOW)
        let sig = try operationalSign(b, action: "packet", timestamp: NOW, payload: Data("x".utf8))
        try verifyOperational(sig, state: state, action: "packet", timestamp: NOW, payload: Data("x".utf8), now: NOW)
        expectCode(.invalidKel) { try SoftwareIdentityExport(json: Data(#"{"rootSeed":"","signingSeed":"","kel":[]}"#.utf8)) }
        expectCode(.invalidArgument) { try SoftwareIdentityExport(json: Data("[]".utf8)) }
        // an old export carrying encryptionSeed is accepted only by ignoring it (unknown member); its KEL still decides
        var old = obj
        old["encryptionSeed"] = "AAAA"
        #expect(try SoftwareIdentityExport(json: try JSONValue.object(old).jsonData()) == e)
    }

    @Test func rotateAndDelegate() throws {
        let a = try makeIdentity(now: NOW)
        try a.delegate(now: NOW + 1, notAfter: NOW + 100)
        var st = a.getState()
        #expect(st.signing?.seq == 2 && st.signing?.notAfter == NOW + 100)
        expectCode(.identityUnavailable) { try checkUsable(a, now: NOW + 100) }
        try rotate(a, now: NOW + 2)
        st = a.getState()
        #expect(st.seq == 4 && st.signing?.seq == 4 && st.signing?.notAfter == nil)
        let reloaded = try reload(a, now: NOW + 2)
        #expect(try reloaded.getACEId() == a.getACEId() && reloaded.getSigningSeq() == 4)
    }

    @Test func recoverForksAtTheEpochStart() throws {
        let next = SoftwareKey.generate()
        let a = try SoftwareIdentity.generate(nextRootDigest: keyDigest(publicKey: next.publicKey()), now: NOW)
        try a.delegate(now: NOW + 1, notAfter: nil)  // e.g. a thief's delegation
        let r = try SoftwareIdentity.recover(kel: try a.getKel(), nextRoot: next, now: NOW + 2)
        let st = r.getState()
        #expect(r.getACEId() == a.getACEId() && st.events.count == 3 && st.events[1]["t"] == "rot" && st.signing?.seq == 2)
        #expect(try ACEKel.extend(pinned: a.getState(), events: try r.getKel(), now: NOW + 2).outcome == .recovered)
        expectCode(.invalidArgument) { try SoftwareIdentity.recover(kel: try a.getKel(), nextRoot: SoftwareKey.generate(), now: NOW + 2) }
    }

    /// SP3(a): a key revealed only after the epoch start (dropped from the recovered log) is exposed all the same.
    @Test func recoveryRefusesANextRootRevealedAfterTheEpochStart() throws {
        let next = SoftwareKey.generate()
        let a = try SoftwareIdentity.generate(nextRootDigest: keyDigest(publicKey: next.publicKey()), now: NOW)
        try a.delegate(now: NOW + 1, notAfter: nil)  // its key is cut from the recovered log, yet revealed
        let dropped = a.getSigningPublicKey()
        expectCode(.invalidArgument) {
            try SoftwareIdentity.recover(kel: try a.getKel(), nextRoot: next, now: NOW + 2, nextRootDigest: keyDigest(publicKey: dropped))
        }
    }

    @Test func secureEnclaveExportJSONRoundTrip() throws {
        let e = SecureEnclaveIdentityExport(rootKey: "cg==", signingKey: "cw==", kel: [["t": "icp"]])
        let back = try SecureEnclaveIdentityExport(json: try e.jsonData())
        #expect(back == e)
        #expect(Set(try JSONValue(json: try e.jsonData()).objectValue!.keys) == ["provider", "rootKey", "signingKey", "kel"])
    }

    @Test(.enabled(if: SecureEnclaveKey.isAvailable)) func secureEnclaveIdentityRoundTrip() throws {
        let a = try SecureEnclaveIdentity.generate(now: NOW)
        let b = try SecureEnclaveIdentity(export: try SecureEnclaveIdentityExport(json: try a.exportKeyReferences().jsonData()), now: NOW)
        #expect(b.getACEId() == a.getACEId())
        let sig = try operationalSign(b, action: "packet", timestamp: NOW, payload: Data())
        try verifyOperational(sig, state: a.getState(), action: "packet", timestamp: NOW, payload: Data(), now: NOW)
        #expect(!"\(a)".contains("Key"))
    }
}
