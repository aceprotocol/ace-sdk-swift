//
//  Key event log (port of sdk-py/tests/test_kel.py, test for test).
//

import CryptoKit
import Foundation
import Testing
@testable import ACE

private func seeded(_ b: UInt8) -> SoftwareKey {
    try! SoftwareKey(seed: Data(repeating: b, count: 32))
}

private let R0 = seeded(1), R1 = seeded(2), R2 = seeded(3)
private let S0 = seeded(9)
private let S1 = seeded(10)

private func digest(_ k: SoftwareKey) -> Data { keyDigest(publicKey: k.publicKey()) }

/// `[icp, dlg(S1), dlg(S0)]` at NOW, NOW+1, NOW+2: the second delegation replaces the first.
private func chain() throws -> [KelEvent] {
    let icp = try ACEKel.createInception(root: R0, nextDigest: digest(R1), ts: NOW)
    var st = try ACEKel.verify([icp], now: NOW)
    let d1 = try ACEKel.createDelegation(state: st, root: R0, keyPublic: S1.publicKey(), ts: NOW + 1)
    st = try ACEKel.verify([icp, d1], now: NOW + 1)
    let d2 = try ACEKel.createDelegation(state: st, root: R0, keyPublic: S0.publicKey(), ts: NOW + 2)
    return [icp, d1, d2]
}

/// `object` with member `key` set to `value` (removed when nil); `object` must be a JSON object.
private func with(_ object: JSONValue?, _ key: String, _ value: JSONValue?) -> JSONValue {
    var o = object!.objectValue!
    o[key] = value
    return .object(o)
}

/// `ev` with `sig` replaced by a signature of `key` over the event's canonical bytes.
private func resign(_ ev: KelEvent, _ key: SoftwareKey, _ aceId: String) throws -> KelEvent {
    var out = ev
    let body = try ACESigning.message(aceId: aceId, timestamp: wireInt(out["ts"])!, seq: nil, payload: ACEKel.eventBytes(out))
    out["sig"] = ["scheme": "ml-dsa-65", "value": .string(ACEBase64.encode(try key.sign(body, action: "kel")))]
    return out
}

/// A root-signed `dlg` built by hand (any scheme and key bytes).
private func rawDlg(_ st: KelState, _ scheme: String, _ pk: Data, _ ts: Int) throws -> KelEvent {
    var ev: KelEvent = ["t": "dlg", "seq": .number(Double(st.seq + 1)), "ts": .number(Double(ts)), "prev": .string(st.lastHash),
                        "key": ["scheme": .string(scheme), "publicKey": .string(ACEBase64.encode(pk))]]
    let eb = try ACEKel.eventBytes(ev)
    ev["sig"] = ["scheme": "ml-dsa-65",
                 "value": .string(ACEBase64.encode(try R0.sign(ACESigning.message(aceId: st.aceId, timestamp: ts, seq: nil, payload: eb), action: "kel")))]
    return ev
}

/// The 01 canonical `dlg` bytes: no role field.
@Test func dlgCanonicalBytesHaveNoRole() throws {
    let icp = try ACEKel.createInception(root: R0, nextDigest: digest(R1), ts: NOW)
    let st = try ACEKel.verify([icp], now: NOW)
    let d = try ACEKel.createDelegation(state: st, root: R0, keyPublic: S0.publicKey(), ts: NOW + 1, notAfter: NOW + 100)
    #expect(try ACEKel.eventBytes(d) == ACESigning.encodePayload([.string("dlg"), .string("1"), .string(String(NOW + 1)), .string(st.lastHash),
                                                                  .string("ml-dsa-65"), .data(S0.publicKey()), .string(String(NOW + 100))]))
    #expect(Set(d.keys) == ["t", "seq", "ts", "prev", "key", "notAfter", "sig"])
}

@Suite struct KelTests {
    @Test func inceptionIdAndSignature() throws {
        let ev = try chain()
        #expect(ev[0]["t"] == "icp" && ev[0]["seq"] == 0 && ev[0]["prev"] == nil)
        let eb = try ACEKel.eventBytes(ev[0])
        let expected = "ace:sha256:" + hexEncode(SHA256.hash(data: eb))
        #expect(ACEKel.computeACEId(inceptionBytes: eb) == expected)
        let st = try ACEKel.verify(ev, now: NOW + 2)
        #expect(st.aceId == expected && st.seq == 2)
        #expect(st.signing?.publicKey == S0.publicKey())
        #expect(st.signing?.seq == 2 && st.signing?.notAfter == nil)
        #expect(ACEKel.isUsable(st, now: NOW + 1_000_000_000))  // no notAfter: never expires
        let body = try ACESigning.message(aceId: st.aceId, timestamp: wireInt(ev[0]["ts"])!, seq: nil, payload: eb)
        let sig = try ACEBase64.decode(ev[0]["sig"]!["value"]!.stringValue!)
        #expect(ACESigning.verifySignature(message: body, action: "kel", signature: sig, publicKey: R0.publicKey()))
    }

    @Test func usableOnceASigningKeyIsDelegated() throws {
        let ev = try chain()
        #expect(!ACEKel.isUsable(try ACEKel.verify(Array(ev[..<1]), now: NOW), now: NOW))
        #expect(ACEKel.isUsable(try ACEKel.verify(Array(ev[..<2]), now: NOW + 1), now: NOW + 1))
    }

    @Test func delegationExpiryEdges() throws {
        let ev = try chain()
        let st = try ACEKel.verify(ev, now: NOW + 2)
        let t = NOW + 3, pk = S0.publicKey(), max = ACELimits.maxSigningKeyLifetime
        let ok = try ACEKel.createDelegation(state: st, root: R0, keyPublic: pk, ts: t,
                                             notAfter: t + max)
        let st2 = try ACEKel.verify(ev + [ok], now: t)
        #expect(st2.signing?.notAfter == t + max && st2.signing?.seq == 3)
        #expect(ACEKel.isUsable(st2, now: t + max - 1))
        #expect(!ACEKel.isUsable(st2, now: t + max))
        expectCode(.invalidKel) {
            try ACEKel.createDelegation(state: st, root: R0, keyPublic: pk, ts: t,
                                        notAfter: t + max + 1)
        }
        expectCode(.invalidKel) {
            try ACEKel.createDelegation(state: st, root: R0, keyPublic: pk, ts: t, notAfter: t)
        }
    }

    @Test func rotationRevealsCommittedRootAndClearsDelegations() throws {
        let ev = try chain()
        let st = try ACEKel.verify(ev, now: NOW + 2)
        let rot = try ACEKel.createRotation(state: st, newRoot: R1, nextDigest: digest(R2), ts: NOW + 3)
        let st2 = try ACEKel.verify(ev + [rot], now: NOW + 3)
        #expect(st2.rootPublicKey == R1.publicKey())
        #expect(st2.next == hexEncode(keyDigest(publicKey: R2.publicKey())))
        #expect(st2.signing == nil && !ACEKel.isUsable(st2, now: NOW + 3))
        // old root can no longer delegate
        let bad = try ACEKel.createDelegation(state: st2, root: R0, keyPublic: S0.publicKey(),
                                              ts: NOW + 4)
        expectCode(.invalidSignature) { try ACEKel.verify(ev + [rot, bad], now: NOW + 4) }
        // new root can
        let good = try ACEKel.createDelegation(state: st2, root: R1, keyPublic: S0.publicKey(),
                                               ts: NOW + 4)
        #expect(try ACEKel.verify(ev + [rot, good], now: NOW + 4).signing?.seq == 4)
    }

    @Test func rotationRejections() throws {
        let ev = try chain()
        let st = try ACEKel.verify(ev, now: NOW + 2)
        expectCode(.invalidKel) {  // R2 was not committed
            try ACEKel.createRotation(state: st, newRoot: R2, nextDigest: digest(R1), ts: NOW + 3)
        }
        let rot = try ACEKel.createRotation(state: st, newRoot: R1, nextDigest: digest(R2), ts: NOW + 3)
        let forged = try resign(rot, S0, st.aceId)  // signed by a key that is neither root
        expectCode(.invalidSignature) { try ACEKel.verify(ev + [forged], now: NOW + 3) }
        var tampered = rot
        let value = rot["sig"]!["value"]!.stringValue!
        tampered["sig"] = with(rot["sig"], "value", .string(String(value.dropLast(4)) + "AAAA"))
        expectCode(.invalidSignature) { try ACEKel.verify(ev + [tampered], now: NOW + 3) }
    }

    @Test func rotHasASingleSigByTheRevealedRoot() throws {
        let ev = try chain()
        let st = try ACEKel.verify(ev, now: NOW + 2)
        let rot = try ACEKel.createRotation(state: st, newRoot: R1, nextDigest: digest(R2), ts: NOW + 3)
        #expect(Set(rot.keys) == ["t", "seq", "ts", "prev", "root", "next", "sig"])
        #expect(rot["sig"]?["scheme"] == "ml-dsa-65")
        let body = try ACESigning.message(aceId: st.aceId, timestamp: NOW + 3, seq: nil, payload: ACEKel.eventBytes(rot))
        let raw = try ACEBase64.decode(rot["sig"]!["value"]!.stringValue!)
        #expect(ACESigning.verifySignature(message: body, action: "kel", signature: raw, publicKey: R1.publicKey()))
        #expect(try ACEKel.verify(ev + [rot], now: NOW + 3).rootPublicKey == R1.publicKey())
    }

    /// Review Focus 1: the holder of the current root cannot rotate.
    @Test func rotSignedByOldRootIsInvalidSignature() throws {
        let ev = try chain()
        let st = try ACEKel.verify(ev, now: NOW + 2)
        let rot = try ACEKel.createRotation(state: st, newRoot: R1, nextDigest: digest(R2), ts: NOW + 3)
        let byOld = try resign(rot, R0, st.aceId)
        expectCode(.invalidSignature) { try ACEKel.verify(ev + [byOld], now: NOW + 3) }
    }

    @Test func rotWithSigsIsInvalidKel() throws {
        let ev = try chain()
        let st = try ACEKel.verify(ev, now: NOW + 2)
        let rot = try ACEKel.createRotation(state: st, newRoot: R1, nextDigest: digest(R2), ts: NOW + 3)
        var plan4 = rot
        plan4["sigs"] = ["prev": try resign(rot, R0, st.aceId)["sig"]!, "next": rot["sig"]!]
        plan4["sig"] = nil
        expectCode(.invalidKel) { try ACEKel.verify(ev + [plan4], now: NOW + 3) }  // unknown member
        var both = rot
        both["sigs"] = ["next": rot["sig"]!]
        expectCode(.invalidKel) { try ACEKel.verify(ev + [both], now: NOW + 3) }
    }

    @Test func rotSigSchemeMustEqualRootScheme() throws {
        let ev = try chain()
        let st = try ACEKel.verify(ev, now: NOW + 2)
        let rot = try ACEKel.createRotation(state: st, newRoot: R1, nextDigest: digest(R2), ts: NOW + 3)
        var relabelled = rot
        relabelled["sig"] = with(rot["sig"], "scheme", "ml-dsa-87")
        expectCode(.invalidKel) { try ACEKel.verify(ev + [relabelled], now: NOW + 3) }
    }

    @Test func structuralRejections() throws {
        let ev = try chain()
        let mutations: [(String, ACEError.Code, (inout [KelEvent]) -> Void)] = [
            ("gap", .invalidKel, { $0[1]["seq"] = 2 }),
            ("broken link", .invalidKel, { $0[1]["prev"] = .string(String(repeating: "00", count: 32)) }),
            ("ts not monotone", .invalidKel, { $0[1]["ts"] = .number(Double(NOW - 1)) }),
            ("future beyond window", .invalidKel, { $0[2]["ts"] = .number(Double(NOW + 2 + 301)) }),
            ("unknown member", .invalidKel, { $0[0]["extra"] = 1 }),
            ("tampered key", .invalidSignature, { e in  // the last event: an earlier one breaks the next prev (structure first)
                let n = e.count - 1
                let pk = e[n]["key"]!["publicKey"]!.stringValue!
                e[n]["key"] = with(e[n]["key"], "publicKey", .string(String(pk.dropLast(4)) + "AAAA"))
            }),
            ("bad next", .invalidKel, { $0[0]["next"] = .string(String(repeating: "zz", count: 32)) }),
        ]
        for (name, code, mutate) in mutations {
            var e = ev
            mutate(&e)
            expectCode(code, name) { try ACEKel.verify(e, now: NOW + 2) }
        }
        expectCode(.invalidKel) { try ACEKel.verify([], now: NOW) }
        expectCode(.invalidKel) { try ACEKel.verify(Array(ev[1...]), now: NOW + 2) }  // must start with icp
    }

    @Test func eventCountLimit() throws {
        var ev = try chain()
        var st = try ACEKel.verify(ev, now: NOW + 2)
        var ts = NOW + 2
        let pk = S0.publicKey()
        // Python re-verifies the growing log after each append (O(n^2) ML-DSA verifies, ~45 s in a debug build);
        // here the next state is derived from the appended event and the full 256-event log is verified once.
        while ev.count < ACELimits.maxKelEvents {
            ts += 1
            let d = try ACEKel.createDelegation(state: st, root: R0, keyPublic: pk, ts: ts)
            ev.append(d)
            st = KelState(aceId: st.aceId, seq: st.seq + 1, lastHash: sha256Hex(try ACEKel.eventBytes(d)),
                          rootPublicKey: st.rootPublicKey, next: st.next, signing: st.signing, events: [])
        }
        #expect(try ACEKel.verify(ev, now: ts).seq == ACELimits.maxKelEvents - 1)
        ts += 1
        ev.append(try ACEKel.createDelegation(state: st, root: R0, keyPublic: pk, ts: ts))
        expectCode(.invalidKel, messageContains: "exceeds 256") { try ACEKel.verify(ev, now: ts) }
    }

    @Test func extendOutcomesAndForkRule() throws {
        let ev = try chain()
        let st = try ACEKel.verify(ev, now: NOW + 2)
        let (pinned, out) = try ACEKel.extend(pinned: nil, events: ev, now: NOW + 2)
        #expect(out == .adopted)
        #expect(try ACEKel.extend(pinned: pinned, events: ev, now: NOW + 2).outcome == .unchanged)
        #expect(try ACEKel.extend(pinned: pinned, events: Array(ev[..<2]), now: NOW + 2).outcome == .unchanged)  // shorter = stale
        let d3 = try ACEKel.createDelegation(state: st, root: R0, keyPublic: S0.publicKey(),
                                             ts: NOW + 3)
        let (longer, out2) = try ACEKel.extend(pinned: pinned, events: ev + [d3], now: NOW + 3)
        #expect(out2 == .extended && longer.seq == 3)
        // attacker with stolen root issues a competing dlg at seq 3; owner rotates at seq 3: rot wins
        let attackerDlg = try ACEKel.createDelegation(state: st, root: R0, 
                                                      keyPublic: R2.publicKey(), ts: NOW + 3)
        let attacked = try ACEKel.extend(pinned: pinned, events: ev + [attackerDlg], now: NOW + 3).state
        let rot = try ACEKel.createRotation(state: st, newRoot: R1, nextDigest: digest(R2), ts: NOW + 4)
        let (recovered, out3) = try ACEKel.extend(pinned: attacked, events: ev + [rot], now: NOW + 4)
        #expect(out3 == .recovered && recovered.rootPublicKey == R1.publicKey())
        // the attacker's dlg cannot displace the pinned rot, nor a different dlg displace a pinned dlg
        expectCode(.kelConflict) { try ACEKel.extend(pinned: recovered, events: ev + [attackerDlg], now: NOW + 4) }
        expectCode(.kelConflict) { try ACEKel.extend(pinned: longer, events: ev + [attackerDlg], now: NOW + 4) }
        expectCode(.kelConflict) {  // different ACE ID entirely
            let other = try ACEKel.createInception(root: R1, nextDigest: digest(R2), ts: NOW)
            return try ACEKel.extend(pinned: pinned, events: [other], now: NOW)
        }
    }

    /// C1: the holder of a revealed root cannot re-reveal it at an earlier `seq` against a pin with a later `rot`.
    @Test func rotCannotDisplaceAPinWithARotAtOrAfterTheFork() throws {
        let R3 = seeded(4), X = seeded(5)
        var ev = try chain()
        var st = try ACEKel.verify(ev, now: NOW + 2)
        ev.append(try ACEKel.createRotation(state: st, newRoot: R1, nextDigest: digest(R2), ts: NOW + 3))
        st = try ACEKel.verify(ev, now: NOW + 3)
        ev.append(try ACEKel.createDelegation(state: st, root: R1, keyPublic: S0.publicKey(),
                                              ts: NOW + 3))
        let pin = try ACEKel.verify(ev, now: NOW + 3)
        // the holder of the current root R1 re-reveals it at seq 1 with its own next root
        let st0 = try ACEKel.verify(Array(ev[..<1]), now: NOW + 4)
        let refork = [ev[0], try ACEKel.createRotation(state: st0, newRoot: R1, nextDigest: digest(X), ts: NOW + 4)]
        expectCode(.kelConflict) { try ACEKel.extend(pinned: pin, events: refork, now: NOW + 4) }
        // ... at seq 3 it conflicts with the pinned rot itself
        let st2 = try ACEKel.verify(Array(ev[..<3]), now: NOW + 4)
        let at3 = try ACEKel.createRotation(state: st2, newRoot: R1, nextDigest: digest(X), ts: NOW + 4)
        expectCode(.kelConflict) { try ACEKel.extend(pinned: pin, events: Array(ev[..<3]) + [at3], now: NOW + 4) }
        // a past root R1 after a second rotation
        ev.append(try ACEKel.createRotation(state: pin, newRoot: R2, nextDigest: digest(R3), ts: NOW + 4))
        let pin2 = try ACEKel.verify(ev, now: NOW + 4)
        expectCode(.kelConflict) { try ACEKel.extend(pinned: pin2, events: refork, now: NOW + 4) }
        // a pin without a rot after the fork point still adopts the rot as recovered
        #expect(try ACEKel.extend(pinned: ACEKel.verify(Array(ev[..<3]), now: NOW + 4), events: refork, now: NOW + 4).outcome == .recovered)
    }

    @Test func shapeErrorsAreACEErrors() throws {
        let ev = try chain()
        for badT: JSONValue in [["icp"], ["t": "icp"]] {
            var e = ev
            e[1]["t"] = badT
            expectCode(.invalidKel) { try ACEKel.verify(e, now: NOW + 2) }
            expectCode(.invalidKel) { try ACEKel.eventBytes(e[1]) }
        }
        // an icp placed at seq > 0 with seq == index has no prev
        var icp2 = ev[0]
        icp2["seq"] = 1
        expectCode(.invalidKel) { try ACEKel.verify([ev[0], icp2], now: NOW + 2) }
        // missing sig (dlg, rot) / malformed rot sig
        var noSig = ev
        noSig[1]["sig"] = nil
        expectCode(.invalidKel) { try ACEKel.verify(noSig, now: NOW + 2) }
        let st = try ACEKel.verify(ev, now: NOW + 2)
        let rot = try ACEKel.createRotation(state: st, newRoot: R1, nextDigest: digest(R2), ts: NOW + 3)
        var noSigRot = rot
        noSigRot["sig"] = nil
        expectCode(.invalidKel) { try ACEKel.verify(ev + [noSigRot], now: NOW + 3) }
        for bad: JSONValue in ["x", ["scheme": "ml-dsa-65"], ["scheme": "ml-dsa-65", "value": "AA==", "x": 1]] {
            var e = rot
            e["sig"] = bad
            expectCode(.invalidKel) { try ACEKel.verify(ev + [e], now: NOW + 3) }
        }
    }

    @Test func rotVsRotAtSameSeqConflicts() throws {
        let ev = try chain()
        let st = try ACEKel.verify(ev, now: NOW + 2)
        let rotA = try ACEKel.createRotation(state: st, newRoot: R1, nextDigest: digest(R2), ts: NOW + 3)
        let rotB = try ACEKel.createRotation(state: st, newRoot: R1, nextDigest: digest(S0), ts: NOW + 3)
        let pinned = try ACEKel.extend(pinned: nil, events: ev + [rotA], now: NOW + 3).state
        expectCode(.kelConflict) { try ACEKel.extend(pinned: pinned, events: ev + [rotB], now: NOW + 3) }  // first seen wins
        let stA = try ACEKel.verify(ev + [rotA], now: NOW + 3)
        let d = try ACEKel.createDelegation(state: stA, root: R1, keyPublic: S0.publicKey(),
                                            ts: NOW + 4)
        let (later, out) = try ACEKel.extend(pinned: pinned, events: ev + [rotA, d], now: NOW + 4)
        #expect(out == .extended && later.seq == 4 && later.signing?.seq == 4)
    }

    @Test func keyTypeRejectionsWhenProperlySigned() throws {
        // root scheme not ML-DSA (Python relabels the provider; a Swift provider's scheme is typed, so sign by hand)
        var icp: KelEvent = ["t": "icp", "seq": 0, "ts": .number(Double(NOW)),
                             "root": ["scheme": "ed25519", "publicKey": .string(ACEBase64.encode(R0.publicKey()))],
                             "next": .string(hexEncode(digest(R1)))]
        let eb = try ACEKel.eventBytes(icp)
        let sig = try R0.sign(ACESigning.message(aceId: ACEKel.computeACEId(inceptionBytes: eb), timestamp: NOW, seq: nil, payload: eb),
                              action: "kel")
        icp["sig"] = ["scheme": "ed25519", "value": .string(ACEBase64.encode(sig))]
        expectCode(.invalidKel) { try ACEKel.verify([icp], now: NOW) }
        let ev = try chain()
        let st = try ACEKel.verify(Array(ev[..<1]), now: NOW)
        // a signing key of the wrong length or scheme, root-signed
        let short = try rawDlg(st, "ml-dsa-65", S0.publicKey().prefix(32), NOW + 1)
        expectCode(.invalidKel) { try ACEKel.verify([ev[0], short], now: NOW + 1) }
        let wrong = try rawDlg(st, "ml-dsa-87", Data(count: 2592), NOW + 1)  // a removed scheme
        expectCode(.invalidKel) { try ACEKel.verify([ev[0], wrong], now: NOW + 1) }
        // a `role` member is unknown (the KEL delegates signing only)
        var withRole = try rawDlg(st, "ml-dsa-65", S0.publicKey(), NOW + 1)
        withRole["role"] = "signing"
        expectCode(.invalidKel) { try ACEKel.verify([ev[0], withRole], now: NOW + 1) }
    }

    @Test func stateOwnsItsEvents() throws {
        var ev = try chain()
        let (pinned, out) = try ACEKel.extend(pinned: nil, events: ev, now: NOW + 2)
        #expect(out == .adopted)
        let untouched = ev
        ev[1]["prev"] = .string(String(repeating: "00", count: 32))  // caller mutates the events it handed in
        #expect(pinned.events[1]["prev"] == untouched[1]["prev"])
        #expect(try ACEKel.extend(pinned: pinned, events: untouched, now: NOW + 2).outcome == .unchanged)
    }

    // MARK: Review Focus 1 (Plan 3): a non-canonical but equal JSON integer

    @Test func kelAcceptsFloatIntegerSeq() throws {
        let root = SoftwareKey.generate(), next = SoftwareKey.generate()
        var icp = try ACEKel.createInception(root: root, nextDigest: keyDigest(publicKey: next.publicKey()), ts: 100)
        let id = try ACEKel.verify([icp], now: 100).aceId
        // Re-parse with `1.0`-style numbers: same bytes, same identity.
        let original = String(decoding: try JSONValue.object(icp).jsonData(), as: UTF8.self)
        let text = original.replacingOccurrences(of: "\"seq\":0", with: "\"seq\":0.0")
            .replacingOccurrences(of: "\"ts\":100", with: "\"ts\":1e2")
        #expect(text.contains("\"seq\":0.0") && text.contains("\"ts\":1e2"))
        icp = try JSONValue(json: Data(text.utf8)).objectValue!
        #expect(try ACEKel.verify([icp], now: 100).aceId == id)
        var bad = icp; bad["seq"] = JSONValue.bool(false)
        expectCode(.invalidKel) { try ACEKel.verify([bad], now: 100) }
        bad = icp; bad["ts"] = .number(Double(maxSafeInteger) + 1)
        expectCode(.invalidKel) { try ACEKel.verify([bad], now: 100) }
        bad = icp; bad["seq"] = .bool(true)
        expectCode(.invalidKel) { try ACEKel.verify([bad], now: 100) }
        bad = icp; bad["ts"] = .number(-0.5)
        expectCode(.invalidKel) { try ACEKel.verify([bad], now: 100) }
    }

    // MARK: Plan 1 Review Focus 1–3

    @Test func notAfterBoundaryAcceptedOnePastRejectedAbsentNeverExpires() throws {
        let ev = try chain()
        let st = try ACEKel.verify(ev, now: NOW + 2)
        let t = NOW + 3, max = ACELimits.maxSigningKeyLifetime
        let edge = try ACEKel.createDelegation(state: st, root: R0, keyPublic: S0.publicKey(),
                                               ts: t, notAfter: t + max)
        #expect(try ACEKel.verify(ev + [edge], now: t).signing?.notAfter == t + max)
        // One past the bound, signed by the root (built by hand: createDelegation refuses it).
        var past: KelEvent = ["t": "dlg", "seq": 3, "ts": .number(Double(t)), "prev": .string(st.lastHash),
                              "key": ["scheme": "ml-dsa-65", "publicKey": .string(ACEBase64.encode(S0.publicKey()))],
                              "notAfter": .number(Double(t + max + 1))]
        let eb = try ACEKel.eventBytes(past)
        past["sig"] = ["scheme": "ml-dsa-65",
                       "value": .string(ACEBase64.encode(try R0.sign(ACESigning.message(aceId: st.aceId, timestamp: t, seq: nil, payload: eb),
                                                                    action: "kel")))]
        expectCode(.invalidKel) { try ACEKel.verify(ev + [past], now: t) }
        #expect(ACEKel.isUsable(st, now: maxSafeInteger))
    }

    @Test func eventSignaturesAreSchemeValueOnly() throws {
        let ev = try chain()
        var e = ev
        e[1]["sig"] = with(e[1]["sig"], "seq", 1)
        expectCode(.invalidKel) { try ACEKel.verify(e, now: NOW + 2) }
        e = ev
        e[1]["sig"] = with(e[1]["sig"], "value", 5)
        expectCode(.invalidKel) { try ACEKel.verify(e, now: NOW + 2) }
        e = ev
        e[1]["sig"] = with(e[1]["sig"], "scheme", "ml-dsa-87")
        expectCode(.invalidKel) { try ACEKel.verify(e, now: NOW + 2) }
    }

    /// Two logs of the same events re-signed (ML-DSA is hedged: other signature values) give equal states.
    @Test func kelStateEqualityIgnoresEvents() throws {
        let ev = try chain(), resigned = try chain()
        #expect(ev != resigned)  // the signatures differ
        let a = try ACEKel.verify(ev, now: NOW + 2), b = try ACEKel.verify(resigned, now: NOW + 2)
        #expect(a.events != b.events)
        #expect(a == b && a.hashValue == b.hashValue)
    }
}
