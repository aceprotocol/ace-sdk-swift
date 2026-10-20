//
//  VectorTests.swift
//  The shared conformance vectors (ace-spec/test-vectors.json, copied byte-identically to Fixtures/; the spec's
//  scripts/check-sdk-artifacts.py enforces the copy). Every section that applies to an SDK is verified here.
//

import CryptoKit
import Foundation
import Testing
@testable import ACE

private let V: JSONValue = {
    let url = URL(fileURLWithPath: #filePath).deletingLastPathComponent().appendingPathComponent("Fixtures/test-vectors.json")
    return try! JSONValue(json: try! Data(contentsOf: url))
}()

private let VNOW = V["now"]!.intValue!

extension JSONValue {
    fileprivate var s: String { stringValue! }
    fileprivate var i: Int { intValue! }
    fileprivate var a: [JSONValue] { arrayValue! }
    fileprivate var o: [String: JSONValue] { objectValue! }
    fileprivate var data: Data { try! jsonData() }
    fileprivate var events: [KelEvent] { a.map { $0.objectValue ?? [:] } }
}

private func agentId(_ name: String) -> String { V["agents"]![name]!["aceId"]!.s }
private func kelOf(_ name: String) -> [KelEvent] { V["agents"]![name]!["export"]!["kel"]!.events }
private func stateOf(_ name: String, _ now: Int = VNOW) throws -> KelState { try ACEKel.verify(kelOf(name), now: now) }
private func label(_ c: JSONValue) -> String { c["name"]?.stringValue ?? "\(c)".prefix(120).description }

/// The ACE error code of `body`, nil on success; a non-ACE error is reported as such.
private func codeOf(_ body: () throws -> Void) -> String? {
    do { try body(); return nil } catch let e as ACEError { return e.code.rawValue } catch { return "non-ace: \(error)" }
}

private func expected(_ c: JSONValue, _ key: String = "error") -> String? { c[key]?.stringValue }

/// A vault holding exactly one seed (the vector prekey).
private struct OneSeedVault: PrekeyVault {
    let seed: Data
    var id: String { sha256Hex(try! XWing.publicKey(fromSeed: seed)) }
    func current() throws -> PrekeyRecord? { PrekeyRecord(prekey: try Prekey(publicKey: XWing.publicKey(fromSeed: seed)), createdAt: 0, supersededAt: nil) }
    func rotate(now: Int) throws -> PrekeyRecord { try current()! }
    func open(_ prekeyId: String, now: Int) throws -> Data? { prekeyId == id ? seed : nil }
    func prune(now: Int) throws {}
}

private let vectorVault = OneSeedVault(seed: hex(V["packet"]!["deterministic"]!["prekeySeed"]!.s))

@Suite struct VectorTests {
    @Test func agentsLoadFromTheirExports() throws {
        for (name, a) in V["agents"]!.o {
            let export = try SoftwareIdentityExport(json: a["export"]!.data)
            #expect(try SoftwareIdentity(export: export, now: VNOW).getACEId() == a["aceId"]!.s, "\(name)")
        }
    }

    // MARK: encoding

    @Test func base64() {
        for c in V["encoding"]!["base64"]!.a {
            if c["valid"] == true {
                #expect(hexEncode(try! ACEBase64.decode(c["text"]!.s)) == c["hex"]!.s)
            } else {
                #expect(codeOf { _ = try ACEBase64.decode(c["text"]!.s) } == "invalid_argument", "\(c)")
            }
        }
    }

    @Test func canonicalJson() {
        for c in V["encoding"]!["canonicalJson"]!.a {
            func run() throws -> Data {
                let v = try JSONValue(json: Data(c["input"]!.s.utf8))
                try checkJSONValue(v, code: .invalidArgument)
                return try v.jsonData()
            }
            if c["error"] == true {
                #expect(throws: (any Error).self, "\(label(c))") { _ = try run() }
            } else {
                #expect((try? run()) == Data(c["canonical"]!.s.utf8), "\(label(c))")
            }
        }
    }

    @Test func wireInts() throws {
        for c in V["encoding"]!["wireInts"]!.a {
            #expect(try JSONValue(json: Data(c["json"]!.s.utf8)).wireInt == c["value"]?.intValue, "\(c)")
        }
    }

    @Test func identifiers() {
        let predicates: [String: (String) -> Bool] = [
            "aceId": isACEId, "messageId": isMessageId, "hexDigest": isSHA256Hex, "namespacedId": isNamespacedIdentifier,
            "threadId": isThreadId, "handle": isHandle, "streamId": isStreamCursor, "outcomeCode": isOutcomeCode,
            "caip10": isCAIP10, "caip19": isCAIP19,
        ]
        let groups = V["encoding"]!["identifiers"]!.o
        #expect(Set(groups.keys) == Set(predicates.keys))
        for (kind, cases) in groups {
            for c in cases.a { #expect(predicates[kind]!(c["value"]!.s) == (c["valid"] == true), "\(kind) \(c["value"]!.s.prefix(80))") }
        }
    }

    @Test func urlsRelayUrlsBlockedAddressesAndPairKey() {
        let e = V["encoding"]!
        for c in e["httpsUrls"]!.a { #expect(isHTTPSURL(c["url"]!.s) == (c["valid"] == true), "\(c["url"]!.s.prefix(80))") }
        for c in e["relayUrls"]!.a {
            if let err = expected(c) {
                #expect(codeOf { _ = try normalizeRelayURL(c["input"]!.s) } == err, "\(c["input"]!.s)")
            } else {
                #expect((try? normalizeRelayURL(c["input"]!.s)) == c["normalized"]!.s, "\(c["input"]!.s)")
            }
        }
        for c in e["blockedAddresses"]!.a { #expect(isBlockedAddress(c["address"]!.s) == (c["blocked"] == true), "\(c["address"]!.s)") }
        let k = e["conversationKey"]!
        #expect(conversationKey(k["a"]!.s, k["b"]!.s) == k["key"]!.s)
        #expect(conversationKey(k["b"]!.s, k["a"]!.s) == k["key"]!.s)
    }

    // MARK: signing

    @Test func encodePayloadMessageAndActionSeparation() throws {
        let s = V["signing"]!
        for c in s["encodePayload"]!.a {
            let fields: [PayloadField] = c["fields"]!.a.map { f in f["text"].map { .string($0.s) } ?? .data(hex(f["hex"]!.s)) }
            #expect(hexEncode(ACESigning.encodePayload(fields)) == c["hex"]!.s)
        }
        for c in s["message"]!.a {
            let m = try ACESigning.message(aceId: c["aceId"]!.s, timestamp: c["timestamp"]!.i, seq: c["seq"]!.intValue, payload: hex(c["payloadHex"]!.s))
            #expect(hexEncode(m) == c["messageHex"]!.s)
        }
        for a in s["actionSeparation"]!.a {
            let key = try stateOf(a["signer"]!.s).signing!.publicKey
            let sig = try ACEBase64.decode(a["signature"]!.s)
            for (action, ok) in a["actions"]!.o {
                #expect(ACESigning.verifySignature(message: hex(a["messageHex"]!.s), action: action, signature: sig, publicKey: key) == (ok == true),
                        "\(action)")
            }
        }
    }

    // MARK: KEL

    @Test func kelValid() throws {
        for c in V["kel"]!["valid"]!.a {
            var events = kelOf(c["agent"]!.s)
            if let n = c["events"]?.intValue { events = Array(events.prefix(n)) }
            let now = c["now"]!.i
            let st = try ACEKel.verify(events, now: now)
            #expect(st.aceId == c["aceId"]!.s && st.seq == c["seq"]!.i && st.lastHash == c["lastHash"]!.s)
            #expect(c["rootScheme"]!.s == SigningScheme.mlDsa65.rawValue && st.next == c["next"]!.s)
            if c["signing"]!.isNull {
                #expect(st.signing == nil)
            } else {
                #expect(st.signing?.seq == c["signing"]!["seq"]!.i && st.signing?.notAfter == c["signing"]!["notAfter"]!.intValue)
            }
            #expect(ACEKel.isUsable(st, now: now) == (c["usable"] == true))
        }
    }

    @Test func kelInvalid() {
        for c in V["kel"]!["invalid"]!.a {
            #expect(codeOf { _ = try ACEKel.verify(c["kel"]!.events, now: c["now"]!.i) } == expected(c), "\(label(c))")
        }
    }

    @Test func kelEventBytesForksAndOperationalSignatures() throws {
        let k = V["kel"]!
        for c in k["eventBytes"]!.a { #expect(hexEncode(try ACEKel.eventBytes(c["event"]!.o)) == c["hex"]!.s) }
        for c in k["forks"]!.a {
            let now = c["now"]!.i
            let pinned = c["pinned"]!.isNull ? nil : try ACEKel.verify(c["pinned"]!.events, now: now)
            if let err = expected(c) {
                #expect(codeOf { _ = try ACEKel.extend(pinned: pinned, events: c["candidate"]!.events, now: now) } == err, "\(label(c))")
            } else {
                let (st, outcome) = try ACEKel.extend(pinned: pinned, events: c["candidate"]!.events, now: now)
                #expect(outcome.rawValue == c["outcome"]!.s && st.seq == c["seq"]!.i, "\(label(c))")
            }
        }
        for c in k["operational"]!.a {
            let st = try stateOf(c["signer"]!.s, c["now"]!.i)
            let got = codeOf {
                guard let sig = SignatureEnvelope(operational: c["signature"]!) else { throw ACEError(.invalidSignature) }
                try verifyOperational(sig, state: st, action: c["action"]!.s, timestamp: c["timestamp"]!.i, payload: hex(c["payloadHex"]!.s),
                                      now: c["now"]!.i)
            }
            #expect(got == expected(c), "\(label(c))")
        }
    }

    // MARK: X-Wing and packets

    @Test func xwingDraft11KnownAnswers() throws {
        for c in V["xwing"]!["cases"]!.a {
            let seed = hex(c["seed"]!.s)
            #expect(hexEncode(try XWing.publicKey(fromSeed: seed)) == c["publicKey"]!.s)
            let ss = try XWing.privateKey(seed).decapsulate(hex(c["ciphertext"]!.s))
            #expect(ss.withUnsafeBytes { hexEncode($0) } == c["sharedSecret"]!.s)
        }
    }

    @Test func packetDeterministic() throws {
        let d = V["packet"]!["deterministic"]!
        let kem = hex(d["kemCiphertext"]!.s), ss = SymmetricKey(data: hex(d["sharedSecret"]!.s)), nonce = try AES.GCM.Nonce(data: hex(d["nonce"]!.s))
        let alice = agentId(d["sender"]!.s), bob = agentId(d["recipient"]!.s)
        let messageId = d["messageId"]!.s, ts = d["timestamp"]!.i, prekeyId = d["prekey"]!["id"]!.s
        let header = Packet.header(from: alice, to: bob, messageId: messageId, timestamp: ts, prekey: prekeyId, kemCiphertext: kem)
        #expect(hexEncode(header) == d["headerHex"]!.s)
        #expect(d["saltHex"]!.s.isEmpty)
        #expect(Packet.aeadKey(ss, header: header).withUnsafeBytes { hexEncode($0) } == d["keyHex"]!.s)
        let c = d["content"]!
        let content = try PrivateContent(type: c["type"]!.s, schemaDigest: c["schemaDigest"]!.s, threadId: c["threadId"]?.stringValue, body: c["body"]!.o)
        let plaintext = try content.jsonData()
        #expect(hexEncode(plaintext) == d["plaintextHex"]!.s)
        let payload = try Packet.seal(plaintext, sharedSecret: ss, header: header, nonce: nonce)
        #expect(hexEncode(payload) == d["payloadHex"]!.s)
        let signPayload = Packet.signPayload(to: bob, messageId: messageId, prekey: prekeyId, kemCiphertext: kem, payload: payload)
        #expect(hexEncode(signPayload) == d["signPayloadHex"]!.s)
        let packetSig = SignatureEnvelope(operational: d["packet"]!["signature"])!
        let m = try ACESigning.message(aceId: alice, timestamp: ts, seq: packetSig.seq, payload: signPayload)
        #expect(hexEncode(m) == d["messageHex"]!.s)
        #expect(ACESigning.verifySignature(message: m, action: "packet", signature: try ACEBase64.decode(packetSig.value),
                                           publicKey: try stateOf("alice").signing!.publicKey))
        let sender = try SoftwareIdentity(export: SoftwareIdentityExport(json: V["agents"]!["alice"]!["export"]!.data), now: VNOW)
        let made = try sealPacket(sender: sender, from: alice, to: bob, messageId: messageId, timestamp: ts, prekey: prekeyId, plaintext: plaintext,
                                  sharedSecret: ss, kemCiphertext: kem, nonce: nonce)
        let enc = d["packet"]!["encryption"]!
        #expect(made.encryption == PacketEncryption(prekey: enc["prekey"]!.s, kemCiphertext: enc["kemCiphertext"]!.s, payload: enc["payload"]!.s))
        for packet in [made, try Packet(json: d["packet"]!.data)] {
            let opened = try openPacket(packet, sender: try stateOf("alice"), recipient: bob, vault: vectorVault, now: VNOW)
            #expect(opened == content)
        }
    }

    @Test func packetDecode() {
        for c in V["packet"]!["decode"]!.a {
            let raw = c["json"].map { Data($0.s.utf8) } ?? c["packet"]!.data
            #expect(codeOf { _ = try Packet(json: raw) } == expected(c), "\(label(c))")
        }
    }

    @Test func packetOpen() {
        for c in V["packet"]!["open"]!.a {
            let now = c["now"]!.i
            let got = codeOf {
                let p = try Packet(json: c["packet"]!.data)
                _ = try openPacket(p, sender: try stateOf(c["sender"]!.s, now), recipient: agentId(c["recipient"]!.s), vault: vectorVault, now: now)
            }
            #expect(got == expected(c), "\(label(c))")
        }
    }

    @Test func privateContent() {
        for c in V["privateContent"]!["cases"]!.a {
            let raw = c["text"].map { Data($0.s.utf8) } ?? hex(c["hex"]!.s)
            #expect(codeOf { _ = try PrivateContent(json: raw) } == expected(c), "\(label(c))")
        }
    }

    // MARK: descriptor, delegation, permit, ERC-8004

    @Test func descriptorValid() throws {
        for c in V["descriptor"]!["valid"]!.a {
            let a = try verifyPublishedAgent(c["publishedAgent"]!, now: c["now"]!.i)
            #expect(a.descriptor.delegations.map(\.issuer) == c["delegations"]!.a.map(\.s), "\(label(c))")
        }
    }

    @Test func descriptorInvalid() {
        for c in V["descriptor"]!["invalid"]!.a {
            #expect(codeOf { _ = try verifyPublishedAgent(c["publishedAgent"]!, now: c["now"]!.i) } == expected(c), "\(label(c))")
        }
    }

    @Test func descriptorAgainstThePin() async throws {
        for c in V["descriptor"]!["pinned"]!.a {
            let now = c["now"]!.i, pinnedName = c["pinned"]!.s
            let pinned = try stateOf(pinnedName, now)
            #expect(codeOf { _ = try verifyPublishedAgent(c["publishedAgent"]!, now: now, pinned: pinned) } == expected(c), "\(label(c))")
            // A PeerStore holding the pin behaves the same (no prekey substitution by a superseded key).
            let peers = PeerStore(store: MemoryStore(), clock: { now })
            try await peers.pin(kel: kelOf(pinnedName))
            var got: String?
            do { _ = try await peers.adopt(source: c["publishedAgent"]!) } catch let e as ACEError { got = e.code.rawValue }
            #expect(got == expected(c), "PeerStore \(label(c))")
            if expected(c) == nil {
                let agent = try await peers.agent(agentId(pinnedName))
                #expect(agent?.descriptor.prekey.id == c["publishedAgent"]!["descriptor"]!["prekey"]!["id"]!.s)
                #expect(agent?.state.seq == pinned.seq)
            }
        }
    }

    // MARK: card records

    @Test func cardRecordsValid() throws {
        #expect(V["version"]!.i >= 10)
        for c in V["cardRecords"]!["valid"]!.a {
            let v = try verifyCardBundle(c["bundle"]!, now: c["now"]!.i)
            let r = v.record
            let got: JSONValue = [
                "aceId": .string(v.aceId), "home": .string(r.home), "handle": r.handle.map { .string($0) } ?? .null,
                "pay": r.pay.map { .array($0.map { .string($0) }) } ?? .null, "contact": .string(r.contact.rawValue), "listed": .bool(r.listed),
            ]
            #expect(got == c["expect"]!, "\(label(c))")
        }
    }

    @Test func cardRecordsInvalid() {
        for c in V["cardRecords"]!["invalid"]!.a {
            #expect(codeOf { _ = try verifyCardBundle(c["bundle"]!, now: c["now"]!.i) } == expected(c), "\(label(c))")
        }
    }

    @Test func delegationPermitAndErc8004() throws {
        for c in V["delegation"]!["cases"]!.a {
            var got: String?
            do {
                got = try checkDelegationEntry(c["entry"]!, subject: c["subject"]!.s, now: c["now"]!.i).live ? "live" : "expired"
            } catch let e as ACEError { got = e.code.rawValue }
            #expect(got == (expected(c, "result") ?? expected(c)), "\(label(c))")
        }
        for c in V["delegation"]!["pinned"]!.a {
            let now = c["now"]!.i
            var got: String?
            do {
                got = try checkDelegationEntry(c["entry"]!, subject: c["subject"]!.s, now: now, pinned: try stateOf(c["pinned"]!.s, now)).live
                    ? "live" : "expired"
            } catch let e as ACEError { got = e.code.rawValue }
            #expect(got == (expected(c, "result") ?? expected(c)), "pinned \(label(c))")
        }
        for c in V["delegation"]!["descriptors"]!.a {
            let now = c["now"]!.i
            var pins: [String: KelState] = [:]
            for x in c["delegationPins"]!.a { pins[agentId(x.s)] = try stateOf(x.s, now) }
            #expect(codeOf { _ = try verifyPublishedAgent(c["publishedAgent"]!, now: now, delegationPins: pins) } == expected(c), "\(label(c))")
            #expect(codeOf { _ = try verifyPublishedAgent(c["publishedAgent"]!, now: now) } == nil, "\(label(c)) without pins")
        }
        for c in V["permit"]!["cases"]!.a {
            let now = c["now"]!.i
            let got = codeOf { _ = try verifyPermit(c["permit"]!, issuer: try stateOf(c["issuer"]!.s, now), subject: c["subject"]!.s, now: now) }
            #expect(got == expected(c), "\(label(c))")
        }
        for c in V["erc8004"]!["shapes"]!.a {
            #expect((codeOf { _ = try validateErc8004Entry(c["entry"]!) } == nil) == (c["valid"] == true), "\(c)")
        }
        for c in V["erc8004"]!["registrations"]!.a {
            let aceId = c["aceId"]!.s
            let got = c["registration"]!.stringValue.map { verifyErc8004Registration(Data($0.utf8), aceId: aceId) }
                ?? verifyErc8004Registration(c["registration"]!, aceId: aceId)
            #expect(got == (c["result"] == true), "\(c)")
        }
    }

    @Test func coreRules() {
        for c in V["coreRules"]!["receipts"]!.a {
            #expect(codeOf { try checkReceiptBody(c["body"]!) } == expected(c), "receipt \(label(c))")
        }
        for c in V["coreRules"]!["strangerSources"]!.a {
            #expect(codeOf { try checkStrangerSource(c["source"]!) } == expected(c), "stranger \(label(c))")
        }
    }

    // MARK: manifests

    @Test func manifests() throws {
        let m = V["manifests"]!
        let bundled = Dictionary(uniqueKeysWithValues: [ProfileManifest.core, .text, .commerce].map { ($0.id, $0) })
        for o in m["official"]!.a {
            let pm = bundled[o["id"]!.s]!
            #expect(pm.digest == o["digest"]!.s)
            #expect(Dictionary(uniqueKeysWithValues: pm.messages.map { ($0.type, JSONValue.string($0.schemaDigest)) }) == o["messages"]!.o)
        }
        for c in m["thirdParty"]!.a {
            if c["valid"] == true {
                let pm = try ProfileManifest(c["manifest"]!)
                #expect(pm.digest == c["digest"]!.s, "\(label(c))")
                #expect(Dictionary(uniqueKeysWithValues: pm.messages.map { ($0.type, JSONValue.string($0.schemaDigest)) }) == c["messages"]!.o)
            } else {
                #expect(codeOf { _ = try ProfileManifest(c["manifest"]!) } == "invalid_argument", "\(label(c))")
            }
        }
        let installed = try InstalledProfiles([.text, .commerce])
        for c in m["bodies"]!.a {
            let got = codeOf {
                try installed.validate(try PrivateContent(type: c["type"]!.s, schemaDigest: c["schemaDigest"]!.s, body: c["body"]!.o))
            }
            #expect(got == expected(c), "\(label(c))")
        }
    }

    // MARK: replay

    @Test func replay() throws {
        for c in V["replay"]!["cases"]!.a {
            let capacity = c["capacity"]!.i
            let det = try c["initialState"].map { try ReplayDetector(state: ReplayState(json: $0.data), capacity: capacity) }
                ?? ReplayDetector(capacity: capacity, horizon: c["horizon"]!.i)
            for op in c["ops"]!.a {
                let m = op["messageId"]!.s, s = op["sender"]!.s, ts = op["timestamp"]!.i
                if op["op"] == "commit" {
                    #expect(try det.commit(m, from: s, timestamp: ts, floor: op["floor"]!.i) == (op["expect"] == true), "\(label(c)) \(op)")
                } else {
                    let got = det.contains(m, from: s) ? "duplicate" : det.covers(sender: s, timestamp: ts) ? "replay_horizon" : "new"
                    #expect(got == op["expect"]!.s, "\(label(c)) \(op)")
                }
            }
            #expect(det.exportState().jsonData() == c["finalState"]!.data, "\(label(c))")
        }
    }

    // MARK: commerce

    @Test func commerceTransitions() throws {
        let parties = V["commerce"]!["parties"]!.o.mapValues { agentId($0.s) }
        for c in V["commerce"]!["transitions"]!.a {
            let local = parties[c["local"]!.s]!
            let rules = CommerceRules(store: MemoryStore(), localAceId: local)
            for st in c["steps"]!.a {
                let from = parties[st["from"]!.s]!, to = parties[st["to"]!.s]!
                let e = ProfileEvent(direction: from == local ? .send : .receive, from: from, to: to, messageId: st["messageId"]!.s,
                                     timestamp: st["timestamp"]!.i, type: st["type"]!.s, threadId: st["threadId"]?.stringValue)
                var got: String
                do {
                    try rules.check(e, body: st["body"]!.o)
                    try rules.commit(e, body: st["body"]!.o)
                    got = try rules.threads.thread(between: from, and: to, threadId: e.threadId!)!.state.rawValue
                } catch let err as ACEError { got = err.code.rawValue }
                #expect(got == st["expect"]!.s, "\(label(c)): \(st["type"]!.s)")
            }
        }
    }

    @Test func commerceSenderStateAndBusyThreads() async throws {
        let alice = agentId("alice"), bob = agentId("bob")
        let me = try SoftwareIdentity(export: SoftwareIdentityExport(json: V["agents"]!["alice"]!["export"]!.data), now: VNOW)
        for c in V["commerce"]!["sender"]!.a {
            let clock = TestClock(VNOW), store = MemoryStore()
            let rules = CommerceRules(store: store, localAceId: alice)
            let outbox = Outbox(identity: me, store: store, profiles: try InstalledProfiles([.text, .commerce]), rules: [rules], clock: clock.fn)
            for (i, st) in c["steps"]!.a.enumerated() {
                clock.now = VNOW + i
                let threadId = st["threadId"]?.stringValue ?? "t1", id = st["messageId"]!.s
                var got = "ok"
                do {
                    switch st["op"]!.s {
                    case "send":
                        _ = try await outbox.enqueue(to: bob, type: st["type"]!.s, body: st["body"]!.o, threadId: threadId, messageId: id)
                    case "receipt":
                        var body: [String: JSONValue] = ["messageId": .string(id), "outcome": st["outcome"]!]
                        if let code = st["code"] { body["code"] = code }
                        try await outbox.handleReceipt(from: bob, body: body)
                    case "abandon":
                        try await outbox.abandon(id)
                    default:  // receive at pipeline step 10
                        let e = ProfileEvent(direction: .receive, from: bob, to: alice, messageId: id, timestamp: VNOW + i, type: st["type"]!.s,
                                             threadId: threadId)
                        if try await outbox.busy(to: bob, threadId: threadId) != nil { throw ACEError(.threadBusy) }
                        try rules.check(e, body: st["body"]!.o)
                        try rules.commit(e, body: st["body"]!.o)
                    }
                } catch let e as ACEError { got = e.outcomeCode }
                let state = try rules.threads.thread(between: alice, and: bob, threadId: "t1")?.state.rawValue
                let busy = try await outbox.busy(to: bob, threadId: "t1") != nil
                #expect(got == st["expect"]!.s && state == st["state"]?.stringValue && busy == (st["busy"] == true), "\(label(c)) step \(i)")
            }
        }
    }

    @Test func commerceExt() {
        for c in V["commerce"]!["ext"]!.a {
            #expect((codeOf { try validateCommerceExt(c["value"]!) } == nil) == (c["valid"] == true), "\(c)")
        }
    }

    // MARK: receive pipeline

    @Test func receivePipeline() async throws {
        for c in V["pipeline"]!["cases"]!.a {
            let clock = TestClock(VNOW), store = MemoryStore()
            let sent = LockedValue<[JSONValue]>([])
            // One recording relay stands for every route: the receipts the receiver posts.
            let relay = try makeRelay({ req, body in
                if req.url!.path == "/v1/send", let v = try? JSONValue(json: body) { sent.value.append(v) }
                return .json(200, ["ok": true] as JSONValue)
            }, clock: clock.fn)
            let network = try await NetworkClient.open(identity: try identity(c["receiver"]!.s), store: store, relay: relay, prekeys: vectorVault,
                                                       configuration: NetworkConfiguration(contact: c["contact"]!.s == "open" ? .open : .closed),
                                                       foreignRelay: { _ in relay }, clock: clock.fn, capacity: c["capacity"]!.i)
            if c["contact"]!.s == "open" { try await network.publish() }  // its own card record is open
            for (_, source) in c["admitted"]!.o {
                let agent = try await network.peers.adopt(source: source)
                try network.admission.update(agent.aceId) { _ in AdmissionRecord(aceId: agent.aceId, state: .admitted, updatedAt: 0) }
            }
            let inbox = try #require(await network.inbox)
            for (i, step) in c["steps"]!.a.enumerated() {
                clock.now = step["now"]!.i
                let before = sent.value.count
                let out = await inbox.receive(step["packet"]!.data)
                let (disposition, code): (String, String?) = switch out {
                case .delivered: ("delivered", nil)
                case .duplicate: ("duplicate", nil)
                case .dropped(let e): ("drop", e.rawValue)
                case .rejected(let r): ("reject", r)
                default: ("\(out)", nil)
                }
                let want = step["expect"]!
                #expect(disposition == want["disposition"]!.s && code == want["code"]?.stringValue, "\(label(c)) step \(i): \(out)")
                #expect((sent.value.count > before) == !want["receipt"]!.isNull, "\(label(c)) step \(i): receipt")
            }
            await network.close()
        }
    }

    // MARK: auth, registration, relay errors (the relay-side negatives are checked by sdk-ts and the relay)

    private func request(_ r: JSONValue) -> RelayAuthRequest {
        switch r["action"]!.s {
        case "listen": return .listen(since: r["since"]!.s)
        case "inbox": return .inbox(since: r["since"]!.s, limit: r["limit"]!.i)
        case "inbox-ack": return .inboxAck(through: r["through"]!.s)
        case "block": return .block(peer: r["peer"]!.s, blocked: r["blocked"] == true, revision: r["revision"]!.i)
        case "wake": return r["gateway"].map { .setWake(gateway: $0.s, token: r["token"]!.s) } ?? .clearWake
        default: return .unregister
        }
    }

    private func identity(_ name: String) throws -> SoftwareIdentity {
        try SoftwareIdentity(export: SoftwareIdentityExport(json: V["agents"]![name]!["export"]!.data), now: VNOW)
    }

    @Test func authHeadersAndRegistration() throws {
        let a = V["auth"]!
        for c in a["cases"]!.a {
            let req = request(c["request"]!), ts = c["timestamp"]!.i, st = try stateOf(c["agent"]!.s, ts)
            #expect(hexEncode(req.payload()) == c["payloadHex"]!.s)
            let ap = try authPayload(req, audience: c["audience"]!.s, nonce: c["nonce"]!.s)
            #expect(hexEncode(ap) == c["authPayloadHex"]!.s)
            let m = try ACESigning.message(aceId: st.aceId, timestamp: ts, seq: st.signing!.seq, payload: ap)
            #expect(hexEncode(m) == c["messageHex"]!.s)
            #expect(ACESigning.verifySignature(message: m, action: req.action, signature: try ACEBase64.decode(c["headers"]!["X-ACE-Signature"]!.s),
                                               publicKey: st.signing!.publicKey))
            // this SDK reproduces the headers' signed content (only the hedged signature differs)
            var mine = try createAuthHeaders(try identity(c["agent"]!.s), request: req, timestamp: ts, audience: c["audience"]!.s, nonce: c["nonce"]!.s)
            var theirs = c["headers"]!.o.mapValues(\.s)
            mine["X-ACE-Signature"] = nil
            theirs["X-ACE-Signature"] = nil
            #expect(mine == theirs)
        }
        let r = a["registration"]!, st = try stateOf(r["agent"]!.s, r["now"]!.i)
        #expect(st.lastHash == r["lastHashHex"]!.s)
        #expect(hexEncode(ACESigning.encodePayload(r["lastHashHex"]!.s, r["audience"]!.s)) == r["payloadHex"]!.s)
        let m = try ACESigning.message(aceId: st.aceId, timestamp: r["request"]!["timestamp"]!.i, seq: st.signing!.seq, payload: hex(r["payloadHex"]!.s))
        #expect(hexEncode(m) == r["messageHex"]!.s && sha256Hex(m) == r["requestDigest"]!.s)
        #expect(ACESigning.verifySignature(message: m, action: "register-request", signature: try ACEBase64.decode(r["request"]!["signature"]!["value"]!.s),
                                           publicKey: st.signing!.publicKey))
        let mine = try createRegistrationRequest(identity: try identity(r["agent"]!.s), timestamp: r["request"]!["timestamp"]!.i, audience: r["audience"]!.s)
        #expect(Set(mine.objectValue!.keys) == Set(r["request"]!.o.keys) && mine["kel"] == r["request"]!["kel"] && mine["audience"] == r["request"]!["audience"])
    }

    /// `auth.wake`: the client-side `{gateway, token}` check. The typed `setWake(gateway:token:)` cannot express a body with
    /// an extra member or a missing token (the relay refuses those), so those two cases are skipped here.
    @Test func wakeValidation() throws {
        let w = V["auth"]!["wake"]!
        for b in w["valid"]!.a {
            try RelayAuthRequest.setWake(gateway: b["gateway"]!.s, token: b["token"]!.s).validate()
        }
        for c in w["invalid"]!.a {
            #expect(c["error"]!.s == "invalid_argument")
            let body = c["body"]!.o
            guard Set(body.keys) == ["gateway", "token"] else { continue }  // not expressible through setWake(gateway:token:)
            expectCode(.invalidArgument, label(c)) { try RelayAuthRequest.setWake(gateway: body["gateway"]!.s, token: body["token"]!.s).validate() }
        }
    }

    @Test func relayErrorMapping() {
        for c in V["relayErrors"]!["cases"]!.a {
            let e = relayError(status: c["status"]!.i, retryAfter: c["headers"]!["Retry-After"]?.stringValue, body: Data(c["body"]!.s.utf8))
            #expect(e.code.rawValue == c["code"]!.s && e.category.rawValue == c["category"]!.s, "\(label(c))")
            #expect(e.relayCode == c["relayCode"]?.stringValue && e.retryAfterSeconds == c["retryAfterSeconds"]?.intValue, "\(label(c))")
            #expect(e.status == c["status"]!.i, "\(label(c))")
        }
    }
}
