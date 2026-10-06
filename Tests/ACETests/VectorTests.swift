//
//  Shared cross-language vectors (ace-spec/test-vectors.json, version 2).
//

import Foundation
import Testing
@testable import ACE

@Suite("Vectors v2")
struct VectorTests {
    let V = Fixtures.vectors

    @Test func versionAndSections() {
        #expect(Fixtures.root["version"] as? String == "2")
        for key in ["envelopes", "bodies", "transitions", "replay", "signatures", "auth", "registrations",
                    "registrationErrors", "urls", "base64", "peerBinding"] {
            #expect(V[key] != nil, "missing \(key)")
        }
    }

    // MARK: identities, X-Wing, conversation, signData

    @Test(arguments: ["alice", "bob"]) func agents(_ name: String) {
        let a = Fixtures.agentInfo(name), ident = Fixtures.agent(name)
        #expect(ACEBase64.encode(ident.getSigningPublicKey()) == a["signingPublicKey"] as? String)
        #expect(ACEBase64.encode(ident.getEncryptionPublicKey()) == a["encryptionPublicKey"] as? String)
        #expect(ident.getACEId() == a["aceId"] as? String)
        #expect(computeACEId(ident.getSigningPublicKey()) == ident.getACEId())
        #expect(ident.getAddress() == a["address"] as? String)
        let export = ident.exportPrivateKey()
        #expect(export.scheme.rawValue == a["scheme"] as? String)
        #expect(export.signingPrivateKey == a["signingPrivateKey"] as? String)
        #expect(export.encryptionPrivateKey == a["encryptionPrivateKey"] as? String)
    }

    @Test func xwingKATs() throws {
        let kats = Fixtures.root["xwing"] as! [[String: Any]]
        #expect(kats.count == 3)
        for v in kats {
            let seed = hex(v["seed"] as! String)
            #expect(hexEncode(try ACEEncryption.publicKey(fromSeed: seed)) == v["publicKey"] as? String)
            #expect(hexEncode(try ACEEncryption.decapsulate(hex(v["ciphertext"] as! String), seed: seed)) == v["sharedSecret"] as? String)
        }
    }

    @Test func saltConversationAndSignData() throws {
        let alice = Fixtures.agent("alice"), bob = Fixtures.agent("bob")
        #expect(hexEncode(ACEEncryption.aceKemSalt) == V["aceKemSalt"] as? String)
        #expect(try ACEEncryption.computeConversationId(pubA: alice.getEncryptionPublicKey(), pubB: bob.getEncryptionPublicKey()) == V["conversationId"] as? String)
        let sd = V["signData"] as! [String: Any]
        let mp = sd["messagePayload"] as! [String: String]
        let payload = ACESigning.encodePayload([
            .string(mp["type"]!), .string(mp["to"]!), .string(mp["conversationId"]!), .string(mp["messageId"]!),
            .string(mp["threadId"]!), .data(Data(base64Encoded: mp["kemCiphertext"]!)!), .data(Data(base64Encoded: mp["ciphertext"]!)!),
        ])
        let data = try ACESigning.buildSignData(action: sd["action"] as! String, aceId: sd["aceId"] as! String,
                                                timestamp: sd["timestamp"] as! Int, payload: payload)
        #expect(hexEncode(data) == sd["signDataHex"] as? String)
        // CryptoKit ed25519 signatures are hedged (randomized), so the reference value is
        // verified and a fresh signature is checked for validity rather than byte equality.
        let reference = try ACEBase64.decode((V["signature"] as! [String: Any])["signatureValue"] as! String)
        #expect(ACESigning.verify(signData: data, signature: reference, scheme: .ed25519, publicKey: alice.getSigningPublicKey()))
        #expect(ACESigning.verify(signData: data, signature: try alice.sign(data), scheme: .ed25519, publicKey: alice.getSigningPublicKey()))
    }

    @Test func encryptedMessage() throws {
        let alice = Fixtures.agent("alice"), bob = Fixtures.agent("bob")
        let em = V["encryptedMessage"] as! [String: Any]
        let envObj = em["envelope"] as! [String: Any]
        let ts = envObj["timestamp"] as! Int
        let env = try decodeEnvelope(json(envObj))
        let parsed = try parseMessage(env, receiver: bob, sender: try peerOf(alice),
                                      threads: try ThreadStateMachine(localAceId: bob.getACEId()),
                                      replay: try ReplayDetector(horizon: ts - 1), clock: { ts })
        #expect(parsed.body == jsonBody(em["expectedBody"]!))
        let seed = Data(base64Encoded: Fixtures.agentInfo("bob")["encryptionPrivateKey"] as! String)!
        let enc = envObj["encryption"] as! [String: String]
        let raw = try ACEEncryption.decrypt(kemCiphertext: Data(base64Encoded: enc["kemCiphertext"]!)!,
                                            payload: Data(base64Encoded: enc["payload"]!)!, seed: seed,
                                            conversationId: envObj["conversationId"] as! String)
        #expect(try JSONValue(json: raw).objectValue == jsonBody(em["expectedBody"]!))
    }

    // MARK: envelopes / bodies

    @Test func envelopes() {
        let cases = V["envelopes"] as! [[String: Any]]
        #expect(cases.count > 30)
        for v in cases {
            let name = v["name"] as! String
            let data = Data((v["json"] as! String).utf8)
            if v["valid"] as! Bool {
                do {
                    let env = try decodeEnvelope(data)
                    #expect(envelopeFingerprint(env) == v["fingerprint"] as? String, "\(name)")
                } catch {
                    Issue.record("\(name): \(error)")
                }
            } else {
                do {
                    _ = try decodeEnvelope(data)
                    Issue.record("\(name): expected \(v["error"]!)")
                } catch let e as ACEError {
                    #expect(e.code.rawValue == v["error"] as? String, "\(name): got \(e)")
                } catch {
                    Issue.record("\(name): \(error)")
                }
            }
        }
    }

    @Test func bodies() {
        let cases = V["bodies"] as! [[String: Any]]
        #expect(cases.count > 50)
        for v in cases {
            let name = v["name"] as! String
            let raw = (v["bodyHex"] as? String).map(hex) ?? Data((v["bodyJson"] as! String).utf8)
            let type = MessageType(rawValue: v["type"] as! String)!
            do {
                _ = try decodeBody(type, raw)
                #expect(v["valid"] as! Bool, "\(name): expected invalid_body")
            } catch let e as ACEError {
                #expect(!(v["valid"] as! Bool), "\(name): \(e)")
                #expect(e.code == .invalidBody, "\(name): \(e)")
            } catch {
                Issue.record("\(name): \(error)")
            }
        }
    }

    // MARK: transitions

    private var T: [String: Any] { V["transitions"] as! [String: Any] }
    private func role(_ r: String) -> String { T[r] as! String }
    private func mid(_ i: Int) -> String { "00000000-0000-4000-8000-" + String(format: "%012d", i) }

    private func step(_ sm: ThreadStateMachine, _ i: Int, _ type: String, _ from: String, _ to: String, _ body: [String: Any]) -> String {
        let e = ThreadEvent(conversationId: T["conversationId"] as! String, threadId: T["threadId"] as? String,
                            type: MessageType(rawValue: type)!, messageId: mid(i), timestamp: 1741000000 + i,
                            from: role(from), to: role(to))
        do {
            return try sm.apply(e, body: jsonBody(body)).rawValue
        } catch let e as ACEError {
            return "error:" + e.code.rawValue
        } catch {
            return "error:\(error)"
        }
    }

    private func synth(_ type: String, _ ids: [String]) -> [String: Any] {
        let tpl = (T["bodyTemplates"] as! [String: [String: Any]])[type]!
        var out: [String: Any] = [:]
        for (k, v) in tpl {
            if v as? String == "$head" { out[k] = ids.last ?? "" }
            else if v as? String == "$beforeHead" { out[k] = ids.count >= 2 ? ids[ids.count - 2] : "" }
            else { out[k] = v }
        }
        return out
    }

    @Test(arguments: ["buyer", "seller"]) func transitionMatrix(_ local: String) throws {
        let matrix = T["matrix"] as! [String: [String: [String: String]]]
        let paths = T["paths"] as! [String: [String]]
        var count = 0
        for (state, row) in matrix {
            for (type, cell) in row {
                for (sender, expect) in cell {
                    let sm = try ThreadStateMachine(localAceId: role(local))
                    var ids: [String] = []
                    for (n, s) in paths[state]!.enumerated() {
                        let parts = s.split(separator: ":").map(String.init)
                        let other = parts[1] == "buyer" ? "seller" : "buyer"
                        let got = step(sm, n + 1, parts[0], parts[1], other, synth(parts[0], ids))
                        #expect(!got.hasPrefix("error"), "path \(state) step \(n): \(got)")
                        ids.append(mid(n + 1))
                    }
                    let before = sm.exportState()
                    let other = sender == "buyer" ? "seller" : "buyer"
                    let got = step(sm, ids.count + 1, type, sender, other, synth(type, ids))
                    #expect(got == expect, "\(state) \(type) \(sender)")
                    if got.hasPrefix("error") { #expect(sm.exportState() == before) }
                    count += 1
                }
            }
        }
        #expect(count > 100)
    }

    @Test func transitionCases() throws {
        for c in T["cases"] as! [[String: Any]] {
            let sm = try ThreadStateMachine(localAceId: role(c["local"] as! String))
            for (n, s) in (c["steps"] as! [[String: Any]]).enumerated() {
                let got = step(sm, n + 1, s["type"] as! String, s["from"] as! String, s["to"] as! String, s["body"] as! [String: Any])
                #expect(got == s["expect"] as? String, "\(c["name"]!) step \(n + 1)")
            }
        }
    }

    // MARK: replay

    @Test func replay() throws {
        for v in V["replay"] as! [[String: Any]] {
            let name = v["name"] as! String
            let capacity = v["capacity"] as! Int
            let det: ReplayDetector
            if let initial = v["initialStateJson"] as? String {
                det = try ReplayDetector(state: try ReplayState(json: Data(initial.utf8)), capacity: capacity)
            } else {
                det = try ReplayDetector(capacity: capacity, horizon: v["horizon"] as? Int)
            }
            for op in v["ops"] as! [[String: Any]] {
                let id = op["messageId"] as! String, s = op["sender"] as! String, ts = op["timestamp"] as! Int
                let got = op["op"] as! String == "commit"
                    ? try det.commit(id, from: s, timestamp: ts, floor: op["floor"] as? Int)
                    : try det.accepts(id, from: s, timestamp: ts)
                #expect(got == op["expect"] as? Bool, "\(name): \(op)")
            }
            #expect(String(decoding: det.exportState().jsonData(), as: UTF8.self) == v["finalStateJson"] as? String, "\(name)")
            // The persisted-JSON writer produces the same canonical bytes.
            let roundTrip = try ReplayState(json: det.exportState().jsonData())
            #expect(roundTrip == det.exportState())
        }
    }

    // MARK: signatures

    @Test(arguments: ["ed25519", "secp256k1"]) func signatures(_ schemeName: String) {
        let scheme = SigningScheme(rawValue: schemeName)!
        let cases = (V["signatures"] as! [String: Any])[schemeName] as! [[String: Any]]
        #expect(cases.count >= 6)
        for v in cases {
            var ok: Bool
            do {
                let sig = try decodeSignature(v["signature"] as! String, scheme: scheme, code: .invalidSignature)
                ok = ACESigning.verify(signData: hex(v["signDataHex"] as! String), signature: sig, scheme: scheme,
                                       publicKey: try ACEBase64.decode(v["publicKey"] as! String))
            } catch {
                ok = false
            }
            #expect(ok == v["valid"] as? Bool, "\(v["name"]!)")
        }
    }

    // MARK: auth

    private func authRequest(_ r: [String: Any]) -> RelayAuthRequest {
        switch r["action"] as! String {
        case "listen": return .listen(since: r["since"] as! String)
        case "inbox": return .inbox(since: r["since"] as! String, limit: r["limit"] as! Int)
        case "unregister": return .unregister
        default:
            return .intent(need: r["need"] as! String, tags: r["tags"] as! [String], maxPrice: r["maxPrice"] as? String,
                           currency: r["currency"] as? String, ttl: r["ttl"] as! Int)
        }
    }

    @Test func auth() throws {
        let cases = V["auth"] as! [[String: Any]]
        #expect(cases.count >= 10)
        for v in cases {
            let ident = Fixtures.agent(v["agent"] as! String)
            let req = authRequest(v["request"] as! [String: Any])
            let ts = v["timestamp"] as! Int
            #expect(hexEncode(req.payload()) == v["payloadHex"] as? String)
            #expect(hexEncode(try req.signData(aceId: ident.getACEId(), timestamp: ts)) == v["signDataHex"] as? String)
            let headers = v["headers"] as! [String: String]
            if !(v["verifyOnly"] as? Bool ?? false) {
                // ed25519 signatures from CryptoKit are hedged: compare the deterministic
                // headers exactly and verify the fresh signature.
                let mine = try createAuthHeaders(identity: ident, request: req, timestamp: ts)
                #expect(mine["X-ACE-Id"] == headers["X-ACE-Id"])
                #expect(mine["X-ACE-Timestamp"] == headers["X-ACE-Timestamp"])
                try verifyAuthHeaders(try parseAuthHeaders(mine), request: req, aceId: ident.getACEId(), scheme: ident.getSigningScheme(),
                                      signingPublicKey: ident.getSigningPublicKey(), clock: { ts })
            }
            let parsed = try parseAuthHeaders(headers)
            try verifyAuthHeaders(parsed, request: req, aceId: ident.getACEId(), scheme: ident.getSigningScheme(),
                                  signingPublicKey: ident.getSigningPublicKey(), clock: { ts })
        }
    }

    // MARK: registrations

    @Test func registrations() throws {
        for v in V["registrations"] as! [[String: Any]] {
            let now = v["now"] as! Int
            let request = v["request"] as! [String: Any]
            let result = try verifyRegistrationRequest(json(request), clock: { now })
            #expect(result.requestDigest == v["requestDigest"] as? String)
            #expect(result.requestDigest == sha256Hex(hex(v["signDataHex"] as! String)))
            #expect(result.peer.aceId == request["aceId"] as? String)
            let back = try JSONSerialization.jsonObject(with: result.request.jsonData()) as! [String: Any]
            #expect(NSDictionary(dictionary: back).isEqual(to: request), "\(v["mode"]!)")
        }
    }

    @Test func registrationErrors() {
        for v in V["registrationErrors"] as! [[String: Any]] {
            let now = v["now"] as! Int
            let code = ACEError.Code(rawValue: v["error"] as! String)!
            expectCode(code) { try verifyRegistrationRequest(json(v["request"]!), clock: { now }) }
        }
    }

    @Test func registrationRoundTrip() throws {
        for name in ["alice", "bob"] {
            let ident = Fixtures.agent(name)
            for profile: RegistrationProfile in [.keep, .remove, .replace(AgentProfile(name: "A", tags: ["x"], pricing: ProfilePricing(currency: "USDC", maxAmount: "1.5")))] {
                let req = try createRegistrationRequest(identity: ident, profile: profile, timestamp: 1741000000)
                let result = try verifyRegistrationRequest(req.jsonData(), clock: { 1741000000 })
                #expect(result.request == req)
                #expect(result.peer.encryptionPublicKey == ident.getEncryptionPublicKey())
            }
        }
    }

    // MARK: urls / base64

    @Test func urls() {
        for v in V["urls"] as! [[String: Any]] {
            #expect(isHTTPSURL(v["url"] as! String) == v["valid"] as? Bool, "\(v["url"]!)")
        }
    }

    @Test func base64() {
        for v in V["base64"] as! [[String: Any]] {
            let text = v["text"] as! String
            do {
                let raw = try ACEBase64.decode(text)
                #expect(v["valid"] as! Bool, "\(text)")
                #expect(hexEncode(raw) == v["hex"] as? String, "\(text)")
            } catch let e as ACEError {
                #expect(!(v["valid"] as! Bool), "\(text)")
                #expect(e.code == .invalidArgument)
            } catch {
                Issue.record("\(error)")
            }
        }
    }

    // MARK: peer binding

    @Test func peerBinding() {
        for c in V["peerBinding"] as! [[String: Any]] {
            let now = c["now"] as! Int
            var pin: VerifiedPeer?
            for step in c["sequence"] as! [[String: Any]] {
                var got: String
                do {
                    let cand: VerifiedPeer
                    if let record = step["record"] {
                        cand = try verifyPeerRecord(try PeerRecord.parse(jvalue(record)))
                    } else {
                        cand = try verifyRegistrationFile(try RegistrationFile.parse(jvalue(step["registrationFile"]!)),
                                                          pinnedAt: step["pinnedAt"] as? Int)
                    }
                    let (next, outcome) = try adoptDecision(pin: pin, candidate: cand, now: now)
                    pin = next
                    got = outcome.rawValue
                } catch let e as ACEError {
                    got = "error:" + e.code.rawValue
                } catch {
                    got = "\(error)"
                }
                #expect(got == step["expect"] as? String, "\(c["name"]!)")
                if let at = step["pinRegisteredAt"] as? Int {
                    #expect(pin?.registeredAt == at, "\(c["name"]!)")
                    #expect(pin.map { ACEBase64.encode($0.encryptionPublicKey) } == step["pinEncryptionPublicKey"] as? String)
                }
            }
        }
    }
}
