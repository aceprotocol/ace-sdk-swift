//
//  Shared cross-language vectors (ace-spec/test-vectors.json, version 4).
//

import Foundation
import Testing
@testable import ACE

@Suite("Vectors v4")
struct VectorTests {
    let V = Fixtures.vectors

    @Test func versionAndSections() {
        #expect(Fixtures.root["version"] as? String == "4")
        for key in ["envelopes", "bodies", "transitions", "replay", "signatures", "auth", "registrations",
                    "registrationErrors", "urls", "base64", "peerBinding", "webhooks", "relayUrls", "blockedAddresses",
                    "relayErrors", "directReceive", "principal", "principalRules"] {
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
        case "webhook":
            switch r["method"] as! String {
            case "PUT": return .webhook(.put(url: r["url"] as! String, secret: r["secret"] as! String))
            case "GET": return .webhook(.get)
            default: return .webhook(.delete)
            }
        default:
            return .intent(need: r["need"] as! String, tags: r["tags"] as! [String], maxPrice: r["maxPrice"] as? String,
                           currency: r["currency"] as? String, ttl: r["ttl"] as! Int)
        }
    }

    @Test func auth() throws {
        let all = V["auth"] as! [[String: Any]]
        #expect(all.count == 22)
        // Principal entries carry no headers: the header runner skips them (see principalAuth).
        let cases = all.filter { $0["action"] as? String != "principal" }
        #expect(cases.count == 18)
        #expect(cases.filter { ($0["request"] as! [String: Any])["action"] as? String == "webhook" }.count == 6)
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

    // MARK: principal (09)

    private var principalAuthEntries: [[String: Any]] { (V["auth"] as! [[String: Any]]).filter { $0["action"] as? String == "principal" } }

    @Test func principalAuth() throws {
        let entries = principalAuthEntries
        #expect(entries.count == 4)
        for v in entries {
            let r = v["request"] as! [String: Any]
            let spk = try ACEBase64.decode(v["subjectSigningPublicKey"] as! String)
            #expect(r["subjectSigningPublicKey"] as? String == v["subjectSigningPublicKey"] as? String)
            let ts = v["timestamp"] as! Int, now = v["now"] as! Int
            let payload = ACESigning.encodePayload([
                .string(r["account"] as! String), .string((r["roles"] as! [String]).joined(separator: ",")),
                .string(r["signerScheme"] as! String), .string(r["signerPublicKey"] as! String),
                .string(r["subjectSigningPublicKey"] as! String), .string(r["scope"] as? String ?? ""),
                .string(String(r["expiresAt"] as! Int)),
            ])
            #expect(hexEncode(payload) == v["payloadHex"] as? String)
            #expect(hexEncode(try ACESigning.buildSignData(action: "principal", aceId: r["subjectAceId"] as! String,
                                                           timestamp: ts, payload: payload)) == v["signDataHex"] as? String)
            let rec = try validatePrincipalRecord(try PrincipalRecord(json: json(v["record"]!)), subjectSigningPublicKey: spk, now: now)
            #expect(rec.signature == v["signature"] as? String)
            #expect(hexEncode(try principalSignData(rec, subjectSigningPublicKey: spk)) == v["signDataHex"] as? String)
            if !(v["verifyOnly"] as? Bool ?? false) {
                // ed25519 signatures are hedged: every member but the signature must match, and the
                // fresh signature must validate (createPrincipalRecord validates its own output).
                let mine = try createPrincipalRecord(signer: PrincipalSigner(identity: Fixtures.agent(v["agent"] as! String)),
                                                     subjectSigningPublicKey: spk, account: r["account"] as! String,
                                                     roles: r["roles"] as! [String], expiresAt: r["expiresAt"] as! Int,
                                                     scope: r["scope"] as? String, issuedAt: ts)
                var a = mine, b = rec
                a.signature = ""; b.signature = ""
                #expect(a == b)
                _ = try validatePrincipalRecord(mine, subjectSigningPublicKey: spk, now: now)
            }
        }
    }

    @Test func principalValidAndInvalid() throws {
        let p = V["principal"] as! [String: Any]
        let valid = p["valid"] as! [[String: Any]], invalid = p["invalid"] as! [[String: Any]]
        #expect(!valid.isEmpty && !invalid.isEmpty)
        for v in valid {
            let spk = try ACEBase64.decode(v["subjectSigningPublicKey"] as! String)
            let r = try validatePrincipalRecord(try PrincipalRecord(json: json(v["record"]!)), subjectSigningPublicKey: spk,
                                                now: v["now"] as? Int ?? p["now"] as! Int)
            #expect(hexEncode(principalPayload(r, subjectSigningPublicKey: spk)) == v["payloadHex"] as? String, "\(v["name"]!)")
            #expect(hexEncode(try principalSignData(r, subjectSigningPublicKey: spk)) == v["signDataHex"] as? String, "\(v["name"]!)")
        }
        for v in invalid {
            let spk = try ACEBase64.decode(v["subjectSigningPublicKey"] as! String)
            var got = "ok"
            do {
                try validatePrincipalRecord(try PrincipalRecord(json: json(v["record"]!)), subjectSigningPublicKey: spk, now: v["now"] as! Int)
            } catch let e as ACEError { got = e.code.rawValue }
            #expect(got == v["error"] as? String, "\(v["name"]!)")
        }
    }

    @Test func principalRules() throws {
        let pr = V["principalRules"] as! [String: Any]
        let conv = pr["conversationId"] as! String
        let senders = pr["senders"] as! [String: [String: Any]]
        let all = pr["cases"] as! [[String: Any]]
        #expect(all.count == 28)
        func key(_ v: Any) -> PrincipalKey { let d = v as! [String: String]; return PrincipalKey(scheme: d["scheme"]!, publicKey: d["publicKey"]!) }
        for c in all {
            let name = c["name"] as! String
            let now = c["now"] as? Int ?? pr["now"] as! Int
            var open = c["openRequests"] as! [String: [String: Any]]
            let selfSigner = (c["selfSigner"]).flatMap { $0 is NSNull ? nil : key($0) }
            let trusted = Set(((c["trustedSigners"] as? [Any]) ?? []).map(key))
            for s in c["steps"] as! [[String: Any]] {
                let snd = senders[s["sender"] as! String]!
                let principal = try (snd["principal"] as? [String: Any]).map { try PrincipalRecord(json: json($0)) }
                let type = MessageType(rawValue: s["type"] as! String)!
                let body = jsonBody(s["body"]!)
                _ = try decodeBody(type, json(s["body"]!))
                var got = "ok"
                do {
                    try checkPrincipalRules(type: type, body: body, conversationId: conv, senderPrincipal: principal,
                                            senderSigningPublicKey: try ACEBase64.decode(snd["signingPublicKey"] as! String),
                                            selfAccount: c["selfAccount"] as? String,
                                            openRequestTo: { cv, rid, at in
                                                guard cv == conv, let e = open[rid] else { return nil }
                                                if let exp = e["expiresAt"] as? Int, at > exp { return nil }
                                                return e["to"] as? String
                                            }, now: now, selfSigner: selfSigner, trustedSigners: trusted)
                } catch let e as ACEError { got = "error:" + e.code.rawValue }
                #expect(got == s["expect"] as? String, "\(name): \(s["type"]!)")
                if got == "ok", type == .decision { open[body["requestId"]!.stringValue!] = nil }
            }
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
                for extreme in [Int.min, Int.max] {
                    expectCode(.staleTimestamp) { try verifyRegistrationRequest(req.jsonData(), clock: { extreme }) }
                }
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

    // MARK: webhooks / relay URLs / blocked addresses / relay errors / direct receive

    private func cases(_ section: String) -> [[String: Any]] {
        (V[section] as! [String: Any])["cases"] as! [[String: Any]]
    }

    @Test func webhooks() {
        let all = cases("webhooks")
        #expect(all.count == 21)
        for c in all {
            let name = c["name"] as! String
            let secret = c["secret"] as! String, timestamp = c["timestamp"] as! String, signature = c["signature"] as! String
            let body = Data((c["body"] as! String).utf8), now = c["now"] as! Int
            do {
                let n = try verifyWebhookNotification(secret: secret, timestamp: timestamp, signature: signature, body: body,
                                                      clock: { now })
                guard let r = c["result"] as? [String: Any] else {
                    Issue.record("\(name): expected \(c["error"]!), got success")
                    continue
                }
                #expect(n.aceId == r["aceId"] as? String && n.streamId == r["streamId"] as? String, "\(name)")
                #expect(signWebhookNotification(secret: secret, timestamp: Int(timestamp)!, body: body) == signature, "\(name)")
            } catch let e as ACEError {
                #expect(e.code.rawValue == c["error"] as? String, "\(name): \(e)")
            } catch {
                Issue.record("\(name): \(error)")
            }
        }
    }

    @Test func relayUrls() {
        let all = cases("relayUrls")
        #expect(all.count == 43)
        for c in all {
            let input = c["input"] as! String
            do {
                let out = try normalizeRelayURL(input)
                #expect(out == c["normalized"] as? String, "\(input.debugDescription)")
            } catch let e as ACEError {
                #expect(e.code.rawValue == c["error"] as? String, "\(input.debugDescription): \(e)")
            } catch {
                Issue.record("\(input.debugDescription): \(error)")
            }
        }
    }

    @Test func blockedAddresses() {
        let all = cases("blockedAddresses")
        #expect(all.count == 91)
        for c in all {
            let address = c["address"] as! String
            #expect(isBlockedAddress(address) == c["blocked"] as? Bool, "\(address)")
        }
    }

    @Test func relayErrors() {
        let all = cases("relayErrors")
        #expect(all.count == 41)
        for c in all {
            let name = c["name"] as! String
            let headers = c["headers"] as! [String: String]
            let retryAfter = headers.first { $0.key.lowercased() == "retry-after" }?.value
            let e = relayError(status: c["status"] as! Int, retryAfter: retryAfter, body: Data((c["body"] as! String).utf8))
            #expect(e.code.rawValue == c["code"] as? String, "\(name)")
            #expect(e.category.rawValue == c["category"] as? String, "\(name)")
            #expect(e.relayCode == c["relayCode"] as? String, "\(name)")
            #expect(e.retryAfterSeconds == c["retryAfterSeconds"] as? Int, "\(name)")
            #expect(e.status == c["status"] as? Int, "\(name)")
        }
    }

    @Test func directReceive() async throws {
        let section = V["directReceive"] as! [String: Any]
        #expect(section["maxDirectBodyBytes"] as? Int == ACELimits.maxDirectBodyBytes)
        let all = cases("directReceive")
        #expect(all.count == 17)
        let bob = Fixtures.agent("bob"), store = MemoryStore()
        let inbox = try await Inbox.open(identity: bob, store: store, peers: try PeerStore(store: store), onMessage: { _ in })
        for c in all {
            let name = c["name"] as! String
            var bytes = (c["bodyHex"] as? String).map(hex) ?? Data((c["body"] as! String).utf8)
            if let padTo = c["padTo"] as? Int, bytes.count < padTo { bytes.append(Data(repeating: 0x20, count: padTo - bytes.count)) }
            let reply = await inbox.receiveDirect(bytes)
            #expect(reply.status == c["status"] as? Int, "\(name)")
            #expect(reply.body == ["ok": false, "error": .string(c["error"] as! String)], "\(name): \(reply.body)")
        }
        await inbox.close()
    }
}
