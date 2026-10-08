import Foundation
import Testing
@testable import ACE

let CONV = String(repeating: "ab", count: 32)
let MID = "00000000-0000-4000-8000-000000000001"

@Suite("Principal")
struct PrincipalTests {
    @Test func typeLists() {
        #expect(messageTypes.count == 13 && Array(messageTypes.suffix(3)) == [.request, .decision, .report])
        #expect(economicTypes.count == 8 && principalTypes == [.request, .decision, .report])
        #expect(principalTypes.allSatisfy { $0.isPrincipal && !$0.isEconomic })
        #expect(!MessageType.text.isPrincipal && !isPrincipalType(.info))
        #expect(ACEError.Code.invalidPrincipal.category == .permanent && ACEError.Code.wrongPrincipal.category == .permanent)
    }

    @Test(arguments: [
        ("request", #"{"action":"pay","summary":"Pay 1 USDC"}"#),
        ("request", #"{"action":"x402.pay","summary":"s","amount":"1","currency":"USDC","ttl":60,"details":{"payTo":"x"},"ref":{"conversationId":"\#(String(repeating: "ab", count: 32))","messageId":"00000000-0000-4000-8000-000000000001","threadId":"t"}}"#),
        ("decision", #"{"requestId":"r","outcome":"deny","reason":"no","result":{"x":1}}"#),
        ("report", #"{"action":"pay","summary":"paid","outcome":"skipped","proof":{},"requestId":"r"}"#),
    ])
    func validBodies(_ t: String, _ body: String) throws {
        try validateBody(MessageType(rawValue: t)!, try JSONValue(json: Data(body.utf8)).objectValue!)
    }

    @Test(arguments: [
        ("request", #"{"action":"a"}"#),
        ("request", #"{"action":"a","summary":"s","details":"x"}"#),
        ("request", #"{"action":"a","summary":"s","ttl":1.5}"#),
        ("request", #"{"action":"a","summary":"s","ref":[]}"#),
        ("request", #"{"action":"a","summary":"s","ref":{"conversationId":"AB","messageId":"00000000-0000-4000-8000-000000000001"}}"#),
        ("request", #"{"action":"a","summary":"s","ref":{"conversationId":"\#(String(repeating: "ab", count: 32))"}}"#),
        ("request", #"{"action":"a","summary":"s","ref":{"conversationId":"\#(String(repeating: "ab", count: 32))","messageId":"00000000-0000-4000-8000-000000000001","threadId":""}}"#),
        ("decision", #"{"requestId":"r","outcome":"maybe"}"#),
        ("decision", #"{"requestId":"r","outcome":"approve","result":[]}"#),
        ("report", #"{"action":"a","summary":"s","outcome":"done"}"#),
        ("report", #"{"action":"a","summary":"s","outcome":"ok","proof":"x"}"#),
    ])
    func invalidBodies(_ t: String, _ body: String) {
        expectCode(.invalidBody) { try validateBody(MessageType(rawValue: t)!, try JSONValue(json: Data(body.utf8)).objectValue!) }
    }

    // MARK: - Task 16: records, signing context, same-account rules, requests ledger

    static let ACC = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp:7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU"
    static let NOW = 1_800_000_000
    static let TO = "ace:sha256:" + String(repeating: "cd", count: 32)

    func rec(_ owner: SoftwareIdentity, _ subject: SoftwareIdentity, roles: [String] = ["agent", "controller", "agent"],
             scope: String? = nil, expiresAt: Int = NOW + 3600, issuedAt: Int = NOW - 10,
             account: String = PrincipalTests.ACC) throws -> PrincipalRecord {
        try createPrincipalRecord(signer: PrincipalSigner(identity: owner), subjectSigningPublicKey: subject.getSigningPublicKey(),
                                  account: account, roles: roles, expiresAt: expiresAt, scope: scope, issuedAt: issuedAt)
    }

    func key(_ id: SoftwareIdentity) -> PrincipalKey {
        PrincipalKey(scheme: id.getSigningScheme().rawValue, publicKey: ACEBase64.encode(id.getSigningPublicKey()))
    }

    @Test(arguments: [SigningScheme.ed25519, .secp256k1]) func createAndValidate(_ scheme: SigningScheme) throws {
        let owner = try SoftwareIdentity.generate(scheme: scheme), subject = try SoftwareIdentity.generate(scheme: .ed25519)
        let r = try rec(owner, subject, scope: "copy:solana,hl")
        #expect(r.roles == ["controller", "agent"])
        #expect(r.signer == key(owner))
        let spk = subject.getSigningPublicKey()
        #expect(try validatePrincipalRecord(r, subjectSigningPublicKey: spk, now: Self.NOW) == r)
        #expect(principalPayload(r, subjectSigningPublicKey: spk) == ACESigning.encodePayload(
            Self.ACC, "controller,agent", scheme.rawValue, r.signer.publicKey, ACEBase64.encode(spk), "copy:solana,hl",
            String(Self.NOW + 3600)))
        #expect(try principalSignData(r, subjectSigningPublicKey: spk) == ACESigning.buildSignData(
            action: "principal", aceId: subject.getACEId(), timestamp: Self.NOW - 10,
            payload: principalPayload(r, subjectSigningPublicKey: spk)))
        // JSON round trip; no scope → member absent, payload uses "".
        #expect(try PrincipalRecord(json: r.jsonData()) == r)
        let bare = try rec(owner, subject, roles: ["agent"])
        #expect(bare.scope == nil && !String(decoding: bare.jsonData(), as: UTF8.self).contains("scope"))
        #expect(String(decoding: bare.jsonData(), as: UTF8.self).contains(#""expiresAt":\#(Self.NOW + 3600)"#))
        // Codable round trip.
        #expect(try JSONDecoder().decode(PrincipalRecord.self, from: JSONEncoder().encode(r)) == r)
    }

    @Test func createRolesAndArguments() throws {
        let owner = try SoftwareIdentity.generate(scheme: .ed25519), subject = try SoftwareIdentity.generate(scheme: .ed25519)
        #expect(try rec(owner, subject, roles: ["controller", "controller"]).roles == ["controller"])
        #expect(try rec(owner, subject, roles: ["agent"]).roles == ["agent"])
        expectCode(.invalidArgument) { try rec(owner, subject, roles: ["owner"]) }
        expectCode(.invalidPrincipal) { try rec(owner, subject, roles: []) }
        expectCode(.invalidPrincipal) { try rec(owner, subject, account: "solana:abc") }
        expectCode(.invalidPrincipal) { try rec(owner, subject, expiresAt: Self.NOW - 10) }
        expectCode(.invalidPrincipal) { try rec(owner, subject, expiresAt: Self.NOW - 10 + 31_622_401) }
        expectCode(.invalidPrincipal) { try rec(owner, subject, issuedAt: -1) }
        #expect(try rec(owner, subject, expiresAt: Self.NOW - 10 + 31_622_400).expiresAt == Self.NOW - 10 + 31_622_400)
        // An invalid draft never reaches the signer.
        let calls = Counter()
        let signer = PrincipalSigner(scheme: .ed25519, publicKey: owner.getSigningPublicKey()) { calls.bump(); return try owner.sign($0) }
        expectCode(.invalidPrincipal) {
            try createPrincipalRecord(signer: signer, subjectSigningPublicKey: subject.getSigningPublicKey(), account: "x",
                                      roles: ["agent"], expiresAt: Self.NOW + 10, issuedAt: Self.NOW)
        }
        #expect(calls.value == 0)
    }

    @Test func invalidRecordsAndBounds() throws {
        let owner = try SoftwareIdentity.generate(scheme: .ed25519)
        let subject = try SoftwareIdentity.generate(scheme: .ed25519), other = try SoftwareIdentity.generate(scheme: .ed25519)
        let r = try rec(owner, subject, scope: "s", expiresAt: Self.NOW + 10)
        let spk = subject.getSigningPublicKey()
        let mutations: [(inout PrincipalRecord) -> Void] = [
            { $0.account = "solana:abc" }, { $0.account = "Solana:x:y" }, { $0.account = Self.ACC + "\n" },
            { $0.roles = [] }, { $0.roles = ["agent", "controller"] }, { $0.roles = ["controller", "controller"] },
            { $0.roles = ["owner"] }, { $0.roles = ["Controller"] }, { $0.roles = ["controller"] },
            { $0.signer = .init(scheme: "p256", publicKey: $0.signer.publicKey) },
            { $0.signer = .init(scheme: "ed25519", publicKey: "QQ==") },
            { $0.signer = .init(scheme: "secp256k1", publicKey: $0.signer.publicKey) },
            { $0.issuedAt = Self.NOW + 301 }, { $0.issuedAt = -1 }, { $0.expiresAt = $0.issuedAt },
            { $0.expiresAt = $0.issuedAt + 31_622_401 }, { $0.expiresAt = Self.NOW + 11 },
            { $0.scope = "" }, { $0.scope = String(repeating: "x", count: 257) }, { $0.scope = "a\nb" },
            { $0.scope = "a\u{7F}" }, { $0.scope = "changed" }, { $0.scope = nil },
            { $0.signature = "0x" + String(repeating: "11", count: 65) }, { $0.signature = "" },
        ]
        for m in mutations {
            var d = r
            m(&d)
            expectCode(.invalidPrincipal) { try validatePrincipalRecord(d, subjectSigningPublicKey: spk, now: Self.NOW) }
        }
        expectCode(.invalidPrincipal) { try validatePrincipalRecord(r, subjectSigningPublicKey: other.getSigningPublicKey(), now: Self.NOW) }
        expectCode(.invalidPrincipal) { try validatePrincipalRecord(r, subjectSigningPublicKey: spk, now: Self.NOW + 10) }
        try validatePrincipalRecord(r, subjectSigningPublicKey: spk, now: Self.NOW + 9)
        // Scope length counts code points: 256 non-BMP scalars are fine.
        try validatePrincipalRecord(try rec(owner, subject, scope: String(repeating: "\u{1F600}", count: 256)),
                                    subjectSigningPublicKey: spk, now: Self.NOW)
    }

    @Test func strictJSONParse() throws {
        let owner = try SoftwareIdentity.generate(scheme: .ed25519), subject = try SoftwareIdentity.generate(scheme: .ed25519)
        let r = try rec(owner, subject, scope: "s")
        let o = try JSONValue(json: r.jsonData()).objectValue!
        func parse(_ patch: [String: JSONValue?]) throws -> PrincipalRecord {
            var d = o
            for (k, v) in patch { d[k] = v }
            return try PrincipalRecord(json: JSONValue.object(d).jsonData())
        }
        #expect(try parse(["extra": .string("x")]) == r)  // unknown members ignored
        var noScope = r
        noScope.scope = nil
        #expect(try parse(["scope": .null]) == noScope)  // null optional = absent
        #expect(try parse(["issuedAt": .number(Double(r.issuedAt))]).issuedAt == r.issuedAt)
        let bad: [[String: JSONValue?]] = [
            ["account": .number(1)], ["account": nil], ["roles": .string("controller")], ["roles": .array([.number(1)])],
            ["signer": nil], ["signer": .object(["scheme": "ed25519"])], ["issuedAt": .string("1")], ["issuedAt": .number(1.5)],
            ["expiresAt": nil], ["expiresAt": .null], ["expiresAt": .string("1")], ["expiresAt": .number(-1)],
            ["scope": .number(1)], ["signature": nil],
        ]
        for p in bad { expectCode(.invalidPrincipal) { try parse(p) } }
        expectCode(.invalidPrincipal) { try PrincipalRecord(json: Data("[]".utf8)) }
        expectCode(.invalidPrincipal) { try PrincipalRecord(json: Data("{".utf8)) }
    }

    @Test func caip10() {
        #expect(isCAIP10(Self.ACC) && isCAIP10("eip155:1:0xabc"))
        #expect(!isCAIP10("eip155:1") && !isCAIP10("EIP155:1:x") && !isCAIP10("eip155:1:x\n") && !isCAIP10("ab:1:x"))
        #expect(!isCAIP10("eip155:1:" + String(repeating: "a", count: 129)) && !isCAIP10("eip155:1:a b"))
        #expect(principalRoles == ["controller", "agent"])
    }

    @Test func rules() throws {
        let owner = try SoftwareIdentity.generate(scheme: .ed25519)
        let ctrl = try SoftwareIdentity.generate(scheme: .ed25519), ctrl2 = try SoftwareIdentity.generate(scheme: .ed25519)
        let agent = try SoftwareIdentity.generate(scheme: .secp256k1)
        let pCtrl = try rec(owner, ctrl, roles: ["controller"]), pCtrl2 = try rec(owner, ctrl2, roles: ["controller"])
        let pAgent = try rec(owner, agent, roles: ["agent"])
        let ownerKey = key(owner)
        func chk(_ t: MessageType, _ body: String, _ p: PrincipalRecord?, _ sender: SoftwareIdentity,
                 _ account: String? = PrincipalTests.ACC, selfSigner: PrincipalKey? = nil, trusted: Set<PrincipalKey> = [],
                 to: String? = nil) throws {
            let recipient = to ?? ctrl.getACEId()
            try checkPrincipalRules(type: t, body: try JSONValue(json: Data(body.utf8)).objectValue!, conversationId: CONV,
                                    senderPrincipal: p, senderSigningPublicKey: sender.getSigningPublicKey(), selfAccount: account,
                                    openRequestTo: { c, r, now in c == CONV && r == MID && now == Self.NOW ? recipient : nil },
                                    now: Self.NOW, selfSigner: selfSigner ?? ownerKey, trustedSigners: trusted)
        }
        let req = #"{"action":"pay","summary":"s"}"#
        let dec = #"{"requestId":"\#(MID)","outcome":"approve"}"#
        try chk(.request, req, pAgent, agent)
        try chk(.request, req, pCtrl, ctrl)
        try chk(.report, #"{"action":"pay","summary":"s","outcome":"ok"}"#, pCtrl, ctrl)
        try chk(.decision, dec, pCtrl, ctrl)
        expectCode(.invalidArgument) { try chk(.text, req, pAgent, agent) }
        expectCode(.wrongPrincipal) { try chk(.request, req, pAgent, agent, nil) }                  // 1
        expectCode(.wrongPrincipal) { try chk(.request, req, nil, agent) }                          // 2
        expectCode(.wrongPrincipal) { try chk(.request, req, pAgent, ctrl) }                        // 3 subject mismatch
        expectCode(.wrongPrincipal) { try chk(.request, req, pAgent, agent, "eip155:1:0xabc") }     // 5
        expectCode(.wrongPrincipal) { try chk(.decision, dec, pAgent, agent) }                      // 6
        expectCode(.badReference) { try chk(.decision, #"{"requestId":"x","outcome":"approve"}"#, pCtrl, ctrl) }  // 7
        expectCode(.wrongPrincipal) { try chk(.decision, dec, pCtrl2, ctrl2) }                      // 7 R-P22 decider
        try chk(.decision, dec, pCtrl2, ctrl2, to: ctrl2.getACEId())
        let none: ((String, String, Int) throws -> String?)? = nil
        expectCode(.badReference) {
            try checkPrincipalRules(type: .decision, body: try JSONValue(json: Data(dec.utf8)).objectValue!, conversationId: CONV,
                                    senderPrincipal: pCtrl, senderSigningPublicKey: ctrl.getSigningPublicKey(), selfAccount: Self.ACC,
                                    openRequestTo: none, now: Self.NOW, selfSigner: ownerKey)
        }

        // R-P21: the signer must be an authority of the account.
        let forger = try SoftwareIdentity.generate(scheme: .ed25519)
        let forged = try rec(forger, agent, roles: ["agent"])
        expectCode(.wrongPrincipal) { try chk(.request, req, forged, agent) }
        try chk(.request, req, forged, agent, trusted: [key(forger)])
        expectCode(.wrongPrincipal) {
            try checkPrincipalRules(type: .request, body: try JSONValue(json: Data(req.utf8)).objectValue!, conversationId: CONV,
                                    senderPrincipal: pAgent, senderSigningPublicKey: agent.getSigningPublicKey(), selfAccount: Self.ACC,
                                    openRequestTo: nil, now: Self.NOW)  // defaults: no selfSigner, no trusted → fail closed
        }
        // eip155: a secp256k1 signer whose address is the account address (case-insensitive).
        let eoa = try SoftwareIdentity.generate(scheme: .secp256k1), stranger = try SoftwareIdentity.generate(scheme: .secp256k1)
        let addr = eoa.getAddress()
        for account in ["eip155:8453:" + addr, "eip155:8453:" + addr.lowercased(), "eip155:8453:0x" + addr.dropFirst(2).uppercased()] {
            let p = try rec(eoa, agent, roles: ["agent"], account: account)
            try chk(.request, req, p, agent, account, selfSigner: ownerKey)
        }
        let wrongAddr = try rec(stranger, agent, roles: ["agent"], account: "eip155:8453:" + addr)
        expectCode(.wrongPrincipal) { try chk(.request, req, wrongAddr, agent, "eip155:8453:" + addr) }
        let edOnEip = try rec(owner, agent, roles: ["agent"], account: "eip155:8453:" + addr)
        try chk(.request, req, edOnEip, agent, "eip155:8453:" + addr)  // via selfSigner (owner)
        expectCode(.wrongPrincipal) { try chk(.request, req, edOnEip, agent, "eip155:8453:" + addr, selfSigner: key(forger)) }
        // A solana account gets no address derivation.
        let solEoa = try rec(eoa, agent, roles: ["agent"])
        expectCode(.wrongPrincipal) { try chk(.request, req, solEoa, agent) }
    }

    @Test func inboxPrincipalDefaults() {
        let p = InboxPrincipal(account: Self.ACC)
        #expect(p.selfSigner == nil && p.trustedSigners.isEmpty)
        let k = PrincipalKey(scheme: "ed25519", publicKey: "x")
        #expect(InboxPrincipal(account: Self.ACC, selfSigner: k, trustedSigners: [k]).trustedSigners == [k])
    }

    // MARK: requests/ ledger

    func msg(conv: String = CONV, mid: String = MID, ts: Int = NOW) -> ACEMessage {
        ACEMessage(messageId: mid, from: "ace:sha256:" + String(repeating: "ef", count: 32), to: Self.TO, conversationId: conv,
                   type: .request, timestamp: ts, encryption: .init(kemCiphertext: "", payload: ""),
                   signature: .init(scheme: .ed25519, value: ""))
    }

    func decision(mid: String = MID, outcome: String = "approve", ts: Int = NOW + 5,
                  own: String = "00000000-0000-4000-8000-0000000000aa", from: String = PrincipalTests.TO) -> ParsedMessage {
        ParsedMessage(messageId: own, from: from, to: "ace:sha256:" + String(repeating: "ef", count: 32), conversationId: CONV,
                      type: .decision, threadId: nil, timestamp: ts, body: ["requestId": .string(mid), "outcome": .string(outcome)])
    }

    @Test func requestKeyShape() {
        var d = Data(CONV.utf8)
        d.append(0)
        d.append(contentsOf: Array(MID.utf8))
        #expect(requestKey(CONV, MID) == "requests/" + sha256Hex(d) + ".json")
    }

    @Test func recordRequestAndFillDecision() throws {
        let store = MemoryStore()
        let other = "00000000-0000-4000-8000-000000000009"
        #expect(try loadRequestRecord(store, conversationId: CONV, messageId: MID) == nil)
        try recordRequest(store, message: msg(), sentAt: Self.NOW + 1, ttl: 60)
        let raw = try #require(try store.read(requestKey(CONV, MID)))
        #expect(String(decoding: raw, as: UTF8.self) ==
            #"{"conversationId":"\#(CONV)","decision":null,"expiresAt":\#(Self.NOW + 60),"messageId":"\#(MID)","sentAt":\#(Self.NOW + 1),"to":"\#(Self.TO)","version":1}"#)
        try recordRequest(store, message: msg(), sentAt: Self.NOW + 99, ttl: 1)  // idempotent
        #expect(try loadRequestRecord(store, conversationId: CONV, messageId: MID)?.sentAt == Self.NOW + 1)
        #expect(try openRequestTo(store, conversationId: CONV, messageId: MID, now: Self.NOW + 60) == Self.TO)
        #expect(try openRequestTo(store, conversationId: CONV, messageId: MID, now: Self.NOW + 61) == nil)
        #expect(try openRequestTo(store, conversationId: CONV, messageId: other, now: Self.NOW) == nil)
        try fillDecision(store, decision())
        let r = try #require(try loadRequestRecord(store, conversationId: CONV, messageId: MID))
        #expect(r.decision == RequestDecision(messageId: "00000000-0000-4000-8000-0000000000aa", outcome: "approve", timestamp: Self.NOW + 5))
        #expect(try openRequestTo(store, conversationId: CONV, messageId: MID, now: Self.NOW) == nil)
        let before = try store.read(requestKey(CONV, MID))
        expectCode(.badReference) { try fillDecision(store, decision(outcome: "deny", own: "00000000-0000-4000-8000-0000000000bb")) }
        try fillDecision(store, decision())  // replay of the accepted decision: no-op
        #expect(try store.read(requestKey(CONV, MID)) == before)
        try fillDecision(store, decision(mid: other))  // unknown request: no-op
        #expect(try loadRequestRecord(store, conversationId: CONV, messageId: other) == nil)

        let store2 = MemoryStore()
        try recordRequest(store2, message: msg(), sentAt: Self.NOW)
        expectCode(.wrongPrincipal) { try fillDecision(store2, decision(from: "ace:sha256:" + String(repeating: "99", count: 32))) }
        #expect(try loadRequestRecord(store2, conversationId: CONV, messageId: MID)?.decision == nil)
        #expect(try loadRequestRecord(store2, conversationId: CONV, messageId: MID)?.expiresAt == nil)
        #expect(try openRequestTo(store2, conversationId: CONV, messageId: MID, now: Self.NOW + 1_000_000_000) == Self.TO)
    }

    @Test func fillDecisionKeepsUnknownMembers() throws {
        let store = MemoryStore()
        try recordRequest(store, message: msg(), sentAt: Self.NOW)
        var o = try JSONValue(json: try #require(try store.read(requestKey(CONV, MID)))).objectValue!
        o["extra"] = .string("kept")
        try store.write(requestKey(CONV, MID), JSONValue.object(o).jsonData())
        try fillDecision(store, decision())
        let after = try JSONValue(json: try #require(try store.read(requestKey(CONV, MID)))).objectValue!
        #expect(after["extra"] == .string("kept") && after["version"] == .number(1))
    }

    @Test func recordRequestRejectsBadArguments() {
        expectCode(.invalidArgument) { try recordRequest(MemoryStore(), message: msg(conv: "xy"), sentAt: Self.NOW) }
        expectCode(.invalidArgument) { try recordRequest(MemoryStore(), message: msg(mid: "nope"), sentAt: Self.NOW) }
        expectCode(.invalidArgument) { try recordRequest(MemoryStore(), message: msg(), sentAt: Self.NOW, ttl: -1) }
        expectCode(.invalidArgument) { try recordRequest(MemoryStore(), message: msg(), sentAt: -1) }
    }

    @Test(arguments: [
        #"{"conversationId":"\#(String(repeating: "cd", count: 32))"}"#,
        #"{"messageId":"00000000-0000-4000-8000-000000000002"}"#,
        #"{"to":"bob"}"#, #"{"sentAt":"1"}"#, #"{"expiresAt":"1"}"#,
        #"{"decision":{"messageId":"\#(MID)","outcome":"maybe","timestamp":1}}"#, #"{"decision":[]}"#, #"{"version":2}"#,
    ])
    func loadRequestRecordRejectsCorrupt(_ patch: String) throws {
        let store = MemoryStore()
        try recordRequest(store, message: msg(), sentAt: Self.NOW)
        var o = try JSONValue(json: try #require(try store.read(requestKey(CONV, MID)))).objectValue!
        for (k, v) in try JSONValue(json: Data(patch.utf8)).objectValue! { o[k] = v }
        try store.write(requestKey(CONV, MID), JSONValue.object(o).jsonData())
        expectCode(.storageFailed) { try loadRequestRecord(store, conversationId: CONV, messageId: MID) }
    }

    // MARK: - Task 17: principal in profile, registration file, payload, verify, pin load

    func peerRecord(_ id: SoftwareIdentity, _ profile: AgentProfile, ts: Int = NOW) throws -> PeerRecord {
        let req = try createRegistrationRequest(identity: id, profile: .replace(profile), timestamp: ts)
        return PeerRecord(aceId: req.aceId, scheme: req.scheme.rawValue, encryptionPublicKey: req.encryptionPublicKey,
                          signingPublicKey: req.signingPublicKey, registrationSignature: req.signature, registeredAt: ts, profile: profile)
    }

    @Test func registrationPayloadAndRequest() throws {
        let owner = try SoftwareIdentity.generate(scheme: .ed25519)
        let me = try SoftwareIdentity.generate(scheme: .secp256k1), other = try SoftwareIdentity.generate(scheme: .ed25519)
        let good = try rec(owner, me, scope: "s", expiresAt: Self.NOW + 99)
        let p = registrationPayload(encryptionPublicKey: "E", signingPublicKey: "S", scheme: .ed25519,
                                    profile: .replace(AgentProfile(name: "A", principal: good)))
        let tail = ACESigning.encodePayload("present", Self.ACC, "controller,agent", "ed25519", good.signer.publicKey,
                                            String(Self.NOW - 10), String(Self.NOW + 99), "s", good.signature)
        #expect(p.suffix(tail.count) == tail)
        let absent = registrationPayload(encryptionPublicKey: "E", signingPublicKey: "S", scheme: .ed25519, profile: .replace(AgentProfile(name: "A")))
        #expect(absent.suffix(ACESigning.encodePayload("absent", "", "", "", "", "", "", "", "").count) == ACESigning.encodePayload("absent", "", "", "", "", "", "", "", ""))
        let req = try createRegistrationRequest(identity: me, profile: .replace(AgentProfile(name: "A", principal: good)), timestamp: Self.NOW)
        let v = try verifyRegistrationRequest(req.jsonData(), clock: { Self.NOW })
        #expect(v.peer.principal?.account == Self.ACC)
        expectCode(.invalidPrincipal) {
            try createRegistrationRequest(identity: me, profile: .replace(AgentProfile(name: "A", principal: try rec(owner, other))), timestamp: Self.NOW)
        }
    }

    @Test func peerRecordAndFile() throws {
        let owner = try SoftwareIdentity.generate(scheme: .ed25519)
        let me = try SoftwareIdentity.generate(scheme: .ed25519), other = try SoftwareIdentity.generate(scheme: .ed25519)
        let r = try peerRecord(me, AgentProfile(name: "A", principal: try rec(owner, me, expiresAt: Self.NOW + 50)))
        #expect(try verifyPeerRecord(r, clock: { Self.NOW }).principal?.roles == ["controller", "agent"])
        expectCode(.invalidPrincipal) { try verifyPeerRecord(r, clock: { Self.NOW + 50 }) }
        // The binding signature does not cover the profile, so a swapped principal is built by hand.
        let base = try peerRecord(me, AgentProfile(name: "A"))
        let swapped = PeerRecord(aceId: base.aceId, scheme: base.scheme, encryptionPublicKey: base.encryptionPublicKey,
                                 signingPublicKey: base.signingPublicKey, registrationSignature: base.registrationSignature,
                                 registeredAt: base.registeredAt, profile: AgentProfile(name: "A", principal: try rec(owner, other)))
        expectCode(.invalidPrincipal) { try verifyPeerRecord(swapped, clock: { Self.NOW }) }
        let reg = try createRegistrationFile(for: me, name: "M", endpoint: "https://m.example/ace", principal: try rec(owner, me))
        let peer = try verifyRegistrationFile(reg, pinnedAt: Self.NOW, clock: { Self.NOW })
        #expect(peer.profile == AgentProfile(principal: reg.principal))
        let wire = try JSONValue(json: try JSONEncoder().encode(reg))
        #expect(wire.objectValue?["principal"] != nil)
        let back = try RegistrationFile(json: try JSONEncoder().encode(reg))
        #expect(back.principal == reg.principal)
    }

    @Test func expiredPinStillLoads() async throws {
        let owner = try SoftwareIdentity.generate(scheme: .ed25519), me = try SoftwareIdentity.generate(scheme: .ed25519)
        let store = MemoryStore(), clock = TestClock(Self.NOW)
        let peers = try PeerStore(store: store, clock: clock.fn)
        try await peers.adopt(try verifyPeerRecord(try peerRecord(me, AgentProfile(principal: try rec(owner, me, expiresAt: Self.NOW + 5))), clock: { Self.NOW }))
        clock.now = Self.NOW + 10_000
        #expect(try await PeerStore(store: store, clock: clock.fn).get(me.getACEId())?.principal != nil)
    }

    @Test func tamperedPinnedPrincipalIsNotRestored() async throws {
        let owner = try SoftwareIdentity.generate(scheme: .ed25519), me = try SoftwareIdentity.generate(scheme: .ed25519)
        let other = try SoftwareIdentity.generate(scheme: .ed25519)
        let store = MemoryStore(), clock = TestClock(Self.NOW)
        let peers = try PeerStore(store: store, clock: clock.fn)
        try await peers.adopt(try verifyPeerRecord(try peerRecord(me, AgentProfile(principal: try rec(owner, me))), clock: { Self.NOW }))
        let key = PinnedPeer.key(me.getACEId())
        var o = try JSONValue(json: try #require(try store.read(key))).objectValue!
        var prof = o["profile"]!.objectValue!
        prof["principal"] = try JSONValue(json: try rec(owner, other).jsonData())
        o["profile"] = .object(prof)
        try store.write(key, JSONValue.object(o).jsonData())
        await expectCodeAsync(.storageFailed) { try await PeerStore(store: store, clock: clock.fn).get(me.getACEId()) }
    }

    @Test func registrationFileNeverRemovesOrDowngradesCachedPrincipal() async throws {
        let owner = try SoftwareIdentity.generate(scheme: .ed25519), me = try SoftwareIdentity.generate(scheme: .ed25519)
        let store = MemoryStore(), clock = TestClock(Self.NOW)
        let peers = try PeerStore(store: store, clock: clock.fn)
        let cached = try rec(owner, me, issuedAt: Self.NOW - 10)
        try await peers.adopt(try verifyPeerRecord(try peerRecord(me, AgentProfile(name: "Rel", tags: ["x"], principal: cached)), clock: { Self.NOW }))
        clock.now = Self.NOW + 100
        // file without principal: keeps it, other members carry over
        let bare = try createRegistrationFile(for: me, name: "M", endpoint: "https://m.example/ace")
        var kept = try await peers.pinRegistrationFile(bare, pinnedAt: Self.NOW)
        #expect(kept.principal == cached && kept.profile?.name == "Rel" && kept.profile?.tags == ["x"])
        // older issuedAt: keeps the cached one
        let older = try createRegistrationFile(for: me, name: "M", endpoint: "https://m.example/ace", principal: try rec(owner, me, issuedAt: Self.NOW - 20))
        kept = try await peers.pinRegistrationFile(older, pinnedAt: Self.NOW)
        #expect(kept.principal == cached)
        // newer issuedAt: replaces
        let newer = try rec(owner, me, issuedAt: Self.NOW + 50)
        let reg = try createRegistrationFile(for: me, name: "M", endpoint: "https://m.example/ace", principal: newer)
        clock.now = Self.NOW + 60
        kept = try await peers.pinRegistrationFile(reg, pinnedAt: Self.NOW)
        #expect(kept.principal == newer && kept.profile?.name == "Rel")
        // relay record without principal clears it
        let relay = try peerRecord(me, AgentProfile(name: "Rel2"), ts: Self.NOW + 70)
        clock.now = Self.NOW + 70
        try await peers.adopt(try verifyPeerRecord(relay, clock: clock.fn))
        #expect(try await peers.get(me.getACEId())?.principal == nil)
    }

    @Test func expiredCachedPrincipalIsDroppedByKeptFile() async throws {
        let owner = try SoftwareIdentity.generate(scheme: .ed25519), me = try SoftwareIdentity.generate(scheme: .ed25519)
        let store = MemoryStore(), clock = TestClock(Self.NOW)
        let peers = try PeerStore(store: store, clock: clock.fn)
        try await peers.adopt(try verifyPeerRecord(try peerRecord(me, AgentProfile(name: "Rel", principal: try rec(owner, me, expiresAt: Self.NOW + 5))), clock: { Self.NOW }))
        let bare = try createRegistrationFile(for: me, name: "M", endpoint: "https://m.example/ace")
        clock.now = Self.NOW + 100
        let kept = try await peers.pinRegistrationFile(bare, pinnedAt: Self.NOW)
        #expect(kept.principal == nil && kept.profile?.name == "Rel")
        #expect(try await PeerStore(store: store, clock: clock.fn).get(me.getACEId())?.principal == nil)
        // unexpired cached principal is still carried
        let me2 = try SoftwareIdentity.generate(scheme: .ed25519)
        clock.now = Self.NOW
        try await peers.adopt(try verifyPeerRecord(try peerRecord(me2, AgentProfile(principal: try rec(owner, me2, expiresAt: Self.NOW + 500))), clock: { Self.NOW }))
        clock.now = Self.NOW + 100
        let k2 = try await peers.pinRegistrationFile(try createRegistrationFile(for: me2, name: "M", endpoint: "https://m.example/ace"), pinnedAt: Self.NOW)
        #expect(k2.principal != nil)
        #expect(try await PeerStore(store: store, clock: clock.fn).get(me2.getACEId())?.principal != nil)
    }

    @Test func relayRollbackAndPrincipalMonotonicity() async throws {
        let owner = try SoftwareIdentity.generate(scheme: .ed25519), me = try SoftwareIdentity.generate(scheme: .ed25519)
        let store = MemoryStore(), clock = TestClock(Self.NOW + 100)
        let peers = try PeerStore(store: store, clock: clock.fn)
        let cached = try rec(owner, me, scope: "a", issuedAt: Self.NOW - 10)
        try await peers.adopt(try verifyPeerRecord(try peerRecord(me, AgentProfile(name: "New", principal: cached), ts: Self.NOW + 50), clock: { Self.NOW + 100 }))
        // older relay record: cached profile unchanged
        clock.now = Self.NOW + 120
        let old = try peerRecord(me, AgentProfile(name: "Old", principal: try rec(owner, me, issuedAt: Self.NOW - 5)), ts: Self.NOW + 40)
        try await peers.adopt(try verifyPeerRecord(old, clock: clock.fn))
        let p1 = try #require(try await peers.get(me.getACEId()))
        #expect(p1.profile?.name == "New" && p1.principal == cached)
        let raw = try JSONValue(json: try #require(try store.read(PinnedPeer.key(me.getACEId())))).objectValue!
        #expect(raw["fetchedAt"] == .number(Double(Self.NOW + 120)))
        // equal issuedAt, different principal: cached kept
        let same = try rec(owner, me, scope: "b", issuedAt: Self.NOW - 10)
        try await peers.adopt(try verifyPeerRecord(try peerRecord(me, AgentProfile(name: "Eq", principal: same), ts: Self.NOW + 60), clock: clock.fn))
        let p2 = try #require(try await peers.get(me.getACEId()))
        #expect(p2.profile?.name == "Eq" && p2.principal == cached)
        // strictly newer issuedAt replaces
        let newer = try rec(owner, me, issuedAt: Self.NOW + 1)
        try await peers.adopt(try verifyPeerRecord(try peerRecord(me, AgentProfile(principal: newer), ts: Self.NOW + 70), clock: clock.fn))
        #expect(try await peers.get(me.getACEId())?.principal == newer)
        // newer relay record without principal clears it
        try await peers.adopt(try verifyPeerRecord(try peerRecord(me, AgentProfile(name: "W"), ts: Self.NOW + 80), clock: clock.fn))
        #expect(try await peers.get(me.getACEId())?.principal == nil)
    }

    @Test func discoverQueryAccount() {
        #expect(DiscoverQuery(q: "x", account: Self.ACC).account == Self.ACC)
    }
}

// MARK: - Task 18: step 7 in the pipeline, Inbox principal + decision fill, Outbox request ledger

/// Relay lookups verify principals at the wall clock, so these tests run at it.
private let T0 = systemClock()
private let RELAY_URL = "https://relay.example"
private let ACC = PrincipalTests.ACC

/// Fake `/v1/peer` endpoint: serves `record`, or fails with `status` / a network error.
final class PeerLookupStub: @unchecked Sendable {
    private let lock = NSLock()
    private var _record: PeerRecord?
    private var _status = 200
    private var _calls = 0
    var onLookup: (@Sendable () -> Void)?

    var record: PeerRecord? { get { lock.withLock { _record } } set { lock.withLock { _record = newValue } } }
    /// 200 = serve `record` (404 `unknown_peer` when nil); < 0 = network failure; else that HTTP error.
    var status: Int { get { lock.withLock { _status } } set { lock.withLock { _status = newValue } } }
    var calls: Int { lock.withLock { _calls } }

    func client() throws -> RelayClient {
        try makeRelay({ [self] req, _ in
            guard req.url?.path == "/v1/peer" else { return .error(404, "not_found") }
            lock.withLock { _calls += 1 }
            onLookup?()
            let (st, rec) = lock.withLock { (_status, _record) }
            if st < 0 { return StubResponse(status: -1) }
            if st != 200 { return .error(st, st == 404 ? "unknown_peer" : "relay_unavailable") }
            guard let rec else { return .error(404, "unknown_peer") }
            return .json(200, peerRecordJSON(rec))
        })
    }
}

/// Counts held locks by name and audits `requests/` accesses.
final class AuditStore: ACEStore, @unchecked Sendable {
    let inner: any ACEStore
    private let mutex = NSLock()
    private var held: [String: Int] = [:]
    private(set) var requestAccesses: [(op: String, underLock: Bool)] = []
    private(set) var log: [(op: String, key: String)] = []
    var failWritePrefix: String?

    init(_ inner: any ACEStore) { self.inner = inner }

    func heldCount(_ name: String) -> Int { mutex.withLock { held[name] ?? 0 } }
    var heldExceptReceive: [String] { mutex.withLock { held.filter { $0.key != "receive" && $0.value > 0 }.map(\.key) } }

    private func audit(_ op: String, _ key: String) {
        mutex.withLock {
            log.append((op, key))
            if key.hasPrefix("requests/") { requestAccesses.append((op, (held["requests"] ?? 0) > 0)) }
        }
    }

    func read(_ key: String) throws -> Data? { audit("read", key); return try inner.read(key) }
    func write(_ key: String, _ value: Data) throws {
        let fail: Bool = mutex.withLock {
            if let p = failWritePrefix, key.hasPrefix(p) { failWritePrefix = nil; return true }
            return false
        }
        if fail { throw ACEError(.storageFailed, "injected") }
        audit("write", key)
        try inner.write(key, value)
    }
    func delete(_ key: String) throws { audit("delete", key); try inner.delete(key) }
    func list(prefix: String) throws -> [String] { try inner.list(prefix: prefix) }
    func lock(_ name: String, timeout: TimeInterval) throws -> any ACEStoreLock {
        let l = try inner.lock(name, timeout: timeout)
        mutex.withLock { held[name, default: 0] += 1 }
        return AuditLock(inner: l) { [self] in mutex.withLock { held[name, default: 0] -= 1 } }
    }

    struct AuditLock: ACEStoreLock {
        let inner: any ACEStoreLock
        let onRelease: @Sendable () -> Void
        func release() { onRelease(); inner.release() }
    }
}

@Suite("PrincipalPipeline")
struct PrincipalPipelineTests {
    struct Party {
        let id: SoftwareIdentity
        let store: any ACEStore
        let sink = Sink()
    }

    struct World {
        let clock: TestClock
        let owner: SoftwareIdentity
        let a: Party
        let b: Party
        let pa: PrincipalRecord
        let pb: PrincipalRecord
    }

    static func rec(_ owner: SoftwareIdentity, _ subject: SoftwareIdentity, roles: [String] = ["controller", "agent"],
                    account: String = ACC) throws -> PrincipalRecord {
        try createPrincipalRecord(signer: PrincipalSigner(identity: owner), subjectSigningPublicKey: subject.getSigningPublicKey(),
                                  account: account, roles: roles, expiresAt: T0 + 3600, issuedAt: T0 - 10)
    }

    static func key(_ id: SoftwareIdentity) -> PrincipalKey {
        PrincipalKey(scheme: id.getSigningScheme().rawValue, publicKey: ACEBase64.encode(id.getSigningPublicKey()))
    }

    static func relayRecord(_ id: SoftwareIdentity, _ profile: AgentProfile, ts: Int = T0) throws -> PeerRecord {
        let req = try createRegistrationRequest(identity: id, profile: .replace(profile), timestamp: ts)
        return PeerRecord(aceId: req.aceId, scheme: req.scheme.rawValue, encryptionPublicKey: req.encryptionPublicKey,
                          signingPublicKey: req.signingPublicKey, registrationSignature: req.signature, registeredAt: ts, profile: profile)
    }

    static func pin(_ store: any ACEStore, _ clock: TestClock, _ id: SoftwareIdentity, _ principal: PrincipalRecord?, name: String) async throws {
        let r = try relayRecord(id, AgentProfile(name: name, principal: principal))
        try await PeerStore(store: store, clock: clock.fn).adopt(try verifyPeerRecord(r, clock: { T0 }))
    }

    /// a (ed25519) and b (secp256k1) under one owner; each pins the other via a relay record.
    static func world(rolesA: [String] = ["controller", "agent"], rolesB: [String] = ["agent"], accB: String = ACC,
                      pinBPrincipal: Bool = true, pinAPrincipal: Bool = true, ownerScheme: SigningScheme = .ed25519,
                      account: String? = nil, aStore: (any ACEStore)? = nil) async throws -> World {
        let clock = TestClock(T0)
        let owner = try SoftwareIdentity.generate(scheme: ownerScheme)
        let a = Party(id: try SoftwareIdentity.generate(scheme: .ed25519), store: aStore ?? MemoryStore())
        let b = Party(id: try SoftwareIdentity.generate(scheme: .secp256k1), store: MemoryStore())
        let pa = try rec(owner, a.id, roles: rolesA, account: account ?? ACC)
        let pb = try rec(owner, b.id, roles: rolesB, account: account ?? accB)
        try await pin(a.store, clock, b.id, pinBPrincipal ? pb : nil, name: "b")
        try await pin(b.store, clock, a.id, pinAPrincipal ? pa : nil, name: "a")
        return World(clock: clock, owner: owner, a: a, b: b, pa: pa, pb: pb)
    }

    static func inbox(_ w: World, _ p: Party, store: (any ACEStore)? = nil, relay: RelayClient? = nil,
                      principal: InboxPrincipal?? = .none) async throws -> Inbox {
        let s = store ?? p.store
        let pr: InboxPrincipal? = principal ?? InboxPrincipal(account: ACC, selfSigner: key(w.owner))
        return try await Inbox.open(identity: p.id, store: s, peers: try PeerStore(store: s, relay: relay, clock: w.clock.fn),
                                    onMessage: p.sink.handler, clock: w.clock.fn, principal: pr)
    }

    static func stage(_ w: World, _ from: Party, _ to: Party, _ type: MessageType, _ body: String,
                      store: (any ACEStore)? = nil) async throws -> (Outbox, PendingSend) {
        let outbox = try await Outbox.open(identity: from.id, store: store ?? from.store, clock: w.clock.fn)
        let peer = try #require(try await PeerStore(store: from.store, clock: w.clock.fn).get(to.id.getACEId()))
        let p = try await outbox.stage(recipient: peer, type: type, body: try JSONValue(json: Data(body.utf8)).objectValue!)
        return (outbox, p)
    }

    static func send(_ w: World, _ from: Party, _ to: Party, _ rx: Inbox, _ type: MessageType, _ body: String,
                     _ n: Int) async throws -> (ReceiveOutcome, PendingSend) {
        let (outbox, p) = try await stage(w, from, to, type, body)
        let out = try await outbox.deliver(p.requestId) { env in
            try await rx.receive(env.jsonData(), source: .relay(url: RELAY_URL, streamId: "\(n)-0"))
        }
        return (out, p)
    }

    static func receive(_ rx: Inbox, _ env: ACEMessage, _ n: Int) async throws -> ReceiveOutcome {
        try await rx.receive(env.jsonData(), source: .relay(url: RELAY_URL, streamId: "\(n)-0"))
    }

    static func cursor(_ rx: Inbox) async throws -> String? {
        await rx.cursor(for: try RelayClient(baseURL: URL(string: RELAY_URL)!))
    }

    static func request(_ store: any ACEStore, _ p: PendingSend) throws -> RequestRecord? {
        try loadRequestRecord(store, conversationId: p.message.conversationId, messageId: p.message.messageId)
    }

    // MARK: parse

    @Test func parseMessageWithoutContextIsWrongPrincipal() async throws {
        let w = try await Self.world()
        let peerA = try #require(try await PeerStore(store: w.b.store).get(w.a.id.getACEId()))
        let env = try createMessage(sender: w.b.id, recipient: peerA, type: .request, body: jsonBody(["action": "pay", "summary": "s"]),
                                    threads: try ThreadStateMachine(localAceId: w.b.id.getACEId()), timestamp: T0)
        #expect(env.threadId == nil)
        let peerB = try #require(try await PeerStore(store: w.a.store).get(w.b.id.getACEId()))
        func parse(_ ctx: PrincipalContext?) throws -> ParsedMessage {
            try parseMessage(env, receiver: w.a.id, sender: peerB, threads: try ThreadStateMachine(localAceId: w.a.id.getACEId()),
                             replay: try ReplayDetector(capacity: 100, horizon: T0 - 100, clock: w.clock.fn), clock: w.clock.fn,
                             principal: ctx)
        }
        expectCode(.wrongPrincipal) { try parse(nil) }
        expectCode(.wrongPrincipal) { try parse(PrincipalContext(account: ACC)) }  // fail closed: no authority
        #expect(try parse(PrincipalContext(account: ACC, selfSigner: Self.key(w.owner))).type == .request)
        // direct callers may plug a one-shot refresh (R-P20)
        let bare = try verifyPeerRecord(try Self.relayRecord(w.b.id, AgentProfile(name: "b")), clock: { T0 })
        let calls = Counter()
        let refreshed = try parseMessage(
            env, receiver: w.a.id, sender: bare, threads: try ThreadStateMachine(localAceId: w.a.id.getACEId()),
            replay: try ReplayDetector(capacity: 100, horizon: T0 - 100, clock: w.clock.fn), clock: w.clock.fn,
            principal: PrincipalContext(account: ACC, selfSigner: Self.key(w.owner), refreshSender: { _ in calls.bump(); return peerB }))
        #expect(refreshed.type == .request && calls.value == 1)
    }

    // MARK: round trip, ledger, R-P25

    @Test func requestDecisionRoundTripAndSecondDecision() async throws {
        let w = try await Self.world()
        let ia = try await Self.inbox(w, w.a), ib = try await Self.inbox(w, w.b)
        let (out, req) = try await Self.send(w, w.b, w.a, ia, .request, #"{"action":"pay","summary":"Pay 1 USDC","ttl":600}"#, 1)
        guard case .delivered(let m) = out else { Issue.record("\(out)"); return }
        #expect(m.threadId == nil && w.a.sink.count == 1)
        let r = try #require(try Self.request(w.b.store, req))
        #expect(r.decision == nil && r.to == w.a.id.getACEId() && r.expiresAt == req.message.timestamp + 600 && r.sentAt == T0)
        #expect(try await Outbox.open(identity: w.b.id, store: w.b.store, clock: w.clock.fn).pending().isEmpty)
        let (d1, p1) = try await Self.send(w, w.a, w.b, ib, .decision,
                                           #"{"requestId":"\#(req.message.messageId)","outcome":"approve","result":{"tx":"0x1"}}"#, 1)
        guard case .delivered = d1 else { Issue.record("\(d1)"); return }
        #expect(w.b.sink.has(p1.message))
        let filled = try #require(try Self.request(w.b.store, req)?.decision)
        #expect(filled == RequestDecision(messageId: p1.message.messageId, outcome: "approve", timestamp: p1.message.timestamp))
        // a second, different decision: bad_reference, record unchanged
        let (d2, _) = try await Self.send(w, w.a, w.b, ib, .decision, #"{"requestId":"\#(req.message.messageId)","outcome":"deny"}"#, 2)
        guard case .quarantined(let e, _) = d2 else { Issue.record("\(d2)"); return }
        #expect(e.code == .badReference)
        #expect(try Self.request(w.b.store, req)?.decision == filled)
        // the accepted decision again: duplicate, no change
        #expect(isDuplicate(try await Self.receive(ib, p1.message, 3)))
        #expect(try Self.request(w.b.store, req)?.decision == filled)
    }

    @Test func decisionForExpiredOrUnknownRequestIsBadReference() async throws {
        let w = try await Self.world()
        let ia = try await Self.inbox(w, w.a), ib = try await Self.inbox(w, w.b)
        let (_, req) = try await Self.send(w, w.b, w.a, ia, .request, #"{"action":"pay","summary":"s","ttl":10}"#, 1)
        w.clock.now = T0 + 11
        let (d, _) = try await Self.send(w, w.a, w.b, ib, .decision, #"{"requestId":"\#(req.message.messageId)","outcome":"approve"}"#, 1)
        #expect(code(d) == .badReference)
        let (u, _) = try await Self.send(w, w.a, w.b, ib, .decision, #"{"requestId":"00000000-0000-4000-8000-0000000000bb","outcome":"approve"}"#, 2)
        #expect(code(u) == .badReference)
    }

    @Test func concurrentDifferentDecisionsAcceptExactlyOne() async throws {
        let w = try await Self.world()
        let ia = try await Self.inbox(w, w.a), ib = try await Self.inbox(w, w.b)
        let (_, req) = try await Self.send(w, w.b, w.a, ia, .request, #"{"action":"pay","summary":"s"}"#, 1)
        let (_, p1) = try await Self.stage(w, w.a, w.b, .decision, #"{"requestId":"\#(req.message.messageId)","outcome":"approve"}"#)
        let (_, p2) = try await Self.stage(w, w.a, w.b, .decision, #"{"requestId":"\#(req.message.messageId)","outcome":"deny"}"#)
        async let r1 = Self.receive(ib, p1.message, 1)
        async let r2 = Self.receive(ib, p2.message, 2)
        let results = try await [r1, r2]
        #expect(results.filter(isDelivered).count == 1 && results.filter { code($0) == .badReference }.count == 1)
        let winner = isDelivered(results[0]) ? p1 : p2
        #expect(try Self.request(w.b.store, req)?.decision?.messageId == winner.message.messageId)
    }

    // MARK: wrong principal, Inbox option

    @Test func wrongPrincipalCases() async throws {
        let w = try await Self.world(rolesA: ["agent"])
        let ia = try await Self.inbox(w, w.a), ib = try await Self.inbox(w, w.b)
        let (_, req) = try await Self.send(w, w.b, w.a, ia, .request, #"{"action":"pay","summary":"s"}"#, 1)
        let (d, _) = try await Self.send(w, w.a, w.b, ib, .decision, #"{"requestId":"\#(req.message.messageId)","outcome":"approve"}"#, 1)
        #expect(code(d) == .wrongPrincipal)
        // another account
        let x = try await Self.world(accB: "eip155:1:0x" + String(repeating: "ab", count: 20))
        let ix = try await Self.inbox(x, x.a)
        let (r, _) = try await Self.send(x, x.b, x.a, ix, .report, #"{"action":"pay","summary":"s","outcome":"ok"}"#, 1)
        #expect(code(r) == .wrongPrincipal)
        // an Inbox without principal
        let y = try await Self.world()
        let none = try await Self.inbox(y, y.a, principal: .some(nil))
        let (r2, _) = try await Self.send(y, y.b, y.a, none, .report, #"{"action":"pay","summary":"s","outcome":"ok"}"#, 1)
        #expect(code(r2) == .wrongPrincipal)
        await none.close()
    }

    @Test func openValidatesPrincipal() async throws {
        let y = try await Self.world()
        let good = Self.key(y.owner)
        for bad in [
            InboxPrincipal(account: "nope"),
            InboxPrincipal(account: ACC, selfSigner: PrincipalKey(scheme: "rsa", publicKey: good.publicKey)),
            InboxPrincipal(account: ACC, selfSigner: PrincipalKey(scheme: "ed25519", publicKey: "")),
            InboxPrincipal(account: ACC, selfSigner: PrincipalKey(scheme: "ed25519", publicKey: "AAAA")),
            InboxPrincipal(account: ACC, selfSigner: PrincipalKey(scheme: "secp256k1", publicKey: good.publicKey)),
            InboxPrincipal(account: ACC, trustedSigners: [good, PrincipalKey(scheme: "ed25519", publicKey: "!!")]),
        ] {
            await expectCodeAsync(.invalidArgument) { try await Self.inbox(y, y.a, principal: .some(bad)) }
        }
        // a failed open releases the receive lock
        await (try await Self.inbox(y, y.a, principal: .some(InboxPrincipal(account: ACC, selfSigner: nil, trustedSigners: [good])))).close()
    }

    @Test func withoutSelfSignerFailsClosed() async throws {
        let w = try await Self.world()
        let ia = try await Self.inbox(w, w.a, principal: .some(InboxPrincipal(account: ACC)))  // solana account, no authority
        let (r, _) = try await Self.send(w, w.b, w.a, ia, .report, #"{"action":"pay","summary":"s","outcome":"ok"}"#, 1)
        #expect(code(r) == .wrongPrincipal)
        await ia.close()
        let it = try await Self.inbox(w, w.a, principal: .some(InboxPrincipal(account: ACC, trustedSigners: [Self.key(w.owner)])))
        let (r2, _) = try await Self.send(w, w.b, w.a, it, .report, #"{"action":"pay","summary":"s2","outcome":"ok"}"#, 2)
        #expect(isDelivered(r2))
    }

    @Test func eip155AccountPassesWithoutSelfSigner() async throws {
        let owner = try SoftwareIdentity.generate(scheme: .secp256k1)
        let acc = "eip155:1:" + (try secp256k1Address(owner.getSigningPublicKey()))
        let clock = TestClock(T0)
        let a = Party(id: try SoftwareIdentity.generate(scheme: .ed25519), store: MemoryStore())
        let b = Party(id: try SoftwareIdentity.generate(scheme: .ed25519), store: MemoryStore())
        try await Self.pin(a.store, clock, b.id, try Self.rec(owner, b.id, account: acc), name: "b")
        try await Self.pin(b.store, clock, a.id, try Self.rec(owner, a.id, account: acc), name: "a")
        let w = World(clock: clock, owner: owner, a: a, b: b, pa: try Self.rec(owner, a.id, account: acc), pb: try Self.rec(owner, b.id, account: acc))
        let ia = try await Self.inbox(w, a, principal: .some(InboxPrincipal(account: acc)))
        let (r, _) = try await Self.send(w, b, a, ia, .report, #"{"action":"pay","summary":"s","outcome":"ok"}"#, 1)
        #expect(isDelivered(r))
    }

    // MARK: R-P20 / R-P29 / R-P30 refresh

    @Test func refreshesPeerOnceThenAccepts() async throws {
        let w = try await Self.world(pinBPrincipal: false)
        let stub = PeerLookupStub()
        stub.record = try Self.relayRecord(w.b.id, AgentProfile(name: "b2", principal: w.pb))
        let ia = try await Self.inbox(w, w.a, relay: try stub.client())
        let (r, _) = try await Self.send(w, w.b, w.a, ia, .request, #"{"action":"pay","summary":"s"}"#, 1)
        #expect(isDelivered(r) && stub.calls == 1)
        let pinned = try #require(try await PeerStore(store: w.a.store, clock: w.clock.fn).get(w.b.id.getACEId()))
        #expect(pinned.principal == w.pb && pinned.profile?.name == "b2")
        let (r2, _) = try await Self.send(w, w.b, w.a, ia, .report, #"{"action":"pay","summary":"s","outcome":"ok"}"#, 2)
        #expect(isDelivered(r2) && stub.calls == 1)  // pin now valid: no refresh
    }

    @Test func transientRefreshFailureIsRetryableThenAccepted() async throws {
        let w = try await Self.world(pinBPrincipal: false)
        let stub = PeerLookupStub()
        stub.status = 503
        let ia = try await Self.inbox(w, w.a, relay: try stub.client())
        let (_, p) = try await Self.stage(w, w.b, w.a, .request, #"{"action":"pay","summary":"s"}"#)
        let r = try await Self.receive(ia, p.message, 1)
        guard case .retryable(let e) = r else { Issue.record("\(r)"); return }
        #expect(e.code == .relayUnavailable && stub.calls == 1)
        #expect(try await Self.cursor(ia) == nil && w.a.sink.count == 0)
        stub.status = -1  // network failure
        let r2 = try await Self.receive(ia, p.message, 1)
        guard case .retryable = r2 else { Issue.record("\(r2)"); return }
        #expect(try await Self.cursor(ia) == nil)
        stub.status = 200
        stub.record = try Self.relayRecord(w.b.id, AgentProfile(principal: w.pb))
        let r3 = try await Self.receive(ia, p.message, 1)
        #expect(isDelivered(r3) && stub.calls == 3)
        #expect(try await Self.cursor(ia) == "1-0")
    }

    @Test func wrongPrincipalAfterPermanentOrUselessRefresh() async throws {
        let w = try await Self.world(pinBPrincipal: false)
        let stub = PeerLookupStub()
        stub.status = 404
        let ia = try await Self.inbox(w, w.a, relay: try stub.client())
        let (r, _) = try await Self.send(w, w.b, w.a, ia, .request, #"{"action":"pay","summary":"s"}"#, 1)
        #expect(code(r) == .wrongPrincipal && stub.calls == 1)
        #expect(try await Self.cursor(ia) == "1-0")
        stub.status = 200
        stub.record = try Self.relayRecord(w.b.id, AgentProfile(name: "b"))  // useless: still no principal
        let (r2, _) = try await Self.send(w, w.b, w.a, ia, .request, #"{"action":"pay","summary":"s2"}"#, 2)
        #expect(code(r2) == .wrongPrincipal && stub.calls == 2)
        // another account: refreshed once, still another account
        let x = try await Self.world(accB: "solana:x:other")
        let stub2 = PeerLookupStub()
        stub2.record = try Self.relayRecord(x.b.id, AgentProfile(principal: x.pb))
        let ix = try await Self.inbox(x, x.a, relay: try stub2.client())
        let (r3, _) = try await Self.send(x, x.b, x.a, ix, .report, #"{"action":"pay","summary":"s","outcome":"ok"}"#, 1)
        #expect(code(r3) == .wrongPrincipal && stub2.calls == 1)
    }

    @Test func forgedPrincipalEnvelopeTriggersNoRefresh() async throws {
        let w = try await Self.world(pinBPrincipal: false)
        let stub = PeerLookupStub()
        stub.record = try Self.relayRecord(w.b.id, AgentProfile(principal: w.pb))
        let ia = try await Self.inbox(w, w.a, relay: try stub.client())
        let (_, p) = try await Self.stage(w, w.b, w.a, .request, #"{"action":"pay","summary":"s"}"#)
        var o = try JSONValue(json: p.message.jsonData()).objectValue!
        var sigObj = o["signature"]!.objectValue!
        var sig = try ACEBase64.decode(sigObj["value"]!.stringValue!)
        sig[5] ^= 0x01
        sigObj["value"] = .string(ACEBase64.encode(sig))
        o["signature"] = .object(sigObj)
        let r = try await ia.receive(JSONValue.object(o).jsonData(), source: .relay(url: RELAY_URL, streamId: "1-0"))
        #expect(code(r) == .invalidSignature && stub.calls == 0)
        let r2 = try await Self.receive(ia, p.message, 2)
        #expect(isDelivered(r2) && stub.calls == 1)
    }

    @Test func decisionRefreshRunsWithNoStoreLockHeldAndLedgerUnderRequestsLock() async throws {
        // b's pin of a lacks the principal: b's Inbox refreshes a before accepting a's decision.
        let w = try await Self.world(pinAPrincipal: false)
        let ia = try await Self.inbox(w, w.a)
        let (_, req) = try await Self.send(w, w.b, w.a, ia, .request, #"{"action":"pay","summary":"s"}"#, 1)
        let audit = AuditStore(w.b.store)
        let stub = PeerLookupStub()
        stub.record = try Self.relayRecord(w.a.id, AgentProfile(principal: w.pa))
        let heldAtLookup = LockedBox<[[String]]>([])
        stub.onLookup = { heldAtLookup.mutate { $0.append(audit.heldExceptReceive) } }
        let ib = try await Self.inbox(w, w.b, store: audit, relay: try stub.client())
        let (d, _) = try await Self.send(w, w.a, w.b, ib, .decision, #"{"requestId":"\#(req.message.messageId)","outcome":"approve"}"#, 1)
        #expect(isDelivered(d))
        #expect(heldAtLookup.value == [[]])
        let ops = audit.requestAccesses.map(\.op)
        #expect(ops.contains("read") && ops.contains("write") && audit.requestAccesses.allSatisfy(\.underLock))
        #expect(try Self.request(w.b.store, req)?.decision != nil)
    }

    @Test func forgedSecp256k1SignatureIsRejectedNotTrapped() throws {
        // P256K's recovery traps on an `r` that is no curve x-coordinate; verify must return false.
        let id = try SoftwareIdentity.generate(scheme: .secp256k1)
        let data = Data(repeating: 7, count: 32)
        let sig = try id.sign(data)
        #expect(ACESigning.verify(signData: data, signature: sig, scheme: .secp256k1, publicKey: id.getSigningPublicKey()))
        for i in 0..<32 {
            var bad = sig
            bad[i] ^= 0x01
            #expect(!ACESigning.verify(signData: data, signature: bad, scheme: .secp256k1, publicKey: id.getSigningPublicKey()))
        }
        var wrongV = sig
        wrongV[64] ^= 0x01
        #expect(!ACESigning.verify(signData: data, signature: wrongV, scheme: .secp256k1, publicKey: id.getSigningPublicKey()))
        // deterministic: r = 5 is in range but 5^3 + 7 is a non-residue mod p (no curve point)
        for v: UInt8 in [0, 1] {
            var offCurve = Data(repeating: 0, count: 65)
            offCurve[31] = 5
            offCurve[63] = 1
            offCurve[64] = v
            #expect(!ACESigning.verify(signData: data, signature: offCurve, scheme: .secp256k1, publicKey: id.getSigningPublicKey()))
        }
    }

    @Test func failureDuringSuspendedRefreshCommitsNothingAndLeaksNoLock() async throws {
        let w = try await Self.world()
        let ia = try await Self.inbox(w, w.a)
        let (_, req) = try await Self.send(w, w.b, w.a, ia, .request, #"{"action":"pay","summary":"s"}"#, 1)
        // c: same owner and account; b's pin of c lacks the principal, so c's report refreshes c.
        let c = Party(id: try SoftwareIdentity.generate(scheme: .ed25519), store: MemoryStore())
        let pc = try Self.rec(w.owner, c.id)
        try await Self.pin(c.store, w.clock, w.b.id, w.pb, name: "b")
        let failing = FailingStore()
        for k in try w.b.store.list(prefix: "") { try failing.inner.write(k, try #require(try w.b.store.read(k))) }
        try await Self.pin(failing, w.clock, c.id, nil, name: "c")
        let stub = PeerLookupStub()
        stub.record = try Self.relayRecord(c.id, AgentProfile(principal: pc))
        let started = LockedBox(false), gate = DispatchSemaphore(value: 0)
        stub.onLookup = { started.mutate { $0 = true }; gate.wait() }
        let ib = try await Self.inbox(w, w.b, store: failing, relay: try stub.client())
        let (_, report) = try await Self.stage(w, c, w.b, .report, #"{"action":"pay","summary":"s","outcome":"ok"}"#)
        let (_, dec) = try await Self.stage(w, w.a, w.b, .decision, #"{"requestId":"\#(req.message.messageId)","outcome":"approve"}"#)
        let pending = Task { try await Self.receive(ib, report.message, 2) }
        while !started.value { try await Task.sleep(nanoseconds: 1_000_000) }  // report suspended in its refresh
        failing.arm(failWrite: 2)  // the decision: 1 = delivery record, 2 = requests/ fill → failed, `requests` kept
        let d = try await Self.receive(ib, dec.message, 1)
        guard case .retryable = d else { Issue.record("\(d)"); gate.signal(); return }
        gate.signal()
        let p = try await pending.value
        guard case .retryable = p else { Issue.record("report committed after failure: \(p)"); return }
        failing.arm(failWrite: nil)
        #expect(try failing.read(DeliveryRecord.key(from: c.id.getACEId(), messageId: report.message.messageId)) == nil)
        #expect(w.b.sink.count == 0 && stub.calls == 1)
        await ib.close()
        for name in ["threads", "requests", "receive"] { try failing.lock(name, timeout: 0).release() }
        // a fresh Inbox recovers the decision fill
        await (try await Self.inbox(w, w.b, store: failing)).close()
        #expect(try Self.request(failing, req)?.decision?.messageId == dec.message.messageId)
    }

    @Test func replayedOrStaleEnvelopeMakesNoRefreshCall() async throws {
        let w = try await Self.world(pinBPrincipal: false)
        let stub = PeerLookupStub()
        stub.record = try Self.relayRecord(w.b.id, AgentProfile(name: "b"))  // useless refresh
        let ia = try await Self.inbox(w, w.a, relay: try stub.client())
        let (_, p) = try await Self.stage(w, w.b, w.a, .request, #"{"action":"pay","summary":"s"}"#)
        #expect(code(try await Self.receive(ia, p.message, 1)) == .wrongPrincipal && stub.calls == 1)
        // the same real envelope again: replay pre-check, no relay call
        #expect(isDuplicate(try await Self.receive(ia, p.message, 2)) && stub.calls == 1)
        // a real envelope outside the timestamp window: no relay call
        w.clock.now = T0 + 1000
        let (_, f) = try await Self.stage(w, w.b, w.a, .request, #"{"action":"pay","summary":"s2"}"#)
        w.clock.now = T0
        #expect(code(try await Self.receive(ia, f.message, 3)) == .staleTimestamp && stub.calls == 1)
    }

    // MARK: durability

    @Test func decisionFillRecoveredAfterCrash() async throws {
        let w = try await Self.world()
        let ia = try await Self.inbox(w, w.a)
        let (_, req) = try await Self.send(w, w.b, w.a, ia, .request, #"{"action":"pay","summary":"s"}"#, 1)
        let failing = FailingStore()
        for k in try w.b.store.list(prefix: "") { try failing.inner.write(k, try #require(try w.b.store.read(k))) }
        let ib = try await Self.inbox(w, w.b, store: failing)
        let (_, p) = try await Self.stage(w, w.a, w.b, .decision, #"{"requestId":"\#(req.message.messageId)","outcome":"approve"}"#)
        failing.arm(failWrite: 2)  // 1 = delivery record, 2 = requests/ fill
        let out = try await Self.receive(ib, p.message, 1)
        guard case .retryable = out else { Issue.record("\(out)"); return }
        await ib.close()
        failing.arm(failWrite: nil)
        #expect(try failing.list(prefix: "deliveries/").count == 1)
        #expect(try Self.request(failing, req)?.decision == nil && w.b.sink.count == 0)
        let ib2 = try await Self.inbox(w, w.b, store: failing)  // recovery fills, then hands over
        let dec = try #require(try Self.request(failing, req)?.decision)
        #expect(dec.messageId == p.message.messageId && dec.outcome == "approve" && w.b.sink.has(p.message))
        #expect(isDuplicate(try await Self.receive(ib2, p.message, 1)))
        await ib2.close()
        await (try await Self.inbox(w, w.b, store: failing)).close()  // recovery again: same decision is a no-op
        #expect(try Self.request(failing, req)?.decision == dec)
    }

    @Test func requestRecordWrittenBeforeAck() async throws {
        let w = try await Self.world()
        let ia = try await Self.inbox(w, w.a)
        let store = AuditStore(w.b.store)
        store.failWritePrefix = "requests/"
        let (outbox, p) = try await Self.stage(w, w.b, w.a, .request, #"{"action":"pay","summary":"s","ttl":30}"#, store: store)
        let transport: @Sendable (ACEMessage) async throws -> ReceiveOutcome = { env in try await Self.receive(ia, env, 1) }
        // transport succeeds, the requests/ write fails: the send stays pending, no record
        await expectCodeAsync(.storageFailed) { try await outbox.deliver(p.requestId, transport: transport) }
        #expect(try Self.request(w.b.store, p) == nil)
        #expect(try await outbox.pending().map(\.requestId) == [p.requestId])
        // restart keeps the ttl; the retry writes the record, then clears the send
        let outbox2 = try await Outbox.open(identity: w.b.id, store: store, clock: w.clock.fn)
        #expect(try await outbox2.pending().first?.requestTtl == 30)
        let res = try await outbox2.deliver(p.requestId, transport: transport)
        #expect(isDuplicate(res))
        let r = try #require(try Self.request(w.b.store, p))
        #expect(r.to == w.a.id.getACEId() && r.expiresAt == p.message.timestamp + 30 && r.sentAt == T0)
        let log = store.log
        let iReq = try #require(log.firstIndex { $0.op == "write" && $0.key == requestKey(p.message.conversationId, p.message.messageId) })
        let iDel = try #require(log.firstIndex { $0.op == "delete" && $0.key.hasPrefix("outbox/") })
        #expect(iReq < iDel)
        #expect(try await outbox2.pending().isEmpty)
    }

    @Test func requestTtlSurvivesResign() async throws {
        let w = try await Self.world()
        let (outbox, p) = try await Self.stage(w, w.b, w.a, .request, #"{"action":"pay","summary":"s","ttl":30}"#)
        await expectCodeAsync(.envelopeExpired) {
            try await outbox.deliver(p.requestId) { _ -> Int in throw ACEError(.envelopeExpired, "x") }
        }
        #expect(try await outbox.pending().first?.requestTtl == 30)
        w.clock.now = T0 + 50
        let q = try await outbox.resign(p.requestId)
        #expect(q.requestTtl == 30 && q.jvalue(version: true).objectValue?["requestTtl"] == .number("30"))
        try await outbox.deliver(p.requestId) { _ in 0 }
        #expect(try Self.request(w.b.store, p)?.expiresAt == T0 + 50 + 30)
    }

    @Test func pendingRequestTtlNormalizedAndTyped() async throws {
        let w = try await Self.world()
        let (outbox, p) = try await Self.stage(w, w.b, w.a, .request, #"{"action":"pay","summary":"s","ttl":30.0}"#)
        #expect(p.requestTtl == 30)
        var o = p.jvalue(version: true).objectValue!
        #expect(o["requestTtl"] == .number("30"))
        o["requestTtl"] = .number("30.0")
        #expect(try PendingSend.parse(.object(o), key: "k", versioned: true).requestTtl == 30)
        o["requestTtl"] = .null
        #expect(try PendingSend.parse(.object(o), key: "k", versioned: true).requestTtl == nil)
        for bad: JValue in [.number("-1"), .string("30"), .bool(true), .number("1.5")] {
            o["requestTtl"] = bad
            expectCode(.storageFailed) { try PendingSend.parse(.object(o), key: "k", versioned: true) }
        }
        let (_, t) = try await Self.stage(w, w.b, w.a, .report, #"{"action":"pay","summary":"s","outcome":"ok","ttl":5}"#)
        var to = t.jvalue(version: true).objectValue!
        #expect(t.requestTtl == nil && to["requestTtl"] == nil)
        to["requestTtl"] = .number("30")
        expectCode(.storageFailed) { try PendingSend.parse(.object(to), key: "k", versioned: true) }
        _ = outbox
    }
}

/// A lock-protected value for `@Sendable` callbacks.
final class LockedBox<T>: @unchecked Sendable {
    private let lock = NSLock()
    private var v: T
    init(_ v: T) { self.v = v }
    var value: T { lock.withLock { v } }
    func mutate(_ f: (inout T) -> Void) { lock.withLock { f(&v) } }
}

final class Counter: @unchecked Sendable {
    private let lock = NSLock()
    private var n = 0
    var value: Int { lock.withLock { n } }
    func bump() { lock.withLock { n += 1 } }
}
