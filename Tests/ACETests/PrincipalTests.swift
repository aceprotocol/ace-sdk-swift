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
}

final class Counter: @unchecked Sendable {
    private let lock = NSLock()
    private var n = 0
    var value: Int { lock.withLock { n } }
    func bump() { lock.withLock { n += 1 } }
}
