import CryptoKit
import Foundation
import Testing
@testable import ACE

private let text = try! InstalledProfiles([.text])

private let offered = somePrekey()

private func textContent(_ m: String = "hi") throws -> PrivateContent {
    try text.content(type: "ace:text:1", body: ["message": .string(m)]).with(prekey: offered)
}

/// The packet JSON with `key` replaced inside the (decoded) object at `path`.
private func mutate(_ p: Packet, _ body: (inout [String: JSONValue]) -> Void) -> Data {
    var o = try! JSONValue(json: p.jsonData()).objectValue!
    body(&o)
    return try! JSONValue.object(o).jsonData()
}

@Suite struct PacketTests {
    @Test func roundTripAndWireShape() throws {
        let a = try TestAgent(), b = try TestAgent()
        let p = try createPacket(sender: a.identity, to: b.aceId, prekey: b.agent.descriptor.prekey, content: textContent(), timestamp: NOW)
        let wire = try JSONValue(json: p.jsonData()).objectValue!
        #expect(Set(wire.keys) == ["ace", "messageId", "from", "to", "timestamp", "encryption", "signature"] && wire["ace"] == "1")
        #expect(Set(wire["encryption"]!.objectValue!.keys) == ["prekey", "kemCiphertext", "payload"])
        #expect(p.encryption.prekey == b.agent.descriptor.prekey.id && p.signature.seq == 1)
        let decoded = try Packet(json: p.jsonData())
        #expect(decoded == p)
        let c = try openPacket(decoded, sender: a.state, recipient: b.aceId, vault: b.vault)
        #expect(c == (try textContent()))
        expectCode(.wrongRecipient) { try openPacket(decoded, sender: a.state, recipient: a.aceId, vault: b.vault) }
        // the signature commits to exactly the 03 payload and the 03 header binds from/to/messageId/timestamp/prekey
        let payload = Packet.signPayload(to: p.to, messageId: p.messageId, prekey: p.encryption.prekey, kemCiphertext: p.kemCiphertext, payload: p.payload)
        #expect(payload == ACESigning.encodePayload([.string(p.to), .string(p.messageId), .string(p.encryption.prekey), .data(p.kemCiphertext), .data(p.payload)]))
        #expect(p.header == ACESigning.encodePayload([.string("ace.v1.packet"), .string(p.from), .string(p.to), .string(p.messageId),
                                                      .string(String(NOW)), .string(p.encryption.prekey), .data(p.kemCiphertext)]))
    }

    @Test func deterministicSealMatchesTheContract() throws {
        let a = try TestAgent(), b = try TestAgent()
        let ss = SymmetricKey(data: Data(repeating: 0x42, count: 32)), kem = Data(repeating: 0x11, count: 1120)
        let nonce = try AES.GCM.Nonce(data: Data(repeating: 0x07, count: 12))
        let plaintext = try textContent().jsonData()
        let id = "550e8400-e29b-41d4-a716-446655440000"
        let p = try sealPacket(sender: a.identity, from: a.aceId, to: b.aceId, messageId: id, timestamp: NOW, prekey: b.agent.descriptor.prekey.id,
                               plaintext: plaintext, sharedSecret: ss, kemCiphertext: kem, nonce: nonce)
        let key = HKDF<SHA256>.deriveKey(inputKeyMaterial: ss, salt: Data(), info: p.header, outputByteCount: 32)
        let box = try AES.GCM.seal(plaintext, using: key, nonce: nonce, authenticating: p.header)
        #expect(p.payload == Data(nonce) + box.ciphertext + box.tag)
        try verifyPacketSignature(p, sender: a.state, now: NOW)
    }

    @Test func strictDecoding() throws {
        let a = try TestAgent(), b = try TestAgent()
        let p = try createPacket(sender: a.identity, to: b.aceId, prekey: b.agent.descriptor.prekey, content: textContent(), timestamp: NOW)
        expectCode(.unsupportedVersion) { try Packet(json: mutate(p) { $0["ace"] = "3"; $0["extra"] = 1 }) }
        expectCode(.invalidPacket) { try Packet(json: mutate(p) { $0["conversationId"] = "x" }) }
        expectCode(.invalidPacket) { try Packet(json: mutate(p) { $0["to"] = $0["from"] }) }
        expectCode(.invalidPacket) { try Packet(json: mutate(p) { o in var e = o["encryption"]!.objectValue!; e["extra"] = 1; o["encryption"] = .object(e) }) }
        expectCode(.invalidPacket) { try Packet(json: mutate(p) { o in var s = o["signature"]!.objectValue!; s["scheme"] = "ml-dsa-87"; o["signature"] = .object(s) }) }
        expectCode(.invalidPacket) { try Packet(json: Data("[]".utf8)) }
        expectCode(.invalidArgument) {
            try createPacket(sender: a.identity, to: a.aceId, prekey: b.agent.descriptor.prekey, content: textContent())
        }
    }

    /// Stripping the signature and re-signing under another identity changes `from`, so the AEAD fails; re-signing with
    /// the original `from` fails the signature.
    @Test func reSignedPacketFails() throws {
        let a = try TestAgent(), b = try TestAgent(), mallory = try TestAgent()
        let p = try createPacket(sender: a.identity, to: b.aceId, prekey: b.agent.descriptor.prekey, content: textContent(), timestamp: NOW)
        let sig = try operationalSign(mallory.identity, action: "packet", timestamp: p.timestamp,
                                      payload: Packet.signPayload(to: p.to, messageId: p.messageId, prekey: p.encryption.prekey,
                                                                  kemCiphertext: p.kemCiphertext, payload: p.payload))
        let forged = Packet(messageId: p.messageId, from: mallory.aceId, to: p.to, timestamp: p.timestamp, prekey: p.encryption.prekey,
                            kemCiphertext: p.kemCiphertext, payload: p.payload, signature: sig)
        try verifyPacketSignature(forged, sender: mallory.state, now: NOW)  // mallory's signature is genuine…
        expectCode(.decryptionFailed) { try openPacket(forged, sender: mallory.state, recipient: b.aceId, vault: b.vault) }  // …but the AEAD is bound to a
        let wrongSigner = Packet(messageId: p.messageId, from: a.aceId, to: p.to, timestamp: p.timestamp, prekey: p.encryption.prekey,
                                 kemCiphertext: p.kemCiphertext, payload: p.payload, signature: sig)
        expectCode(.invalidSignature) { try verifyPacketSignature(wrongSigner, sender: a.state, now: NOW) }
        // another timestamp breaks both the signature and the header
        let moved = Packet(messageId: p.messageId, from: p.from, to: p.to, timestamp: p.timestamp + 1, prekey: p.encryption.prekey,
                           kemCiphertext: p.kemCiphertext, payload: p.payload, signature: p.signature)
        expectCode(.invalidSignature) { try verifyPacketSignature(moved, sender: a.state, now: NOW) }
        expectCode(.decryptionFailed) { try decryptPacket(moved, seed: try #require(try b.vault.open(p.encryption.prekey, now: NOW))) }
    }

    @Test func privateContentIsClosed() throws {
        let d = String(repeating: "a", count: 64)
        expectCode(.invalidBody) { try PrivateContent(json: Data(#"{"type":"ace:text:1","schemaDigest":"\#(d)","body":{},"x":1}"#.utf8)) }
        expectCode(.invalidBody) { try PrivateContent(json: Data(#"{"type":"ace:text:1","schemaDigest":"\#(d)","body":{},"threadId":null}"#.utf8)) }
        expectCode(.invalidBody) { try PrivateContent(type: "nope", schemaDigest: d, body: [:]) }
        #expect(conversationKey("ace:a", "ace:b") == conversationKey("ace:b", "ace:a"))
        #expect(conversationKey("ace:a", "ace:b") == sha256Hex(Data("ace:a\u{0}ace:b".utf8)))
    }
}

/// 03 § Encryption: the payload bounds; 03 § Private content: `prekey` is required.
@Suite struct PayloadTests {
    @Test func payloadBounds() throws {
        let a = try TestAgent(), b = try TestAgent()
        let p = try createPacket(sender: a.identity, to: b.aceId, prekey: b.agent.descriptor.prekey, content: textContent(), timestamp: NOW)
        #expect(p.payload.count == (try textContent().jsonData().count) + 28)
        func withPayload(_ n: Int) -> Data {
            mutate(p) { o in var e = o["encryption"]!.objectValue!; e["payload"] = .string(ACEBase64.encode(Data(count: n))); o["encryption"] = .object(e) }
        }
        expectCode(.invalidPacket) { try Packet(json: withPayload(27)) }
        #expect(try Packet(json: withPayload(28)).payload.count == 28)
    }

    /// Content of exactly `MAX_PLAINTEXT_BYTES` fits a packet of at most `MAX_PACKET_BYTES`.
    @Test func largestContentFitsAPacket() throws {
        let a = try TestAgent(), b = try TestAgent(), d = String(repeating: "a", count: 64)
        let key = somePrekey()
        func content(_ n: Int) throws -> PrivateContent {
            try PrivateContent(type: "ace:text:1", schemaDigest: d, body: ["message": .string(String(repeating: "x", count: n))]).with(prekey: key)
        }
        let c = try content(ACELimits.maxPlaintextBytes - (try content(0).jsonData().count))
        #expect(try c.jsonData().count == ACELimits.maxPlaintextBytes)
        let p = try createPacket(sender: a.identity, to: b.aceId, prekey: b.agent.descriptor.prekey, content: c, timestamp: NOW)
        #expect(p.payload.count == ACELimits.maxPlaintextBytes + 28 && p.jsonData().count <= ACELimits.maxPacketBytes)
        #expect(try openPacket(Packet(json: p.jsonData()), sender: a.state, recipient: b.aceId, vault: b.vault) == c)
        expectCode(.limitExceeded) { try content(ACELimits.maxPlaintextBytes - (try content(0).jsonData().count) + 1).jsonData() }
    }

    @Test func contentCarriesPrekey() throws {
        let d = String(repeating: "a", count: 64), key = somePrekey()
        let bare = try PrivateContent(type: "ace:text:1", schemaDigest: d, body: [:])
        expectCode(.invalidArgument) { try bare.jsonData() }
        expectCode(.invalidArgument) { try bare.with(prekey: key.prefix(1215)).jsonData() }
        let raw = try bare.with(prekey: key).jsonData()
        #expect(try JSONValue(json: raw)["prekey"] == .string(ACEBase64.encode(key)))
        let back = try PrivateContent(json: raw)
        #expect(back.prekey == key && back == bare.with(prekey: key))
        expectCode(.invalidBody) { try PrivateContent(json: Data(#"{"body":{},"schemaDigest":"\#(d)","type":"ace:text:1"}"#.utf8)) }
        expectCode(.invalidBody) { try PrivateContent(json: Data(#"{"body":{},"prekey":"QQ==","schemaDigest":"\#(d)","type":"ace:text:1"}"#.utf8)) }
        expectCode(.invalidBody) { try PrivateContent(json: Data(#"{"body":{},"prekey":null,"schemaDigest":"\#(d)","type":"ace:text:1"}"#.utf8)) }
    }
}

@Suite struct PrekeyVaultTests {
    @Test(arguments: ["memory", "file"]) func rotationRetentionAndCap(_ kind: String) throws {
        let store: any ACEStore = kind == "memory" ? MemoryStore() : try FileStore(directory: tempDirectory())
        let vault = StorePrekeyVault(store: store)
        #expect(try vault.current() == nil)
        let first = try vault.rotate(now: NOW)
        let second = try vault.rotate(now: NOW + 10)
        #expect(try vault.current()?.prekey == second.prekey && first.prekey.id == sha256Hex(first.prekey.publicKey))
        #expect(try XWing.publicKey(fromSeed: try #require(try vault.open(first.prekey.id, now: NOW + 10))) == first.prekey.publicKey)
        try vault.prune(now: NOW + 10 + ACELimits.offlineWindowSeconds - 1)
        #expect(try vault.open(first.prekey.id, now: NOW + 10 + ACELimits.offlineWindowSeconds - 1) != nil)
        // L3: open refuses a seed whose retention ended even before prune runs, and prunes it
        #expect(try vault.open(first.prekey.id, now: NOW + 10 + ACELimits.offlineWindowSeconds) == nil)
        #expect(try vault.open(first.prekey.id, now: NOW + 11) == nil && (try vault.open(second.prekey.id, now: NOW + 11)) != nil)
        var ids: [String] = []
        for i in 0..<20 { ids.append(try vault.rotate(now: NOW + 100 + i).prekey.id) }
        #expect(try ids.suffix(16).allSatisfy { try vault.open($0, now: NOW + 200) != nil })
        #expect(try ids.prefix(4).allSatisfy { try vault.open($0, now: NOW + 200) == nil })
        #expect(try vault.open(String(repeating: "0", count: 64), now: NOW + 200) == nil)
    }

    @Test(.enabled(if: SecureEnclaveKey.isAvailable)) func secureEnclaveSealedSeeds() throws {
        let store = MemoryStore()
        let vault = StorePrekeyVault(store: store, protection: .secureEnclave)
        let k = try vault.rotate(now: NOW)
        let raw = String(decoding: try #require(try store.read("prekeys.json")), as: UTF8.self)
        #expect(raw.contains("\"seal\"") && !raw.contains("\"seed\""))
        #expect(try XWing.publicKey(fromSeed: try #require(try vault.open(k.prekey.id, now: NOW))) == k.prekey.publicKey)
    }
}

@Suite struct ProfileTests {
    @Test func officialDigestsAndSources() throws {
        for m in [ProfileManifest.core, .text, .commerce] { #expect(ProfileManifest.officialDigests[m.id] == m.digest) }
        #expect(ProfileManifest.core.message("ace:receipt:1")?.schemaDigest == "a79fea8c61d30c484fdc9ba71fee310c612da84f84827fe2c4b2e99e5708d3e3")
        #expect(ProfileManifest.core.message("ace:contact:1")?.schemaDigest == "29fc76bbaa5a437aa068f823b1f2b2466c89fed6b2ea4b9cfa7c31cc80df15e9")
        #expect(ProfileManifest.text.message("ace:text:1")?.schemaDigest == "e91541145d670369cf651d062e6bb8a94ce2605d4a9f2261ceef1d8a29c2e7da")
        #expect(ProfileManifest.commerce.message(CommerceType.payment)?.schemaDigest == "33a1fde87d16bf5ad5d4387d73e0823ed14ccd15149f51bee938b54be8d95ff5")
        // the bundled resources are byte-identical to the spec checkout, when present
        let spec = URL(fileURLWithPath: #filePath).deletingLastPathComponent().appendingPathComponent("../../../ace-spec/profiles").standardizedFileURL
        for name in ["core", "text", "commerce"] {
            let bundled = ProfileManifest.officialBytes(name)
            if let data = try? Data(contentsOf: spec.appendingPathComponent(name + ".json")) { #expect(data == bundled, "\(name) differs from ace-spec") }
        }
    }

    @Test func manifestRules() throws {
        let third = try JSONValue(json: Data(#"{"id":"urn:example:x:1","messages":[{"type":"urn:example:x:1","schema":{"type":"object","properties":{"n":{"type":"integer","minimum":0}},"required":["n"],"additionalProperties":false}}]}"#.utf8))
        let m = try ProfileManifest(third)
        #expect(m.digest == sha256Hex(try third.jsonData()))
        var reserved = third.objectValue!
        reserved["id"] = "ace:x:1"
        expectCode(.invalidArgument) { try ProfileManifest(.object(reserved)) }
        let installed = try InstalledProfiles([.text, m])
        #expect(installed.refs.map(\.id) == ["ace:text:1", "urn:example:x:1"])
        expectCode(.unsupportedSchema) { try installed.validate(try PrivateContent(type: "urn:example:x:1", schemaDigest: String(repeating: "0", count: 64), body: ["n": 1])) }
        expectCode(.invalidBody) { try installed.content(type: "urn:example:x:1", body: ["n": -1]) }
        _ = try installed.content(type: "urn:example:x:1", body: ["n": 3])
        expectCode(.invalidArgument) { try InstalledProfiles([.text, .text]) }
    }

    @Test func canonicalJSON() throws {
        let v = try JSONValue(json: Data(#"{"b":1.0,"a":[true,null,"\u0001/é"],"￿":0,"𐀀":1e21,"c":-0}"#.utf8))
        #expect(String(decoding: try v.jsonData(), as: UTF8.self) == "{\"a\":[true,null,\"\\u0001/é\"],\"b\":1,\"c\":0,\"\u{FFFF}\":0,\"\u{10000}\":1e+21}")
    }
}

@Suite struct DocumentTests {
    @Test func descriptorFieldsAndVerification() throws {
        let a = try TestAgent()
        let d = a.agent.descriptor
        #expect(d.relays == ["https://relay.example"] && d.profiles == [ProfileManifest.text.ref])
        let wire = a.agent.source["descriptor"]!.objectValue!
        #expect(Set(wire.keys) == ["aceId", "issuedAt", "expiresAt", "relays", "prekey", "profiles", "signature"])
        #expect(d.expiresAt - d.issuedAt == ACELimits.defaultDescriptorSeconds)
        _ = try verifyPublishedAgent(a.agent.source, now: NOW + 100)
        expectCode(.invalidAuthorization) { try verifyPublishedAgent(a.agent.source, now: NOW + ACELimits.defaultDescriptorSeconds) }
        // any edit breaks the signature; unknown members (the retired visibility, handle and card too) are invalid
        var o = a.agent.source.objectValue!, desc = wire
        desc["expiresAt"] = .number(Double(NOW + 10))
        o["descriptor"] = .object(desc)
        expectCode(.invalidAuthorization) { try verifyPublishedAgent(.object(o), now: NOW) }
        for (key, value) in [("visibility", "public"), ("handle", "bob"), ("card", [:]), ("contact", "requests")] as [(String, JSONValue)] {
            desc = wire
            desc[key] = value
            o["descriptor"] = .object(desc)
            expectCode(.invalidAuthorization, key) { try verifyPublishedAgent(.object(o), now: NOW) }
        }
        // the lifetime is at most 7 days
        let claims = DescriptorClaims(relays: ["https://relay.example"], prekey: d.prekey)
        let week = try createPublishedAgent(identity: a.identity, claims: claims, now: NOW, lifetime: ACELimits.maxDescriptorSeconds)
        #expect(week.descriptor.expiresAt == NOW + 604_800)
        expectCode(.invalidArgument) { try createPublishedAgent(identity: a.identity, claims: claims, now: NOW, lifetime: 604_801) }
    }

    @Test func claimRules() throws {
        let id = try makeIdentity(now: NOW)
        let prekey = try Prekey(publicKey: XWing.publicKey(fromSeed: XWing.generateSeed()))
        func make(_ c: DescriptorClaims) throws -> VerifiedAgent { try createPublishedAgent(identity: id, claims: c, now: NOW) }
        expectCode(.invalidAuthorization) { try make(DescriptorClaims(relays: ["http://relay.example"], prekey: prekey)) }
        expectCode(.invalidAuthorization) { try make(DescriptorClaims(relays: ["https://Relay.example/"], prekey: prekey)) }
        _ = try createPublishedAgent(identity: id, claims: DescriptorClaims(relays: ["http://127.0.0.1:8080"], prekey: prekey), now: NOW, allowLoopback: true)
        // ext: listed profile, object values, official schemas
        let commerce = ProfileManifest.commerce.ref
        _ = try make(DescriptorClaims(relays: ["https://r.example"], prekey: prekey, profiles: [commerce],
                                      ext: ["ace:commerce:1": ["settlement": [["method": "stablecoin", "asset": "eip155:8453/erc20:0x833589fcd6edb6e08f4c7c32d4f71b54bda02913"], ["method": "stripe-link"]]]]))
        expectCode(.invalidAuthorization) {
            try make(DescriptorClaims(relays: ["https://r.example"], prekey: prekey, profiles: [commerce], ext: ["ace:commerce:1": ["settlement": [["method": "card"]]]]))
        }
        expectCode(.invalidAuthorization) {
            try make(DescriptorClaims(relays: ["https://r.example"], prekey: prekey, profiles: [ProfileManifest.text.ref], ext: ["ace:text:1": [:]]))
        }
        expectCode(.invalidAuthorization) { try make(DescriptorClaims(relays: ["https://r.example"], prekey: prekey, ext: ["urn:x:1": [:]])) }  // not listed
    }

    @Test func delegationsAndErc8004() throws {
        let controller = try makeIdentity(now: NOW), delegate = try makeIdentity(now: NOW)
        let prekey = try Prekey(publicKey: XWing.publicKey(fromSeed: XWing.generateSeed()))
        let entry = try createDelegation(issuer: controller, subject: delegate.getACEId(), now: NOW, lifetime: 1000)
        let binding = try ERC8004Binding(agentRegistry: "eip155:8453:0x8004a169fb4a3325136eb29fa0ceb6d2e539a432", agentId: "42")
        let agent = try createPublishedAgent(identity: delegate, claims: DescriptorClaims(relays: ["https://r.example"], prekey: prekey,
                                                                                          delegations: [entry], erc8004: [binding]), now: NOW)
        #expect(agent.descriptor.delegations.map(\.issuer) == [controller.getACEId()] && agent.descriptor.erc8004 == [binding])
        // expired entries are dropped, not fatal
        #expect(try verifyPublishedAgent(agent.source, now: NOW + 1000).descriptor.delegations.isEmpty)
        // an entry for another subject is fatal
        let stranger = try makeIdentity(now: NOW)
        let other = try createDelegation(issuer: controller, subject: stranger.getACEId(), now: NOW)
        expectCode(.invalidAuthorization) {
            try createPublishedAgent(identity: delegate, claims: DescriptorClaims(relays: ["https://r.example"], prekey: prekey, delegations: [other]), now: NOW)
        }
        expectCode(.invalidArgument) { try createDelegation(issuer: controller, subject: controller.getACEId(), now: NOW) }
        expectCode(.invalidArgument) { try createDelegation(issuer: controller, subject: delegate.getACEId(), now: NOW, lifetime: ACELimits.maxCredentialSeconds + 1) }
        expectCode(.invalidArgument) { try ERC8004Binding(agentRegistry: "eip155:8453:0xabc", agentId: "007") }
        // the pure registration-file helper
        let id = delegate.getACEId()
        #expect(verifyErc8004Registration(Data(#"{"services":[{"name":"A2A","endpoint":"x"},{"name":"ACE","endpoint":"\#(id)"}]}"#.utf8), aceId: id))
        #expect(!verifyErc8004Registration(Data(#"{"endpoints":[{"name":"ACE","endpoint":"\#(id)"}]}"#.utf8), aceId: id))  // services only
        #expect(!verifyErc8004Registration(Data(#"{"services":[{"name":"ace","endpoint":"\#(id)"}]}"#.utf8), aceId: id))
        #expect(!verifyErc8004Registration(Data("not json".utf8), aceId: id))
    }

    @Test func permits() throws {
        let issuer = try makeIdentity(now: NOW), subject = try makeIdentity(now: NOW)
        let p = try createPermit(identity: issuer, subject: subject.getACEId(), now: NOW)
        let v = try verifyPermit(p, issuer: issuer.getState(), subject: subject.getACEId(), now: NOW + 1)
        #expect(v.expiresAt - v.issuedAt == 2_592_000 && Set(p.objectValue!.keys) == ["issuer", "subject", "issuedAt", "expiresAt", "signature"])
        expectCode(.invalidAuthorization) { try verifyPermit(p, issuer: issuer.getState(), subject: subject.getACEId(), now: v.expiresAt) }
        expectCode(.invalidAuthorization) { try verifyPermit(p, issuer: subject.getState(), subject: issuer.getACEId(), now: NOW) }
        expectCode(.invalidArgument) { try createPermit(identity: issuer, subject: subject.getACEId(), now: NOW, lifetime: 2_592_001) }
        // a new signing delegation at the issuer invalidates earlier permits
        try issuer.delegate(now: NOW + 1, notAfter: nil)
        expectCode(.stalePeerBinding) { try verifyPermit(p, issuer: issuer.getState(), subject: subject.getACEId(), now: NOW + 2) }
    }
}

@Suite struct CommerceTests {
    @Test func stateMachineReferencesAndSettlement() throws {
        let buyer = "ace:sha256:" + String(repeating: "1", count: 64), seller = "ace:sha256:" + String(repeating: "2", count: 64)
        let rules = commerceRules(store: MemoryStore(), localAceId: seller)
        var ts = NOW
        func event(_ type: String, _ from: String, _ id: String = UUID().uuidString.lowercased(), thread: String? = "t1") -> ProfileEvent {
            ts += 1
            return ProfileEvent(direction: from == seller ? .send : .receive, from: from, to: from == seller ? buyer : seller, messageId: id,
                                timestamp: ts, type: type, threadId: thread)
        }
        func apply(_ e: ProfileEvent, _ body: [String: JSONValue]) throws { try rules.check(e, body: body); try rules.commit(e, body: body) }
        expectCode(.invalidBody) { try rules.check(event(CommerceType.rfq, buyer, thread: nil), body: ["need": "x"]) }
        expectCode(.transitionNotAllowed) { try rules.check(event(CommerceType.offer, seller), body: ["price": "1", "currency": "USDC"]) }
        let rfq = event(CommerceType.rfq, buyer)
        try apply(rfq, ["need": "translate"])
        try apply(rfq, ["need": "translate"])  // idempotent per messageId
        #expect(try rules.threads.thread(between: buyer, and: seller, threadId: "t1")?.state == .requested)
        expectCode(.wrongRole) { try rules.check(event(CommerceType.offer, buyer), body: ["price": "1", "currency": "USDC"]) }
        let offer = event(CommerceType.offer, seller)
        try apply(offer, ["price": "10", "currency": "USDC"])
        expectCode(.badReference) { try rules.check(event(CommerceType.accept, buyer), body: ["offerId": .string(rfq.messageId)]) }
        let accept = event(CommerceType.accept, buyer)
        try apply(accept, ["offerId": .string(offer.messageId)])
        let asset = "eip155:8453/erc20:0x833589fcd6edb6e08f4c7c32d4f71b54bda02913"
        expectCode(.invalidBody) {
            try rules.check(event(CommerceType.invoice, seller), body: ["offerId": .string(offer.messageId), "amount": "10", "currency": "USDC",
                                                                       "settlement": ["method": "stablecoin", "asset": .string(asset)]])  // no recipient
        }
        expectCode(.invalidBody) {
            try rules.check(event(CommerceType.invoice, seller), body: ["offerId": .string(offer.messageId), "amount": "10", "currency": "USDC",
                                                                       "settlement": ["method": "stripe-link", "url": "https://x.example", "asset": .string(asset)]])
        }
        let invoice = event(CommerceType.invoice, seller)
        try apply(invoice, ["offerId": .string(offer.messageId), "amount": "10", "currency": "USDC",
                            "settlement": ["method": "stablecoin", "asset": .string(asset), "recipient": "0xabc"]])
        expectCode(.invalidBody) {
            try rules.check(event(CommerceType.payment, buyer), body: ["referenceId": .string(invoice.messageId), "amount": "10", "currency": "USDC",
                                                                       "settlement": ["method": "stablecoin", "proof": ["paymentId": "p"]]])
        }
        let receipt = event(CommerceType.payment, buyer)
        try apply(receipt, ["referenceId": .string(invoice.messageId), "amount": "10", "currency": "USDC",
                            "settlement": ["method": "stablecoin", "proof": ["txHash": "0xdead"]]])
        let deliver = event(CommerceType.deliver, seller)
        expectCode(.invalidBody) { try rules.check(deliver, body: ["type": "inline"]) }
        try apply(deliver, ["type": "inline", "content": "done"])
        try apply(event(CommerceType.confirm, buyer), ["deliverId": .string(deliver.messageId)])
        #expect(try rules.threads.thread(between: seller, and: buyer, threadId: "t1")?.state == .confirmed)
        expectCode(.transitionNotAllowed) { try rules.check(event(CommerceType.rfq, buyer), body: ["need": "again"]) }
        let third = "ace:sha256:" + String(repeating: "3", count: 64)
        expectCode(.wrongParty) {
            try rules.check(ProfileEvent(direction: .receive, from: third, to: buyer, messageId: UUID().uuidString.lowercased(), timestamp: ts,
                                         type: CommerceType.rfq, threadId: "t2"), body: ["need": "x"])
        }
    }
}
