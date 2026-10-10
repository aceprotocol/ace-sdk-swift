import Foundation
import Testing
@testable import ACE

@Suite("Core")
struct CoreTests {
    let alice = Fixtures.agent("alice")
    let bob = Fixtures.agent("bob")
    let now = 1741000000

    @Test func errorCategories() {
        #expect(ACEError.Code.allCases.count == 40)
        #expect(ACEError(.lockBusy).category == .local && ACEError(.directRejected).category == .permanent
                && ACEError(.deliveryRejected).category == .permanent && ACEError(.directUnavailable).category == .transient)
        #expect(ACEError(.relayUnavailable).category == .transient)
        #expect(ACEError(.storageFailed).category == .local && ACEError(.storageFailed).isTransient)
        #expect(ACEError(.decryptionFailed).category == .permanent && !ACEError(.decryptionFailed).isTransient)
        #expect(ACEError(.invalidBody, "x").description == "invalid_body: x")
        #expect(ACEError(.replay).description == "replay")
    }

    @Test func limits() {
        #expect(ACELimits.maxPlaintextBytes == 65508 && ACELimits.maxPayloadBytes == 65536 && ACELimits.maxEnvelopeBytes == 131072)
        #expect(ACELimits.kemPublicKeySize == 1216 && ACELimits.kemCiphertextSize == 1120 && ACELimits.kemSeedSize == 32)
        #expect(ACELimits.maxDirectBodyBytes == 132096)
        #expect(signingSchemes == [.ed25519, .secp256k1] && isSigningScheme("secp256k1") && !isSigningScheme("p256"))
    }

    @Test func predicates() {
        #expect(isACEId(alice.getACEId()) && !isACEId(alice.getACEId().uppercased()))
        #expect(isMessageId("00000000-0000-4000-8000-000000000001") && !isMessageId("00000000-0000-1000-8000-000000000001"))
        #expect(isThreadId(String(repeating: "é", count: 256)) && !isThreadId(String(repeating: "a", count: 257)))
        #expect(!isThreadId("") && !isThreadId("a\u{7f}"))
        #expect(isConversationId(String(repeating: "a", count: 64)) && !isConversationId(String(repeating: "A", count: 64)))
    }

    @Test func codableRejectsNullThreadId() throws {
        let env = try createMessage(sender: alice, recipient: try peerOf(bob), type: .text, body: ["message": "x"],
                                    threads: try ThreadStateMachine(localAceId: alice.getACEId()))
        let data = try JSONEncoder().encode(env)
        #expect(try JSONDecoder().decode(ACEMessage.self, from: data) == env)
        var obj = try JSONSerialization.jsonObject(with: data) as! [String: Any]
        #expect(obj["threadId"] == nil)
        obj["threadId"] = NSNull()
        expectCode(.invalidEnvelope) { try JSONDecoder().decode(ACEMessage.self, from: json(obj)) }
        expectCode(.invalidEnvelope) { try decodeEnvelope(json(obj)) }
    }

    @Test func noPreconditions() {
        expectCode(.invalidArgument) { try ReplayDetector(capacity: 0) }
        expectCode(.invalidArgument) { try ThreadStateMachine(localAceId: "x") }
        expectCode(.invalidArgument) { try ThreadStateMachine(localAceId: alice.getACEId(), maxThreads: 0) }
        expectCode(.invalidArgument) { try ACESigning.buildSignData(action: "a", aceId: "b", timestamp: -1) }
        expectCode(.invalidArgument) { try ReplayDetector().commit("x", from: "", timestamp: 1) }
        expectCode(.invalidArgument) { try ReplayDetector().commit("", from: "s", timestamp: 1) }
        expectCode(.invalidArgument) { try ReplayDetector().accepts("", from: "s", timestamp: 1) }
        expectCode(.invalidArgument) { try ReplayDetector().accepts("x", from: "s", timestamp: -1) }
        expectCode(.invalidArgument) { try ReplayDetector().commit("x", from: "s", timestamp: 1, floor: -1) }
        expectCode(.invalidArgument) { try ReplayDetector(state: try ReplayState(json: Data("{\"version\":true,\"horizon\":0,\"senderHorizons\":{},\"entries\":[]}".utf8))) }
    }

    @Test func replayStateAcceptsWireIntegers() throws {
        let s = try ReplayState(json: Data("{\"version\":1.0,\"horizon\":10,\"senderHorizons\":{},\"entries\":[[\"00000000-0000-4000-8000-000000000001\",\"s\",11.0]],\"x\":1}".utf8))
        let r = try ReplayDetector(state: s, capacity: 100)
        #expect(try !r.accepts("00000000-0000-4000-8000-000000000001", from: "s", timestamp: 11))
        let clone = r.clone()
        try clone.commit("00000000-0000-4000-8000-000000000002", from: "s", timestamp: 12, floor: 0)
        #expect(try r.accepts("00000000-0000-4000-8000-000000000002", from: "s", timestamp: 12))
    }

    @Test func createMessageValidation() throws {
        let threads = try ThreadStateMachine(localAceId: alice.getACEId())
        let peer = try peerOf(bob)
        expectCode(.invalidArgument) { try createMessage(sender: alice, recipient: peer, type: .rfq, body: ["need": "x"], threads: threads) }
        expectCode(.invalidArgument) { try createMessage(sender: alice, recipient: peer, type: .text, body: ["message": "x"], threads: threads, threadId: "") }
        expectCode(.invalidArgument) {
            try createMessage(sender: alice, recipient: peer, type: .text, body: ["message": "x"],
                              threads: try ThreadStateMachine(localAceId: bob.getACEId()))
        }
        expectCode(.invalidBody) { try createMessage(sender: alice, recipient: peer, type: .text, body: ["message": .number(.nan)], threads: threads) }
        expectCode(.invalidBody) { try createMessage(sender: alice, recipient: peer, type: .text, body: ["message": "x", "n": .number(.infinity)], threads: threads) }
        expectCode(.invalidBody) { try createMessage(sender: alice, recipient: peer, type: .text, body: ["message": 1], threads: threads) }
        var deep: JSONValue = ["a": 1]
        for _ in 0..<30 { deep = ["a": deep] }
        // Depth 32 (private content object = 0) is accepted, 33 is not.
        _ = try createMessage(sender: alice, recipient: peer, type: .text, body: ["message": "x", "d": deep], threads: threads)
        deep = ["a": deep]
        expectCode(.invalidBody) { try createMessage(sender: alice, recipient: peer, type: .text, body: ["message": "x", "d": deep], threads: threads) }
        expectCode(.limitExceeded) {
            try createMessage(sender: alice, recipient: peer, type: .text, body: ["message": .string(String(repeating: "a", count: 65500))], threads: threads)
        }
        expectCode(.transitionNotAllowed) {
            let t = try ThreadStateMachine(localAceId: alice.getACEId())
            _ = try createMessage(sender: alice, recipient: peer, type: .rfq, body: ["need": "x"], threads: t, threadId: "t")
            return try createMessage(sender: alice, recipient: peer, type: .accept, body: ["offerId": "x"], threads: t, threadId: "t")
        }
    }

    @Test func parseMessageOrder() throws {
        let peerA = try peerOf(alice), peerB = try peerOf(bob)
        let env = try createMessage(sender: alice, recipient: peerB, type: .text, body: ["message": "x"],
                                    threads: try ThreadStateMachine(localAceId: alice.getACEId()), timestamp: now)
        func parse(_ e: ACEMessage, receiver: any ACEIdentity = Fixtures.agent("bob"), sender: VerifiedPeer? = nil,
                   replay: ReplayDetector? = nil, floor: Int? = nil) throws -> ParsedMessage {
            try parseMessage(e, receiver: receiver, sender: sender ?? peerA,
                             threads: try ThreadStateMachine(localAceId: receiver.getACEId()),
                             replay: try replay ?? ReplayDetector(horizon: now - 300), floor: floor, clock: { 1741000000 })
        }
        #expect(try parse(env).body["message"]?.stringValue == "x")
        expectCode(.wrongRecipient) { try parse(env, receiver: Fixtures.agent("alice")) }
        expectCode(.invalidEnvelope) { try parse(env, sender: peerB) }
        expectCode(.invalidArgument) { try parse(env, floor: now + 1) }
        let old = try createMessage(sender: alice, recipient: peerB, type: .text, body: ["message": "x"],
                                    threads: try ThreadStateMachine(localAceId: alice.getACEId()), timestamp: now - 301)
        expectCode(.staleTimestamp) { try parse(old) }
        #expect(try parse(old, replay: try ReplayDetector(horizon: now - 500), floor: now - 400).timestamp == now - 301)
        let future = try createMessage(sender: alice, recipient: peerB, type: .text, body: ["message": "x"],
                                       threads: try ThreadStateMachine(localAceId: alice.getACEId()), timestamp: now + 301)
        expectCode(.staleTimestamp) { try parse(future) }
        let replay = try ReplayDetector(horizon: now - 300)
        _ = try parse(env, replay: replay)
        expectCode(.replay) { try parse(env, replay: replay) }
        // Wrong signature → invalid_signature, and the replay store is untouched.
        let other = try ACE.resign(env, sender: Fixtures.agent("bob"), timestamp: now)
        let forged = ACEMessage(messageId: env.messageId, from: env.from, to: env.to, conversationId: env.conversationId,
                                timestamp: now, encryption: env.encryption, signature: SignatureEnvelope(scheme: .ed25519, value: ACEBase64.encode(Data(repeating: 7, count: 64))))
        _ = other
        let fresh = try ReplayDetector(horizon: now - 300)
        expectCode(.invalidSignature) { try parse(forged, replay: fresh) }
        #expect(try fresh.accepts(env.messageId, from: env.from, timestamp: now))
        // Scheme mismatch.
        let secp = ACEMessage(messageId: env.messageId, from: env.from, to: env.to, conversationId: env.conversationId,
                              timestamp: now, encryption: env.encryption, signature: SignatureEnvelope(scheme: .secp256k1, value: "0x" + String(repeating: "1", count: 130)))
        expectCode(.schemeMismatch) { try parse(secp) }
    }

    @Test func customIdentityErrorMapping() throws {
        struct Broken: ACEIdentity {
            let inner: SoftwareIdentity
            let error: any Error
            func getACEId() -> String { inner.getACEId() }
            func getSigningScheme() -> SigningScheme { inner.getSigningScheme() }
            func getSigningPublicKey() -> Data { inner.getSigningPublicKey() }
            func getEncryptionPublicKey() -> Data { inner.getEncryptionPublicKey() }
            func sign(_ data: Data) throws -> Data { try inner.sign(data) }
            func decrypt(kemCiphertext: Data, payload: Data, conversationId: String) throws -> Data { throw error }
        }
        struct Keychain: Error {}
        let env = try createMessage(sender: alice, recipient: try peerOf(bob), type: .text, body: ["message": "x"],
                                    threads: try ThreadStateMachine(localAceId: alice.getACEId()), timestamp: now)
        for (err, expected) in [(Keychain() as any Error, ACEError.Code.identityUnavailable), (ACEError(.decryptionFailed), .decryptionFailed)] {
            let r = Broken(inner: bob, error: err)
            expectCode(expected) {
                try parseMessage(env, receiver: r, sender: try peerOf(alice), threads: try ThreadStateMachine(localAceId: bob.getACEId()),
                                 replay: try ReplayDetector(horizon: now - 300), clock: { 1741000000 })
            }
        }
    }

    @Test func encryptionErrors() throws {
        let seed = ACEEncryption.generateSeed()
        let pub = try ACEEncryption.publicKey(fromSeed: seed)
        let conv = try ACEEncryption.computeConversationId(pubA: pub, pubB: pub)
        let (kem, payload) = try ACEEncryption.encrypt(Data("hi".utf8), recipientPublicKey: pub, conversationId: conv)
        #expect(try ACEEncryption.decrypt(kemCiphertext: kem, payload: payload, seed: seed, conversationId: conv) == Data("hi".utf8))
        expectCode(.invalidKey) { try ACEEncryption.decrypt(kemCiphertext: kem, payload: payload, seed: Data(count: 31), conversationId: conv) }
        expectCode(.invalidArgument) { try ACEEncryption.decrypt(kemCiphertext: kem, payload: payload, seed: seed, conversationId: "X") }
        expectCode(.decryptionFailed) { try ACEEncryption.decrypt(kemCiphertext: kem, payload: payload.prefix(27), seed: seed, conversationId: conv) }
        expectCode(.decryptionFailed) { try ACEEncryption.decrypt(kemCiphertext: kem.prefix(1119), payload: payload, seed: seed, conversationId: conv) }
        expectCode(.decryptionFailed) { try ACEEncryption.decrypt(kemCiphertext: kem, payload: payload, seed: ACEEncryption.generateSeed(), conversationId: conv) }
        expectCode(.invalidKey) { try ACEEncryption.computeConversationId(pubA: pub, pubB: pub.prefix(10)) }
        expectCode(.invalidKey) { try ACEEncryption.publicKey(fromSeed: Data(count: 33)) }
    }

    @Test func registrationBindsEncryptionKeyAndTimestamp() throws {
        let victim = try SoftwareIdentity.generate(scheme: .ed25519)
        let attacker = try SoftwareIdentity.generate(scheme: .ed25519)
        let reg = try createRegistrationFile(for: victim, name: "Victim", endpoint: "https://victim.example")
        #expect(try verifyRegistrationFile(reg).aceId == victim.getACEId())
        var substituted = reg
        substituted.signing = SigningConfig(scheme: reg.signing.scheme, address: reg.signing.address,
                                            signingPublicKey: reg.signing.signingPublicKey,
                                            encryptionPublicKey: ACEBase64.encode(attacker.getEncryptionPublicKey()))
        expectCode(.invalidRegistration) { try verifyRegistrationFile(substituted) }
        var wire = try JSONSerialization.jsonObject(with: JSONEncoder().encode(reg)) as! [String: Any]
        wire["registeredAt"] = reg.registeredAt + 1
        expectCode(.invalidRegistration) { try verifyRegistrationFile(RegistrationFile(json: JSONSerialization.data(withJSONObject: wire))) }
        wire.removeValue(forKey: "registrationSignature")
        expectCode(.invalidRegistration) { try RegistrationFile(json: JSONSerialization.data(withJSONObject: wire)) }
    }

    @Test func identityExportAndRegistration() throws {
        for scheme in SigningScheme.allCases {
            let id = try SoftwareIdentity.generate(scheme: scheme)
            let back = try SoftwareIdentity(export: id.exportPrivateKey())
            #expect(back.getACEId() == id.getACEId() && back.getEncryptionPublicKey() == id.getEncryptionPublicKey())
            let reg = try createRegistrationFile(for: id, name: "X", endpoint: "https://x.example/ace", tier: .chainRegistered)
            #expect(reg.tier == .chainRegistered)
            let peer = try verifyRegistrationFile(try RegistrationFile(json: try JSONEncoder().encode(reg)))
            #expect(peer.registeredAt == reg.registeredAt && peer.address == id.getAddress())
            expectCode(.invalidRegistration) { try createRegistrationFile(for: id, name: "X", endpoint: "http://x.example") }
        }
        expectCode(.invalidKey) { try SoftwareIdentity(export: SoftwareIdentityExport(scheme: .ed25519, signingPrivateKey: "QR==", encryptionPrivateKey: "")) }
    }

    @Test func authHeaderParsing() throws {
        let h = try createAuthHeaders(identity: alice, request: .listen(since: "-"), timestamp: now)
        let lower = Dictionary(uniqueKeysWithValues: h.map { ($0.key.lowercased(), $0.value) })
        let auth = try parseAuthHeaders(lower)
        expectCode(.invalidArgument) { try verifyAuthHeaders(auth, request: .listen(since: "-"), aceId: bob.getACEId(), scheme: .ed25519, signingPublicKey: alice.getSigningPublicKey(), clock: { 1741000000 }) }
        expectCode(.staleTimestamp) { try verifyAuthHeaders(auth, request: .listen(since: "-"), aceId: alice.getACEId(), scheme: .ed25519, signingPublicKey: alice.getSigningPublicKey(), clock: { 1741000301 }) }
        for extreme in [Int.min, Int.max] {
            expectCode(.staleTimestamp) { try verifyAuthHeaders(auth, request: .listen(since: "-"), aceId: alice.getACEId(), scheme: .ed25519, signingPublicKey: alice.getSigningPublicKey(), clock: { extreme }) }
        }
        expectCode(.invalidSignature) { try verifyAuthHeaders(auth, request: .listen(since: "1-1"), aceId: alice.getACEId(), scheme: .ed25519, signingPublicKey: alice.getSigningPublicKey(), clock: { 1741000000 }) }
        expectCode(.invalidArgument) { try parseAuthHeaders(["X-ACE-Id": alice.getACEId(), "X-ACE-Timestamp": "01", "X-ACE-Signature": "x"]) }
        expectCode(.invalidArgument) { try parseAuthHeaders(["X-ACE-Id": alice.getACEId(), "X-ACE-Timestamp": "1", "X-ACE-Signature": String(repeating: "a", count: 513)]) }
        expectCode(.invalidArgument) { try createAuthHeaders(identity: alice, request: .inbox(since: "x", limit: 1), timestamp: now) }
        expectCode(.invalidArgument) { try createAuthHeaders(identity: alice, request: .intent(need: "n", tags: ["a,b"], ttl: 1), timestamp: now) }
    }

    @Test func blockedAddresses() {
        for v4 in [[0, 1, 2, 3], [10, 0, 0, 1], [100, 64, 0, 1], [127, 0, 0, 1], [169, 254, 1, 1], [172, 31, 0, 1], [192, 0, 0, 5],
                   [192, 0, 2, 1], [192, 168, 1, 1], [198, 19, 0, 1], [198, 51, 100, 1], [203, 0, 113, 9], [224, 0, 0, 1], [255, 255, 255, 255]] {
            #expect(isBlockedIPv4(v4.map(UInt8.init)), "\(v4)")
        }
        for v4 in [[8, 8, 8, 8], [100, 128, 0, 1], [172, 32, 0, 1], [192, 0, 1, 1], [198, 20, 0, 1], [1, 1, 1, 1]] {
            #expect(!isBlockedIPv4(v4.map(UInt8.init)), "\(v4)")
        }
        func v6(_ s: String) -> [UInt8] {
            var a = in6_addr()
            inet_pton(AF_INET6, s, &a)
            return withUnsafeBytes(of: a) { Array($0) }
        }
        for s in ["::", "::1", "::ffff:127.0.0.1", "64:ff9b::a00:1", "100::1", "2001:db8::1", "fc00::1", "fd12::1", "fe80::1", "ff02::1"] {
            #expect(isBlockedIPv6(v6(s)), "\(s)")
        }
        for s in ["2606:4700::1111", "::ffff:8.8.8.8", "64:ff9b::808:808"] {
            #expect(!isBlockedIPv6(v6(s)), "\(s)")
        }
    }

    @Test func fetchArgumentValidation() async {
        await expectCodeAsync(.invalidArgument) { try await fetchRegistrationFile("localhost") }
        await expectCodeAsync(.invalidArgument) { try await fetchRegistrationFile("example.com", timeout: 0) }
        await expectCodeAsync(.invalidArgument) { try await fetchRegistrationFile("example.com", maxBytes: 0) }
    }

    @Test func profileValidation() throws {
        let commerce = CommerceProfileExt(chains: ["eip155:1"], pricing: CommercePricing(currency: "USDC", maxAmount: "10.5"),
                                          settlement: ["crypto/instant"], accounts: [CommerceAccount(network: "eip155:8453", address: "0xabc")])
        let profile = AgentProfile(name: "A", tags: ["a-1"], endpoint: "https://a.example", ext: [commerceExt: commerce.jsonValue])
        #expect(try validateProfile(profile) == profile)
        #expect(profile.commerce == commerce)
        expectCode(.invalidProfile) { try validateProfile(AgentProfile(name: "")) }
        expectCode(.invalidProfile) { try validateProfile(AgentProfile(tags: ["A"])) }
        expectCode(.invalidProfile) { try validateProfile(AgentProfile(ext: [commerceExt: ["pricing": ["currency": "USDC", "maxAmount": "1e3"]]])) }
        expectCode(.invalidProfile) { try AgentProfile.parse(jvalue(["ext": [commerceExt: ["pricing": ["currency": "USDC", "model": "x"]]]])) }
        expectCode(.invalidProfile) { try AgentProfile.parse(jvalue(["ext": [commerceExt: ["pricing": ["currency": "USDC", "maxAmount": NSNull()]]]])) }
        expectCode(.invalidProfile) { try AgentProfile.parse(jvalue(["ext": [commerceExt: ["accounts": [["network": "eip155:1", "address": "a", "x": 1]]]]])) }
        expectCode(.invalidProfile) { try AgentProfile.parse(jvalue(["ext": [commerceExt: ["chains": ["EIP155:1"]]]])) }
        expectCode(.invalidProfile) { try AgentProfile.parse(jvalue(["ext": [commerceExt: ["pricing": ["currency": "US\u{01}D"]]]])) }
        expectCode(.invalidProfile) { try AgentProfile.parse(jvalue(["ext": "x"])) }
        // Old top-level commerce fields are unknown members: dropped, never an error. An empty `ext` is absent.
        #expect(try AgentProfile.parse(jvalue(["name": "A", "unknown": 1, "image": NSNull(), "chains": ["eip155:1"],
                                               "pricing": ["currency": "USDC"], "ext": [:]])) == AgentProfile(name: "A"))
        let parsed = try AgentProfile.parse(jvalue(["ext": ["urn:x:1": ["n": 1.0, "s": "é"], commerceExt: ["chains": ["eip155:1"]]]]))
        #expect(parsed.ext?["urn:x:1"] == ["n": 1, "s": "é"] && parsed.commerce?.chains == ["eip155:1"])
        #expect(String(decoding: try extCanonical(parsed.ext!), as: UTF8.self) == #"{"urn:ace:commerce:1":{"chains":["eip155:1"]},"urn:x:1":{"n":1,"s":"é"}}"#)
    }

    @Test func extRules() throws {
        for carrier in [ExtCarrier.profile, .intent] {
            let code = carrier.code
            #expect(code == (carrier == .profile ? .invalidProfile : .invalidArgument))
            try validateExt([:], carrier: carrier)
            try validateExt(["urn:x:1": [:], "a:b": ["k": [1, [2, [3]]]]], carrier: carrier)
            expectCode(code) { try validateExt(["urn:x:1": "s"], carrier: carrier) }
            expectCode(code) { try validateExt(["urn:x:1": [:], "Bad": [:]], carrier: carrier) }
            expectCode(code) { try validateExt(["x": [:]], carrier: carrier) }
            expectCode(code) { try validateExt(["a:" + String(repeating: "b", count: 255): [:]], carrier: carrier) }
            try validateExt(["a:" + String(repeating: "b", count: 254): [:]], carrier: carrier)
            expectCode(code) { try validateExt(["a:é": [:]], carrier: carrier) }
            expectCode(code) { try validateExt(Dictionary(uniqueKeysWithValues: (0..<9).map { ("urn:x:\($0)", JSONValue.object([:])) }), carrier: carrier) }
            try validateExt(Dictionary(uniqueKeysWithValues: (0..<8).map { ("urn:x:\($0)", JSONValue.object([:])) }), carrier: carrier)
            // Depth: the ext root is depth 0; a container at depth 9 is rejected.
            var deep: JSONValue = [:]
            for _ in 0..<7 { deep = ["k": deep] }  // value at depth 1 holding containers down to depth 8
            try validateExt(["urn:x:1": deep], carrier: carrier)
            expectCode(code) { try validateExt(["urn:x:1": ["k": deep]], carrier: carrier) }
            expectCode(code) { try validateExt(["urn:x:1": ["s": .string(String(repeating: "a", count: 4096))]], carrier: carrier) }
            expectCode(code) { try validateExt(["urn:x:1": ["s": .string(String(repeating: "a", count: 4096 - 19))]], carrier: carrier) }
            try validateExt(["urn:x:1": ["s": .string(String(repeating: "a", count: 4096 - 20))]], carrier: carrier)  // {"urn:x:1":{"s":""}} is 20 bytes
            expectCode(code) { try validateExt(["urn:x:1": ["n": .number(.infinity)]], carrier: carrier) }
        }
        try validateExt([commerceExt: ["maxPrice": "5", "currency": "US\u{01}"]], carrier: .intent)  // code points only
        try validateExt([commerceExt: [:]], carrier: .intent)
        expectCode(.invalidArgument) { try validateExt([commerceExt: ["maxPrice": "5"]], carrier: .intent) }
        expectCode(.invalidArgument) { try validateExt([commerceExt: ["maxPrice": "5", "currency": .string(String(repeating: "c", count: 17))]], carrier: .intent) }
        expectCode(.invalidArgument) { try validateExt([commerceExt: ["maxPrice": "5", "currency": .null]], carrier: .intent) }
        expectCode(.invalidArgument) { try validateExt([commerceExt: ["maxPrice": "", "currency": "USDC"]], carrier: .intent) }
        expectCode(.invalidArgument) { try validateExt([commerceExt: ["maxPrice": "5", "currency": "USDC", "chains": []]], carrier: .intent) }
        expectCode(.invalidArgument) { try validateExt([commerceExt: ["chains": ["eip155:1"]]], carrier: .intent) }
        expectCode(.invalidProfile) { try validateExt([commerceExt: ["maxPrice": "5", "currency": "USDC"]], carrier: .profile) }
        expectCode(.invalidProfile) { try validateExt([commerceExt: ["chains": .array(Array(repeating: "eip155:1", count: 11))]], carrier: .profile) }
        expectCode(.invalidProfile) { try validateExt([commerceExt: ["settlement": [1]]], carrier: .profile) }
        expectCode(.invalidProfile) { try validateExt([commerceExt: ["accounts": [["network": "eip155:1"]]]], carrier: .profile) }
        expectCode(.invalidProfile) { try validateExt([commerceExt: ["pricing": ["maxAmount": "1"]]], carrier: .profile) }
        #expect(commerceIntentExt([commerceExt: ["maxPrice": "5", "currency": "USDC"]]) == CommerceIntentExt(maxPrice: "5", currency: "USDC"))
        #expect(commerceIntentExt(["urn:x:1": [:]]) == nil)
    }

    @Test func streamIdOrdering() throws {
        #expect(compareStreamIds("10-0", "9-99") > 0)
        #expect(compareStreamIds("1-2", "1-10") < 0)
        #expect(compareStreamIds("01-2", "1-2") == 0)
        #expect(try normalizeRelayURL("HTTPS://Relay.Example:8443/base/") == "https://relay.example:8443/base")
    }

    @Test func threadMachineSnapshotRoundTrip() throws {
        let sm = try ThreadStateMachine(localAceId: alice.getACEId())
        let peer = try peerOf(bob)
        _ = try createMessage(sender: alice, recipient: peer, type: .rfq, body: ["need": "x"], threads: sm, threadId: "t")
        let restored = try ThreadStateMachine(state: sm.exportState(), localAceId: alice.getACEId())
        #expect(restored.exportState() == sm.exportState())
        var snap = sm.exportState()[0]
        snap = ThreadSnapshot(conversationId: snap.conversationId, threadId: snap.threadId, localAceId: snap.localAceId,
                              peerAceId: snap.peerAceId, state: .offered, history: snap.history)
        expectCode(.invalidArgument) { try ThreadStateMachine(state: [snap], localAceId: alice.getACEId()) }
        #expect(sm.allowedTypes(conversationId: snap.conversationId, threadId: "t", senderAceId: bob.getACEId()) == [.offer, .reject])
        #expect(sm.allowedTypes(conversationId: snap.conversationId, threadId: "t", senderAceId: alice.getACEId()) == [])
    }
}
