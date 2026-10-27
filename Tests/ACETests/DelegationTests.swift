//
//  DelegationTests.swift
//  The `ace:delegation:1` profile (profiles/delegation.md): credentials, the descriptor extension, the hand-over message
//  rule and `NetworkClient.verifyDelegation`; plus the core changes that came with it: ERC-8004 on the card record,
//  signers at the log tail (01 § Operational signatures), card lookups that need a live descriptor (04 § Card record)
//  and the one page default. The same scenarios as sdk-py tests/test_delegation.py.
//

import Foundation
import Testing
@testable import ACE

private let SOL = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp:7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU"
private let REGISTRY = "eip155:1:0x8004a169fb4a3325136eb29fa0ceb6d2e539a432"
private let MID = "8a4f6a2e-3c0b-4d1e-9f7a-1b2c3d4e5f60"

private func identity() throws -> any ACEManagedIdentity { try makeIdentity(now: NOW - 10) }

private func state(_ i: any ACEIdentity, _ now: Int = NOW) throws -> KelState { try ACEKel.verify(try i.getKel(), now: now) }

/// The PublishedAgent of `subject` announcing `profiles`, with `ext`.
private func source(_ subject: any ACEIdentity, profiles: [ProfileRef], ext: [String: JSONValue]?) throws -> VerifiedAgent {
    let vault = StorePrekeyVault(store: MemoryStore())
    return try createPublishedAgent(identity: subject, claims: DescriptorClaims(
        relays: ["https://relay.example"], prekey: try vault.rotate(now: NOW).prekey, profiles: profiles, ext: ext), now: NOW)
}

/// `credential` with member `key` replaced (the signature is kept).
private func with(_ credential: DelegationCredential, _ key: String, _ value: JSONValue) -> JSONValue {
    var o = credential.jsonValue.objectValue!
    o[key] = value
    return .object(o)
}

private func event(_ direction: ProfileEvent.Direction, _ from: String, _ to: String) -> ProfileEvent {
    ProfileEvent(direction: direction, from: from, to: to, messageId: MID, timestamp: NOW, type: delegationType, threadId: nil)
}

@Suite struct DelegationTests {
    @Test func credentialRoundTripAndExtShape() throws {
        let subject = try identity(), s = subject.getACEId()
        let issuers = try (0...maxDelegationCredentials).map { _ in try identity() }
        let creds = try issuers.map { try createDelegationCredential(issuer: $0, subject: s, now: NOW) }
        let c = creds[0]
        #expect(Set(c.jsonValue.objectValue!.keys) == ["issuer", "subject", "issuedAt", "expiresAt", "signature"])
        #expect(c.issuer == issuers[0].getACEId() && c.subject == s)
        #expect(c.expiresAt - c.issuedAt == maxDelegationCredentialLifetime)
        #expect(try verifyDelegationCredential(c.jsonValue, issuer: try state(issuers[0]), now: NOW) == c)
        // signed with the profile's own action, never a core one
        expectCode(.invalidAuthorization) { try verifyDelegationCredential(c.jsonValue, issuer: try state(issuers[1]), now: NOW) }
        #expect(try validateDelegationExt(["credentials": .array(creds.prefix(4).map(\.jsonValue))], subject: s, now: NOW) == Array(creds.prefix(4)))
        let bad: [JSONValue] = [
            ["credentials": .array(creds.map(\.jsonValue))],  // five
            ["credentials": []],
            ["credentials": [c.jsonValue, c.jsonValue]],  // one issuer twice
            ["credentials": [c.jsonValue], "x": 1],
            [c.jsonValue],
        ]
        for value in bad { expectCode(.invalidAuthorization, "\(value)") { try validateDelegationExt(value, subject: s, now: NOW) } }
        expectCode(.invalidAuthorization, "another subject") {
            try validateDelegationExt(["credentials": [c.jsonValue]], subject: issuers[1].getACEId(), now: NOW)
        }
        expectCode(.invalidAuthorization, "issuer == subject") {
            try validateDelegationExt(["credentials": [with(c, "subject", .string(c.issuer))]], subject: c.issuer, now: NOW)
        }
        expectCode(.invalidAuthorization, "lifetime above the max") {
            try validateDelegationExt(["credentials": [with(c, "expiresAt", .number(Double(c.issuedAt + 604_801)))]], subject: s, now: NOW)
        }
        expectCode(.invalidArgument) { try createDelegationCredential(issuer: issuers[0], subject: s, now: NOW, ttl: 604_801) }
        expectCode(.invalidArgument) { try createDelegationCredential(issuer: issuers[0], subject: issuers[0].getACEId(), now: NOW) }
        #expect(try createDelegationCredential(issuer: issuers[0], subject: s, now: NOW, ttl: 60).expiresAt == NOW + 60)
        // the extension is checked by descriptor verification (shape only)
        let subj = try identity()
        let ext: [String: JSONValue] = [
            delegationProfileId: ["credentials": [try createDelegationCredential(issuer: issuers[0], subject: subj.getACEId(), now: NOW).jsonValue]],
        ]
        #expect(try source(subj, profiles: [ProfileManifest.delegation.ref], ext: ext).descriptor.ext == ext)
        expectCode(.invalidAuthorization, "subject is not the descriptor's") {
            try source(subj, profiles: [ProfileManifest.delegation.ref], ext: [delegationProfileId: ["credentials": [c.jsonValue]]])
        }
    }

    @Test func verifyRejectsExpiredAndTampered() throws {
        let issuer = try identity(), s = try identity().getACEId()
        let c = try createDelegationCredential(issuer: issuer, subject: s, now: NOW, ttl: 60)
        expectCode(.invalidAuthorization) { try verifyDelegationCredential(c.jsonValue, issuer: try state(issuer), now: NOW + 60) }
        // the descriptor extension does not check expiry
        #expect(try validateDelegationExt(["credentials": [c.jsonValue]], subject: s, now: NOW + 60) == [c])
        var sig = try ACEBase64.decode(c.signature.value)
        sig[0] ^= 1
        let tampered = with(c, "signature", SignatureEnvelope(value: ACEBase64.encode(sig), seq: c.signature.seq).jsonValue)
        expectCode(.invalidAuthorization) { try verifyDelegationCredential(tampered, issuer: try state(issuer), now: NOW) }
        // a new dlg supersedes the key: stale_peer_binding passes through
        try issuer.delegate(now: NOW + 1, notAfter: nil)
        expectCode(.stalePeerBinding) { try verifyDelegationCredential(c.jsonValue, issuer: try state(issuer, NOW + 1), now: NOW + 1) }
    }

    @Test func ruleRequiresIssuerFromAndSubjectTo() async throws {
        let clock = TestClock(NOW)
        let dave = try identity(), bob = try identity(), carol = try identity()
        let d = dave.getACEId(), b = bob.getACEId(), cId = carol.getACEId()
        let peers = PeerStore(store: MemoryStore(), clock: clock.fn)
        let rules = delegationRules(peers: peers, localAceId: b)
        #expect(rules.types == [delegationType])
        let c = try createDelegationCredential(issuer: dave, subject: b, now: NOW)
        let body: [String: JSONValue] = ["credential": c.jsonValue]
        expectCode(.invalidBody, "the sender is not pinned") { try rules.check(event(.receive, d, b), body: body) }
        try await peers.pin(kel: try dave.getKel())
        try rules.check(event(.receive, d, b), body: body)
        try rules.commit(event(.receive, d, b), body: body)
        let carolC = try createDelegationCredential(issuer: carol, subject: b, now: NOW)
        try await peers.pin(kel: try carol.getKel())
        expectCode(.invalidBody, "issuer != from") { try rules.check(event(.receive, d, b), body: ["credential": carolC.jsonValue]) }
        expectCode(.invalidBody, "subject != to") { try rules.check(event(.receive, d, cId), body: body) }
        expectCode(.invalidBody, "not the issuer's signature") {
            try rules.check(event(.receive, d, b), body: ["credential": with(carolC, "issuer", .string(d))])
        }
        clock.now = c.expiresAt
        expectCode(.invalidBody, "expired") { try rules.check(event(.receive, d, b), body: body) }
        // on send: the sender is the issuer (its own credential), no pin needed
        let senderRules = delegationRules(peers: PeerStore(store: MemoryStore(), clock: clock.fn), localAceId: d)
        clock.now = NOW
        try senderRules.check(event(.send, d, b), body: body)
        expectCode(.invalidBody) { try senderRules.check(event(.send, d, cId), body: body) }
    }

    @Test func networkVerifyDelegationPinsTheIssuer() async throws {
        let clock = TestClock(systemClock()), relay = FakeRelay(clock: clock.fn)
        let dave = try await NetPeer.make(relay, clock: clock)
        let bob = try await NetPeer.make(relay, clock: clock, configuration: NetworkConfiguration())
        let c = try createDelegationCredential(issuer: dave.identity, subject: bob.aceId, now: clock.now)
        #expect(try await bob.network.peers.pinned(dave.aceId) == nil)
        #expect(try await bob.network.verifyDelegation(c.jsonValue) == c)
        #expect(try await bob.network.peers.pinned(dave.aceId) != nil)
        let stranger = try makeIdentity(now: clock.now - 10)
        let unknown = try createDelegationCredential(issuer: stranger, subject: bob.aceId, now: clock.now)
        await expectCodeAsync(.unknownPeer) { try await bob.network.verifyDelegation(unknown.jsonValue) }
        await expectCodeAsync(.invalidAuthorization) { try await bob.network.verifyDelegation(with(c, "expiresAt", "x")) }
    }

    @Test func networkClientInstallsTheDelegationRule() async throws {
        let clock = TestClock(systemClock()), relay = FakeRelay(clock: clock.fn)
        let dave = try await NetPeer.make(relay, clock: clock, configuration: NetworkConfiguration(profiles: [.text, .delegation], contact: .open))
        let bob = try await NetPeer.make(relay, clock: clock, configuration: NetworkConfiguration(profiles: [.text, .delegation]))
        try await bob.network.connect(dave.aceId, profile: delegationProfileId)
        _ = try await dave.network.pull()
        try await dave.network.accept(bob.aceId)
        _ = try await bob.network.pull()
        let c = try createDelegationCredential(issuer: dave.identity, subject: bob.aceId, now: clock.now)
        await expectCodeAsync(.invalidBody) {  // checked on send: subject must be the recipient
            try await dave.network.send(to: bob.aceId, type: delegationType, body: ["credential": with(c, "subject", .string(dave.aceId))])
        }
        _ = try await dave.network.send(to: bob.aceId, type: delegationType, body: ["credential": c.jsonValue])
        _ = try await bob.network.pull()
        #expect(bob.received.value.filter { $0.type == delegationType }.map(\.body) == [["credential": c.jsonValue]])
    }

    @Test func signerTimestampIsTheLogTail() throws {
        let me = try identity(), peer = try identity()
        try me.delegate(now: NOW + 100, notAfter: nil)
        let st = try state(me, NOW + 100)
        let prekey = try StorePrekeyVault(store: MemoryStore()).rotate(now: NOW).prekey
        let content = try InstalledProfiles([.text]).content(type: "ace:text:1", body: ["message": "hi"]).with(prekey: somePrekey())
        let p = try createPacket(sender: me, to: peer.getACEId(), prekey: prekey, content: content, timestamp: NOW)
        #expect(p.timestamp == NOW + 100)
        try verifyPacketSignature(p, sender: st, now: NOW + 100)
        let permit = try createPermit(identity: me, subject: peer.getACEId(), now: NOW)
        #expect(permit["issuedAt"]?.wireInt == NOW + 100)
        _ = try verifyPermit(permit, issuer: st, subject: peer.getACEId(), now: NOW + 100)
        let aud = "https://relay.example"
        let h = try createAuthHeaders(me, request: .inbox(since: "-", limit: 1), timestamp: NOW, audience: aud)
        #expect(h["X-ACE-Timestamp"] == String(NOW + 100))
        let request = try createRegistrationRequest(identity: me, timestamp: NOW, audience: aud)
        #expect(request["timestamp"]?.wireInt == NOW + 100)
        // a packet signed one second before the dlg's ts does not verify (signed while live)
        let payload = Packet.signPayload(to: p.to, messageId: p.messageId, prekey: p.encryption.prekey,
                                         kemCiphertext: try ACEBase64.decode(p.encryption.kemCiphertext), payload: try ACEBase64.decode(p.encryption.payload))
        let early = try operationalSign(me, action: "packet", timestamp: NOW + 99, payload: payload)
        expectCode(.stalePeerBinding) {
            try verifyOperational(early, state: st, action: "packet", timestamp: NOW + 99, payload: payload, now: NOW + 100)
        }
    }

    @Test func cardRecordErc8004() throws {
        let i = try identity()
        let entry = try ERC8004Binding(agentRegistry: REGISTRY, agentId: "42")
        let native = try ERC8004Binding(agentRegistry: SOL, agentId: "Ab12")
        let bundle = try createCardRecord(identity: i, home: "https://relay.test", erc8004: [entry, native], contact: .closed, listed: false, now: NOW)
        #expect(try verifyCardBundle(bundle, now: NOW).record.erc8004 == [entry, native])
        let plain = try createCardRecord(identity: i, home: "https://relay.test", contact: .closed, listed: false, now: NOW + 1)
        #expect(try verifyCardBundle(plain, now: NOW + 1).record.erc8004 == nil)
        let bad: [JSONValue] = [
            [["agentRegistry": .string(REGISTRY), "agentId": "042"]],  // leading zero under eip155
            [["agentRegistry": .string(SOL), "agentId": "a-b"]],
            [entry.jsonValue, entry.jsonValue],
            .array((0..<5).map { ["agentRegistry": .string(REGISTRY), "agentId": .string(String($0))] }),
            [],
        ]
        for value in bad {
            var record = bundle["card"]!.objectValue!
            record["erc8004"] = value
            expectCode(.invalidAuthorization, "\(value)") { try verifyCardBundle(["kel": bundle["kel"]!, "card": .object(record)], now: NOW) }
        }
        for list in [[entry, entry], (0..<5).map { try! ERC8004Binding(agentRegistry: REGISTRY, agentId: String($0)) }, []] {
            expectCode(.invalidAuthorization, "\(list)") {
                try createCardRecord(identity: i, home: "https://relay.test", erc8004: list, contact: .closed, listed: false, now: NOW)
            }
        }
        expectCode(.invalidArgument) { try ERC8004Binding(agentRegistry: REGISTRY, agentId: "042") }
    }

    @Test func lookupCardNeedsALiveDescriptor() async throws {
        let clock = TestClock(systemClock()), relay = FakeRelay(clock: clock.fn)
        let alice = try await NetPeer.make(relay, clock: clock, configuration: NetworkConfiguration(handle: "alice", pay: [SOL], contact: .open))
        // Alice is offline past her descriptor's lifetime: her card is served, no descriptor.
        clock.now += 8 * 86_400
        for target in [alice.aceId, "@alice@\(relay.host)"] {
            let bob = try await NetPeer.make(relay, clock: clock)
            await expectCodeAsync(.unknownPeer) { try await bob.network.lookupCard(target) }
            #expect(try await bob.network.peers.pinned(alice.aceId) == nil, "\(target)")
        }
    }

    @Test func directoryDefaultLimitIsMaxInboxPage() async throws {
        let clock = TestClock(systemClock()), relay = FakeRelay(clock: clock.fn)
        let bob = try await NetPeer.make(relay, clock: clock)
        _ = try await bob.network.discover()
        _ = try await relay.client(clock: clock.fn).directory()
        #expect(relay.queries.filter { $0.path == "/v1/cards" }.map { $0.query["limit"] } == [String(ACELimits.maxInboxPage), String(ACELimits.maxInboxPage)])
    }

    @Test func strangerSourceWithDelegationExtCostsOnlyItsOwnKel() throws {
        let subj = try identity()
        let creds = try (0..<4).map { _ in try createDelegationCredential(issuer: try identity(), subject: subj.getACEId(), now: NOW).jsonValue }
        let s = try source(subj, profiles: [ProfileManifest.delegation.ref], ext: [delegationProfileId: ["credentials": .array(creds)]]).source
        try checkStrangerSource(s)
        var long = s.objectValue!
        long["kel"] = .array(Array(repeating: s["kel"]!.arrayValue![0], count: 33))
        expectCode(.notPermitted) { try checkStrangerSource(.object(long)) }
    }

    @Test func extSizeBoundIs32768() throws {
        let subj = try identity()
        let big = ProfileRef(id: "x:big:1", digest: String(repeating: "0", count: 64))
        // {"x:big:1":{"v":"…"}} is 20 bytes around the string
        expectCode(.invalidAuthorization) {
            try source(subj, profiles: [big], ext: ["x:big:1": ["v": .string(String(repeating: "a", count: 32768 - 19))]])
        }
        #expect(try source(subj, profiles: [big], ext: ["x:big:1": ["v": .string(String(repeating: "a", count: 32768 - 20))]]).descriptor.ext != nil)
    }
}
