//
//  GlueTests.swift
//  ACE SDK
//
//  The integration glue every host needs once: inboxPrincipalFromOwnRecord, openSecureMailbox,
//  deliverSecure (mirrors sdk-ts tests/glue.test.ts).
//

import Foundation
import Testing
@testable import ACE

private let ACC = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp:7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU"
private let NOW = 1_800_000_000

/// An engine that is never reached by these tests (no handshake completes); counts `close()`.
private final class StubEngine: ClosableMLSEngine, @unchecked Sendable {
    private let lock = NSLock()
    private var closes = 0
    var closed: Int { lock.withLock { closes } }
    func execute(_ command: Data) throws -> Data { throw MLSError("engine_must_not_run") }
    func close() { lock.withLock { closes += 1 } }
}

private struct Stopped: Error {}

@Suite("Glue")
struct GlueTests {
    // MARK: inboxPrincipalFromOwnRecord

    @Test func noRecordIsNoPrincipalWithoutAWarning() throws {
        let me = try SoftwareIdentity.generate(scheme: .ed25519)
        let r = inboxPrincipalFromOwnRecord(nil, identity: me)
        #expect(r.principal == nil && r.warning == nil)
    }

    @Test func validOwnRecordBindsItsAccountWithTheRecordSignerAsSelfSigner() throws {
        let owner = try SoftwareIdentity.generate(scheme: .secp256k1), me = try SoftwareIdentity.generate(scheme: .ed25519)
        let record = try createPrincipalRecord(signer: PrincipalSigner(identity: owner), subjectSigningPublicKey: me.getSigningPublicKey(),
                                               account: ACC, roles: ["controller", "delegate"], expiresAt: NOW + 3600, issuedAt: NOW - 10)
        let other = PrincipalKey(scheme: "ed25519", publicKey: "x")
        let r = inboxPrincipalFromOwnRecord(record, identity: me, now: NOW)
        #expect(r.principal == InboxPrincipal(account: ACC, selfSigner: record.signer, trustedSigners: []) && r.warning == nil)
        #expect(inboxPrincipalFromOwnRecord(record, identity: me, now: NOW, trustedSigners: [other]).principal?.trustedSigners == [other])
    }

    @Test func expiredOrForeignRecordIsNoPrincipalWithACodedWarningAndNeverThrows() throws {
        let owner = try SoftwareIdentity.generate(scheme: .ed25519), me = try SoftwareIdentity.generate(scheme: .ed25519)
        let someone = try SoftwareIdentity.generate(scheme: .ed25519)
        let expired = try createPrincipalRecord(signer: PrincipalSigner(identity: owner), subjectSigningPublicKey: me.getSigningPublicKey(),
                                                account: ACC, roles: ["delegate"], expiresAt: NOW - 50, issuedAt: NOW - 100)
        let r = inboxPrincipalFromOwnRecord(expired, identity: me, now: NOW)
        #expect(r.principal == nil)
        #expect(r.warning?.hasPrefix("invalid_principal: ") == true && r.warning?.contains("expired") == true)
        let foreign = inboxPrincipalFromOwnRecord(expired, identity: someone, now: NOW - 75)
        #expect(foreign.principal == nil && foreign.warning?.hasPrefix("invalid_principal: ") == true)
        // The wall clock is the default: the expired record is expired now too.
        #expect(inboxPrincipalFromOwnRecord(expired, identity: me).warning?.hasPrefix("invalid_principal: ") == true)
    }

    // MARK: openSecureMailbox

    @Test func oneCloseReleasesTheReceiveLockAndFreesTheEngine() async throws {
        let p = try await Pair(), engine = StubEngine()
        let relay = try makeRelay({ _, _ in .error(503, "x") }, clock: p.clock.fn)
        let mailbox = try await openSecureMailbox(identity: p.alice, store: p.aliceStore, peers: p.alicePeers, relay: relay, engine: engine,
                                                  inbox: InboxSetup(onMessage: { _ in }, clock: p.clock.fn, commerce: true), clock: p.clock.fn)
        expectCode(.receiverBusy) { try p.aliceStore.lock("receive", timeout: 0) }
        expectCode(.lockBusy) { try p.aliceStore.lock("secure-mailbox", timeout: 0) }
        #expect(engine.closed == 0)
        await mailbox.close()
        #expect(engine.closed == 1)
        try p.aliceStore.lock("receive", timeout: 0).release()
        try p.aliceStore.lock("secure-mailbox", timeout: 0).release()
        // A second close does not free the engine again.
        await mailbox.close()
        #expect(engine.closed == 1)
    }

    @Test func failureAfterTheInboxOpenedClosesItAndLeavesTheEngineToTheCaller() async throws {
        let p = try await Pair(), engine = StubEngine()
        let relay = try makeRelay({ _, _ in .error(503, "x") }, clock: p.clock.fn)
        // SecureMailbox.open refuses a corrupt persisted cursor: the failure comes after Inbox.open took `receive`.
        try p.aliceStore.write("secure/cursors/\(sha256Hex(Data(relay.baseURLString.utf8))).json",
                               JSONValue.object(["version": 1, "identity": .string(p.alice.getACEId()), "cursor": "nope"]).jsonData())
        await expectCodeAsync(.storageFailed) {
            try await openSecureMailbox(identity: p.alice, store: p.aliceStore, peers: p.alicePeers, relay: relay, engine: engine,
                                        inbox: InboxSetup(onMessage: { _ in }, clock: p.clock.fn))
        }
        #expect(engine.closed == 0)
        try p.aliceStore.lock("receive", timeout: 0).release()
        try p.aliceStore.lock("secure-mailbox", timeout: 0).release()
    }

    // MARK: deliverSecure / secureTransportFor

    private struct Staged {
        let p: Pair
        let peer: VerifiedPeer
        let secure: SecureTransport
        let outbox: Outbox
        let pending: PendingSend
    }

    private func staged() async throws -> Staged {
        let p = try await Pair()
        let peer = try await p.alicePeers.get(p.bob.getACEId())!
        try SecureTransport.setPeerAllowed(store: p.aliceStore, peer: p.bob.getACEId(), allowed: true)
        let secure = SecureTransport(identity: p.alice, engine: StubEngine(), store: p.aliceStore, clock: p.clock.fn)
        let outbox = try await p.outbox(p.alice)
        let pending = try await outbox.stage(recipient: peer, type: .text, body: ["message": "hi"])
        return Staged(p: p, peer: peer, secure: secure, outbox: outbox, pending: pending)
    }

    @Test func sendsEveryHandshakeFrameThroughTheGivenSend() async throws {
        let s = try await staged(), requests = Locked<[String]>([]), sent = Locked<[ACEMessage]>([])
        let relay = try makeRelay({ req, _ in requests.mutate { $0.append(req.url!.path) }; return .error(503, "x") }, clock: s.p.clock.fn)
        do {
            try await deliverSecure(s.outbox, s.pending.requestId, identity: s.p.alice, secure: s.secure, relay: relay, peer: s.peer,
                                    send: { packet, _ in sent.mutate { $0.append(packet) }; throw Stopped() })
            Issue.record("expected the frame transport to stop the delivery")
        } catch is Stopped {}
        #expect(sent.value.count == 1)
        #expect(sent.value.first?.from == s.p.alice.getACEId() && sent.value.first?.to == s.p.bob.getACEId())
        #expect(sent.value.first?.messageId != s.pending.message.messageId)   // a frame, not the application envelope
        #expect(requests.value.isEmpty)   // the relay is not used for frames, and no reply was read
        // The operation stays pending under its requestId.
        #expect(try await s.outbox.pending().map(\.requestId) == [s.pending.requestId])
        try await s.secure.close()
    }

    @Test func defaultsToRelaySendAndResolvesOnlyThroughOutboxDeliver() async throws {
        let s = try await staged(), requests = Locked<[String]>([])
        let relay = try makeRelay({ req, _ in requests.mutate { $0.append(req.url!.path) }; return .error(503, "x") }, clock: s.p.clock.fn)
        let transport = secureTransportFor(identity: s.p.alice, secure: s.secure, relay: relay, peer: s.peer)
        await expectCodeAsync(.relayUnavailable) { try await transport(s.pending.message) }
        #expect(requests.value == ["/v1/send"])
        await expectCodeAsync(.invalidArgument) {
            try await deliverSecure(s.outbox, "", identity: s.p.alice, secure: s.secure, relay: relay, peer: s.peer)
        }
        #expect(requests.value == ["/v1/send"])
        try await s.secure.close()
    }

    // MARK: public store-key validators

    @Test func checkKeyAndCheckLockNameAreTheStoreContract() throws {
        #expect(try checkKey("secure/in/a.json") == "secure/in/a.json")
        #expect(try checkLockName("receive") == "receive")
        for bad in ["", "/x", "A", "a//b", "a/", String(repeating: "a", count: 201)] {
            expectCode(.invalidArgument) { try checkKey(bad) }
        }
        for bad in ["", "a/b", "A", String(repeating: "a", count: 65)] {
            expectCode(.invalidArgument) { try checkLockName(bad) }
        }
    }
}
