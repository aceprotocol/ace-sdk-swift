//
//  SecureMailboxTests.swift
//  ACE SDK
//
//  The network receive boundary without an MLS engine: every path here stops before the
//  handshake (malformed bodies, static envelopes, peer policy, relay failures, cursors).
//  The full authenticated handshake runs in Engine/ (NativeMLSEngine over the session-core XCFramework).
//

import Foundation
import Testing
@testable import ACE

/// An MLS engine that is never reached.
struct UnreachableEngine: MLSEngine {
    func execute(_ command: Data) throws -> Data { throw MLSError("session_failed") }
}

@Suite("SecureMailbox")
struct SecureMailboxTests {
    /// Bob's mailbox over `relay`, with his application Inbox feeding `sink`.
    private func open(_ p: Pair, relay: RelayClient, sink: Sink = Sink()) async throws -> (SecureMailbox, Inbox) {
        let inbox = try await p.inbox(p.bob, sink)
        let secure = SecureTransport(identity: p.bob, engine: UnreachableEngine(), store: p.bobStore, clock: p.clock.fn)
        let mailbox = try SecureMailbox.open(identity: p.bob, store: p.bobStore, peers: p.bobPeers, relay: relay, secure: secure,
                                             inbox: inbox, send: { packet, _ in try await relay.send(packet); return .relay })
        return (mailbox, inbox)
    }

    /// A static application envelope to bob (never a secure delivery frame).
    private func text(_ p: Pair, _ s: String, from sender: SoftwareIdentity? = nil) async throws -> ACEMessage {
        let sender = sender ?? p.alice
        let bobPeer = try await p.alicePeers.get(p.bob.getACEId())!
        return try createMessage(sender: sender, recipient: bobPeer, type: .text, body: ["message": .string(s)],
                                 threads: try ThreadStateMachine(localAceId: sender.getACEId()), timestamp: p.clock.now)
    }

    private func request(_ env: ACEMessage) -> Data {
        JSONWriter.serialize(.object(["message": env.jvalue, "extra": .bool(true)]))
    }

    /// Refused before the application Inbox: `invalid_body` carrying the session-core code.
    private func refused(_ o: ReceiveOutcome, _ reason: String) -> Bool {
        if case .quarantined(let e, let fp) = o { return e.code == .invalidBody && e.message == reason && fp != nil }
        return false
    }

    @Test func deadlineReleasesACallerFromAnExchangeThatIgnoresCancellation() async throws {
        let start = ContinuousClock.now
        await #expect(throws: MLSError("delivery_expired")) {
            try await withDeadline(seconds: 1) {
                await withCheckedContinuation { (c: CheckedContinuation<Int, Never>) in
                    DispatchQueue.global().asyncAfter(deadline: .now() + 3) { c.resume(returning: 1) }
                }
            }
        }
        #expect(ContinuousClock.now - start < .seconds(3))
        #expect(try await withDeadline(seconds: 5) { 7 } == 7)
        await #expect(throws: MLSError("delivery_expired")) { try await withDeadline(seconds: 0) { 7 } }
    }

    @Test func pullRefusesStaticEnvelopesPagesAndAdvancesTheCursor() async throws {
        let p = try await Pair()
        let fake = FakeRelay()
        let relay = try makeRelay(fake.handle, clock: p.clock.fn)
        for i in 0..<4 { _ = fake.enqueue(try await text(p, "m\(i)")) }
        let sink = Sink()
        let (mailbox, inbox) = try await open(p, relay: relay, sink: sink)
        // Argument errors are reported, not thrown.
        #expect(await mailbox.pull(maxPages: 0).blocked == ACEError(.invalidArgument))
        #expect(await mailbox.pull(limit: 101).blocked == ACEError(.invalidArgument))
        #expect(await mailbox.cursor == nil)
        // The peer is not enabled: every entry is refused, and the cursor passes it.
        let first = await mailbox.pull(limit: 3, maxPages: 1)
        #expect(first.hasMore && first.blocked == nil && first.outcomes.count == 3 && first.quarantined == 3)
        #expect(first.outcomes.allSatisfy { refused($0, "delivery_peer_disabled") })
        #expect(await mailbox.cursor == "1741000000000-3")
        // Enabled, but a static application packet is not a secure delivery frame: no downgrade.
        try SecureTransport.setPeerAllowed(store: p.bobStore, peer: p.alice.getACEId(), allowed: true)
        let rest = await mailbox.pull(limit: 3)
        #expect(!rest.hasMore && rest.blocked == nil && rest.outcomes.count == 1 && refused(rest.outcomes[0], "secure_delivery_required"))
        #expect(await mailbox.cursor == "1741000000000-4")
        let again = await mailbox.pull()
        #expect(again.outcomes.isEmpty && again.blocked == nil && !again.hasMore)
        // Nothing reached the application Inbox; the cursor is durable under secure/cursors/.
        #expect(sink.count == 0 && first.delivered == 0 && first.messages.isEmpty)
        #expect(try p.bobStore.list(prefix: "deliveries/").isEmpty)
        #expect(try p.bobStore.list(prefix: "quarantine/").isEmpty)
        #expect(try p.bobStore.list(prefix: "secure/cursors/") == ["secure/cursors/\(sha256Hex(Data(relay.baseURLString.utf8))).json"])
        await mailbox.close()
        await inbox.close()
        // A reopened mailbox resumes from the durable cursor.
        _ = fake.enqueue(try await text(p, "m4"))
        let (reopened, inbox2) = try await open(p, relay: relay)
        #expect(await reopened.cursor == "1741000000000-4")
        let after = await reopened.pull()
        #expect(after.outcomes.count == 1)
        #expect(await reopened.cursor == "1741000000000-5")
        await reopened.close()
        await inbox2.close()
    }

    @Test func unadmittedStrangerFrameNeverResolvesOrPinsThePeer() async throws {
        let p = try await Pair()
        let fake = FakeRelay()
        let relay = try makeRelay(fake.handle, clock: p.clock.fn)
        let stranger = try SoftwareIdentity.generate(scheme: .ed25519)
        fake.add(try peerRecord(stranger, registeredAt: 1))
        let sink = Sink()
        let inbox = try await p.inbox(p.bob, sink)
        // Bob resolves peers through the relay: resolving the stranger would cost a lookup and a pin.
        let peers = try PeerStore(store: p.bobStore, relay: relay, clock: p.clock.fn)
        let secure = SecureTransport(identity: p.bob, engine: UnreachableEngine(), store: p.bobStore, clock: p.clock.fn)
        let mailbox = try SecureMailbox.open(identity: p.bob, store: p.bobStore, peers: peers, relay: relay, secure: secure,
                                             inbox: inbox, send: { packet, _ in try await relay.send(packet); return .relay })
        let pinned = try p.bobStore.list(prefix: "peers/")
        _ = fake.enqueue(try await text(p, "?", from: stranger))
        let pulled = await mailbox.pull()
        #expect(pulled.outcomes.count == 1 && pulled.blocked == nil && refused(pulled.outcomes[0], "delivery_peer_disabled"))
        let direct = await mailbox.receiveDirect(request(try await text(p, "??", from: stranger)))
        #expect(direct.status == 400 && direct.body["error"] == "delivery_peer_disabled" && direct.outcome == nil)
        #expect(!fake.requests.contains("/v1/peer"))
        #expect(try p.bobStore.list(prefix: "peers/") == pinned)
        #expect(sink.count == 0)
        // The public admission read never throws: invalid id, missing or malformed row are false.
        #expect(!SecureTransport.isPeerAllowed(store: p.bobStore, peer: stranger.getACEId()))
        #expect(!SecureTransport.isPeerAllowed(store: p.bobStore, peer: "not-an-ace-id"))
        try p.bobStore.write("secure/peers/\(sha256Hex(Data(p.alice.getACEId().utf8))).json", Data("{".utf8))
        #expect(!SecureTransport.isPeerAllowed(store: p.bobStore, peer: p.alice.getACEId()))
        try p.bobStore.delete("secure/peers/\(sha256Hex(Data(p.alice.getACEId().utf8))).json")
        try SecureTransport.setPeerAllowed(store: p.bobStore, peer: p.alice.getACEId(), allowed: true)
        #expect(SecureTransport.isPeerAllowed(store: p.bobStore, peer: p.alice.getACEId()))
        try SecureTransport.setPeerAllowed(store: p.bobStore, peer: p.alice.getACEId(), allowed: false)
        #expect(!SecureTransport.isPeerAllowed(store: p.bobStore, peer: p.alice.getACEId()))
        await mailbox.close()
        await inbox.close()
    }

    @Test func followPullsOnWakeUpAndEndsWhenTheRelayRejects() async throws {
        let p = try await Pair()
        let env = try await text(p, "live")
        let entry = Data(#"{"cursor":"5-1","messages":[{"message":"#.utf8) + env.jsonData() + Data(#","streamId":"5-1"}]}"#.utf8)
        let inboxCalls = Locked(0), listenCalls = Locked(0)
        let relay = try makeRelay({ req, _ in
            switch req.url!.path {
            case "/v1/inbox":
                // Empty backlog; the entry is served after the first wake-up, from the cursor.
                inboxCalls.mutate { $0 += 1 }
                let fromCursor = req.url!.query?.contains("since=5-1") == true
                return inboxCalls.value == 1 || fromCursor ? .json(200, ["messages": [], "cursor": NSNull()])
                                                          : StubResponse(status: 200, chunks: [entry])
            case "/v1/listen":
                // An SSE event is only a wake-up: its payload is never ingested.
                listenCalls.mutate { $0 += 1 }
                return listenCalls.value == 1 ? .sse(["id: 5-1\nevent: message\ndata: {}\n\n"]) : .error(401, "invalid_signature")
            default: return .error(404, "x")
            }
        }, clock: p.clock.fn)
        let sink = Sink()
        let (mailbox, inbox) = try await open(p, relay: relay, sink: sink)
        let live = Locked(0)
        var outcomes: [ReceiveOutcome] = []
        do {
            for try await o in mailbox.follow(onLive: { live.mutate { $0 += 1 } }) { outcomes.append(o) }
            Issue.record("expected relay_rejected")
        } catch {
            #expect(error as? ACEError == ACEError(.relayRejected))
        }
        #expect(outcomes.count == 1 && refused(outcomes[0], "delivery_peer_disabled") && live.value == 1)
        #expect(await mailbox.cursor == "5-1")
        #expect(sink.count == 0 && inboxCalls.value == 2)
        await mailbox.close()
        await inbox.close()
    }

    @Test func followThrowsWithoutGoingLiveWhenTheBacklogFetchFails() async throws {
        let p = try await Pair()
        let (mailbox, inbox) = try await open(p, relay: try makeRelay({ _, _ in .error(503, "x") }, clock: p.clock.fn))
        let live = Locked(0)
        await expectCodeAsync(.relayUnavailable) { for try await _ in mailbox.follow(onLive: { live.mutate { $0 += 1 } }) {} }
        #expect(live.value == 0)
        #expect(await mailbox.cursor == nil)
        await mailbox.close()
        await inbox.close()
    }

    @Test func receiveDirectMapsRefusalsToHTTPReplies() async throws {
        let p = try await Pair()
        let sink = Sink()
        let (mailbox, inbox) = try await open(p, relay: try makeRelay({ _, _ in .error(503, "x") }, clock: p.clock.fn), sink: sink)
        let env = try await text(p, "x")
        // 08 § Direct Delivery, Receiver: body size, then the request, then the envelope.
        let tooBig = await mailbox.receiveDirect(Data(count: ACELimits.maxDirectBodyBytes + 1))
        #expect(tooBig.status == 413 && tooBig.body == ["ok": false, "error": "payload_too_large"] && tooBig.outcome == nil)
        #expect(try JSONValue(json: tooBig.bodyData) == .object(tooBig.body))
        for (body, status, error) in [("{", 400, "invalid_argument"), (#"{"msg":{}}"#, 400, "invalid_argument"),
                                      (#"{"message":5}"#, 400, "invalid_envelope")] {
            let r = await mailbox.receiveDirect(Data(body.utf8))
            #expect(r.status == status && r.body["error"] == .string(error), "\(body): \(r.body)")
        }
        // Then peer policy and the frame: a static application envelope never reaches the Inbox.
        let disabled = await mailbox.receiveDirect(request(env))
        #expect(disabled.status == 400 && disabled.body["error"] == "delivery_peer_disabled" && disabled.outcome == nil)
        try SecureTransport.setPeerAllowed(store: p.bobStore, peer: p.alice.getACEId(), allowed: true)
        let downgrade = await mailbox.receiveDirect(request(env))
        #expect(downgrade.status == 400 && downgrade.body["error"] == "secure_delivery_required" && downgrade.outcome == nil)
        // An unadmitted stranger is refused by local policy, before any peer resolution.
        let stranger = try SoftwareIdentity.generate(scheme: .ed25519)
        let unknown = await mailbox.receiveDirect(request(try await text(p, "?", from: stranger)))
        #expect(unknown.status == 400 && unknown.body["error"] == "delivery_peer_disabled")
        #expect(sink.count == 0)
        #expect(try p.bobStore.list(prefix: "deliveries/").isEmpty)
        #expect(try p.bobStore.list(prefix: "quarantine/").isEmpty)
        // A closed mailbox is not accepting: 503 internal_error (the sender falls back to the
        // relay); 08 § Receiver puts that row before the size check.
        await mailbox.close()
        let closed = await mailbox.receiveDirect(request(env))
        #expect(closed.status == 503 && closed.body["error"] == "internal_error" && closed.outcome == nil)
        #expect(await mailbox.receiveDirect(Data(count: ACELimits.maxDirectBodyBytes + 1)).status == 503)
        await inbox.close()
    }
}
