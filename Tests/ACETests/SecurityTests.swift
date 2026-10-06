//
//  SecurityTests.swift
//  ACE SDK
//

import Testing
import Foundation
@testable import ACE

@Suite("Security")
struct SecurityTests {

    // MARK: - Timestamp

    @Test("accepts current timestamp")
    func currentTimestamp() throws {
        let now = Int(Date().timeIntervalSince1970)
        try checkTimestampFreshness(now)
    }

    @Test("rejects stale timestamp")
    func staleTimestamp() {
        let old = Int(Date().timeIntervalSince1970) - 600
        #expect(throws: ACEError.self) {
            try checkTimestampFreshness(old)
        }
    }

    @Test("rejects extreme timestamp without overflowing")
    func extremeTimestampRejectedSafely() {
        let rejected = {
            do {
                try checkTimestampFreshness(Int.min)
                return false
            } catch ACEError.timestampNotFresh {
                return true
            } catch {
                return false
            }
        }()

        #expect(rejected)
    }

    // MARK: - Message ID

    @Test("accepts valid UUID v4")
    func validUUID() throws {
        try validateMessageId("550e8400-e29b-41d4-a716-446655440000")
    }

    @Test("rejects non-UUID")
    func invalidUUID() {
        #expect(throws: ACEError.self) {
            try validateMessageId("not-a-uuid")
        }
    }

    @Test("UUID match is case-insensitive and full-string")
    func uuidFullMatch() throws {
        try validateMessageId("550E8400-E29B-41D4-A716-446655440000")
        #expect(throws: ACEError.self) {
            try validateMessageId("550e8400-e29b-41d4-a716-446655440000\n")
        }
    }

    // MARK: - Replay Detector

    static let t = 1_800_000_000
    static func id(_ n: Int) -> String { String(format: "550e8400-e29b-41d4-a716-4466554400%02d", n) }
    static let alice = "ace:sha256:alice", mallory = "ace:sha256:mallory"
    /// A new store at time `t`.
    static func store(capacity: Int = 100_000) -> ReplayDetector {
        ReplayDetector(capacity: capacity, horizon: t - maxDriftSeconds)
    }
    /// Commit with the online floor at time `now`.
    @discardableResult
    static func commit(_ d: ReplayDetector, _ n: Int, _ ts: Int, now: Int = t, from sender: String = alice) -> Bool {
        d.commit(id(n), from: sender, timestamp: ts, floor: now - maxDriftSeconds)
    }

    @Test("new store starts with horizon = now - 5 min")
    func replayInitialHorizon() {
        let now = Int(Date().timeIntervalSince1970)
        #expect(abs(ReplayDetector().horizon - (now - maxDriftSeconds)) <= 1)
    }

    @Test("rejects duplicates and timestamps at or below the horizon")
    func replayDuplicatesAndHorizon() {
        let d = Self.store()
        #expect(Self.commit(d, 1, Self.t))
        #expect(!d.accepts(Self.id(1), from: Self.alice, timestamp: Self.t))
        #expect(!Self.commit(d, 1, Self.t))
        #expect(!d.accepts(Self.id(2), from: Self.alice, timestamp: Self.t - 300))
        #expect(d.accepts(Self.id(2), from: Self.alice, timestamp: Self.t - 299))
    }

    @Test("keeps an entry until it falls below the floor, then raises the horizon to it")
    func replayFloorEviction() {
        let d = Self.store()
        Self.commit(d, 1, Self.t + 300) // max future drift: acceptable until t + 600
        Self.commit(d, 2, Self.t + 450, now: Self.t + 450)
        #expect(!d.accepts(Self.id(1), from: Self.alice, timestamp: Self.t + 300))
        Self.commit(d, 3, Self.t + 650, now: Self.t + 650) // floor t + 350 > t + 300
        #expect(d.horizon == Self.t + 300)
        #expect(!d.accepts(Self.id(1), from: Self.alice, timestamp: Self.t + 300))
    }

    @Test("a fixed earlier floor keeps entries; only capacity removes them")
    func replayOfflineFloor() {
        // A store that has been running since before the receiver went offline.
        let d = ReplayDetector(capacity: 2, horizon: Self.t - 7200)
        _ = d.commit(Self.id(1), from: Self.alice, timestamp: Self.t - 3000, floor: Self.t - 7200)
        _ = d.commit(Self.id(2), from: Self.alice, timestamp: Self.t - 1000, floor: Self.t - 7200)
        #expect(d.horizon == Self.t - 7200)
        _ = d.commit(Self.id(3), from: Self.alice, timestamp: Self.t - 2000, floor: Self.t - 7200)
        #expect(d.horizon == Self.t - 7200)
        #expect(d.export().senderHorizons == [Self.alice: Self.t - 3000])
    }

    @Test("at capacity removes the smallest timestamp and raises only its sender's horizon")
    func replayCapacityEviction() {
        let d = Self.store(capacity: 2)
        Self.commit(d, 1, Self.t - 10)
        Self.commit(d, 2, Self.t - 50)
        Self.commit(d, 3, Self.t - 20)
        #expect(d.horizon == Self.t - 300)
        for (n, ts) in [(1, Self.t - 10), (2, Self.t - 50), (3, Self.t - 20)] {
            #expect(!d.accepts(Self.id(n), from: Self.alice, timestamp: ts))
        }
        #expect(!d.accepts(Self.id(4), from: Self.alice, timestamp: Self.t - 50))
        #expect(d.accepts(Self.id(4), from: Self.alice, timestamp: Self.t - 49))
        #expect(d.accepts(Self.id(4), from: Self.mallory, timestamp: Self.t - 50))
    }

    @Test("one sender flooding the store cannot block other senders")
    func replayFloodIsolated() {
        let d = Self.store(capacity: 3)
        for n in 1...4 { Self.commit(d, n, Self.t + 300, from: Self.mallory) }
        #expect(d.horizon == Self.t - 300)
        #expect(!d.accepts(Self.id(5), from: Self.mallory, timestamp: Self.t + 300))
        #expect(Self.commit(d, 5, Self.t))
    }

    @Test("sender horizons are bounded by capacity, folding the lowest into the horizon")
    func replaySenderHorizonsBounded() {
        let d = Self.store(capacity: 2)
        for n in 1...6 { Self.commit(d, n, Self.t + n, from: "ace:sha256:s\(n)") }
        let state = d.export()
        #expect(state.senderHorizons.count <= 2)
        #expect(d.horizon > Self.t - 300)
        for n in 1...4 {
            #expect(!d.accepts(Self.id(n), from: "ace:sha256:s\(n)", timestamp: Self.t + n))
        }
    }

    @Test("export/import roundtrip")
    func replayExportImport() throws {
        let d = Self.store()
        Self.commit(d, 1, Self.t - 10)
        Self.commit(d, 2, Self.t - 20)
        let restored = try ReplayDetector.fromExport(d.export())
        #expect(restored.horizon == d.horizon)
        #expect(!restored.accepts(Self.id(1), from: Self.alice, timestamp: Self.t - 10))
        #expect(!restored.accepts(Self.id(2), from: Self.alice, timestamp: Self.t - 20))
        #expect(restored.accepts(Self.id(3), from: Self.alice, timestamp: Self.t - 20))
    }

    @Test("fromExport over capacity removes the smallest timestamps and raises their sender horizon")
    func replayImportOverCapacity() throws {
        let entries = [(1, Self.t - 30), (2, Self.t - 10), (3, Self.t - 20)]
            .map { ReplayDetectorExport.Entry(messageId: Self.id($0.0), sender: Self.alice, timestamp: $0.1) }
        let restored = try ReplayDetector.fromExport(.init(horizon: Self.t - 300, entries: entries), capacity: 2)
        #expect(restored.horizon == Self.t - 300)
        #expect(restored.export().senderHorizons == [Self.alice: Self.t - 30])
        #expect(restored.export().entries.count == 2)
    }

    @Test("export entries encode as [messageId, sender, timestamp] arrays")
    func replayExportJSONFormat() throws {
        let state = ReplayDetectorExport(
            horizon: Self.t, senderHorizons: [Self.alice: Self.t + 1],
            entries: [.init(messageId: Self.id(1), sender: Self.alice, timestamp: Self.t + 2)]
        )
        let json = try #require(JSONSerialization.jsonObject(with: JSONEncoder().encode(state)) as? [String: Any])
        let entries = try #require(json["entries"] as? [[Any]])
        #expect(entries.count == 1)
        #expect(entries[0][0] as? String == Self.id(1))
        #expect(entries[0][1] as? String == Self.alice)
        #expect(entries[0][2] as? Int == Self.t + 2)
        #expect(try JSONDecoder().decode(ReplayDetectorExport.self, from: JSONEncoder().encode(state)) == state)

        // senderHorizons is required; entries must be exactly 3 elements
        let noSenderHorizons = #"{"horizon":1,"entries":[]}"#
        #expect(throws: DecodingError.self) { try JSONDecoder().decode(ReplayDetectorExport.self, from: Data(noSenderHorizons.utf8)) }
        let shortEntry = #"{"horizon":1,"senderHorizons":{},"entries":[["id","s"]]}"#
        #expect(throws: DecodingError.self) { try JSONDecoder().decode(ReplayDetectorExport.self, from: Data(shortEntry.utf8)) }
    }

    @Test("fromExport rejects malformed state")
    func replayImportRejectsMalformed() {
        let t = Self.t
        let bad: [ReplayDetectorExport] = [
            .init(horizon: -1, entries: []),
            .init(horizon: t, senderHorizons: ["": t], entries: []),
            .init(horizon: t, senderHorizons: [Self.alice: -1], entries: []),
            .init(horizon: t, entries: [.init(messageId: "msg-1", sender: Self.alice, timestamp: t + 1)]),
            .init(horizon: t, entries: [.init(messageId: Self.id(1), sender: "", timestamp: t + 1)]),
            .init(horizon: t, entries: [.init(messageId: Self.id(1), sender: Self.alice, timestamp: t)]),
            .init(horizon: t, senderHorizons: [Self.alice: t + 5], entries: [.init(messageId: Self.id(1), sender: Self.alice, timestamp: t + 5)]),
            .init(horizon: t, entries: [.init(messageId: Self.id(1), sender: Self.alice, timestamp: t + 1), .init(messageId: Self.id(1), sender: Self.alice, timestamp: t + 2)]),
        ]
        for state in bad {
            #expect(throws: ACEError.self) { try ReplayDetector.fromExport(state) }
        }
    }

    @Test("rejects oversized payload before Base64 decode")
    func rejectsOversizedPayloadBeforeDecode() throws {
        let sender = try SoftwareIdentity.generate(scheme: .ed25519)
        let receiver = try SoftwareIdentity.generate(scheme: .ed25519)
        let oversizedDecodedLength = ACEEncryption.maxPayloadSize + 1
        let oversizedBase64Length = ((oversizedDecodedLength + 2) / 3) * 4
        let oversizedPayload = String(repeating: "A", count: oversizedBase64Length)

        let msg = ACEMessage(
            messageId: UUID().uuidString.lowercased(),
            from: sender.getACEId(),
            to: receiver.getACEId(),
            conversationId: String(repeating: "a", count: 64),
            type: .text,
            timestamp: Int(Date().timeIntervalSince1970),
            encryption: EncryptionEnvelope(
                kemCiphertext: ACEBase64.encode(Data(repeating: 1, count: 1120)),
                payload: oversizedPayload
            ),
            signature: SignatureEnvelope(
                scheme: .ed25519,
                value: "AAAA"
            )
        )

        let rejected = {
            do {
                _ = try parseMessage(
                    msg,
                    receiver: receiver,
                    senderSigningPubKey: sender.getSigningPublicKey(),
                    opts: ParseMessageOptions(stateMachine: ThreadStateMachine(), replayDetector: ReplayDetector())
                )
                return false
            } catch ACEError.invalidMessage(let reason) {
                return reason.hasPrefix("Payload too large")
            } catch {
                return false
            }
        }()

        #expect(rejected)
    }
}
