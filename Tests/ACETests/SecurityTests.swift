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

    // MARK: - Replay Detector

    @Test("accepts new message, rejects replay")
    func replayDetection() {
        let detector = ReplayDetector(capacity: 10)
        #expect(detector.checkAndReserve("msg-1"))
        #expect(!detector.checkAndReserve("msg-1")) // replay
        #expect(detector.checkAndReserve("msg-2"))
    }

    @Test("FIFO eviction at capacity")
    func fifoEviction() {
        let detector = ReplayDetector(capacity: 3)
        #expect(detector.checkAndReserve("a"))
        #expect(detector.checkAndReserve("b"))
        #expect(detector.checkAndReserve("c"))
        // At capacity — next insert evicts oldest ("a")
        #expect(detector.checkAndReserve("d"))
        #expect(detector.checkAndReserve("a")) // "a" was evicted, so it's new again
        // "a" evicted "b", so "b" should be accepted as new
        #expect(detector.checkAndReserve("b"))
    }

    @Test("release allows re-processing")
    func release() {
        let detector = ReplayDetector(capacity: 10)
        #expect(detector.checkAndReserve("msg-1"))
        detector.release("msg-1")
        #expect(detector.checkAndReserve("msg-1")) // released, so new again
    }

    @Test("export/import roundtrip")
    func exportImport() {
        let detector = ReplayDetector(capacity: 100)
        _ = detector.checkAndReserve("a")
        _ = detector.checkAndReserve("b")
        _ = detector.checkAndReserve("c")

        let exported = detector.export()
        #expect(exported.count == 3)

        let restored = ReplayDetector.fromExport(exported)
        #expect(!restored.checkAndReserve("a"))
        #expect(!restored.checkAndReserve("b"))
        #expect(!restored.checkAndReserve("c"))
        #expect(restored.checkAndReserve("d"))
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
                ephemeralPubKey: ACEBase64.encode(Data(repeating: 1, count: 32)),
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
                    opts: ParseMessageOptions(stateMachine: ThreadStateMachine())
                )
                return false
            } catch ACEError.payloadTooLarge(let size) {
                return size > ACEEncryption.maxPayloadSize
            } catch {
                return false
            }
        }()

        #expect(rejected)
    }
}
