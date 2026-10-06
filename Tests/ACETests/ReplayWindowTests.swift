import Foundation
import Testing
@testable import ACE

/// Replay horizon end to end: online future drift and offline backlog.
struct ReplayWindowTests {
    static let t = 1_800_000_000
    let alice: SoftwareIdentity
    let bob: SoftwareIdentity

    init() throws {
        alice = try SoftwareIdentity.generate(scheme: .ed25519)
        bob = try SoftwareIdentity.generate(scheme: .ed25519)
    }

    func message(_ timestamp: Int) throws -> ACEMessage {
        try createMessage(CreateMessageOptions(sender: alice, recipientPubKey: bob.getEncryptionPublicKey(),
            recipientACEId: bob.getACEId(), type: .text, body: ["message": "offline"],
            stateMachine: ThreadStateMachine(), timestamp: timestamp))
    }

    @discardableResult
    func parse(_ msg: ACEMessage, _ store: ReplayDetector, now: Int = t, oldestTimestamp: Int? = nil) throws -> ParsedMessage {
        var opts = ParseMessageOptions(stateMachine: ThreadStateMachine(), replayDetector: store, oldestTimestamp: oldestTimestamp)
        opts.currentTimestamp = now
        return try parseMessage(msg, receiver: bob, senderSigningPubKey: alice.getSigningPublicKey(), opts: opts)
    }

    /// A store that has been running since before the receiver went offline.
    func runningStore(capacity: Int = 100_000) -> ReplayDetector {
        ReplayDetector(capacity: capacity, horizon: Self.t - 7200)
    }

    func expectReplay(_ body: () throws -> Void) {
        #expect { try body() } throws: { error in
            if case ACEError.replayDetected = error { return true }
            return false
        }
    }

    @Test func onlineMaxFutureDriftMessageCannotBeReplayedAfterFiveMinutes() throws {
        let store = ReplayDetector(capacity: 100_000, horizon: Self.t - maxDriftSeconds)
        let msg = try message(Self.t + 300)
        try parse(msg, store)
        expectReplay { try parse(msg, store, now: Self.t + 450) }
    }

    @Test func offlineFloorAdmitsBacklogOnceAndRejectsFutureOrTooOld() throws {
        let store = runningStore()
        let floor = Self.t - 7200
        let old = try message(Self.t - 3600)
        #expect(throws: ACEError.self) { try parse(old, store) }
        #expect(try parse(old, store, oldestTimestamp: floor).body["message"] as? String == "offline")
        expectReplay { try parse(old, store, oldestTimestamp: floor) }
        for timestamp in [Self.t + 3600, Self.t - 7201] {
            #expect(throws: ACEError.self) { try parse(message(timestamp), store, oldestTimestamp: floor) }
        }
    }

    @Test func freshStoreRejectsBacklogItCannotVouchFor() throws {
        let store = ReplayDetector(capacity: 100_000, horizon: Self.t - maxDriftSeconds)
        let old = try message(Self.t - 3600)
        expectReplay { try parse(old, store, oldestTimestamp: Self.t - 7200) }
    }

    @Test func backlogEvictedAtCapacityCannotBeReplayed() throws {
        let store = runningStore(capacity: 1)
        let floor = Self.t - 7200
        let a = try message(Self.t - 3600), b = try message(Self.t - 1800)
        try parse(a, store, oldestTimestamp: floor)
        try parse(b, store, oldestTimestamp: floor)
        expectReplay { try parse(a, store, oldestTimestamp: floor) }
    }

    @Test func backlogEvictedByOnlineFloorCannotBeReplayed() throws {
        let store = runningStore()
        let floor = Self.t - 7200
        let backlog = try message(Self.t - 3600), fresh = try message(Self.t)
        try parse(backlog, store, oldestTimestamp: floor)
        try parse(fresh, store)
        #expect(store.horizon == Self.t - 3600)
        expectReplay { try parse(backlog, store, oldestTimestamp: floor) }
    }
}
