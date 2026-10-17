//
//  ArchitectureTests.swift
//  ACE SDK
//
//  Mechanism-level fixes (parity with sdk-ts tests/architecture.test.ts): the caching predicate includes the subject's
//  usability, one held permit per issuer, accepting a held request whose source expired, KEL verification resumed from
//  a verified prefix, and the O(1) canonical Base64 check.
//

import Foundation
import Testing
@testable import ACE

@Suite struct ArchitectureTests {
    /// 04 § Caching + 01 § Verifier rules 5: a cached descriptor whose subject delegation passed `notAfter` is stale.
    @Test func cachedDescriptorOfAnUnusableIdentityIsStale() async throws {
        let clock = TestClock(systemClock()), relay = FakeRelay(clock: clock.fn)
        let alice = try await NetPeer.make(relay, clock: clock)
        let bob = try await NetPeer.make(relay, clock: clock)
        clock.now += 10
        try bob.identity.delegate(now: clock.now, notAfter: clock.now + 3600)
        try await alice.network.importAgent(try await bob.network.publish(force: true).source)
        #expect(try await alice.network.peers.usableAgent(bob.aceId) != nil)
        clock.now += 3601  // the descriptor is unexpired, the subject's signing key is not
        #expect(try await alice.network.peers.usableAgent(bob.aceId) == nil)
        await #expect(throws: ACEError.self) { _ = try await alice.network.agent(bob.aceId) }
        await alice.network.close()
        await bob.network.close()
    }

    /// 05 § Flow step 3: a held request (24 h) that outlived its source descriptor is still accepted.
    @Test func acceptRefreshesAnExpiredSourceWithTheRequesterPermit() async throws {
        let clock = TestClock(systemClock()), relay = FakeRelay(clock: clock.fn)
        let alice = try await NetPeer.make(relay, clock: clock)
        let bob = try await NetPeer.make(relay, clock: clock, configuration: NetworkConfiguration(visibility: .private))
        let first = try await bob.network.publish()
        clock.now = first.descriptor.expiresAt - 3601  // publish still reuses it (more than an hour left)
        try await bob.network.connect(alice.aceId, profile: "ace:text:1")
        _ = try await alice.network.pull()
        let held = try #require(try await alice.network.requests().first)
        #expect(held.source["descriptor"]?["expiresAt"]?.wireInt == first.descriptor.expiresAt)
        clock.now += 7200
        try await bob.network.publish()
        try await alice.network.accept(bob.aceId)
        _ = try await bob.network.pull()
        #expect(try bob.network.admission.get(alice.aceId)?.state == .admitted)
        await alice.network.close()
        await bob.network.close()
    }

    @Test func heldPermitIsTheNewestByIssuedAtUnlessKept() throws {
        let issuer = try makeIdentity(), me = try makeIdentity()
        let table = AdmissionTable(store: MemoryStore())
        let state = try checkUsable(issuer, now: NOW)
        func permit(_ at: Int, _ lifetime: Int = ACELimits.maxPermitSeconds) throws -> VerifiedPermit {
            try verifyPermit(try createPermit(identity: issuer, subject: me.getACEId(), now: at, lifetime: lifetime), issuer: state, subject: me.getACEId(), now: NOW + 10)
        }
        let older = try permit(NOW), newer = try permit(NOW + 10, 60)  // issued later, expires earlier
        try table.holdPermit(newer)
        try table.holdPermit(older)
        #expect(try table.heldPermit(issuer.getACEId())?["issuedAt"] == newer.value["issuedAt"])
        try table.holdPermit(older, keep: { _ in false })  // the caller found the held one invalid
        #expect(try table.heldPermit(issuer.getACEId())?["issuedAt"] == older.value["issuedAt"])
        try table.holdPermit(newer, when: { $0?.state == .admitted })  // no row: not held
        #expect(try table.heldPermit(issuer.getACEId())?["issuedAt"] == older.value["issuedAt"])
    }

    @Test func kelVerificationResumedFromAPrefixStillChecksEverySignature() throws {
        let id = try makeIdentity()
        let prefix = try id.getKel()
        _ = try ACEKel.verify(prefix, now: NOW)  // cached
        try id.delegate(now: NOW + 10, notAfter: nil)
        let full = try id.getKel()
        #expect(try ACEKel.verify(full, now: NOW + 10).seq == full.count - 1)
        // a forged signature on the new event is rejected although its prefix is cached
        var forged = full
        forged[forged.count - 1]["sig"] = full[0]["sig"]
        #expect(throws: ACEError.self) { try ACEKel.verify(forged, now: NOW + 10) }
        // another signature on a cached prefix event is not that prefix: verified from scratch, and rejected
        var tampered = full
        tampered[0]["sig"] = full[full.count - 1]["sig"]
        #expect(throws: ACEError.self) { try ACEKel.verify(tampered, now: NOW + 10) }
    }

    @Test func nonCanonicalBase64PaddingBitsAreRejected() throws {
        #expect(try decodeB64("AA==", code: .invalidArgument, what: "v") == Data([0]))
        #expect(try decodeB64("AAA=", code: .invalidArgument, what: "v") == Data([0, 0]))
        expectCode(.invalidArgument) { try decodeB64("AB==", code: .invalidArgument, what: "v") }
        expectCode(.invalidArgument) { try decodeB64("AAB=", code: .invalidArgument, what: "v") }
    }
}
