import CryptoKit
import Foundation
import Testing
@testable import ACE

@Suite struct WebhookTests {
    let secret = "0123456789abcdef0123456789abcdef"
    let ts = 1741000000
    let ace = "ace:sha256:" + String(repeating: "a", count: 64)
    var body: String { "{\"event\":\"message\",\"aceId\":\"\(ace)\",\"streamId\":\"1741000000000-0\"}" }

    func sig(secret: String? = nil, ts: Int? = nil, body: String? = nil, prefix: String = "sha256=") -> String {
        let key = SymmetricKey(data: Data((secret ?? self.secret).utf8))
        var mac = HMAC<SHA256>(key: key)
        mac.update(data: Data("\(ts ?? self.ts).".utf8))
        mac.update(data: Data((body ?? self.body).utf8))
        return prefix + mac.finalize().map { String(format: "%02x", $0) }.joined()
    }

    @Test func payloads() throws {
        let put = RelayAuthRequest.webhook(.put(url: "https://example.com/h", secret: secret))
        #expect(put.action == "webhook")
        #expect(put.payload() == ACESigning.encodePayload("PUT", "https://example.com/h", secret))
        #expect(RelayAuthRequest.webhook(.get).payload() == ACESigning.encodePayload("GET", "", ""))
        try put.validate()
    }

    @Test func rejects() {
        for req in [
            RelayAuthRequest.webhook(.put(url: "http://example.com", secret: secret)),
            .webhook(.put(url: "https://example.com", secret: "short")),
            .webhook(.put(url: "https://example.com", secret: String(repeating: "x", count: 129))),
        ] {
            #expect(code { try req.validate() } == .invalidArgument)
        }
        // control characters in the secret are rejected
        for bad in ["0123456789abcdef\u{0}", "0123456789abcdef\n", "0123456789abcdef\u{7F}"] {
            #expect(!isWebhookSecret(bad))
            #expect(code { try RelayAuthRequest.webhook(.put(url: "https://example.com", secret: bad)).validate() } == .invalidArgument)
        }
    }

    @Test func multibyteSecretCountsScalars() throws {
        for s in [String(repeating: "\u{E9}", count: 16), String(repeating: "\u{1F600}", count: 16)] {
            #expect(s.unicodeScalars.count == 16 && s.utf8.count > 16)
            #expect(isWebhookSecret(s))
            #expect(code { try RelayAuthRequest.webhook(.put(url: "https://example.com", secret: s)).validate() } == nil)
        }
        #expect(!isWebhookSecret(String(repeating: "\u{E9}", count: 15)))
    }

    @Test func verifyOK() throws {
        let n = try verifyWebhookNotification(secret: secret, timestamp: String(ts), signature: sig(), body: Data(body.utf8), clock: { ts + 10 })
        #expect(n.aceId == ace)
        #expect(n.streamId == "1741000000000-0")
    }

    /// Verify the fixture notification, overriding one input at a time; `nil` on success.
    func verify(timestamp: String? = nil, signature: String? = nil, body: String? = nil,
                now: Int? = nil, window: Int = ACELimits.timestampWindowSeconds) -> ACEError.Code? {
        code {
            _ = try verifyWebhookNotification(
                secret: secret, timestamp: timestamp ?? String(ts), signature: signature ?? sig(body: body),
                body: Data((body ?? self.body).utf8), clock: { [ts] in now ?? ts }, windowSeconds: window)
        }
    }

    @Test func verifyRejects() {
        #expect(verify(signature: sig(secret: "wrong-secret-wrong-secret")) == .invalidSignature)
        #expect(verify(signature: sig(prefix: "sha1=")) == .invalidSignature)
        #expect(verify(signature: sig().uppercased()) == .invalidSignature)
        #expect(verify(now: ts + 301) == .staleTimestamp)
        #expect(verify(timestamp: "nope") == .invalidArgument)
        #expect(verify(body: "{\"event\":\"message\",\"aceId\":\"\(ace)\"}") == .invalidArgument)
        #expect(verify(window: -1) == .invalidArgument)
        #expect(verify(window: 0) == nil)
        let twenty = String(repeating: "9", count: 20)
        for (streamId, expected) in [("\(twenty)-\(twenty)", nil), ("9\(twenty)-0", ACEError.Code.invalidArgument), ("0-9\(twenty)", .invalidArgument)] {
            #expect(verify(body: "{\"event\":\"message\",\"aceId\":\"\(ace)\",\"streamId\":\"\(streamId)\"}") == expected)
        }
    }
    /// `nil` only on success; a non-`ACEError` maps to a sentinel so `== nil` cannot pass vacuously.
    func code(_ f: () throws -> Void) -> ACEError.Code? {
        do { try f(); return nil } catch let e as ACEError { return e.code } catch { return Self.nonACEError }
    }
    static let nonACEError = ACEError.Code.storageFailed

    struct OtherError: Error {}

    @Test func codeHelperSentinel() {
        #expect(code { throw OtherError() } != nil)
        #expect(code { throw OtherError() } == Self.nonACEError)
        #expect(code {} == nil)
    }

    @Test func timestampHeaderShape() {
        for t in ["\(ts)\n", "0\(ts)", " \(ts)", "+\(ts)", ""] {
            #expect(verify(timestamp: t) == .invalidArgument)
        }
    }

    @Test func windowBoundary() {
        for d in [300, -300] { #expect(verify(now: ts + d) == nil) }
        for d in [301, -301] { #expect(verify(now: ts + d) == .staleTimestamp) }
        #expect(verify(now: ts + 10, window: 10) == nil)
        #expect(verify(now: ts + 11, window: 10) == .staleTimestamp)
    }

    @Test func isWithinWindowHelper() {
        #expect(isWithinWindow(now: 10, ts: 0, window: 10) && isWithinWindow(now: 0, ts: 10, window: 10))
        #expect(!isWithinWindow(now: 11, ts: 0, window: 10) && !isWithinWindow(now: 0, ts: 0, window: -1))
        #expect(!isWithinWindow(now: Int.min, ts: 0, window: Int.max))
        #expect(!isWithinWindow(now: Int.min, ts: 1, window: Int.max))
        #expect(!isWithinWindow(now: Int.max, ts: -1, window: Int.max))
        #expect(isWithinWindow(now: Int.max, ts: 0, window: Int.max))
    }

    @Test func streamIdsAreBoundedEverywhere() {
        let twenty = String(repeating: "9", count: 20)
        #expect(isStreamCursor("\(twenty)-\(twenty)") && isStreamCursor("0-0"))
        for bad in ["9\(twenty)-0", "0-9\(twenty)", "-0", "0-", "1-2-3", "\u{0661}-0", "+1-0"] { #expect(!isStreamCursor(bad)) }
        #expect(code { try RelayAuthRequest.listen(since: "9\(twenty)-0").validate() } == .invalidArgument)
    }

    @Test func windowSecondsRangeIsShared() {
        #expect(code { try checkWindowSeconds(maxSafeInteger) } == nil)
        for w in [-1, maxSafeInteger + 1] { #expect(code { try checkWindowSeconds(w) } == .invalidArgument) }
    }

    @Test func clockIsClampedToWireRange() {
        #expect(wireNow { Int.min } == 0 && wireNow { -1 } == 0 && wireNow { ts } == ts)
        #expect(wireNow { Int.max } == maxSafeInteger && wireClock { Int.max }() == maxSafeInteger)
        #expect(windowFloor(now: 100) == 0 && windowFloor(now: ts) == ts - 300 && windowFloor(now: ts, window: 10) == ts - 10)
    }

    @Test func replayAndAdoptWithExtremeClocks() throws {
        let ace = "ace:sha256:" + String(repeating: "b", count: 64)
        let reg = try Fixtures.agent("alice").toRegistrationFile(name: "X", endpoint: "https://x.example/ace")
        let peer = try verifyRegistrationFile(try RegistrationFile(json: try JSONEncoder().encode(reg)), pinnedAt: 1741000000)
        for (extreme, expected) in [(Int.min, ACEError.Code.invalidPeer), (Int.max, nil)] {
            let r = try ReplayDetector(clock: { extreme })
            // `commit` derives its default floor from the clamped clock.
            _ = try r.commit("m1", from: ace, timestamp: 1741000000)
            #expect(code { _ = try adoptDecision(pin: nil, candidate: peer, now: wireNow { extreme }) } == expected)
        }
    }

    @Test func extremeClocksReadAsWireRangeEnds() {
        // Int.min reads as 0 and Int.max as 2^53 − 1: stale against a current timestamp, fresh at the ends.
        for c in [Int.min, Int.max] { #expect(verify(now: c) == .staleTimestamp) }
        #expect(verify(timestamp: "0", signature: sig(ts: 0), now: Int.min) == nil)
        #expect(verify(timestamp: String(maxSafeInteger), signature: sig(ts: maxSafeInteger), now: Int.max) == nil)
        #expect(verify(now: Int.min, window: maxSafeInteger) == nil)
    }

    @Test func timestampSafeIntegerBound() {
        #expect(verify(timestamp: String(maxSafeInteger), signature: sig(ts: maxSafeInteger), now: maxSafeInteger) == nil)
        for t in ["9007199254740992", "9007199254740993", "9999999999999999"] {
            #expect(verify(timestamp: t) == .invalidArgument)
        }
        #expect(verify(window: maxSafeInteger + 1) == .invalidArgument)
    }

    @Test func checkOrder() {
        let badSig = "sha256=" + String(repeating: "Z", count: 64)
        let wrongSig = sig(secret: "wrong-secret-wrong-secret")
        // malformed timestamp wins over a malformed signature
        #expect(verify(timestamp: "nope", signature: badSig) == .invalidArgument)
        #expect(verify(timestamp: "9007199254740993", signature: badSig) == .invalidArgument)
        // malformed signature wins over a bad windowSeconds and over staleness
        #expect(verify(signature: badSig, window: -1) == .invalidSignature)
        #expect(verify(signature: badSig, now: ts + 301) == .invalidSignature)
        // well-formed but wrong HMAC: staleness is reported first
        #expect(verify(signature: wrongSig, now: ts + 301) == .staleTimestamp)
        // bad windowSeconds wins over staleness and a wrong HMAC
        #expect(verify(signature: wrongSig, now: ts + 301, window: -1) == .invalidArgument)
    }
}
