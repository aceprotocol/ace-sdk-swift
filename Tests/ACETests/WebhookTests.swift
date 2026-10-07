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
        let put = RelayAuthRequest.webhook(method: .put, url: "https://example.com/h", secret: secret)
        #expect(put.action == "webhook")
        #expect(put.payload() == ACESigning.encodePayload("PUT", "https://example.com/h", secret))
        #expect(RelayAuthRequest.webhook(method: .get).payload() == ACESigning.encodePayload("GET", "", ""))
        try put.validate()
    }

    @Test func rejects() {
        for req in [
            RelayAuthRequest.webhook(method: .put, url: "http://example.com", secret: secret),
            .webhook(method: .put, url: "https://example.com", secret: "short"),
            .webhook(method: .put, url: "https://example.com", secret: String(repeating: "x", count: 129)),
            .webhook(method: .get, url: "https://example.com"),
            .webhook(method: .delete, secret: secret),
        ] {
            #expect(code { try req.validate() } == .invalidArgument)
        }
        // control characters in the secret are rejected
        for bad in ["0123456789abcdef\u{0}", "0123456789abcdef\n", "0123456789abcdef\u{7F}"] {
            #expect(!isWebhookSecret(bad))
            #expect(code { try RelayAuthRequest.webhook(method: .put, url: "https://example.com", secret: bad).validate() } == .invalidArgument)
        }
    }

    @Test func multibyteSecretCountsScalars() throws {
        for s in [String(repeating: "\u{E9}", count: 16), String(repeating: "\u{1F600}", count: 16)] {
            #expect(s.unicodeScalars.count == 16 && s.utf8.count > 16)
            #expect(isWebhookSecret(s))
            #expect(code { try RelayAuthRequest.webhook(method: .put, url: "https://example.com", secret: s).validate() } == nil)
        }
        #expect(!isWebhookSecret(String(repeating: "\u{E9}", count: 15)))
    }

    @Test func verifyOK() throws {
        let n = try verifyWebhookNotification(secret: secret, timestamp: String(ts), signature: sig(), body: Data(body.utf8), clock: { ts + 10 })
        #expect(n.aceId == ace)
        #expect(n.streamId == "1741000000000-0")
    }

    @Test func verifyRejects() {
        #expect(code { _ = try verifyWebhookNotification(secret: secret, timestamp: String(ts), signature: sig(secret: "wrong-secret-wrong-secret"), body: Data(body.utf8), clock: { ts }) } == .invalidSignature)
        #expect(code { _ = try verifyWebhookNotification(secret: secret, timestamp: String(ts), signature: sig(prefix: "sha1="), body: Data(body.utf8), clock: { ts }) } == .invalidSignature)
        #expect(code { _ = try verifyWebhookNotification(secret: secret, timestamp: String(ts), signature: sig().uppercased(), body: Data(body.utf8), clock: { ts }) } == .invalidSignature)
        #expect(code { _ = try verifyWebhookNotification(secret: secret, timestamp: String(ts), signature: sig(), body: Data(body.utf8), clock: { ts + 301 }) } == .staleTimestamp)
        #expect(code { _ = try verifyWebhookNotification(secret: secret, timestamp: "nope", signature: sig(), body: Data(body.utf8), clock: { ts }) } == .invalidArgument)
        let noStream = "{\"event\":\"message\",\"aceId\":\"\(ace)\"}"
        #expect(code { _ = try verifyWebhookNotification(secret: secret, timestamp: String(ts), signature: sig(body: noStream), body: Data(noStream.utf8), clock: { ts }) } == .invalidArgument)
        #expect(code { _ = try verifyWebhookNotification(secret: secret, timestamp: String(ts), signature: sig(), body: Data(body.utf8), clock: { ts }, windowSeconds: -1) } == .invalidArgument)
        #expect(code { _ = try verifyWebhookNotification(secret: secret, timestamp: String(ts), signature: sig(), body: Data(body.utf8), clock: { ts }, windowSeconds: 0) } == nil)
        let twenty = String(repeating: "9", count: 20)
        for (streamId, expected) in [("\(twenty)-\(twenty)", nil), ("9\(twenty)-0", ACEError.Code.invalidArgument), ("0-9\(twenty)", .invalidArgument)] {
            let b = "{\"event\":\"message\",\"aceId\":\"\(ace)\",\"streamId\":\"\(streamId)\"}"
            #expect(code { _ = try verifyWebhookNotification(secret: secret, timestamp: String(ts), signature: sig(body: b), body: Data(b.utf8), clock: { ts }) } == expected)
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
            #expect(code { _ = try verifyWebhookNotification(secret: secret, timestamp: t, signature: sig(), body: Data(body.utf8), clock: { ts }) } == .invalidArgument)
        }
        #expect("0\(ts)" == "01741000000")
    }

    @Test func windowBoundary() {
        let b = Data(body.utf8)
        for d in [300, -300] {
            #expect(code { _ = try verifyWebhookNotification(secret: secret, timestamp: String(ts), signature: sig(), body: b, clock: { ts + d }) } == nil)
        }
        for d in [301, -301] {
            #expect(code { _ = try verifyWebhookNotification(secret: secret, timestamp: String(ts), signature: sig(), body: b, clock: { ts + d }) } == .staleTimestamp)
        }
        #expect(code { _ = try verifyWebhookNotification(secret: secret, timestamp: String(ts), signature: sig(), body: b, clock: { ts + 10 }, windowSeconds: 10) } == nil)
        #expect(code { _ = try verifyWebhookNotification(secret: secret, timestamp: String(ts), signature: sig(), body: b, clock: { ts + 11 }, windowSeconds: 10) } == .staleTimestamp)
    }

    @Test func isWithinWindowHelper() {
        #expect(isWithinWindow(now: 10, ts: 0, window: 10) && isWithinWindow(now: 0, ts: 10, window: 10))
        #expect(!isWithinWindow(now: 11, ts: 0, window: 10) && !isWithinWindow(now: 0, ts: 0, window: -1))
        #expect(!isWithinWindow(now: Int.min, ts: 0, window: Int.max))
        #expect(!isWithinWindow(now: Int.min, ts: 1, window: Int.max))
        #expect(!isWithinWindow(now: Int.max, ts: -1, window: Int.max))
        #expect(isWithinWindow(now: Int.max, ts: 0, window: Int.max))
    }

    @Test func clampedArithmetic() {
        #expect(clampedAdd(1741000000, 300) == 1741000300 && clampedSub(1741000000, 300) == 1740999700)
        #expect(clampedAdd(-5, 3) == -2 && clampedSub(-5, -3) == -2)
        #expect(clampedAdd(Int.max, 1) == Int.max && clampedAdd(Int.min, -1) == Int.min)
        #expect(clampedSub(Int.min, 1) == Int.min && clampedSub(Int.max, -1) == Int.max)
        #expect(clampedSub(0, Int.min) == Int.max && clampedAdd(Int.max - 300, 300) == Int.max)
    }

    @Test func replayAndAdoptWithExtremeClocks() throws {
        let ace = "ace:sha256:" + String(repeating: "b", count: 64)
        for extreme in [Int.min, Int.max] {
            let r = try ReplayDetector(clock: { extreme })
            // `commit` derives its default floor from the clock (saturating, clamped at 0).
            _ = try r.commit("m1", from: ace, timestamp: 1741000000)
            let reg = try Fixtures.agent("alice").toRegistrationFile(name: "X", endpoint: "https://x.example/ace")
            let peer = try verifyRegistrationFile(try RegistrationFile(json: try JSONEncoder().encode(reg)), pinnedAt: 1741000000)
            if extreme == Int.max {
                #expect(code { _ = try adoptDecision(pin: nil, candidate: peer, now: extreme) } == nil)
            } else {
                #expect(code { _ = try adoptDecision(pin: nil, candidate: peer, now: extreme) } == .invalidPeer)
            }
        }
    }

    @Test func extremeClockIsStaleNotTrap() {
        let b = Data(body.utf8)
        let max = 9_007_199_254_740_991
        for t in [0, ts, max] {
            for c in [Int.min, Int.max, Int.min + 1] {
                #expect(code { _ = try verifyWebhookNotification(secret: secret, timestamp: String(t), signature: sig(ts: t), body: b, clock: { c }) } == .staleTimestamp)
                #expect(code { _ = try verifyWebhookNotification(secret: secret, timestamp: String(t), signature: sig(ts: t), body: b, clock: { c }, windowSeconds: max) } == .staleTimestamp)
            }
        }
    }

    @Test func timestampSafeIntegerBound() {
        let max = 9_007_199_254_740_991
        #expect(code { _ = try verifyWebhookNotification(secret: secret, timestamp: String(max), signature: sig(ts: max), body: Data(body.utf8), clock: { max }) } == nil)
        for t in ["9007199254740992", "9007199254740993", "9999999999999999"] {
            #expect(code { _ = try verifyWebhookNotification(secret: secret, timestamp: t, signature: sig(), body: Data(body.utf8), clock: { ts }) } == .invalidArgument)
        }
        #expect(code { _ = try verifyWebhookNotification(secret: secret, timestamp: String(ts), signature: sig(), body: Data(body.utf8), clock: { ts }, windowSeconds: max + 1) } == .invalidArgument)
    }

    @Test func checkOrder() {
        let badSig = "sha256=" + String(repeating: "Z", count: 64)
        let wrongSig = sig(secret: "wrong-secret-wrong-secret")
        let b = Data(body.utf8)
        // malformed timestamp wins over a malformed signature
        #expect(code { _ = try verifyWebhookNotification(secret: secret, timestamp: "nope", signature: badSig, body: b, clock: { ts }) } == .invalidArgument)
        #expect(code { _ = try verifyWebhookNotification(secret: secret, timestamp: "9007199254740993", signature: badSig, body: b, clock: { ts }) } == .invalidArgument)
        // malformed signature wins over a bad windowSeconds and over staleness
        #expect(code { _ = try verifyWebhookNotification(secret: secret, timestamp: String(ts), signature: badSig, body: b, clock: { ts }, windowSeconds: -1) } == .invalidSignature)
        #expect(code { _ = try verifyWebhookNotification(secret: secret, timestamp: String(ts), signature: badSig, body: b, clock: { ts + 301 }) } == .invalidSignature)
        // well-formed but wrong HMAC: staleness is reported first
        #expect(code { _ = try verifyWebhookNotification(secret: secret, timestamp: String(ts), signature: wrongSig, body: b, clock: { ts + 301 }) } == .staleTimestamp)
        // bad windowSeconds wins over staleness and a wrong HMAC
        #expect(code { _ = try verifyWebhookNotification(secret: secret, timestamp: String(ts), signature: wrongSig, body: b, clock: { ts + 301 }, windowSeconds: -1) } == .invalidArgument)
    }
}
