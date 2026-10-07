import Foundation
import Testing
@testable import ACE

/// The shared cross-language vectors (`ace-spec/test-vectors.json`, version 3).
enum Fixtures {
    nonisolated(unsafe) static let root: [String: Any] = {
        let url = Bundle.module.url(forResource: "test-vectors", withExtension: "json", subdirectory: "Fixtures")!
        return try! JSONSerialization.jsonObject(with: Data(contentsOf: url)) as! [String: Any]
    }()

    static var vectors: [String: Any] { root["vectors"] as! [String: Any] }
    static var agents: [String: Any] { root["agents"] as! [String: Any] }

    static func agentInfo(_ name: String) -> [String: Any] { agents[name] as! [String: Any] }

    static func agent(_ name: String) -> SoftwareIdentity {
        let a = agentInfo(name)
        return try! SoftwareIdentity(export: SoftwareIdentityExport(
            scheme: SigningScheme(rawValue: a["scheme"] as! String)!,
            signingPrivateKey: a["signingPrivateKey"] as! String,
            encryptionPrivateKey: a["encryptionPrivateKey"] as! String
        ))
    }
}

func json(_ object: Any) -> Data {
    try! JSONSerialization.data(withJSONObject: object, options: [.fragmentsAllowed])
}

/// A Foundation JSON object as a body.
func jsonBody(_ object: Any) -> [String: JSONValue] {
    try! JSONValue(json: json(object)).objectValue!
}

func jvalue(_ object: Any) -> JValue {
    try! JSONParser.parse(json(object))
}

func hex(_ s: String) -> Data { hexDecode(s)! }

/// A registration-file peer for a local identity.
func peerOf(_ identity: SoftwareIdentity, pinnedAt: Int = 0) throws -> VerifiedPeer {
    try verifyRegistrationFile(try identity.toRegistrationFile(name: "Peer", endpoint: "https://peer.example/ace"), pinnedAt: pinnedAt)
}

/// Expect an `ACEError` with `code`.
func expectCode<T>(_ code: ACEError.Code, sourceLocation: SourceLocation = #_sourceLocation, _ body: () throws -> T) {
    do {
        _ = try body()
        Issue.record("expected \(code.rawValue), got success", sourceLocation: sourceLocation)
    } catch let e as ACEError {
        #expect(e.code == code, "expected \(code.rawValue), got \(e)", sourceLocation: sourceLocation)
    } catch {
        Issue.record("expected ACEError \(code.rawValue), got \(error)", sourceLocation: sourceLocation)
    }
}

func expectCodeAsync<T>(_ code: ACEError.Code, sourceLocation: SourceLocation = #_sourceLocation, _ body: () async throws -> T) async {
    do {
        _ = try await body()
        Issue.record("expected \(code.rawValue), got success", sourceLocation: sourceLocation)
    } catch let e as ACEError {
        #expect(e.code == code, "expected \(code.rawValue), got \(e)", sourceLocation: sourceLocation)
    } catch {
        Issue.record("expected ACEError \(code.rawValue), got \(error)", sourceLocation: sourceLocation)
    }
}

/// A mutable clock for tests.
final class TestClock: @unchecked Sendable {
    private let lock = NSLock()
    private var value: Int
    init(_ value: Int) { self.value = value }
    var now: Int {
        get { lock.lock(); defer { lock.unlock() }; return value }
        set { lock.lock(); value = newValue; lock.unlock() }
    }
    var fn: @Sendable () -> Int { { [self] in self.now } }
}
