import Foundation
import Testing
@testable import ACE

let CONV = String(repeating: "ab", count: 32)
let MID = "00000000-0000-4000-8000-000000000001"

@Suite("Principal")
struct PrincipalTests {
    @Test func typeLists() {
        #expect(messageTypes.count == 13 && Array(messageTypes.suffix(3)) == [.request, .decision, .report])
        #expect(economicTypes.count == 8 && principalTypes == [.request, .decision, .report])
        #expect(principalTypes.allSatisfy { $0.isPrincipal && !$0.isEconomic })
        #expect(!MessageType.text.isPrincipal && !isPrincipalType(.info))
        #expect(ACEError.Code.invalidPrincipal.category == .permanent && ACEError.Code.wrongPrincipal.category == .permanent)
    }

    @Test(arguments: [
        ("request", #"{"action":"pay","summary":"Pay 1 USDC"}"#),
        ("request", #"{"action":"x402.pay","summary":"s","amount":"1","currency":"USDC","ttl":60,"details":{"payTo":"x"},"ref":{"conversationId":"\#(String(repeating: "ab", count: 32))","messageId":"00000000-0000-4000-8000-000000000001","threadId":"t"}}"#),
        ("decision", #"{"requestId":"r","outcome":"deny","reason":"no","result":{"x":1}}"#),
        ("report", #"{"action":"pay","summary":"paid","outcome":"skipped","proof":{},"requestId":"r"}"#),
    ])
    func validBodies(_ t: String, _ body: String) throws {
        try validateBody(MessageType(rawValue: t)!, try JSONValue(json: Data(body.utf8)).objectValue!)
    }

    @Test(arguments: [
        ("request", #"{"action":"a"}"#),
        ("request", #"{"action":"a","summary":"s","details":"x"}"#),
        ("request", #"{"action":"a","summary":"s","ttl":1.5}"#),
        ("request", #"{"action":"a","summary":"s","ref":[]}"#),
        ("request", #"{"action":"a","summary":"s","ref":{"conversationId":"AB","messageId":"00000000-0000-4000-8000-000000000001"}}"#),
        ("request", #"{"action":"a","summary":"s","ref":{"conversationId":"\#(String(repeating: "ab", count: 32))"}}"#),
        ("request", #"{"action":"a","summary":"s","ref":{"conversationId":"\#(String(repeating: "ab", count: 32))","messageId":"00000000-0000-4000-8000-000000000001","threadId":""}}"#),
        ("decision", #"{"requestId":"r","outcome":"maybe"}"#),
        ("decision", #"{"requestId":"r","outcome":"approve","result":[]}"#),
        ("report", #"{"action":"a","summary":"s","outcome":"done"}"#),
        ("report", #"{"action":"a","summary":"s","outcome":"ok","proof":"x"}"#),
    ])
    func invalidBodies(_ t: String, _ body: String) {
        expectCode(.invalidBody) { try validateBody(MessageType(rawValue: t)!, try JSONValue(json: Data(body.utf8)).objectValue!) }
    }
}
