import Foundation
import Testing
@testable import ACE

@Suite("Resource grants")
struct GrantTests {
    @Test func sharedVectors() throws {
        let v = Fixtures.vectors["grants"] as! [String: Any], cases = v["cases"] as! [[String: Any]]
        let root = try peerOf(Fixtures.agent("alice"))
        for c in cases {
            let chain = (c["chain"] as! [[String: Any]]).map(jsonBody), intent = jsonBody(c["intent"]!)
            let policy = ResourcePolicy(resource: (cases[0]["intent"] as! [String: Any])["resource"] as! String,
                                        authority: root, epoch: c["epoch"] as! Int, revoked: c["revoked"] as! [String])
            let verify = { try ACEGrants.verifyExecutionGrantChain(chain, intent: intent, sender: c["sender"] as! String,
                                                                    executor: c["executor"] as! String, policy: policy, now: c["now"] as! Int) }
            if c["expected"] as! String == "ok" { #expect(try verify() == v["intentDigest"] as! String, "\(c["name"]!)") }
            else { expectCode(.invalidAuthorization, verify) }
        }
        #expect(try ACEGrants.executionIntentDigest(jsonBody(cases[0]["intent"]!)) == v["intentDigest"] as! String)
        let first = (cases[0]["chain"] as! [[String: Any]])[0]
        #expect(try ACEGrants.executionGrantDigest(jsonBody(first)) == v["rootDigest"] as! String)
        let created = try ACEGrants.createExecutionGrant(signer: Fixtures.agent("alice"), claims: jsonBody(first["claims"]!))
        #expect(try ACEGrants.executionGrantDigest(created) == v["rootDigest"] as! String)
        let intent = jsonBody(cases[0]["intent"]!), b = Fixtures.agent("bob")
        let policy = ResourcePolicy(resource: intent["resource"]!.stringValue!, authority: root, epoch: 1)
        #expect(try ACEGrants.verifyExecutionGrantChain([created], intent: intent, sender: b.getACEId(), executor: b.getACEId(), policy: policy, now: 150) == v["intentDigest"] as! String)
        let second = (cases[0]["chain"] as! [[String: Any]])[1]
        let delegated = try ACEGrants.createExecutionGrant(signer: b, claims: jsonBody(second["claims"]!))
        #expect(try ACEGrants.verifyExecutionGrantChain([created, delegated], intent: intent, sender: root.aceId, executor: b.getACEId(), policy: policy, now: 150) == v["intentDigest"] as! String)
    }
}
