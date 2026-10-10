import Foundation
import Testing
@testable import ACE

@Suite("Optional private audit")
struct AuditTests {
    let logId = "550e8400-e29b-41d4-a716-446655440000"
    var commitments: [String] { (0..<35).map { try! ACEAudit.commitment(statement: Data([UInt8($0)]), salt: Data(repeating: 0, count: 32)) } }

    @Test func sharedVectors() throws {
        let v = Fixtures.vectors["audit"] as! [String: Any]
        let openings = v["openings"] as! [[String: String]], roots = v["roots"] as! [String]
        let cs = openings.map { $0["commitment"]! }, tree = try AuditTree(commitments: cs)
        for o in openings { #expect(try ACEAudit.commitment(statement: hex(o["statementHex"]!), salt: hex(o["saltHex"]!)) == o["commitment"]!) }
        for (n, r) in roots.enumerated() { #expect(try tree.root(size: n) == r) }
        for p in v["inclusions"] as! [[String: Any]] {
            let i = p["index"] as! Int, n = p["size"] as! Int, proof = p["proof"] as! [String]
            #expect(try tree.inclusion(index: i, size: n) == proof)
            #expect(ACEAudit.verifyInclusion(commitment: cs[i], index: i, size: n, root: roots[n], proof: proof))
        }
        for p in v["consistencies"] as! [[String: Any]] {
            let m = p["first"] as! Int, n = p["second"] as! Int, proof = p["proof"] as! [String]
            #expect(try tree.consistency(first: m, second: n) == proof)
            #expect(ACEAudit.verifyConsistency(first: m, second: n, firstRoot: roots[m], secondRoot: roots[n], proof: proof))
        }
        for (i, c) in (v["checkpoints"] as! [[String: Any]]).enumerated() {
            let checkpoint = try AuditCheckpoint(json: json(c))
            try ACEAudit.verifyCheckpoint(checkpoint, operator: peerOf(Fixtures.agent(i == 0 ? "alice" : "bob")))
            #expect(try JSONDecoder().decode(AuditCheckpoint.self, from: JSONEncoder().encode(checkpoint)) == checkpoint)
            var extra = c; extra["extra"] = "unsigned"
            expectCode(.invalidArgument) { try AuditCheckpoint(json: json(extra)) }
        }
        for w in v["witnesses"] as! [[String: Any]] {
            let c = try AuditCheckpoint(json: json(w["checkpoint"] as! [String: Any]))
            let r = try AuditWitnessReceipt(json: json(w["receipt"] as! [String: Any]))
            let op = try peerOf(Fixtures.agent(w["operator"] as! String)), witness = try peerOf(Fixtures.agent(w["witness"] as! String))
            #expect(try ACEAudit.checkpointDigest(c) == w["checkpointDigest"] as! String)
            try ACEAudit.verifyWitnessReceipt(r, checkpoint: c, operator: op, witness: witness)
            #expect(try JSONDecoder().decode(AuditWitnessReceipt.self, from: JSONEncoder().encode(r)) == r)
            var extra = w["receipt"] as! [String: Any]; extra["extra"] = "unsigned"
            expectCode(.invalidArgument) { try AuditWitnessReceipt(json: json(extra)) }
            let p = AuditWitnessPolicy(witnesses: [witness], threshold: 1, maxFaulty: 0, maxAgeSeconds: 2, maxFutureSkewSeconds: 0)
            try ACEAudit.verifyWitnessQuorum(c, receipts: [r], operator: op, policy: p, now: r.timestamp)
            expectCode(.invalidSignature) { try ACEAudit.verifyWitnessQuorum(c, receipts: [r], operator: op, policy: p, now: r.timestamp + 3) }
        }
    }

    @Test func independentWitnessQuorum() throws {
        let a = Fixtures.agent("alice"), op = try peerOf(a)
        let ids = try [Fixtures.agent("bob"), SoftwareIdentity.generate(scheme: .ed25519), SoftwareIdentity.generate(scheme: .ed25519), SoftwareIdentity.generate(scheme: .secp256k1)]
        let ws = try ids.map { try peerOf($0) }
        let c = try ACEAudit.createCheckpoint(tree: AuditTree(commitments: commitments), logId: logId, signer: a, timestamp: 100)
        let rs = try ids.map { try ACEAudit.createWitnessReceipt(c, operator: op, witness: $0, timestamp: 101) }
        let p = AuditWitnessPolicy(witnesses: ws, threshold: 3, maxFaulty: 1, maxAgeSeconds: 10, maxFutureSkewSeconds: 1)
        try ACEAudit.verifyWitnessQuorum(c, receipts: Array(rs.prefix(3)), operator: op, policy: p, now: 102)
        for bad in [Array(rs.prefix(2)), [rs[0], rs[0], rs[1]]] {
            expectCode(.invalidSignature) { try ACEAudit.verifyWitnessQuorum(c, receipts: bad, operator: op, policy: p, now: 102) }
        }
        for now in [99, 112] { expectCode(.invalidSignature) { try ACEAudit.verifyWitnessQuorum(c, receipts: rs, operator: op, policy: p, now: now) } }
        let unsafe = AuditWitnessPolicy(witnesses: ws, threshold: 2, maxFaulty: 1, maxAgeSeconds: 10, maxFutureSkewSeconds: 1)
        expectCode(.invalidSignature) { try ACEAudit.verifyWitnessQuorum(c, receipts: rs, operator: op, policy: unsafe, now: 102) }
        expectCode(.invalidArgument) { try ACEAudit.createWitnessReceipt(c, operator: op, witness: a, timestamp: 101) }
    }

    @Test func saltsAndAllTreeShapes() throws {
        let a = try ACEAudit.createOpening(statement: Data("pay 1".utf8)), b = try ACEAudit.createOpening(statement: Data("pay 1".utf8))
        #expect(a.salt.count == 32 && a.commitment != b.commitment)
        #expect(try ACEAudit.commitment(statement: Data("pay 1".utf8), salt: a.salt) == a.commitment)
        expectCode(.invalidArgument) { try ACEAudit.commitment(statement: Data(), salt: Data()) }
        let cs = commitments, tree = try AuditTree(commitments: cs)
        for n in 1...35 {
            let root = try tree.root(size: n)
            for i in 0..<n {
                let p = try tree.inclusion(index: i, size: n)
                #expect(ACEAudit.verifyInclusion(commitment: cs[i], index: i, size: n, root: root, proof: p))
                #expect(!ACEAudit.verifyInclusion(commitment: cs[(i + 1) % 35], index: i, size: n, root: root, proof: p))
                #expect(!ACEAudit.verifyInclusion(commitment: cs[i], index: i, size: n, root: root, proof: p + [cs[0]]))
                if !p.isEmpty { #expect(!ACEAudit.verifyInclusion(commitment: cs[i], index: i, size: n, root: root, proof: Array(p.dropLast()))) }
            }
            for m in 0...n {
                let p = try tree.consistency(first: m, second: n), old = try tree.root(size: m)
                #expect(ACEAudit.verifyConsistency(first: m, second: n, firstRoot: old, secondRoot: root, proof: p))
                #expect(!ACEAudit.verifyConsistency(first: m, second: n, firstRoot: old, secondRoot: root, proof: p + [cs[0]]))
                if !p.isEmpty { #expect(!ACEAudit.verifyConsistency(first: m, second: n, firstRoot: old, secondRoot: root, proof: Array(p.dropLast()))) }
            }
        }
        #expect(!ACEAudit.verifyConsistency(first: 2, second: 1, firstRoot: try tree.root(size: 2), secondRoot: try tree.root(size: 1), proof: []))
        #expect(!ACEAudit.verifyInclusion(commitment: cs[0], index: 0, size: 0, root: try tree.root(size: 0), proof: []))
        #expect(!ACEAudit.verifyConsistency(first: 0, second: 0, firstRoot: cs[0], secondRoot: cs[0], proof: []))
    }

    @Test(arguments: ["alice", "bob"]) func checkpointBindings(_ name: String) throws {
        let a = Fixtures.agent(name), peer = try peerOf(a), cs = commitments, tree = try AuditTree(commitments: cs)
        let first = try ACEAudit.createCheckpoint(tree: AuditTree(commitments: Array(cs.prefix(5))), logId: logId, signer: a, timestamp: 100)
        let next = try ACEAudit.createCheckpoint(tree: tree, logId: logId, signer: a, timestamp: 101)
        try ACEAudit.verifyCheckpoint(first, operator: peer)
        try ACEAudit.verifyCheckpoint(next, operator: peer, previous: first, proof: tree.consistency(first: 5))
        for (key, val) in [("size", 4 as Any), ("root", cs[0]), ("timestamp", 99), ("logId", "00000000-0000-4000-8000-000000000001")] {
            var o = try JSONSerialization.jsonObject(with: JSONEncoder().encode(next)) as! [String: Any]; o[key] = val
            expectCode(.invalidSignature) { try ACEAudit.verifyCheckpoint(AuditCheckpoint(json: json(o)), operator: peer, previous: first, proof: tree.consistency(first: 5)) }
        }
        let fork = try ACEAudit.createCheckpoint(tree: AuditTree(commitments: Array(cs.dropFirst())), logId: logId, signer: a, timestamp: 102)
        expectCode(.invalidSignature) { try ACEAudit.verifyCheckpoint(fork, operator: peer, previous: next) }
        expectCode(.invalidSignature) { try ACEAudit.verifyCheckpoint(next, operator: peerOf(Fixtures.agent(name == "alice" ? "bob" : "alice"))) }
    }
}
