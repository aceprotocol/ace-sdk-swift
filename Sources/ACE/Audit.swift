import Foundation

/// Optional salted commitments and RFC 9162 proofs. These APIs never publish or execute anything.
public enum ACEAudit {
    static func bad() -> ACEError { ACEError(.invalidArgument, "invalid audit input") }
    static func hash(_ data: Data) -> String { sha256Hex(data) }
    static let empty = hash(Data())
    static func bytes(_ digest: String) -> Data { hexDecode(digest)! }
    static func node(_ a: String, _ b: String) -> String { hash(Data([1]) + bytes(a) + bytes(b)) }
    static func leaf(_ commitment: String) -> String { hash(Data([0]) + bytes(commitment)) }
    static func split(_ n: Int) -> Int { var k = 1; while k * 2 < n { k *= 2 }; return k }
    static func validProof(_ proof: [String]) -> Bool { proof.count <= 54 && proof.allSatisfy(isSha256Hex) }

    /// The random salt stays private until intentional disclosure. Use a fresh opening per publication.
    public static func commitment(statement: Data, salt: Data) throws -> String {
        guard salt.count == 32 else { throw bad() }
        return hash(Data("ace.audit.commitment.v1\0".utf8) + salt + statement)
    }
    public static func createOpening(statement: Data) throws -> (salt: Data, commitment: String) {
        let salt = Data(randomBytes(32))
        return (salt, try commitment(statement: statement, salt: salt))
    }
    public static func verifyInclusion(commitment: String, index: Int, size: Int, root: String, proof: [String]) -> Bool {
        guard isSha256Hex(commitment), isSha256Hex(root), isWireInt(index), isWireInt(size), index < size, validProof(proof) else { return false }
        var at = 0
        func walk(_ i: Int, _ n: Int) throws -> String {
            if n == 1 { return leaf(commitment) }
            let k = split(n)
            let child = try i < k ? walk(i, k) : walk(i - k, n - k)
            guard at < proof.count else { throw bad() }
            let sibling = proof[at]; at += 1
            return i < k ? node(child, sibling) : node(sibling, child)
        }
        do { return try walk(index, size) == root && at == proof.count } catch { return false }
    }
    public static func verifyConsistency(first: Int, second: Int, firstRoot: String, secondRoot: String, proof: [String]) -> Bool {
        guard isWireInt(first), isWireInt(second), first <= second, isSha256Hex(firstRoot), isSha256Hex(secondRoot), validProof(proof) else { return false }
        if first == second { return proof.isEmpty && firstRoot == secondRoot && (first != 0 || firstRoot == empty) }
        if first == 0 { return firstRoot == empty && proof.isEmpty }
        var at = 0
        func take() throws -> String {
            guard at < proof.count else { throw bad() }
            let h = proof[at]; at += 1; return h
        }
        func walk(_ m: Int, _ n: Int, _ complete: Bool) throws -> (String, String) {
            if m == n { let h = try complete ? firstRoot : take(); return (h, h) }
            let k = split(n)
            if m <= k { let (old, next) = try walk(m, k, complete); return (old, try node(next, take())) }
            let (old, next) = try walk(m - k, n - k, false), left = try take()
            return (node(left, old), node(left, next))
        }
        do { let (old, next) = try walk(first, second, true); return old == firstRoot && next == secondRoot && at == proof.count }
        catch { return false }
    }

    static func checkpointData(_ c: AuditCheckpoint) throws -> Data {
        guard isMessageId(c.logId), isWireInt(c.size), isSha256Hex(c.root), isWireInt(c.timestamp), c.size != 0 || c.root == empty else { throw bad() }
        return try ACESigning.buildSignData(action: "audit", aceId: c.signer, timestamp: c.timestamp,
            payload: ACESigning.encodePayload([.string(c.logId), .string(String(c.size)), .data(bytes(c.root))]))
    }
    public static func createCheckpoint(tree: AuditTree, logId: String, signer: any ACEIdentity, timestamp: Int) throws -> AuditCheckpoint {
        let c = AuditCheckpoint(logId: logId, size: tree.size, root: try tree.root(), timestamp: timestamp, signer: signer.getACEId(), signature: .init(scheme: signer.getSigningScheme(), value: ""))
        let value = try encodeSignature(signer.sign(checkpointData(c)), scheme: signer.getSigningScheme())
        return AuditCheckpoint(logId: logId, size: c.size, root: c.root, timestamp: timestamp, signer: c.signer, signature: .init(scheme: c.signature.scheme, value: value))
    }
    /// The operator must be locally trusted. Retain accepted checkpoints durably.
    public static func verifyCheckpoint(_ c: AuditCheckpoint, operator: VerifiedPeer, previous: AuditCheckpoint? = nil, proof: [String] = []) throws {
        func valid(_ v: AuditCheckpoint) throws -> Bool {
            guard v.signer == `operator`.aceId, v.signature.scheme == `operator`.scheme else { return false }
            return try ACESigning.verify(signData: checkpointData(v),
                signature: decodeSignature(v.signature.value, scheme: `operator`.scheme, code: .invalidSignature), scheme: `operator`.scheme, publicKey: `operator`.signingPublicKey)
        }
        do {
            guard try valid(c) else { throw bad() }
            if let previous {
                guard try valid(previous), previous.logId == c.logId, c.timestamp >= previous.timestamp,
                      verifyConsistency(first: previous.size, second: c.size, firstRoot: previous.root, secondRoot: c.root, proof: proof) else { throw bad() }
            } else if !proof.isEmpty { throw bad() }
        } catch { throw ACEError(.invalidSignature, "invalid or inconsistent audit checkpoint") }
    }
}

/// Reference builder. Inputs are commitments, never plaintext or salts.
public struct AuditTree: Sendable {
    /// `levels[j][i]`: the perfect subtree of `2^j` leaves starting at `i * 2^j` (`levels[0]` are
    /// the leaves). Every split lands on such a subtree, and it is the same in every prefix
    /// tree, so each is hashed once (< 2n hashes).
    private let levels: [[String]]
    public init(commitments: [String] = []) throws {
        guard commitments.count <= 65536, commitments.allSatisfy(isSha256Hex) else { throw ACEAudit.bad() }
        var levels = [commitments.map(ACEAudit.leaf)]
        while let last = levels.last, last.count > 1 {
            levels.append(stride(from: 0, to: last.count - 1, by: 2).map { ACEAudit.node(last[$0], last[$0 + 1]) })
        }
        self.levels = levels
    }
    public var size: Int { levels[0].count }
    private func root(_ start: Int, _ count: Int) -> String {
        if count == 0 { return ACEAudit.empty }
        if count & (count - 1) == 0 { return levels[count.trailingZeroBitCount][start / count] }
        let k = ACEAudit.split(count)
        return ACEAudit.node(root(start, k), root(start + k, count - k))
    }
    public func root(size: Int? = nil) throws -> String {
        let n = size ?? self.size
        guard isWireInt(n), n <= self.size else { throw ACEAudit.bad() }
        return root(0, n)
    }
    public func inclusion(index: Int, size: Int? = nil) throws -> [String] {
        let n = size ?? self.size
        guard isWireInt(index), isWireInt(n), index < n, n <= self.size else { throw ACEAudit.bad() }
        func walk(_ i: Int, _ start: Int, _ n: Int) -> [String] {
            if n == 1 { return [] }
            let k = ACEAudit.split(n)
            return i < k ? walk(i, start, k) + [root(start + k, n - k)] : walk(i - k, start + k, n - k) + [root(start, k)]
        }
        return walk(index, 0, n)
    }
    public func consistency(first: Int, second: Int? = nil) throws -> [String] {
        let n = second ?? size
        guard isWireInt(first), isWireInt(n), first <= n, n <= size else { throw ACEAudit.bad() }
        if first == 0 || first == n { return [] }
        func walk(_ m: Int, _ start: Int, _ n: Int, _ complete: Bool) -> [String] {
            if m == n { return complete ? [] : [root(start, n)] }
            let k = ACEAudit.split(n)
            return m <= k ? walk(m, start, k, complete) + [root(start + k, n - k)] : walk(m - k, start + k, n - k, false) + [root(start, k)]
        }
        return walk(first, 0, n, true)
    }
}

public struct AuditCheckpoint: Codable, Sendable, Equatable {
    public let logId: String
    public let size: Int
    public let root: String
    public let timestamp: Int
    public let signer: String
    public let signature: SignatureEnvelope

    public init(logId: String, size: Int, root: String, timestamp: Int, signer: String, signature: SignatureEnvelope) {
        self.logId = logId; self.size = size; self.root = root; self.timestamp = timestamp; self.signer = signer; self.signature = signature
    }
    public init(json: Data) throws {
        guard let o = try JSONValue(json: json).objectValue,
              Set(o.keys) == ["logId", "size", "root", "timestamp", "signer", "signature"],
              let logId = o["logId"]?.stringValue, let size = o["size"]?.wireInt, let root = o["root"]?.stringValue,
              let timestamp = o["timestamp"]?.wireInt, let signer = o["signer"]?.stringValue,
              let sig = o["signature"]?.objectValue, let signature = SignatureEnvelope(exactly: sig) else { throw ACEAudit.bad() }
        self.init(logId: logId, size: size, root: root, timestamp: timestamp, signer: signer, signature: signature)
    }
    public init(from decoder: any Decoder) throws { self = try AuditCheckpoint(json: JSONValue(from: decoder).jsonData()) }
}
