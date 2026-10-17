//
//  Keys.swift
//  ACE SDK
//
//  Key providers (spec § 8): where a root or signing key lives and how it signs.
//  ML-DSA-65 only. SoftwareKey expands a 32-byte seed in process memory; SecureEnclaveKey never leaves the
//  Secure Enclave and persists as its device-bound `dataRepresentation`.
//

import CryptoKit
import Foundation

public protocol ACEKeyProvider: Sendable {
    /// The 1952-byte ML-DSA-65 public key.
    func publicKey() -> Data
    /// ML-DSA-65 over `message` with ctx = UTF-8(action); `action` at most 255 UTF-8 bytes (`invalid_argument`).
    func sign(_ message: Data, action: String) throws -> Data
}

/// `SHA-256("ml-dsa-65" || 0x00 || publicKey)`: the pre-rotation commitment of a key.
public func keyDigest(publicKey: Data) -> Data {
    var m = Data(SigningScheme.mlDsa65.rawValue.utf8)
    m.append(0)
    m.append(publicKey)
    return Data(SHA256.hash(data: m))
}

package func checkAction(_ action: String) throws -> Data {
    let ctx = Data(action.utf8)
    guard ctx.count <= 255 else { throw ACEError(.invalidArgument, "action must be a string of at most 255 UTF-8 bytes") }
    return ctx
}

public final class SoftwareKey: ACEKeyProvider, @unchecked Sendable {
    public let seed: Data
    private let key: MLDSA65.PrivateKey
    private let pk: Data

    /// `invalid_argument` unless `seed` is a 32-byte ML-DSA-65 seed (FIPS 204 § 3.6.3).
    public init(seed: Data) throws {
        guard seed.count == ACESigning.seedSize else { throw ACEError(.invalidArgument, "seed must be \(ACESigning.seedSize) bytes") }
        do { key = try MLDSA65.PrivateKey(seedRepresentation: seed, publicKey: nil) } catch {
            throw ACEError(.invalidArgument, "seed does not expand to an ml-dsa-65 key")
        }
        pk = key.publicKey.rawRepresentation
        self.seed = seed
    }

    public static func generate() -> SoftwareKey { try! SoftwareKey(seed: Data(randomBytes(ACESigning.seedSize))) }

    public func publicKey() -> Data { pk }

    public func sign(_ message: Data, action: String) throws -> Data {
        let ctx = try checkAction(action)
        do { return try key.signature(for: message, context: ctx) } catch {
            throw ACEError(.identityUnavailable, "software signing failed")
        }
    }
}

/// `print`, `dump` and string interpolation never show the seed.
extension SoftwareKey: CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public var description: String { "SoftwareKey(seed: <redacted>)" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(self, children: [:], displayStyle: .class) }
}

public final class SecureEnclaveKey: ACEKeyProvider, @unchecked Sendable {
    private let key: SecureEnclave.MLDSA65.PrivateKey
    private let pk: Data

    public static var isAvailable: Bool { SecureEnclave.isAvailable }

    public static func generate() throws -> SecureEnclaveKey {
        guard isAvailable else { throw ACEError(.identityUnavailable, "the Secure Enclave is not available") }
        do { return SecureEnclaveKey(try SecureEnclaveGate.run { try SecureEnclave.MLDSA65.PrivateKey() }) } catch {
            throw ACEError(.identityUnavailable, "Secure Enclave key generation failed")
        }
    }

    /// Restores a key from its `dataRepresentation` (device-bound). A blob that is not an ML-DSA-65 key on this device is
    /// `invalid_argument`.
    ///
    /// Two checks CryptoKit does not make: (1) CryptoKit traps (a `try!` in `SEP_MLDSA`) instead of
    /// throwing when the blob's `pub` attribute is missing, malformed or of another ML-DSA
    /// parameter set, so the blob structure is read strictly first (`SecureEnclaveBlob`) and
    /// anything it does not recognise is rejected, never handed to CryptoKit; (2) a well-formed
    /// but altered blob restores and fails only at the first signature, so a probe signature is
    /// verified against the restored public key here.
    public convenience init(dataRepresentation: Data) throws {
        let bad = ACEError(.invalidArgument, "not a Secure Enclave ml-dsa-65 key on this device")
        guard SecureEnclaveBlob.publicKeyLength(dataRepresentation) == ACESigning.publicKeySize else { throw bad }
        let key: SecureEnclave.MLDSA65.PrivateKey
        do { key = try SecureEnclaveGate.run { try SecureEnclave.MLDSA65.PrivateKey(dataRepresentation: dataRepresentation) } } catch {
            throw bad
        }
        self.init(key)
        let probe = Data("ace.key-check".utf8)
        guard pk.count == ACESigning.publicKeySize, let sig = try? sign(probe, action: "key-check"),
              ACESigning.verifySignature(message: probe, action: "key-check", signature: sig, publicKey: pk)
        else { throw bad }
    }

    private init(_ key: SecureEnclave.MLDSA65.PrivateKey) {
        self.key = key
        pk = key.publicKey.rawRepresentation
    }

    public var dataRepresentation: Data { key.dataRepresentation }

    public func publicKey() -> Data { pk }

    public func sign(_ message: Data, action: String) throws -> Data {
        let ctx = try checkAction(action)
        do { return try SecureEnclaveGate.run { try key.signature(for: message, context: ctx) } } catch {
            throw ACEError(.identityUnavailable, "Secure Enclave signing failed")
        }
    }
}

/// One Secure Enclave operation at a time in this process. Measured (macOS 27.0.1, 8 cores): eight
/// concurrent Swift tasks that each generate an ML-DSA key, sign and create an ML-KEM-768 sealing key
/// block forever in their synchronous CryptoTokenKit XPC calls (seven do not); serialized, they complete
/// (throughput unchanged: the Secure Enclave executes one operation at a time anyway).
package enum SecureEnclaveGate {
    private static let lock = NSLock()

    package static func run<T>(_ body: () throws -> T) rethrows -> T {
        lock.lock()
        defer { lock.unlock() }
        return try body()
    }
}

/// Strict reader of a Secure Enclave ML-DSA key blob (`dataRepresentation`, a CryptoTokenKit
/// object): `04 L { 31 L { 30 { 0c "rk", 31 L { 30 L { 0c name, value } … } }, 30 { 0c "ed", acl } } }`,
/// DER lengths in short, `81` or `82` form, each container filled exactly, the outer length equal
/// to the blob, attribute names unique, exactly one `pub` OCTET STRING. The `ed` item must be the
/// default access control the SDK's keys carry (`acl` = `{dacl: true}`): a blob with any other
/// ACL makes CryptoTokenKit ask for user authentication (measured: restore blocks in the auth
/// helper). Returns the `pub` length, or nil for anything else: the caller fails closed, because
/// CryptoKit traps on a blob whose `pub` it cannot read.
package enum SecureEnclaveBlob {
    package typealias Node = (tag: UInt8, start: Int, end: Int)

    /// Content of the `ed` SET with no access control: `30 { 0c "acl", 31 { 30 { 0c "dacl", BOOLEAN true } } }`.
    package static let defaultAccessControl: [UInt8] = [
        0x30, 0x12, 0x0c, 0x03, 0x61, 0x63, 0x6c, 0x31, 0x0b,
        0x30, 0x09, 0x0c, 0x04, 0x64, 0x61, 0x63, 0x6c, 0x01, 0x01, 0x01,
    ]

    package static func publicKeyLength(_ blob: Data) -> Int? { publicKey(blob)?.count }

    /// Strict default-access-control blob with one ML-KEM-768 public key.
    package static func isMLKEM768Key(_ blob: Data) -> Bool {
        publicKeyLength(blob) == 1184
    }

    /// The `pub` attribute's bytes, or nil for anything the strict reader does not accept.
    package static func publicKey(_ blob: Data) -> Data? {
        let b = [UInt8](blob)
        guard let top = node(b, 0, b.count), top.tag == 0x04, top.end == b.count,
              let outer = children(b, top), outer.count == 1, outer[0].tag == 0x31,
              let items = children(b, outer[0]), let byName = named(b, items), byName.count == 2,
              let ed = byName[Array("ed".utf8)], ed.tag == 0x31, Array(b[ed.start..<ed.end]) == defaultAccessControl,
              let rk = byName[Array("rk".utf8)], rk.tag == 0x31, let attrItems = children(b, rk), let attrs = named(b, attrItems),
              let pub = attrs[Array("pub".utf8)], pub.tag == 0x04 else { return nil }
        return Data(b[pub.start..<pub.end])
    }

    /// One TLV at `i`, inside `[i, end)`; minimal DER lengths only.
    package static func node(_ b: [UInt8], _ i: Int, _ end: Int) -> Node? {
        guard end - i >= 2 else { return nil }
        let len: Int, header: Int
        switch b[i + 1] {
        case 0..<0x80:
            len = Int(b[i + 1]); header = 2
        case 0x81:
            guard end - i >= 3, b[i + 2] >= 0x80 else { return nil }
            len = Int(b[i + 2]); header = 3
        case 0x82:
            guard end - i >= 4, b[i + 2] != 0 else { return nil }
            len = Int(b[i + 2]) << 8 | Int(b[i + 3]); header = 4
        default:
            return nil
        }
        guard len <= end - i - header else { return nil }
        return (b[i], i + header, i + header + len)
    }

    package static func children(_ b: [UInt8], _ n: Node) -> [Node]? {
        var out: [Node] = [], i = n.start
        while i < n.end {
            guard let c = node(b, i, n.end) else { return nil }
            out.append(c)
            i = c.end
        }
        return out
    }

    /// `30 { 0c name, value }` items keyed by the raw name bytes; nil on any other shape or a repeated
    /// name. Names are never decoded: `String(bytes:encoding:)` drops a leading UTF-8 BOM, so a
    /// BOM + "pub" attribute (unknown to CryptoTokenKit, which then traps CryptoKit) would read as `pub`.
    package static func named(_ b: [UInt8], _ items: [Node]) -> [[UInt8]: Node]? {
        var out: [[UInt8]: Node] = [:]
        for item in items {
            guard item.tag == 0x30, let kids = children(b, item), kids.count == 2, kids[0].tag == 0x0c,
                  case let name = Array(b[kids[0].start..<kids[0].end]), out[name] == nil else { return nil }
            out[name] = kids[1]
        }
        return out
    }
}

