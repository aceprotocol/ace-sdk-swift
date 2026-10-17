//
//  SecureEnclaveIdentity.swift
//  ACE SDK
//
//  An ACEIdentity whose root, next root and signing key are Secure Enclave ML-DSA keys, and the Secure Enclave
//  ML-KEM-768 seal used for secrets that must exist in software for a moment (prekey seeds). The export holds
//  device-bound key references (not portable); persisting it, e.g. in the Keychain, is the host's job.
//

import CryptoKit
import Foundation

/// A 32-byte secret sealed to a fresh Secure Enclave ML-KEM-768 key: device-bound key blob, KEM ciphertext and
/// AES-GCM `nonce ‖ ciphertext ‖ tag` (all Base64). KEM/DEM: the KEM ciphertext and the domain are bound to both the KDF
/// and the AEAD. A local storage format, independent of the wire protocol.
public struct SecureEnclaveSeal: Sendable, Equatable {
    public var key: String
    public var encapsulatedKey: String
    public var ciphertext: String

    public init(key: String, encapsulatedKey: String, ciphertext: String) {
        self.key = key
        self.encapsulatedKey = encapsulatedKey
        self.ciphertext = ciphertext
    }

    package var jsonValue: JSONValue {
        ["key": .string(key), "encapsulatedKey": .string(encapsulatedKey), "ciphertext": .string(ciphertext)]
    }

    package init(_ v: JSONValue?) throws {
        guard let o = v?.objectValue, let key = o["key"]?.stringValue, let enc = o["encapsulatedKey"]?.stringValue,
              let ct = o["ciphertext"]?.stringValue else { throw ACEError(.invalidArgument, "seal must be {key, encapsulatedKey, ciphertext}") }
        self.init(key: key, encapsulatedKey: enc, ciphertext: ct)
    }

    private static func wrappingKey(_ secret: SymmetricKey, _ encapsulated: Data, _ info: Data) -> SymmetricKey {
        HKDF<SHA256>.deriveKey(inputKeyMaterial: secret, salt: encapsulated, info: info, outputByteCount: 32)
    }

    /// Seal `secret` (32 bytes) under domain `info`; `identity_unavailable` when the Secure Enclave fails.
    package static func seal(_ secret: Data, info: String) throws -> SecureEnclaveSeal {
        let info = Data(info.utf8)
        do {
            let kek = try SecureEnclaveGate.run { try SecureEnclave.MLKEM768.PrivateKey.generate() }
            let kem = try kek.publicKey.encapsulate()
            let ct = try AES.GCM.seal(secret, using: wrappingKey(kem.sharedSecret, kem.encapsulated, info), authenticating: info + kem.encapsulated)
            return .init(key: ACEBase64.encode(kek.dataRepresentation), encapsulatedKey: ACEBase64.encode(kem.encapsulated),
                         ciphertext: ACEBase64.encode(ct.combined!))
        } catch {
            throw ACEError(.identityUnavailable, "Secure Enclave sealing failed")
        }
    }

    /// The 32-byte secret, or `invalid_argument` when the seal is not one this device can open under `info`.
    package func open(info: String) throws -> Data {
        let info = Data(info.utf8)
        let key = try decodeB64(key, code: .invalidArgument, what: "seal.key", maxBytes: 16384)
        let enc = try decodeB64(encapsulatedKey, code: .invalidArgument, what: "seal.encapsulatedKey", maxBytes: 1088)
        let ct = try decodeB64(ciphertext, code: .invalidArgument, what: "seal.ciphertext", maxBytes: 256)
        // Strict pre-check before the Secure Enclave sees the blob: an altered access-control item can block the restore
        // in the authentication helper, and it would block every other SE call behind the gate.
        guard SecureEnclaveBlob.isMLKEM768Key(key), enc.count == 1088, ct.count == 60 else {
            throw ACEError(.invalidArgument, "invalid Secure Enclave ML-KEM-768 seal")
        }
        do {
            let secret = try SecureEnclaveGate.run {
                let kek = try SecureEnclave.MLKEM768.PrivateKey(dataRepresentation: key)
                let shared = try kek.decapsulate(enc)
                return try AES.GCM.open(AES.GCM.SealedBox(combined: ct), using: Self.wrappingKey(shared, enc, info), authenticating: info + enc)
            }
            guard secret.count == 32 else { throw ACEError(.invalidArgument, "sealed secret has the wrong size") }
            return secret
        } catch let e as ACEError {
            throw e
        } catch {
            throw ACEError(.invalidArgument, "seal cannot be opened on this device")
        }
    }
}

/// The device-bound key references of a `SecureEnclaveIdentity` (Base64 Secure Enclave blobs) and its log.
public struct SecureEnclaveIdentityExport: Sendable, Equatable {
    /// Always `"secure-enclave"`.
    public var provider: String
    public var rootKey: String
    public var nextRootKey: String?
    public var signingKey: String
    public var kel: [KelEvent]

    public init(provider: String = SecureEnclaveIdentity.provider, rootKey: String, nextRootKey: String? = nil, signingKey: String, kel: [KelEvent]) {
        self.provider = provider
        self.rootKey = rootKey
        self.nextRootKey = nextRootKey
        self.signingKey = signingKey
        self.kel = kel
    }

    /// Not an object, or a missing or malformed member → `invalid_argument`; a bad `kel` → `invalid_kel`. Unknown members
    /// are ignored.
    public init(json: Data) throws {
        let o = try ExportJSON.object(json)
        provider = try ExportJSON.string(o, "provider")
        kel = try ExportJSON.kel(o)
        rootKey = try ExportJSON.string(o, "rootKey")
        nextRootKey = try ExportJSON.optionalString(o, "nextRootKey")
        signingKey = try ExportJSON.string(o, "signingKey")
    }

    /// Canonical JSON.
    public func jsonData() throws -> Data {
        var o: [String: JSONValue] = ["provider": .string(provider), "rootKey": .string(rootKey), "signingKey": .string(signingKey),
                                      "kel": ExportJSON.kelValue(kel)]
        if let nextRootKey { o["nextRootKey"] = .string(nextRootKey) }
        return try JSONValue.object(o).jsonData()
    }
}

/// Root, next root and signing key in the Secure Enclave. There is no software fallback: without a Secure Enclave,
/// `generate` is `identity_unavailable`.
public final class SecureEnclaveIdentity: ACEManagedIdentity, HeldKelIdentity, @unchecked Sendable {
    public static let provider = "secure-enclave"
    package let core: KelIdentityCore<SecureEnclaveKey>

    private init(core: KelIdentityCore<SecureEnclaveKey>) { self.core = core }

    /// A new identity whose keys are generated in the Secure Enclave (see `SoftwareIdentity.generate`).
    public static func generate(nextRootDigest: Data? = nil, now: Int? = nil) throws -> SecureEnclaveIdentity {
        SecureEnclaveIdentity(core: try .generate(nextRootDigest: nextRootDigest, now: now, makeKey: SecureEnclaveKey.generate))
    }

    /// Restore from key references made on this device. A `provider` other than `"secure-enclave"`, a blob that is not a
    /// Secure Enclave key on this device, or a key that is not the one the log names is `invalid_argument`; a log that
    /// does not verify at `now` is `invalid_kel`.
    public convenience init(export: SecureEnclaveIdentityExport, now: Int? = nil) throws {
        guard export.provider == Self.provider else { throw ACEError(.invalidArgument, "export provider must be secure-enclave") }
        let ts = try identityNow(now)
        _ = try ACEKel.verify(export.kel, now: ts)
        func key(_ text: String, _ what: String) throws -> SecureEnclaveKey {
            try SecureEnclaveKey(dataRepresentation: decodeB64(text, code: .invalidArgument, what: what, maxBytes: 16384))
        }
        self.init(core: try KelIdentityCore(root: key(export.rootKey, "rootKey"), nextRoot: export.nextRootKey.map { try key($0, "nextRootKey") },
                                            signing: key(export.signingKey, "signingKey"), kel: export.kel, now: ts,
                                            makeKey: SecureEnclaveKey.generate))
    }

    /// The key references and the log (device-bound; the host persists them).
    public func exportKeyReferences() -> SecureEnclaveIdentityExport {
        core.withLock { c in
            SecureEnclaveIdentityExport(rootKey: ACEBase64.encode(c.root.dataRepresentation),
                                        nextRootKey: c.nextRoot.map { ACEBase64.encode($0.dataRepresentation) },
                                        signingKey: ACEBase64.encode(c.signing.dataRepresentation), kel: c.state.events)
        }
    }

    // MARK: ACEIdentity

    public func getACEId() -> String { core.aceId }
    public func getSigningPublicKey() -> Data { core.signingPublicKey }
    public func getSigningSeq() throws -> Int { try core.signingSeq() }
    public func getKel() throws -> [KelEvent] { core.currentKel }
    public func sign(_ message: (Int) throws -> Data, action: String) throws -> (seq: Int, signature: Data) {
        try core.sign(message, action: action)
    }
    package var heldState: KelState { core.currentState }

    // MARK: ACEManagedIdentity

    public func getState() -> KelState { core.currentState }

    /// Reveals the held next root (a `rot` signed by it alone) and commits a new one. There is no `recover`: a Secure
    /// Enclave identity cannot hold a next root kept outside the device.
    public func rotate(now: Int? = nil, nextRootDigest: Data? = nil) throws {
        try core.rotate(now: now, nextRootDigest: nextRootDigest)
    }

    public func delegate(now: Int? = nil, notAfter: Int? = nil) throws {
        try core.delegate(now: now, notAfter: notAfter)
    }
}

/// `print`, `dump` and string interpolation never show the key blobs.
extension SecureEnclaveIdentity: CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public var description: String { "SecureEnclaveIdentity(\(getACEId()))" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(self, children: ["aceId": getACEId()], displayStyle: .class) }
}

/// `print`, `dump` and string interpolation never show the key blobs (any process of the same user holding them can sign).
extension SecureEnclaveIdentityExport: CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public var description: String { "SecureEnclaveIdentityExport(keys: <redacted>, kel: \(kel.count) events)" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(self, children: ["kelEvents": kel.count], displayStyle: .struct) }
}
