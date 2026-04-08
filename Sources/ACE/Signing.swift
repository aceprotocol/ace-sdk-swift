//
//  Signing.swift
//  ACE SDK
//
//  Sign data construction + Ed25519/secp256k1 signature verification.
//
//  Unified domain prefix "ace.v1" for all signature contexts.
//  Format: SHA-256("ace.v1" || len(action) || action || len(aceId) || aceId || timestamp[8 BE] || len(payload) || payload)
//

import Foundation
import CryptoKit
import P256K

// MARK: - Domain Prefix

private let domainPrefix = Data("ace.v1".utf8)

// MARK: - Sign Data Builder

public enum ACESigning {

    /// A field that can be included in a signed payload.
    public enum SignField {
        case string(String)
        case data(Data)
    }

    /// Encode multiple fields into a single payload blob.
    /// Each field is length-prefixed: [len(4 BE)] || data
    public static func encodePayload(_ fields: [SignField]) -> Data {
        var buffer = Data()
        for field in fields {
            switch field {
            case .string(let str):
                appendLengthPrefixed(str, to: &buffer)
            case .data(let data):
                appendLengthPrefixedBytes(data, to: &buffer)
            }
        }
        return buffer
    }

    /// Build signData hash per ACE Protocol V1 spec:
    ///
    /// SHA-256(
    ///   "ace.v1" ||
    ///   len(action)[4 BE] || UTF-8(action) ||
    ///   len(aceId)[4 BE] || UTF-8(aceId) ||
    ///   timestamp[8 big-endian] ||
    ///   len(payload)[4 BE] || payload
    /// )
    public static func buildSignData(action: String, aceId: String, timestamp: Int, payload: Data = Data()) -> Data {
        var buffer = Data()
        buffer.append(domainPrefix)
        appendLengthPrefixed(action, to: &buffer)
        appendLengthPrefixed(aceId, to: &buffer)
        appendTimestamp(timestamp, to: &buffer)
        appendLengthPrefixedBytes(payload, to: &buffer)
        return Data(SHA256.hash(data: buffer))
    }

    // MARK: - Signature Verification

    /// Verify a signature against signData.
    /// - For ed25519: direct verification with public key (CryptoKit)
    /// - For secp256k1: recover public key from signature and compare (constant-time)
    public static func verifySignature(
        signData: Data,
        signature: Data,
        scheme: SigningScheme,
        signingPublicKey: Data
    ) -> Bool {
        switch scheme {
        case .ed25519:
            return verifyEd25519(signData: signData, signature: signature, publicKey: signingPublicKey)
        case .secp256k1:
            return verifySecp256k1(signData: signData, signature: signature, expectedPublicKey: signingPublicKey)
        }
    }

    // MARK: - Signature Encoding

    /// Encode a signature to its wire format.
    /// ed25519: Base64(64 bytes)
    /// secp256k1: 0x + hex(r[32] || s[32] || v[1])
    public static func encodeSignature(_ signature: Data, scheme: SigningScheme) -> String {
        switch scheme {
        case .ed25519:
            return ACEBase64.encode(signature)
        case .secp256k1:
            return "0x" + ACEHex.encode(signature)
        }
    }

    /// Decode a signature from its wire format.
    public static func decodeSignature(_ encoded: String, scheme: SigningScheme) throws -> Data {
        switch scheme {
        case .ed25519:
            return try ACEBase64.decode(encoded)
        case .secp256k1:
            return try ACEHex.decode(encoded)
        }
    }

    // MARK: - Private: Ed25519 Verification

    private static func verifyEd25519(signData: Data, signature: Data, publicKey: Data) -> Bool {
        guard signature.count == 64, publicKey.count == 32 else { return false }
        do {
            let pubKey = try Curve25519.Signing.PublicKey(rawRepresentation: publicKey)
            return pubKey.isValidSignature(signature, for: signData)
        } catch {
            return false
        }
    }

    // MARK: - Private: secp256k1 Verification (recover-and-compare)

    private static func verifySecp256k1(signData: Data, signature: Data, expectedPublicKey: Data) -> Bool {
        guard signature.count == 65 else { return false }

        let r = signature.prefix(32)
        let s = signature.dropFirst(32).prefix(32)
        let vByte = signature[signature.startIndex + 64]
        // Recovery ID must be 0 or 1 (2/3 are theoretically valid but
        // practically impossible for secp256k1 and not used in ACE)
        guard vByte <= 1 else { return false }
        let v = Int32(vByte)

        do {
            // Build recoverable signature: compact(r||s) + recoveryId
            let compactSig = r + s
            let recoverableSig = try P256K.Recovery.ECDSASignature(
                compactRepresentation: [UInt8](compactSig),
                recoveryId: v
            )

            // Recover public key from signature + signData hash
            let digest = HashDigest([UInt8](signData))
            let recoveredPub = try P256K.Recovery.PublicKey(
                digest,
                signature: recoverableSig
            )

            // Compare compressed public keys (constant-time)
            let recoveredCompressed = Data(recoveredPub.dataRepresentation)
            return constantTimeEqual(recoveredCompressed, expectedPublicKey)
        } catch {
            return false
        }
    }

    // MARK: - Private: Encoding Helpers

    /// Encode a string as length-prefixed: [len(4 BE)] || UTF-8(str)
    private static func appendLengthPrefixed(_ field: String, to buffer: inout Data) {
        appendLengthPrefixedBytes(Data(field.utf8), to: &buffer)
    }

    /// Encode binary data as length-prefixed: [len(4 BE)] || data
    private static func appendLengthPrefixedBytes(_ data: Data, to buffer: inout Data) {
        var len = UInt32(data.count).bigEndian
        buffer.append(Data(bytes: &len, count: 4))
        buffer.append(data)
    }

    /// Encode timestamp as 8-byte big-endian uint64.
    /// Precondition: ts must be non-negative (enforced by checkTimestampFreshness).
    private static func appendTimestamp(_ ts: Int, to buffer: inout Data) {
        precondition(ts >= 0, "Timestamp must be non-negative")
        var val = UInt64(ts).bigEndian
        buffer.append(Data(bytes: &val, count: 8))
    }
}
