//
//  CoreTypes.swift
//  ACE SDK
//
//  The signing scheme and the `{scheme, seq, value}` signature member shared by packets and signed documents.
//

import Foundation

/// The ACE signing scheme (02 § Signatures): `ml-dsa-65` is the only one, for roots and signing keys alike. Key and
/// signature objects carry it so that a later revision can add a scheme through a committed next root.
public enum SigningScheme: String, Sendable, CaseIterable {
    case mlDsa65 = "ml-dsa-65"
}

/// `{scheme, seq, value}`: an operational signature under the signing delegation at `seq` of the signer's KEL.
public struct SignatureEnvelope: Sendable, Equatable {
    /// Padded standard Base64 of the ML-DSA-65 signature.
    public let value: String
    /// The `seq` of the `dlg` event that delegated the signing key.
    public let seq: Int

    public init(value: String, seq: Int) {
        self.value = value
        self.seq = seq
    }

    /// Exactly `{scheme, seq, value}` with scheme `ml-dsa-65`, a wire-integer `seq` and a canonical Base64 signature of
    /// the right size; nil otherwise.
    package init?(operational v: JSONValue?) {
        guard let o = v?.objectValue, Set(o.keys) == ["scheme", "value", "seq"], o["scheme"]?.stringValue == SigningScheme.mlDsa65.rawValue,
              let value = o["value"]?.stringValue, let seq = o["seq"]?.wireInt,
              (try? decodeSignature(value, code: .invalidSignature)) != nil else { return nil }
        self.init(value: value, seq: seq)
    }

    package var jsonValue: JSONValue {
        .object(["scheme": .string(SigningScheme.mlDsa65.rawValue), "value": .string(value), "seq": .number(Double(seq))])
    }
}
