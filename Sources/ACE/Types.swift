//
//  Types.swift
//  ACE SDK
//
//  ACE Protocol type definitions (packet 2.0, identity/relay API 1.0).
//

import Foundation

// MARK: - Identity

public enum SigningScheme: String, Codable, Sendable, CaseIterable {
    case ed25519
    case secp256k1
}

/// Every supported signing scheme (`SIGNING_SCHEMES` in the TS and Python SDKs).
public let signingSchemes: [SigningScheme] = SigningScheme.allCases

/// True when `value` is the wire name of a supported signing scheme.
public func isSigningScheme(_ value: String) -> Bool { SigningScheme(rawValue: value) != nil }

public enum IdentityTier: Int, Codable, Sendable {
    case keyOnly = 0
    case chainRegistered = 1
}

public enum HardwareBacking: String, Codable, Sendable {
    case secureEnclave = "secure-enclave"
    case tpm
    case hsm
    case tee
}

/// What the SDK needs from an identity (software, Secure Enclave, HSM, ...).
///
/// `decrypt`: an `ACEError` passes through unchanged (`decryption_failed` is permanent);
/// any other thrown error is reported by the SDK as `identity_unavailable` (local,
/// retryable). A Keychain / Secure Enclave wrapper borrows its X-Wing seed inside
/// `decrypt` and calls `ACEEncryption.decrypt(kemCiphertext:payload:seed:conversationId:)`.
public protocol ACEIdentity: Sendable {
    func getACEId() -> String
    func getSigningScheme() -> SigningScheme
    func getSigningPublicKey() -> Data
    func getEncryptionPublicKey() -> Data
    /// Sign a 32-byte signData digest. ed25519: 64 bytes. secp256k1: r‖s‖v (65 bytes, low-S, v ∈ {0,1}).
    func sign(_ data: Data) throws -> Data
    /// `kemCiphertext` is the 1120-byte X-Wing ciphertext, `payload` is nonce[12] ‖ ct ‖ tag[16].
    func decrypt(kemCiphertext: Data, payload: Data, conversationId: String) throws -> Data
}

// MARK: - Namespaced extensions (`ext`)

/// Namespaced extensions of a profile, registration file or intent (02 § Profile Fields):
/// each key is a namespaced identifier (04 grammar, at most 256 bytes), each value a JSON
/// object; at most 8 keys, canonical JSON at most 4096 bytes, nesting depth at most 8.
/// Validated by `validateExt`; the bundled `commerceExt` member is typed
/// (`CommerceProfileExt`, `CommerceIntentExt`). Any other namespace is opaque data.
public typealias ExtMap = [String: JSONValue]

/// The bundled commerce extension namespace, `urn:ace:commerce:1` (04 § Commerce extension).
public let commerceExt = "urn:ace:commerce:1"

/// `urn:ace:commerce:1` in a profile or registration file (04 § Commerce extension).
public struct CommerceProfileExt: Codable, Sendable, Equatable {
    /// CAIP-2 identifiers, at most 10.
    public var chains: [String]?
    public var pricing: CommercePricing?
    /// Settlement methods (05), at most 10.
    public var settlement: [String]?
    /// Payment addresses, at most 10.
    public var accounts: [CommerceAccount]?

    public init(chains: [String]? = nil, pricing: CommercePricing? = nil, settlement: [String]? = nil, accounts: [CommerceAccount]? = nil) {
        self.chains = chains
        self.pricing = pricing
        self.settlement = settlement
        self.accounts = accounts
    }
}

public struct CommercePricing: Codable, Sendable, Equatable {
    /// 1-16 characters without control characters.
    public var currency: String
    /// 1-32 characters matching `^[0-9]+(\.[0-9]+)?$`.
    public var maxAmount: String?

    public init(currency: String, maxAmount: String? = nil) {
        self.currency = currency
        self.maxAmount = maxAmount
    }
}

public struct CommerceAccount: Codable, Sendable, Equatable {
    /// CAIP-2.
    public var network: String
    public var address: String

    public init(network: String, address: String) {
        self.network = network
        self.address = address
    }
}

/// `urn:ace:commerce:1` in an intent: `maxPrice` (1-64) and `currency` (1-16), both present or both absent.
public struct CommerceIntentExt: Codable, Sendable, Equatable {
    public var maxPrice: String?
    public var currency: String?

    public init(maxPrice: String? = nil, currency: String? = nil) {
        self.maxPrice = maxPrice
        self.currency = currency
    }
}

// MARK: - Registration file

public struct Capability: Codable, Sendable, Equatable {
    public let id: String
    public let description: String
    public let input: String?
    public let output: String?

    public init(id: String, description: String, input: String? = nil, output: String? = nil) {
        self.id = id
        self.description = description
        self.input = input
        self.output = output
    }
}

public struct SigningConfig: Codable, Sendable, Equatable {
    public let scheme: SigningScheme
    public let address: String
    /// Base64; required for secp256k1.
    public var signingPublicKey: String?
    /// Base64 of the 1216-byte X-Wing public key.
    public let encryptionPublicKey: String

    public init(scheme: SigningScheme, address: String, signingPublicKey: String? = nil, encryptionPublicKey: String) {
        self.scheme = scheme
        self.address = address
        self.signingPublicKey = signingPublicKey
        self.encryptionPublicKey = encryptionPublicKey
    }
}

/// `/.well-known/ace.json`. Semantic checks are in `verifyRegistrationFile`.
public struct RegistrationFile: Codable, Sendable, Equatable {
    public let registeredAt: Int
    public let registrationSignature: String
    public let ace: String
    public let id: String
    public let name: String
    public var description: String?
    public let endpoint: String
    public let tier: IdentityTier
    public var hardwareBacking: HardwareBacking?
    public var signing: SigningConfig
    public var capabilities: [Capability]?
    /// Namespaced extensions, same rules as a profile's `ext` (commerce data lives under `commerceExt`).
    public var ext: ExtMap?
    public var principal: PrincipalRecord?

    public init(
        ace: String = "1.0",
        registeredAt: Int,
        registrationSignature: String,
        id: String,
        name: String,
        description: String? = nil,
        endpoint: String,
        tier: IdentityTier,
        hardwareBacking: HardwareBacking? = nil,
        signing: SigningConfig,
        capabilities: [Capability]? = nil,
        ext: ExtMap? = nil,
        principal: PrincipalRecord? = nil
    ) {
        self.ace = ace
        self.registeredAt = registeredAt
        self.registrationSignature = registrationSignature
        self.id = id
        self.name = name
        self.description = description
        self.endpoint = endpoint
        self.tier = tier
        self.hardwareBacking = hardwareBacking
        self.signing = signing
        self.capabilities = capabilities
        self.ext = ext
        self.principal = principal
    }

    /// The typed `urn:ace:commerce:1` member of `ext`, or nil when absent (no validation).
    public var commerce: CommerceProfileExt? { ext.flatMap(commerceProfileExt) }

    /// Parse the wire JSON (strict types, unknown fields ignored, optional `null` = absent).
    /// Failures are `invalid_registration`.
    public init(json: Data) throws {
        let v: JValue
        do { v = try JSONParser.parse(json) } catch {
            throw ACEError(.invalidRegistration, "registration file is not JSON")
        }
        self = try RegistrationFile.parse(v)
    }
}

// MARK: - Discovery profile

/// Relay discovery profile (self-asserted metadata). All fields optional.
public struct AgentProfile: Codable, Sendable, Equatable {
    public var name: String?
    public var description: String?
    public var image: String?
    public var tags: [String]?
    public var capabilities: [String]?
    public var endpoint: String?
    /// Namespaced extensions (02 § Profile Fields); served by relays in canonical form, never indexed.
    public var ext: ExtMap?
    public var principal: PrincipalRecord?

    public init(
        name: String? = nil,
        description: String? = nil,
        image: String? = nil,
        tags: [String]? = nil,
        capabilities: [String]? = nil,
        endpoint: String? = nil,
        ext: ExtMap? = nil,
        principal: PrincipalRecord? = nil
    ) {
        self.name = name
        self.description = description
        self.image = image
        self.tags = tags
        self.capabilities = capabilities
        self.endpoint = endpoint
        self.ext = ext
        self.principal = principal
    }

    /// The typed `urn:ace:commerce:1` member of `ext`, or nil when absent (no validation).
    public var commerce: CommerceProfileExt? { ext.flatMap(commerceProfileExt) }
}

/// Query parameters for `GET /v1/discover`.
public struct DiscoverQuery: Codable, Sendable, Equatable {
    public var q: String?
    /// Sent comma-joined; a tag must not contain `,`.
    public var tags: [String]?
    public var scheme: String?
    public var online: Bool?
    /// CAIP-10 account: only agents whose served principal record names it (02 § Search Parameters).
    public var account: String?
    public var limit: Int?
    public var cursor: String?

    public init(
        q: String? = nil, tags: [String]? = nil,
        scheme: String? = nil, online: Bool? = nil, limit: Int? = nil, cursor: String? = nil,
        account: String? = nil
    ) {
        self.q = q
        self.tags = tags
        self.scheme = scheme
        self.online = online
        self.account = account
        self.limit = limit
        self.cursor = cursor
    }
}

/// Wire shape of `GET /v1/peer` and each `/v1/discover` entry. Verify with `verifyPeerRecord`.
public struct PeerRecord: Codable, Sendable, Equatable {
    public let aceId: String
    /// Kept as a string so an unsupported scheme is reported as `invalid_peer`.
    public let scheme: String
    public let encryptionPublicKey: String
    public let signingPublicKey: String
    public let registrationSignature: String
    public let registeredAt: Int
    public let profile: AgentProfile?

    public init(
        aceId: String, scheme: String, encryptionPublicKey: String, signingPublicKey: String,
        registrationSignature: String, registeredAt: Int, profile: AgentProfile? = nil
    ) {
        self.aceId = aceId
        self.scheme = scheme
        self.encryptionPublicKey = encryptionPublicKey
        self.signingPublicKey = signingPublicKey
        self.registrationSignature = registrationSignature
        self.registeredAt = registeredAt
        self.profile = profile
    }

    /// Parse the wire JSON strictly. Failures are `invalid_peer`.
    public init(json: Data) throws {
        let v: JValue
        do { v = try JSONParser.parse(json) } catch {
            throw ACEError(.invalidPeer, "peer record is not JSON")
        }
        self = try PeerRecord.parse(v)
    }
}

// MARK: - Messages

public struct MessageType: RawRepresentable, Codable, Sendable, Hashable, CaseIterable {
    public let rawValue: String
    private init(_ value: String) { rawValue = value }
    public init?(rawValue: String) {
        guard Self.allCases.contains(where: { $0.rawValue == rawValue }) || isNamespacedIdentifier(rawValue) else { return nil }
        self.rawValue = rawValue
    }
    public init(from decoder: any Decoder) throws {
        let c = try decoder.singleValueContainer()
        let raw = try c.decode(String.self)
        guard let value = Self(rawValue: raw) else { throw DecodingError.dataCorruptedError(in: c, debugDescription: "invalid message type") }
        self = value
    }
    public func encode(to encoder: any Encoder) throws {
        var c = encoder.singleValueContainer()
        try c.encode(rawValue)
    }
    public static let rfq = Self("rfq")
    public static let offer = Self("offer")
    public static let accept = Self("accept")
    public static let reject = Self("reject")
    public static let invoice = Self("invoice")
    public static let receipt = Self("receipt")
    public static let deliver = Self("deliver")
    public static let confirm = Self("confirm")
    public static let info = Self("info")
    public static let text = Self("text")
    public static let request = Self("request")
    public static let decision = Self("decision")
    public static let report = Self("report")
    public static let allCases: [Self] = [.rfq, .offer, .accept, .reject, .invoice, .receipt, .deliver, .confirm, .info, .text, .request, .decision, .report]
    public var isEconomic: Bool { [.rfq, .offer, .accept, .reject, .invoice, .receipt, .deliver, .confirm].contains(self) }
    public var isPrincipal: Bool { self == .request || self == .decision || self == .report }
}

/// The thirteen bundled profile names, in profile order. Namespaced types may extend this set.
public let messageTypes: [MessageType] = MessageType.allCases
/// The eight economic types, in protocol order.
public let economicTypes: [MessageType] = MessageType.allCases.filter(\.isEconomic)
/// The three principal types, in protocol order.
public let principalTypes: [MessageType] = MessageType.allCases.filter(\.isPrincipal)

public struct EncryptionEnvelope: Codable, Sendable, Equatable {
    /// Base64(X-Wing ciphertext[1120]).
    public let kemCiphertext: String
    /// Base64(nonce ‖ ciphertext ‖ tag).
    public let payload: String

    public init(kemCiphertext: String, payload: String) {
        self.kemCiphertext = kemCiphertext
        self.payload = payload
    }
}

public struct SignatureEnvelope: Codable, Sendable, Equatable {
    public let scheme: SigningScheme
    /// Base64 (ed25519) or `0x` + 130 lowercase hex (secp256k1).
    public let value: String

    public init(scheme: SigningScheme, value: String) {
        self.scheme = scheme
        self.value = value
    }

    /// Exactly `{scheme, value}` with a known scheme; nil otherwise.
    init?(exactly o: [String: JSONValue]) {
        guard Set(o.keys) == ["scheme", "value"], let text = o["scheme"]?.stringValue,
              let scheme = SigningScheme(rawValue: text), let value = o["value"]?.stringValue else { return nil }
        self.init(scheme: scheme, value: value)
    }

    var jsonValue: JSONValue { .object(["scheme": .string(scheme.rawValue), "value": .string(value)]) }
}

/// A decoded envelope. Obtain from `decodeEnvelope` or `createMessage`.
///
/// `Codable` decoding rejects `"threadId": null`; full validation is `decodeEnvelope`.
public struct ACEMessage: Codable, Sendable, Equatable {
    public let ace: String
    public let messageId: String
    public let from: String
    public let to: String
    public let conversationId: String
    public let timestamp: Int
    public let encryption: EncryptionEnvelope
    public let signature: SignatureEnvelope

    public init(
        ace: String = "2.0",
        messageId: String,
        from: String,
        to: String,
        conversationId: String,
        timestamp: Int,
        encryption: EncryptionEnvelope,
        signature: SignatureEnvelope
    ) {
        self.ace = ace
        self.messageId = messageId
        self.from = from
        self.to = to
        self.conversationId = conversationId
        self.timestamp = timestamp
        self.encryption = encryption
        self.signature = signature
    }

    public init(from decoder: any Decoder) throws {
        let value = try JSONValue(from: decoder)
        guard let v = value.jvalue else { throw ACEError(.invalidEnvelope, "invalid JSON") }
        self = try decodeEnvelope(value: v)
    }

    /// The wire JSON (compact, keys sorted).
    public func jsonData() -> Data {
        JSONWriter.serialize(jvalue)
    }

    var jvalue: JValue {
        let o: [String: JValue] = [
            "ace": .string(ace),
            "messageId": .string(messageId),
            "from": .string(from),
            "to": .string(to),
            "conversationId": .string(conversationId),
            "timestamp": .number(String(timestamp)),
            "encryption": .object([
                "kemCiphertext": .string(encryption.kemCiphertext),
                "payload": .string(encryption.payload),
            ]),
            "signature": .object([
                "scheme": .string(signature.scheme.rawValue),
                "value": .string(signature.value),
            ]),
        ]
        return .object(o)
    }
}

/// A verified, decrypted and validated inbound message.
public struct ParsedMessage: Sendable, Equatable {
    public let messageId: String
    public let from: String
    public let to: String
    public let conversationId: String
    public let type: MessageType
    public let threadId: String?
    public let timestamp: Int
    public let body: [String: JSONValue]
    public let schemaDigest: String

    public init(messageId: String, from: String, to: String, conversationId: String, type: MessageType, threadId: String?, timestamp: Int, body: [String: JSONValue], schemaDigest: String) {
        self.messageId = messageId
        self.from = from
        self.to = to
        self.conversationId = conversationId
        self.type = type
        self.threadId = threadId
        self.timestamp = timestamp
        self.body = body
        self.schemaDigest = schemaDigest
    }
}
