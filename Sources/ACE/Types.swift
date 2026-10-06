//
//  Types.swift
//  ACE SDK
//
//  ACE Protocol v1.0 type definitions.
//

import Foundation

// MARK: - Identity

public enum SigningScheme: String, Codable, Sendable, CaseIterable {
    case ed25519
    case secp256k1
}

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

// MARK: - Registration file

public struct PricingInfo: Codable, Sendable, Equatable {
    /// "per-call" | "per-token" | "per-hour" | "flat"
    public let model: String
    public let amount: String
    public let currency: String

    public init(model: String, amount: String, currency: String) {
        self.model = model
        self.amount = amount
        self.currency = currency
    }
}

public struct Capability: Codable, Sendable, Equatable {
    public let id: String
    public let description: String
    public let input: String?
    public let output: String?
    public let pricing: PricingInfo?

    public init(id: String, description: String, input: String? = nil, output: String? = nil, pricing: PricingInfo? = nil) {
        self.id = id
        self.description = description
        self.input = input
        self.output = output
        self.pricing = pricing
    }
}

public struct ChainInfo: Codable, Sendable, Equatable {
    /// CAIP-2.
    public let network: String
    public let address: String

    public init(network: String, address: String) {
        self.network = network
        self.address = address
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
    public let ace: String
    public let id: String
    public let name: String
    public var description: String?
    public let endpoint: String
    public let tier: IdentityTier
    public var hardwareBacking: HardwareBacking?
    public var signing: SigningConfig
    public var capabilities: [Capability]?
    public var settlement: [String]?
    public var chains: [ChainInfo]?

    public init(
        ace: String = "1.0",
        id: String,
        name: String,
        description: String? = nil,
        endpoint: String,
        tier: IdentityTier,
        hardwareBacking: HardwareBacking? = nil,
        signing: SigningConfig,
        capabilities: [Capability]? = nil,
        settlement: [String]? = nil,
        chains: [ChainInfo]? = nil
    ) {
        self.ace = ace
        self.id = id
        self.name = name
        self.description = description
        self.endpoint = endpoint
        self.tier = tier
        self.hardwareBacking = hardwareBacking
        self.signing = signing
        self.capabilities = capabilities
        self.settlement = settlement
        self.chains = chains
    }

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

public struct ProfilePricing: Codable, Sendable, Equatable {
    public let currency: String
    public let maxAmount: String?

    public init(currency: String, maxAmount: String? = nil) {
        self.currency = currency
        self.maxAmount = maxAmount
    }
}

/// Relay discovery profile (self-asserted metadata). All fields optional.
public struct AgentProfile: Codable, Sendable, Equatable {
    public var name: String?
    public var description: String?
    public var image: String?
    public var tags: [String]?
    public var capabilities: [String]?
    public var chains: [String]?
    public var endpoint: String?
    public var pricing: ProfilePricing?

    public init(
        name: String? = nil,
        description: String? = nil,
        image: String? = nil,
        tags: [String]? = nil,
        capabilities: [String]? = nil,
        chains: [String]? = nil,
        endpoint: String? = nil,
        pricing: ProfilePricing? = nil
    ) {
        self.name = name
        self.description = description
        self.image = image
        self.tags = tags
        self.capabilities = capabilities
        self.chains = chains
        self.endpoint = endpoint
        self.pricing = pricing
    }
}

/// Query parameters for `GET /v1/discover`.
public struct DiscoverQuery: Codable, Sendable, Equatable {
    public var q: String?
    public var tags: String?
    public var chain: String?
    public var scheme: String?
    public var online: Bool?
    public var limit: Int?
    public var cursor: String?

    public init(
        q: String? = nil, tags: String? = nil, chain: String? = nil,
        scheme: String? = nil, online: Bool? = nil, limit: Int? = nil, cursor: String? = nil
    ) {
        self.q = q
        self.tags = tags
        self.chain = chain
        self.scheme = scheme
        self.online = online
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

public enum MessageType: String, Codable, Sendable, CaseIterable {
    case rfq, offer, accept, reject, invoice, receipt, deliver, confirm
    case info
    case text

    /// The eight economic types (tracked by the thread state machine).
    public var isEconomic: Bool {
        switch self {
        case .info, .text: return false
        default: return true
        }
    }
}

/// All ten message types, in protocol order.
public let messageTypes: [MessageType] = MessageType.allCases
/// The eight economic types, in protocol order.
public let economicTypes: [MessageType] = MessageType.allCases.filter(\.isEconomic)

public func isMessageType(_ value: String) -> Bool { MessageType(rawValue: value) != nil }
public func isEconomicType(_ type: MessageType) -> Bool { type.isEconomic }

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
    public let type: MessageType
    public let threadId: String?
    public let timestamp: Int
    public let encryption: EncryptionEnvelope
    public let signature: SignatureEnvelope

    public init(
        ace: String = "1.0",
        messageId: String,
        from: String,
        to: String,
        conversationId: String,
        type: MessageType,
        threadId: String? = nil,
        timestamp: Int,
        encryption: EncryptionEnvelope,
        signature: SignatureEnvelope
    ) {
        self.ace = ace
        self.messageId = messageId
        self.from = from
        self.to = to
        self.conversationId = conversationId
        self.type = type
        self.threadId = threadId
        self.timestamp = timestamp
        self.encryption = encryption
        self.signature = signature
    }

    private enum CodingKeys: String, CodingKey {
        case ace, messageId, from, to, conversationId, type, threadId, timestamp, encryption, signature
    }

    public init(from decoder: any Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        ace = try c.decode(String.self, forKey: .ace)
        messageId = try c.decode(String.self, forKey: .messageId)
        from = try c.decode(String.self, forKey: .from)
        to = try c.decode(String.self, forKey: .to)
        conversationId = try c.decode(String.self, forKey: .conversationId)
        type = try c.decode(MessageType.self, forKey: .type)
        if c.contains(.threadId) {
            if try c.decodeNil(forKey: .threadId) {
                throw DecodingError.dataCorruptedError(forKey: .threadId, in: c, debugDescription: "threadId must not be null")
            }
            threadId = try c.decode(String.self, forKey: .threadId)
        } else {
            threadId = nil
        }
        timestamp = try c.decode(Int.self, forKey: .timestamp)
        encryption = try c.decode(EncryptionEnvelope.self, forKey: .encryption)
        signature = try c.decode(SignatureEnvelope.self, forKey: .signature)
    }

    /// The wire JSON (compact, keys sorted).
    public func jsonData() -> Data {
        JSONWriter.serialize(jvalue)
    }

    var jvalue: JValue {
        var o: [String: JValue] = [
            "ace": .string(ace),
            "messageId": .string(messageId),
            "from": .string(from),
            "to": .string(to),
            "conversationId": .string(conversationId),
            "type": .string(type.rawValue),
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
        if let threadId { o["threadId"] = .string(threadId) }
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

    public init(messageId: String, from: String, to: String, conversationId: String, type: MessageType, threadId: String?, timestamp: Int, body: [String: JSONValue]) {
        self.messageId = messageId
        self.from = from
        self.to = to
        self.conversationId = conversationId
        self.type = type
        self.threadId = threadId
        self.timestamp = timestamp
        self.body = body
    }
}
