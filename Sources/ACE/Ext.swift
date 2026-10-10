//
//  Ext.swift
//  ACE SDK
//
//  Namespaced extensions (`ext`) of profiles, registration files and intents
//  (02 § Profile Fields) and the bundled commerce extension (04 § Commerce extension).
//

import Foundation

/// What carries an `ext` object. Profiles and registration files fail with `invalid_profile`,
/// intents with `invalid_argument`.
public enum ExtCarrier: String, Sendable {
    case profile
    case intent

    var code: ACEError.Code { self == .profile ? .invalidProfile : .invalidArgument }
}

/// The 04 namespaced-identifier grammar (message types and `ext` keys).
private let namespacedIdRegex = try! NSRegularExpression(pattern: "^[a-z][a-z0-9+.-]*:[A-Za-z0-9._~:/?#\\[\\]@!$&'()*+,;=%-]+$")
private let caip2Regex = try! NSRegularExpression(pattern: "^[-a-z0-9]{3,8}:[-_a-zA-Z0-9]{1,32}$")
private let amountRegex = try! NSRegularExpression(pattern: "^[0-9]+(\\.[0-9]+)?$")

/// True when `value` is a namespaced identifier of at most 256 bytes (04 § Message Types grammar).
public func isNamespacedIdentifier(_ value: String) -> Bool {
    value.utf8.count <= ACELimits.maxExtKeyBytes && regexFullMatch(namespacedIdRegex, value)
}

/// An empty `ext` (`{}`) is absent everywhere: signed as `""`, not sent, not stored.
func normalizedExt(_ ext: ExtMap?) -> ExtMap? {
    guard let ext, !ext.isEmpty else { return nil }
    return ext
}

/// The canonical JSON of an `ext` object (06 § Appendix A form: compact, keys sorted), as signed
/// in the registration and intent payloads and as relays store and serve it.
public func extCanonical(_ ext: ExtMap) throws -> Data {
    do { return try JSONValue.object(ext).jsonData() } catch {
        throw ACEError(.invalidArgument, "ext cannot represent a non-finite number")
    }
}

/// `extCanonicalOrEmpty`: the canonical JSON text of `ext`, or `""` when absent or empty.
func extCanonicalOrEmpty(_ ext: ExtMap?) throws -> String {
    guard let ext = normalizedExt(ext) else { return "" }
    return String(decoding: try extCanonical(ext), as: UTF8.self)
}

/// Validate an `ext` object (02 § Profile Fields): each key a namespaced identifier of at most
/// 256 bytes, each value a JSON object, at most 8 keys, canonical JSON at most 4096 bytes, nesting
/// depth at most 8; when `urn:ace:commerce:1` is present it is checked by `validateCommerceExt`.
/// Failures are `invalid_profile` (`.profile`) or `invalid_argument` (`.intent`).
@discardableResult
public func validateExt(_ ext: ExtMap, carrier: ExtCarrier) throws -> ExtMap {
    let code = carrier.code
    guard ext.count <= ACELimits.maxExtKeys else { throw ACEError(code, "ext has more than \(ACELimits.maxExtKeys) namespaces") }
    for (key, value) in ext {
        guard isNamespacedIdentifier(key) else {
            throw ACEError(code, "ext key is not a namespaced identifier: \(String(key.prefix(64)))")
        }
        guard value.objectValue != nil else { throw ACEError(code, "ext[\(key)] must be a JSON object") }
    }
    do { try checkJSONValue(.object(ext), maxDepth: ACELimits.maxExtDepth, code: code) } catch let e as ACEError {
        throw ACEError(code, "ext: \(e.message)")
    }
    guard try extCanonical(ext).count <= ACELimits.maxExtBytes else {
        throw ACEError(code, "ext canonical JSON exceeds \(ACELimits.maxExtBytes) bytes")
    }
    if let commerce = ext[commerceExt] { try validateCommerceExt(commerce, carrier: carrier) }
    return ext
}

// MARK: - Commerce extension (urn:ace:commerce:1)

/// A string of `lo`...`hi` code points; `controls: false` additionally rejects control characters.
private func commerceText(_ v: JSONValue?, _ name: String, _ lo: Int, _ hi: Int, _ code: ACEError.Code, controls: Bool) throws -> String {
    guard let s = v?.stringValue else { throw ACEError(code, "\(commerceExt).\(name) must be a string") }
    let n = s.unicodeScalars.count
    guard n >= lo, n <= hi, controls || !hasControlCharacter(s) else {
        throw ACEError(code, "\(commerceExt).\(name) must be \(lo)-\(hi) characters\(controls ? "" : " without control characters")")
    }
    return s
}

private func commerceStrings(_ v: JSONValue, _ name: String, _ code: ACEError.Code) throws -> [String] {
    guard let a = v.arrayValue, a.count <= 10 else { throw ACEError(code, "\(commerceExt).\(name) must be an array of at most 10 strings") }
    return try a.map {
        guard let s = $0.stringValue else { throw ACEError(code, "\(commerceExt).\(name) must be an array of strings") }
        return s
    }
}

/// Validate the `urn:ace:commerce:1` member of an `ext` object against the 04 table for its
/// carrier. Profile / registration-file members: `chains` (at most 10 CAIP-2), `pricing`
/// (`currency` 1-16, `maxAmount` 1-32 matching `^[0-9]+(\.[0-9]+)?$`), `settlement` (at most 10
/// strings), `accounts` (at most 10 `{network: CAIP-2, address}`); intent members: `maxPrice`
/// (1-64) and `currency` (1-16), both or neither. Unknown members are invalid.
private func onlyMembers(_ o: [String: JSONValue], _ allowed: Set<String>, _ subject: String, _ code: ACEError.Code) throws {
    let extra = Set(o.keys).subtracting(allowed)
    guard extra.isEmpty else { throw ACEError(code, "\(subject) unknown members: \(extra.sorted().prefix(3))") }
}

public func validateCommerceExt(_ value: JSONValue, carrier: ExtCarrier) throws {
    let code = carrier.code
    guard let o = value.objectValue else { throw ACEError(code, "\(commerceExt) must be a JSON object") }
    switch carrier {
    case .profile:
        try onlyMembers(o, ["chains", "pricing", "settlement", "accounts"], "\(commerceExt) has", code)
        if let v = o["chains"] {
            let chains = try commerceStrings(v, "chains", code)
            guard chains.allSatisfy({ regexFullMatch(caip2Regex, $0) }) else {
                throw ACEError(code, "\(commerceExt).chains must be CAIP-2 identifiers")
            }
        }
        if let v = o["pricing"] {
            guard let p = v.objectValue else { throw ACEError(code, "\(commerceExt).pricing must be a JSON object") }
            try onlyMembers(p, ["currency", "maxAmount"], "\(commerceExt).pricing has", code)
            _ = try commerceText(p["currency"], "pricing.currency", 1, 16, code, controls: false)
            if let m = p["maxAmount"] {
                guard let s = m.stringValue, s.unicodeScalars.count <= 32, regexFullMatch(amountRegex, s) else {
                    throw ACEError(code, "\(commerceExt).pricing.maxAmount must match ^[0-9]+(\\.[0-9]+)?$ (1-32 chars)")
                }
            }
        }
        if let v = o["settlement"] { _ = try commerceStrings(v, "settlement", code) }
        if let v = o["accounts"] {
            guard let a = v.arrayValue, a.count <= 10 else {
                throw ACEError(code, "\(commerceExt).accounts must be an array of at most 10 objects")
            }
            for entry in a {
                guard let e = entry.objectValue else { throw ACEError(code, "\(commerceExt).accounts entries must be objects") }
                try onlyMembers(e, ["network", "address"], "\(commerceExt).accounts entries have", code)
                guard let network = e["network"]?.stringValue, regexFullMatch(caip2Regex, network) else {
                    throw ACEError(code, "\(commerceExt).accounts[].network must be a CAIP-2 identifier")
                }
                guard e["address"]?.stringValue != nil else { throw ACEError(code, "\(commerceExt).accounts[].address must be a string") }
            }
        }
    case .intent:
        try onlyMembers(o, ["maxPrice", "currency"], "\(commerceExt) has", code)
        guard (o["maxPrice"] == nil) == (o["currency"] == nil) else {
            throw ACEError(code, "\(commerceExt).maxPrice and .currency must both be present or both absent")
        }
        if o["maxPrice"] != nil {
            _ = try commerceText(o["maxPrice"], "maxPrice", 1, 64, code, controls: true)
            _ = try commerceText(o["currency"], "currency", 1, 16, code, controls: true)
        }
    }
}

/// The typed `urn:ace:commerce:1` member of a profile / registration-file `ext`, or nil when the
/// namespace is absent. Members of an unexpected type are dropped; use `validateCommerceExt` to check.
public func commerceProfileExt(_ ext: ExtMap) -> CommerceProfileExt? {
    guard let o = ext[commerceExt]?.objectValue else { return nil }
    let strings: (JSONValue?) -> [String]? = { $0?.arrayValue.flatMap { a in
        let s = a.compactMap(\.stringValue)
        return s.count == a.count ? s : nil
    } }
    var pricing: CommercePricing?
    if let p = o["pricing"]?.objectValue, let currency = p["currency"]?.stringValue {
        pricing = CommercePricing(currency: currency, maxAmount: p["maxAmount"]?.stringValue)
    }
    let accounts: [CommerceAccount]? = o["accounts"]?.arrayValue.flatMap { a in
        let out = a.compactMap { e -> CommerceAccount? in
            guard let n = e["network"]?.stringValue, let ad = e["address"]?.stringValue else { return nil }
            return CommerceAccount(network: n, address: ad)
        }
        return out.count == a.count ? out : nil
    }
    return CommerceProfileExt(chains: strings(o["chains"]), pricing: pricing, settlement: strings(o["settlement"]), accounts: accounts)
}

/// The typed `urn:ace:commerce:1` member of an intent `ext`, or nil when the namespace is absent.
public func commerceIntentExt(_ ext: ExtMap) -> CommerceIntentExt? {
    guard let o = ext[commerceExt]?.objectValue else { return nil }
    return CommerceIntentExt(maxPrice: o["maxPrice"]?.stringValue, currency: o["currency"]?.stringValue)
}

extension CommerceProfileExt {
    /// The JSON object form, for `ext[commerceExt]`.
    public var jsonValue: JSONValue {
        var o: [String: JSONValue] = [:]
        if let chains { o["chains"] = .array(chains.map { .string($0) }) }
        if let pricing {
            var p: [String: JSONValue] = ["currency": .string(pricing.currency)]
            if let m = pricing.maxAmount { p["maxAmount"] = .string(m) }
            o["pricing"] = .object(p)
        }
        if let settlement { o["settlement"] = .array(settlement.map { .string($0) }) }
        if let accounts {
            o["accounts"] = .array(accounts.map { .object(["network": .string($0.network), "address": .string($0.address)]) })
        }
        return .object(o)
    }
}

extension CommerceIntentExt {
    /// The JSON object form, for `ext[commerceExt]`.
    public var jsonValue: JSONValue {
        var o: [String: JSONValue] = [:]
        if let maxPrice { o["maxPrice"] = .string(maxPrice) }
        if let currency { o["currency"] = .string(currency) }
        return .object(o)
    }
}
