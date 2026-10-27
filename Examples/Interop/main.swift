//
//  ACEInterop: the ACE interop matrix driver for the Swift SDK (contract: ace-spec/interop/README.md).
//
//    ACEInterop gen-identity <dir> [--handle H] --now N
//    ACEInterop create-packet <dir> --to-agent F --kind K --out P [--prekey-agent F2] [--message M] [--message-id ID]
//                             [--ref-message-id ID] [--ref-prekey ID] [--code C] [--note N]
//                             [--to-prekey B64] --now N
//    ACEInterop open-packet <dir> --from-agent F --packet P --out R --now N
//    ACEInterop verify-card <card.json> --now N        (prints {"ok": true, aceId, handle?, contact, listed} or {"error": code})
//
//  The identity export (identity.json) and the prekey vault (store/, a FileStore with 0600 files) live in <dir>.
//  Exit 0 on success (a protocol rejection while opening is a success whose result is {"error": code}); 2 otherwise.
//

import ACE
import Foundation

let relayRoute = "https://relay.interop.test"
let installed = try! InstalledProfiles([.text])

struct Failure: Error, CustomStringConvertible { let description: String }

func readJSON(_ path: String) throws -> JSONValue {
    try JSONValue(json: try Data(contentsOf: URL(fileURLWithPath: path)))
}

func writeJSON(_ path: String, _ value: JSONValue) throws {
    var data = try value.jsonData()
    data.append(0x0A)
    try data.write(to: URL(fileURLWithPath: path))
}

func path(_ dir: String, _ name: String) -> String { (dir as NSString).appendingPathComponent(name) }

func vault(_ dir: String) throws -> StorePrekeyVault {
    StorePrekeyVault(store: try FileStore(directory: URL(fileURLWithPath: path(dir, "store"), isDirectory: true)))
}

func loadIdentity(_ dir: String, now: Int) throws -> SoftwareIdentity {
    let data = try Data(contentsOf: URL(fileURLWithPath: path(dir, "identity.json")))
    return try SoftwareIdentity(export: SoftwareIdentityExport(json: data), now: now)
}

func genIdentity(_ dir: String, handle: String?, now: Int) throws {
    try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
    let identity = try SoftwareIdentity.generate(now: now)
    let prekey = try vault(dir).rotate(now: now).prekey
    let agent = try createPublishedAgent(identity: identity, claims: DescriptorClaims(
        relays: [relayRoute], prekey: prekey, profiles: [ProfileManifest.text.ref]),
        now: now, lifetime: 86_400)
    let export = try identity.exportPrivateKey().jsonData()
    FileManager.default.createFile(atPath: path(dir, "identity.json"), contents: export, attributes: [.posixPermissions: 0o600])
    try writeJSON(path(dir, "agent.json"), agent.source)
    let card = try createCardRecord(identity: identity, home: relayRoute, handle: handle, contact: .open, listed: false, now: now)
    try writeJSON(path(dir, "card.json"), card)
}

func verifyCardCommand(_ file: String, now: Int) throws -> JSONValue {
    let value = try readJSON(file)
    do {
        let record = try verifyCardBundle(value, now: now).record
        var out: [String: JSONValue] = ["ok": true, "aceId": .string(record.aceId), "contact": .string(record.contact.rawValue),
                                        "listed": .bool(record.listed)]
        if let h = record.handle { out["handle"] = .string(h) }
        return .object(out)
    } catch let e as ACEError {
        return ["error": .string(e.outcomeCode)]
    }
}

func createPacketCommand(_ dir: String, _ o: [String: String], now: Int) throws {
    let identity = try loadIdentity(dir, now: now)
    let own = try readJSON(path(dir, "agent.json"))
    guard let toPath = o["to-agent"], let kind = o["kind"], let out = o["out"] else { throw Failure(description: "missing arguments") }
    let to = try verifyPublishedAgent(try readJSON(toPath), now: now)
    // --to-prekey: a peer prekey the recipient offered (04 § Peer prekeys), else a descriptor prekey.
    let target: Prekey
    if let b64 = o["to-prekey"] {
        guard let raw = Data(base64Encoded: b64) else { throw Failure(description: "--to-prekey is not Base64") }
        target = try Prekey(publicKey: raw)
    } else {
        target = try o["prekey-agent"].map { try verifyPublishedAgent(try readJSON($0), now: now) }?.descriptor.prekey ?? to.descriptor.prekey
    }
    func permit() throws -> JSONValue { try createPermit(identity: identity, subject: to.aceId, now: now) }
    let content: PrivateContent
    switch kind {
    case "text":
        content = try installed.content(type: ProfileManifest.text.id, body: ["message": .string(o["message"] ?? "hello")])
    case "receipt-delivered":
        content = try installed.content(type: CoreTypes.receipt, body: ["messageId": .string(o["ref-message-id"] ?? ""), "outcome": "delivered"])
    case "receipt-unknown-prekey":
        content = try installed.content(type: CoreTypes.receipt, body: [
            "messageId": .string(o["ref-message-id"] ?? ""), "outcome": "rejected", "code": "unknown_prekey",
            "prekey": .string(o["ref-prekey"] ?? ""),
        ])
    case "receipt-rejected":
        content = try installed.content(type: CoreTypes.receipt, body: [
            "messageId": .string(o["ref-message-id"] ?? ""), "outcome": "rejected", "code": .string(o["code"] ?? "unsupported_schema"),
            "permit": try permit(),
        ])
    case "contact-request", "contact-accepted":
        content = try installed.content(type: CoreTypes.contact, body: [
            "kind": .string(String(kind.dropFirst("contact-".count))), "profile": .string(ProfileManifest.text.id),
            "note": .string(o["note"] ?? "hi"), "source": own, "permit": try permit(),
        ])
    case "contact-rejected":
        content = try installed.content(type: CoreTypes.contact, body: [
            "kind": "rejected", "profile": .string(ProfileManifest.text.id), "note": "", "source": own,
        ])
    default:
        throw Failure(description: "unknown kind \(kind)")
    }
    let offered = try vault(dir).offer(peer: to.aceId, now: now).publicKey  // the prekey offered to the recipient
    let packet = try createPacket(sender: identity, to: to.aceId, prekey: target, content: content.with(prekey: offered),
                                  messageId: o["message-id"] ?? UUID().uuidString.lowercased(), timestamp: now)
    try packet.jsonData().write(to: URL(fileURLWithPath: out))
    try writeJSON(out + ".content.json", content.with(prekey: offered).jsonValue)
}

/// The receive pipeline of 06 minus admission, pinning and deduplication, in the README's order.
func openPacketCommand(_ dir: String, _ o: [String: String], now: Int) throws -> JSONValue {
    guard let fromPath = o["from-agent"], let packetPath = o["packet"] else { throw Failure(description: "missing arguments") }
    let identity = try loadIdentity(dir, now: now)
    let me = identity.getACEId()
    let raw = try Data(contentsOf: URL(fileURLWithPath: packetPath))
    do {
        let packet = try Packet(json: raw)                                                   // 1
        guard packet.to == me else { throw ACEError(.wrongRecipient) }
        // The sender's KEL stands for the receiver's pin (06 step 3); its descriptor is not needed here.
        let events = (try readJSON(fromPath))["kel"]?.arrayValue?.compactMap(\.objectValue) ?? []
        let sender = try ACEKel.verify(events, now: now)                                     // 2
        guard sender.aceId == packet.from else { throw ACEError(.invalidSignature, "packet is not from the given agent") }
        try verifyPacketSignature(packet, sender: sender, now: now)                         // 3
        guard packet.timestamp >= now - ACELimits.offlineWindowSeconds,
              packet.timestamp <= now + ACELimits.timestampWindowSeconds else { throw ACEError(.staleTimestamp) }  // 4
        let content = try PrivateContent(json: try decryptPacket(packet, vault: vault(dir), now: now))  // 5
        try installed.validate(content)                                                      // 6
        let b = content.body                                                                 // 7
        if content.type == CoreTypes.contact {
            guard let src = b["source"], src["descriptor"]?["aceId"]?.stringValue == packet.from else { throw ACEError(.invalidAuthorization) }
            let source: VerifiedAgent
            do { source = try verifyPublishedAgent(src, now: now) } catch let e as ACEError {
                throw ACEError(.invalidAuthorization, "contact source: \(e.message)")
            }
            try verifyPacketSignature(packet, sender: source.state, now: now)
            guard (b["note"]?.stringValue ?? "").utf8.count <= ACELimits.maxNoteBytes else { throw ACEError(.invalidBody, "note too long") }
            guard (b["kind"] == "rejected") == (b["permit"] == nil) else { throw ACEError(.invalidAuthorization, "permit presence") }
            if let permit = b["permit"] { _ = try verifyPermit(permit, issuer: source.state, subject: me, now: now) }
        } else if content.type == CoreTypes.receipt {
            try checkReceiptBody(.object(b))
            if let permit = b["permit"] { _ = try verifyPermit(permit, issuer: sender, subject: me, now: now) }
        }
        var out: [String: JSONValue] = ["ok": true, "from": .string(packet.from), "messageId": .string(packet.messageId),
                                        "type": .string(content.type), "schemaDigest": .string(content.schemaDigest), "body": .object(b),
                                        "prekeyId": .string(sha256Hex(content.prekey ?? Data()))]
        if let t = content.threadId { out["threadId"] = .string(t) }
        return .object(out)
    } catch let e as ACEError {
        return ["error": .string(e.outcomeCode)]
    }
}

func main() throws {
    var args = Array(CommandLine.arguments.dropFirst())
    guard args.count >= 2 else { throw Failure(description: "usage: ACEInterop <gen-identity|create-packet|open-packet|verify-card> <dir> [options] --now N") }
    let command = args.removeFirst(), dir = args.removeFirst()
    var options: [String: String] = [:]
    while !args.isEmpty {
        let flag = args.removeFirst()
        guard flag.hasPrefix("--"), !args.isEmpty else { throw Failure(description: "bad option \(flag)") }
        options[String(flag.dropFirst(2))] = args.removeFirst()
    }
    guard let nowText = options["now"] ?? ProcessInfo.processInfo.environment["ACE_INTEROP_NOW"], let now = Int(nowText) else {
        throw Failure(description: "--now is required")
    }
    switch command {
    case "gen-identity": try genIdentity(dir, handle: options["handle"], now: now)
    case "verify-card":
        var line = try verifyCardCommand(dir, now: now).jsonData()
        line.append(0x0A)
        FileHandle.standardOutput.write(line)
    case "create-packet": try createPacketCommand(dir, options, now: now)
    case "open-packet":
        guard let out = options["out"] else { throw Failure(description: "--out is required") }
        try writeJSON(out, try openPacketCommand(dir, options, now: now))
    default: throw Failure(description: "unknown command \(command)")
    }
}

do {
    try main()
} catch {
    FileHandle.standardError.write(Data("driver error: \(error)\n".utf8))
    exit(2)
}
