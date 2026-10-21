//
//  NetworkClient.swift
//  ACE SDK
//
//  The networking runtime of one identity: publish (descriptor, then card record), discover, look up (descriptors and
//  card records), import, connect (contact packets), accept /
//  reject, block, invitations, send, pull / follow and upkeep. Admission is local configuration: descriptors, notes and
//  messages never change `acceptProfiles` or install profiles.
//

import Foundation

/// What a `NetworkClient` publishes and admits, and its host callbacks.
public struct NetworkConfiguration: Sendable {
    /// Installed profiles besides `core` (announced in the descriptor).
    public var profiles: [ProfileManifest]
    /// Profile IDs whose contact requests are accepted without an explicit `accept` (must be installed).
    public var acceptProfiles: [String]
    /// The card record's handle at the home relay: set once, it can never change or be dropped (04 § Card record).
    public var handle: String?
    /// The card record's presentation card.
    public var card: AgentCard
    /// The card record's payment accounts: 1–`ACELimits.maxPayAccounts` distinct CAIP-10 accounts.
    public var pay: [String]?
    /// Whether strangers' contact requests are processed (05 § Flow; default `closed`).
    public var contact: Contact
    /// Whether the home relay's directory lists this identity (default false).
    public var listed: Bool
    public var ext: [String: JSONValue]?
    /// `{kel, credential}` entries issued to this identity by its controllers (`createDelegation`).
    public var delegations: [JSONValue]
    public var erc8004: [ERC8004Binding]
    /// Profile rules for the Outbox and Inbox (for example `commerceRules`).
    public var rules: [any ProfileRules]
    /// Development only: accept loopback HTTP relays in descriptors and as peers' relays.
    public var allowLoopbackRelays: Bool
    /// Each delivered application message, after it was committed. Persist the effect durably and idempotently, keyed by
    /// `(from, messageId)`; throwing `receiver_capacity` holds the inbox, any other throw retries the packet.
    public var onMessage: (@Sendable (ReceivedMessage) async throws -> Void)?
    /// Each authenticated receipt `(from, body, entry)`, with the Outbox entry it settled or updated (nil when it matched
    /// none).
    public var onReceipt: (@Sendable (String, [String: JSONValue], OutboxEntry?) async -> Void)?

    public init(profiles: [ProfileManifest] = [.text], acceptProfiles: [String] = [], handle: String? = nil, card: AgentCard = AgentCard(),
                pay: [String]? = nil, contact: Contact = .closed, listed: Bool = false,
                ext: [String: JSONValue]? = nil, delegations: [JSONValue] = [], erc8004: [ERC8004Binding] = [],
                rules: [any ProfileRules] = [], allowLoopbackRelays: Bool = false,
                onMessage: (@Sendable (ReceivedMessage) async throws -> Void)? = nil,
                onReceipt: (@Sendable (String, [String: JSONValue], OutboxEntry?) async -> Void)? = nil) {
        self.profiles = profiles
        self.acceptProfiles = acceptProfiles
        self.handle = handle
        self.card = card
        self.pay = pay
        self.contact = contact
        self.listed = listed
        self.ext = ext
        self.delegations = delegations
        self.erc8004 = erc8004
        self.rules = rules
        self.allowLoopbackRelays = allowLoopbackRelays
        self.onMessage = onMessage
        self.onReceipt = onReceipt
    }
}

/// An invitation (05 § Invitations): the closed `{agent, permit}`, the inviter's PublishedAgent and a delivery permit it
/// issued to one peer. Share it only over a private channel: the permit is a bearer credential.
public struct Invitation: Sendable, Equatable {
    public let agent: JSONValue
    public let permit: JSONValue

    public init(agent: JSONValue, permit: JSONValue) {
        self.agent = agent
        self.permit = permit
    }

    /// Exactly `{agent, permit}` (`invalid_argument` otherwise); verified by `importInvitation`.
    public init(_ value: JSONValue) throws {
        guard let o = value.objectValue, Set(o.keys) == ["agent", "permit"], let agent = o["agent"], let permit = o["permit"] else {
            throw ACEError(.invalidArgument, "an invitation is {agent, permit}")
        }
        self.init(agent: agent, permit: permit)
    }

    public var jsonValue: JSONValue { ["agent": agent, "permit": permit] }
}

/// The networking runtime of one identity. Create it with `NetworkClient.open`.
public actor NetworkClient: PacketTransport {
    public nonisolated let identity: any ACEIdentity
    public nonisolated let store: any ACEStore
    /// The home relay.
    public nonisolated let relay: RelayClient
    public nonisolated let prekeys: any PrekeyVault
    public nonisolated let configuration: NetworkConfiguration
    public nonisolated let profiles: InstalledProfiles
    public nonisolated let peers: PeerStore
    public nonisolated let outbox: Outbox
    public nonisolated let admission: AdmissionTable
    private let foreignRelay: @Sendable (String) throws -> RelayClient
    package nonisolated let clock: @Sendable () -> Int
    /// Nil for a send-only client (`receive: false`) and after `close()`.
    package private(set) var inbox: Inbox?

    private init(identity: any ACEIdentity, store: any ACEStore, relay: RelayClient, prekeys: any PrekeyVault,
                 configuration: NetworkConfiguration, foreignRelay: (@Sendable (String) throws -> RelayClient)?,
                 clock: @escaping @Sendable () -> Int) throws {
        let profiles = try InstalledProfiles(configuration.profiles)
        for id in configuration.acceptProfiles where profiles.manifest(id) == nil || id == ProfileManifest.core.id {
            throw ACEError(.invalidArgument, "acceptProfiles must name installed profiles")
        }
        let loopback = configuration.allowLoopbackRelays
        self.identity = identity
        self.store = store
        self.relay = relay
        self.prekeys = prekeys
        self.configuration = configuration
        self.profiles = profiles
        self.foreignRelay = foreignRelay ?? { url in try RelayClient.foreign(url, allowLoopbackRelays: loopback, clock: clock) }
        self.clock = clock
        self.peers = PeerStore(store: store, clock: clock)
        self.outbox = Outbox(identity: identity, store: store, profiles: profiles, rules: configuration.rules, clock: clock)
        self.admission = AdmissionTable(store: store, clock: clock)
    }

    /// A client over `relay` (the home relay). With `receive` (the default) it opens the Inbox, taking the store's
    /// exclusive `receive` lock until `close()` (`lock_busy` when another process holds it); `receive: false` gives a
    /// send-only client beside a receiving one, without `pull` and `follow`. `foreignRelay` builds the clients for relays
    /// named in peers' descriptors and must enforce the host's outbound policy; the default is `RelayClient.foreign`
    /// (https, blocked addresses refused). The identity is registered on demand by `publish`.
    public static func open(identity: any ACEIdentity, store: any ACEStore, relay: RelayClient, prekeys: any PrekeyVault,
                            configuration: NetworkConfiguration = NetworkConfiguration(), receive: Bool = true,
                            foreignRelay: (@Sendable (String) throws -> RelayClient)? = nil,
                            clock: @escaping @Sendable () -> Int = systemClock) async throws -> NetworkClient {
        try await open(identity: identity, store: store, relay: relay, prekeys: prekeys, configuration: configuration, receive: receive,
                       foreignRelay: foreignRelay, clock: clock, capacity: ACELimits.defaultReplayCapacity)
    }

    /// `open` with a seen-store capacity (tests and vectors use small ones).
    package static func open(identity: any ACEIdentity, store: any ACEStore, relay: RelayClient, prekeys: any PrekeyVault,
                             configuration: NetworkConfiguration = NetworkConfiguration(), receive: Bool = true,
                             foreignRelay: (@Sendable (String) throws -> RelayClient)? = nil,
                             clock: @escaping @Sendable () -> Int = systemClock, capacity: Int) async throws -> NetworkClient {
        let client = try NetworkClient(identity: identity, store: store, relay: relay, prekeys: prekeys, configuration: configuration,
                                       foreignRelay: foreignRelay, clock: clock)
        if receive {
            await client.setInbox(try await Inbox.open(network: client, onMessage: configuration.onMessage, capacity: capacity, clock: clock))
        }
        return client
    }

    private func setInbox(_ inbox: Inbox?) { self.inbox = inbox }

    /// Close the Inbox (after the pass in progress) and release the `receive` lock. Idempotent.
    public func close() async {
        await inbox?.close()
        inbox = nil
    }

    private func now() throws -> Int { try unixNow(clock) }
    private nonisolated var me: String { identity.getACEId() }

    /// The home relay, or a fresh client for a relay named by a peer (not cached, as in sdk-ts and sdk-py: a URL set
    /// chosen by peers must not grow a cache of sessions).
    private func client(_ url: String) throws -> RelayClient {
        url == relay.baseURLString ? relay : try foreignRelay(url)
    }

    /// Try `body` on each route in order until one serves. `unknown_peer` only when every route answered it; otherwise the
    /// first other failure (a transient one included), so an unreachable route never reads as "not there". Every route is
    /// tried even after a permanent failure: one route replaying an old document (`stale_peer_binding`) or serving a bad
    /// one must not block a lookup the next route serves.
    private func onRoutes<T>(_ routes: [String], _ body: (RelayClient) async throws -> T) async throws -> T {
        var unknown: any Error = ACEError(.unknownPeer, "no route")
        var other: (any Error)?
        for url in routes {
            do { return try await body(try client(url)) } catch let e as ACEError where e.code == .unknownPeer {
                unknown = e
            } catch { other = other ?? error }
        }
        throw other ?? unknown
    }

    // MARK: Publishing

    /// Publish this identity's card record, then its descriptor. The card record goes first because it is the post a relay
    /// refuses (handle rules); a refused card leaves the published descriptor unchanged. The card record is re-signed when
    /// its settings change or after a new `dlg`; the PublishedAgent is re-signed and posted to the home relay when it is
    /// missing, changed, expiring within an hour or when the prekey rotates (every 24 hours). Unchanged ones are posted
    /// again only with `force`. A relay holding no registration (`not_registered`) or an older KEL (`kel_conflict`) gets
    /// the current KEL registered first. Prunes the prekey vault. Returns the PublishedAgent.
    @discardableResult
    public func publish(force: Bool = false) async throws -> VerifiedAgent {
        try await publishCard(force: force)
        return try await publishDescriptor(force: force)
    }

    private func publishDescriptor(force: Bool) async throws -> VerifiedAgent {
        let now = try now()
        var rotated = false
        var current = try prekeys.current()
        if current == nil || current!.createdAt + ACELimits.prekeyRotationSeconds <= now {
            current = try prekeys.rotate(now: now)
            rotated = true
        }
        try prekeys.prune(now: now)
        let claims = DescriptorClaims(relays: [relay.baseURLString], prekey: current!.prekey, profiles: profiles.refs, ext: configuration.ext,
                                      delegations: configuration.delegations, erc8004: configuration.erc8004)
        let old = try selfAgent()
        if !rotated, let old, old.descriptor.expiresAt - now > 3600, try same(old, claims) {
            if force { try await post(old) }
            return old
        }
        let issuedAt = max(now, (old?.descriptor.issuedAt ?? -1) + 1)
        let agent = try createPublishedAgent(identity: identity, claims: claims, now: issuedAt, allowLoopback: configuration.allowLoopbackRelays)
        try await post(agent)
        try store.checkedWrite("network/self.json", try agent.source.jsonData())
        return agent
    }

    private func post(_ agent: VerifiedAgent) async throws {
        try await registered { try await self.relay.publish(agent) }
    }

    /// `post` once; when the home relay lacks the current KEL, register it and post again.
    private func registered(_ post: () async throws -> Void) async throws {
        do {
            try await post()
        } catch let e as ACEError where e.code == .notRegistered || e.relayCode == "kel_conflict" {
            try await relay.register(identity)
            try await post()
        }
    }

    private static let cardKey = "network/card.json"

    /// The card record: re-signed (at `max(now, previous issuedAt + 1)`) and posted when its settings or the KEL changed
    /// (a new `dlg` re-signs it), else posted again only with `force`.
    private func publishCard(force: Bool) async throws {
        let now = try now()
        let settings = cardClaims(home: relay.baseURLString, handle: configuration.handle, card: configuration.card, pay: configuration.pay,
                                  contact: configuration.contact, listed: configuration.listed)
        let lastHash = try checkUsable(identity, now: now).lastHash
        let digest = sha256Hex(try JSONValue.object(["settings": .object(settings), "lastHash": .string(lastHash)]).jsonData())
        let old = try selfCard()
        if let old, old.params == digest {
            if force { try await registered { try await self.relay.publishCard(old.bundle) } }
            return
        }
        let issuedAt = max(now, (old?.bundle["card"]?["issuedAt"]?.wireInt ?? -1) + 1)
        let bundle = try createCardRecord(identity: identity, home: relay.baseURLString, handle: configuration.handle, card: configuration.card,
                                          pay: configuration.pay, contact: configuration.contact, listed: configuration.listed, now: issuedAt,
                                          allowLoopback: configuration.allowLoopbackRelays)
        try await registered { try await self.relay.publishCard(bundle) }
        try store.checkedWrite(Self.cardKey, try JSONValue.object(["bundle": bundle, "params": .string(digest)]).jsonData())
    }

    /// The last published card bundle and its settings digest (nil before the first card `publish`).
    private nonisolated func selfCard() throws -> (bundle: CardBundle, params: String)? {
        guard let raw = try store.checkedRead(Self.cardKey) else { return nil }
        guard let v = JSONValue(stored: raw), let bundle = v["bundle"], bundle["card"]?["contact"] != nil,
              let params = v["params"]?.stringValue else { throw ACEError(.storageFailed, "\(Self.cardKey) is invalid") }
        return (bundle, params)
    }

    /// The `contact` strangers meet (05 § Flow): `open` only while configured so and the published card record says so; no
    /// card record is `closed`.
    package nonisolated func publishedContact() throws -> Contact {
        guard configuration.contact == .open, try selfCard()?.bundle["card"]?["contact"]?.stringValue == Contact.open.rawValue else { return .closed }
        return .open
    }

    /// The last published PublishedAgent (nil before the first `publish`).
    private func selfAgent() throws -> VerifiedAgent? {
        guard let raw = try store.checkedRead("network/self.json") else { return nil }
        guard let v = JSONValue(stored: raw), let issued = v["descriptor"]?["issuedAt"]?.wireInt,
              let a = try? verifyPublishedAgent(v, now: issued, allowLoopback: true) else { throw ACEError(.storageFailed, "network/self.json is invalid") }
        return a
    }

    private func same(_ old: VerifiedAgent, _ c: DescriptorClaims) throws -> Bool {
        let kel = ExportJSON.kelValue(try identity.getKel())
        let d = old.descriptor
        return old.source["kel"] == kel && d.relays == c.relays && d.prekey == c.prekey && d.profiles == c.profiles
            && d.ext == c.ext && (old.source["descriptor"]?["delegations"]?.arrayValue ?? []) == c.delegations
            && d.erc8004 == c.erc8004
    }

    // MARK: Discovery

    /// The public directory of the home relay: identities whose card record is listed (verified, not pinned).
    public func discover(profile: String? = nil, cursor: String? = nil, limit: Int = ACELimits.defaultPageLimit) async throws -> RelayClient.DirectoryPage {
        try await relay.directory(profile: profile, cursor: cursor, limit: limit)
    }

    /// Verify a PublishedAgent shared out of band against the pin (the descriptor must verify under the newest pinned
    /// state) and pin it. Grants no admission.
    @discardableResult
    public func importAgent(_ source: JSONValue) async throws -> VerifiedAgent {
        try await peers.adopt(source: source, allowLoopback: configuration.allowLoopbackRelays)
    }

    /// An ACE ID (`agent(_:)`), or `@name@relay-host`: the verified, pinned descriptor of the identity whose card record
    /// holds that handle at that relay (checked against the card pin, see `lookupCard`).
    @discardableResult
    public func lookup(_ target: String) async throws -> VerifiedAgent {
        try await resolve(target).agent
    }

    /// `lookup` plus the peer's verified card record (nil: it has none, `unknown_peer` at every route). By handle, the
    /// card record the handle resolved through; by ACE ID, `lookupCard`.
    public func lookupWithCard(_ target: String) async throws -> (agent: VerifiedAgent, card: VerifiedCard?) {
        let found = try await resolve(target)
        if found.card != nil { return found }
        return (found.agent, try await cardOrNone(found.agent.aceId))
    }

    /// `lookup`, with the card record verified on the way when `target` is a handle.
    private func resolve(_ target: String) async throws -> (agent: VerifiedAgent, card: VerifiedCard?) {
        if isACEId(target) { return (try await agent(target), nil) }
        let (bundle, url, handle) = try await cardByHandle(target)
        let id = Self.aceId(of: bundle)
        // The descriptor first: it pins or advances the KEL (live), so the card verifies under the current KEL.
        let agent = try await fetchAgent(id, routes: [url])
        // The pin's own `kelLive`: a relay replaying an older revision confirms nothing (as `lookupCard`).
        return (agent, try await checkCard(bundle, resolved: (home: url, handle: handle), kelLive: try await peers.kelLive(id)))
    }

    /// The verified card record of `target` (an ACE ID or `@name@relay-host`). A handle resolves only to a record whose
    /// `home` is the queried relay and whose `handle` is the queried one (`unknown_peer`). Every record is checked against
    /// the identity's card pin, kept durably: an older `issuedAt` than one already verified, or an equal one with other
    /// claims, is `stale_descriptor`; a handle is set once per home, so after a record with a handle was seen, a record
    /// naming the same home with another or no handle is `invalid_authorization` (a new home re-pins). A handle's first
    /// resolution pins its ACE ID; a later resolution to another one is `invalid_authorization`. Without a KEL pin for the
    /// identity, its descriptor is looked up first and its KEL pinned, so the card is verified under the current KEL, never
    /// one a relay chose. When every route answers `unknown_peer` (no live descriptor: offline past its lifetime), the card
    /// is verified under the bundle's own KEL instead, that KEL is pinned as a descriptor's would be, and the result has
    /// `kelLive` false (04 § Card record). That pin is recorded as not confirmed live: later lookups look the descriptor up
    /// again and report false until one confirms it.
    public func lookupCard(_ target: String) async throws -> VerifiedCard {
        if isACEId(target) {
            let (kelLive, fetched) = try await cardKel(target, { _ = try await self.agent(target, refresh: true) }, { try await self.fetchCard(target) })
            let bundle: CardBundle
            if let fetched { bundle = fetched } else { bundle = try await fetchCard(target) }
            return try await checkCard(bundle, kelLive: kelLive)
        }
        let (bundle, url, handle) = try await cardByHandle(target)
        let id = Self.aceId(of: bundle)
        let (kelLive, _) = try await cardKel(id, { _ = try await self.fetchAgent(id, routes: [url]) }, { bundle })
        return try await checkCard(bundle, resolved: (home: url, handle: handle), kelLive: kelLive)
    }

    /// The KEL a card lookup verifies under, and whether a live descriptor confirmed it. A pin confirmed live is used as is.
    /// Otherwise the descriptor is looked up at a relay through `fetch` (never a cached one) and the result is the pin's
    /// `kelLive` after it: a relay's descriptor bound to the pin confirms it, a replayed or older one does not. When
    /// every route answers `unknown_peer`, an unconfirmed pin stays unconfirmed, and
    /// without a pin the card's own bundle (`card`) pins the KEL (`pinBundleKel`). Every other failure propagates.
    private func cardKel(_ aceId: String, _ fetch: () async throws -> Void,
                         _ card: () async throws -> CardBundle) async throws -> (Bool, CardBundle?) {
        guard isACEId(aceId) else { return (true, nil) }
        let pinned = try await peers.pinned(aceId)
        if pinned != nil, try await peers.kelLive(aceId) { return (true, nil) }
        do {
            try await fetch()
        } catch let e as ACEError where e.code == .unknownPeer {
            if pinned != nil { return (false, nil) }
            return (false, try await pinBundleKel(aceId, try await card()))
        }
        return (try await peers.kelLive(aceId), nil)
    }

    /// Pin the verified KEL of `bundle` (no live descriptor: not `kelLive`).
    private func pinBundleKel(_ aceId: String, _ bundle: CardBundle) async throws -> CardBundle {
        let v = try verifyCardBundle(bundle, now: try now(), allowLoopback: configuration.allowLoopbackRelays,
                                     pinned: try await peers.pinned(aceId))
        guard v.aceId == aceId else { throw ACEError(.invalidAuthorization, "the card record names another identity") }
        // As for a descriptor: another path advanced the pin past the state the card verified under (left as it was).
        guard try await peers.pin(kel: v.state.events).state.lastHash == v.state.lastHash else {
            throw ACEError(.stalePeerBinding, "the pin advanced past the card record")
        }
        return bundle
    }

    private static func cardPinKey(_ aceId: String) -> String { "network/handles/\(sha256Hex(Data(aceId.utf8))).json" }

    /// The reverse handle pin: the ACE ID `@handle@home` first resolved to. A binding is permanent, so a later other one is
    /// misbehavior.
    private static func handleOwnerKey(home: String, handle: String) -> String {
        "network/handle-owners/\(sha256Hex(Data("\(home) \(handle)".utf8))).json"
    }

    /// A stored pin object, nil when absent; one that is not an object or lacks a required member (`valid`) is
    /// `storage_failed`, never no pin.
    private nonisolated func readPin(_ key: String, _ valid: (JSONValue) -> Bool) throws -> JSONValue? {
        guard let v = try store.readJSON(key) else { return nil }
        guard v.objectValue != nil, valid(v) else { throw ACEError(.storageFailed, "\(key) is invalid") }
        return v
    }

    private nonisolated static func validCardPin(_ p: JSONValue) -> Bool {
        guard p["issuedAt"]?.wireInt != nil, let digest = p["digest"]?.stringValue, isSHA256Hex(digest),
              let home = p["home"]?.stringValue, isRelayRoute(home, allowLoopback: true),
              p["handle"].map({ $0.stringValue.map(isHandle) == true && URLComponents(string: home)?.percentEncodedPath.isEmpty == true }) ?? true else { return false }
        guard let raw = p["handles"] else { return true }  // legacy single-home pin
        guard let handles = raw.objectValue,
              handles.allSatisfy({ isRelayRoute($0.key, allowLoopback: true) && URLComponents(string: $0.key)?.percentEncodedPath.isEmpty == true
                  && $0.value.stringValue.map(isHandle) == true }) else { return false }
        // New records retain the legacy fields for older readers; disagreement is corruption, never a forgotten pin.
        return handles[home]?.stringValue == p["handle"]?.stringValue
    }

    private nonisolated static func validOwnerPin(_ p: JSONValue) -> Bool {
        p["aceId"]?.stringValue != nil && p["home"]?.stringValue != nil && p["handle"]?.stringValue != nil
    }

    /// Verify a fetched card record against the identity's KEL pin and its card pin `{home, handle?, handles, issuedAt, digest}`
    /// (written on first sight, only after full verification): no rollback first, then the set-once handle per home. A
    /// record `resolved` from `@handle@home` must name the ACE ID that handle first resolved to (`invalid_authorization`).
    private func checkCard(_ bundle: CardBundle, resolved: (home: String, handle: String)? = nil, kelLive: Bool) async throws -> VerifiedCard {
        let id = Self.aceId(of: bundle)
        let pinned = isACEId(id) ? try await peers.pinned(id) : nil
        let v = try verifyCardBundle(bundle, now: try now(), allowLoopback: configuration.allowLoopbackRelays, pinned: pinned)
        let r = v.record, digest = try documentDigest(r.value), key = Self.cardPinKey(v.aceId)
        let ownerKey = resolved.map { Self.handleOwnerKey(home: $0.home, handle: $0.handle) }
        try store.withLock("network-handles") {
            let owner = try ownerKey.flatMap { try readPin($0, Self.validOwnerPin) }
            if let owner, owner["aceId"]?.stringValue != v.aceId {
                throw ACEError(.invalidAuthorization, "the handle resolved to another identity than before", reason: .handleRebound)
            }
            try advanceCardPin(r, digest: digest, key: key)
            if let ownerKey, let resolved, owner == nil {
                let pin: JSONValue = .object(["home": .string(resolved.home), "handle": .string(resolved.handle), "aceId": .string(v.aceId)])
                try store.checkedWrite(ownerKey, try pin.jsonData())
            }
        }
        var out = v
        out.kelLive = kelLive
        return out
    }

    /// The card pin checks and update of `checkCard`, under the `network-handles` lock.
    private nonisolated func advanceCardPin(_ r: CardRecord, digest: String, key: String) throws {
        let pin = try readPin(key, Self.validCardPin)
        let pinHome = pin?["home"]?.stringValue, pinHandle = pin?["handle"]?.stringValue
        var handles = pin?["handles"]?.objectValue ?? [:]
        if let pinHome, let pinHandle { handles[pinHome] = .string(pinHandle) }
        if let pinAt = pin?["issuedAt"]?.wireInt {
            if r.issuedAt < pinAt { throw ACEError(.staleDescriptor, "an older card record than one already verified") }
            if r.issuedAt == pinAt {
                guard digest == pin?["digest"]?.stringValue else { throw ACEError(.staleDescriptor, "another card record with the same issuedAt") }
            }
        }
        if let expected = handles[r.home]?.stringValue, expected != r.handle {
            throw ACEError(.invalidAuthorization, "the card record does not carry the handle this identity set")
        }
        if let handle = r.handle { handles[r.home] = .string(handle) }
        // Preserve every home's binding in the same atomic record. Import the legacy binding before moving homes;
        // keep its fields too so existing readers retain their last-home behavior.
        var next: [String: JSONValue] = ["issuedAt": .number(Double(r.issuedAt)), "digest": .string(digest), "handles": .object(handles)]
        if let pinHandle, let pinHome, r.handle == nil || pinHome == r.home {
            next["home"] = .string(pinHome)
            next["handle"] = .string(pinHandle)
        } else {
            next["home"] = .string(r.home)
            if let h = r.handle { next["handle"] = .string(h) }
        }
        try store.checkedWrite(key, try JSONValue.object(next).jsonData())
    }

    /// The peer's card record from the first route that serves it: its cached descriptor's relays, then the home relay.
    private func fetchCard(_ aceId: String) async throws -> CardBundle {
        try await onRoutes(routes(of: try await peers.heldRelays(aceId))) { try await $0.card(aceId) }
    }

    /// A peer's routes: its held descriptor's relays (`PeerStore.heldRelays`), then the home relay.
    private func routes(of held: [String]?) -> [String] {
        var routes: [String] = []
        for url in (held ?? []) + [relay.baseURLString] where !routes.contains(url) { routes.append(url) }
        return routes
    }

    /// The ACE ID a CardBundle's record names ("" when absent; verification rejects it).
    private static func aceId(of bundle: CardBundle) -> String { bundle["card"]?["aceId"]?.stringValue ?? "" }

    /// `@name@relay-host`: the CardBundle the relay serves for that handle, the relay's URL and the handle.
    private func cardByHandle(_ target: String) async throws -> (bundle: CardBundle, url: String, handle: String) {
        let parts = target.split(separator: "@", omittingEmptySubsequences: false)
        guard parts.count == 3, parts[0].isEmpty, isHandle(String(parts[1])), !parts[2].isEmpty,
              parts[2].utf8.allSatisfy({ ($0 >= 0x61 && $0 <= 0x7A) || ($0 >= 0x30 && $0 <= 0x39) || $0 == 0x2E || $0 == 0x2D || $0 == 0x3A }) else {
            throw ACEError(.invalidArgument, "use an ACE ID or @name@relay-host")
        }
        let host = String(parts[2])
        // The home relay is reused only when its authority is exactly `host` (a prefix such as `relay` must not select
        // `https://relay.example`).
        let home = relay.baseURLString
        let rest = home.range(of: "://").map { home[$0.upperBound...] } ?? ""
        let url = rest[..<(rest.firstIndex(of: "/") ?? rest.endIndex)] == host ? home : "https://\(host)"
        return (try await client(url).handle(String(parts[1])), url, String(parts[1]))
    }

    /// The peer's current descriptor (04 § Caching): the pinned one while it is unexpired, bound to the current pins and
    /// its identity usable (unless `refresh`), else fetched from its relays (`GET /v1/descriptor`) and pinned. A failed
    /// refresh throws: a stale descriptor is never used.
    @discardableResult
    public func agent(_ aceId: String, refresh: Bool = false) async throws -> VerifiedAgent {
        guard isACEId(aceId) else { throw ACEError(.invalidArgument, "invalid ACE ID") }
        if !refresh, let a = try await peers.usableAgent(aceId) { return a }
        // A cached descriptor bound to the current pins (`peers.agent`: KEL and delegation issuers) names the routes; a stale
        // one (the pin advanced past its KEL, or past a delegation issuer's key; possibly a compromised key) may name
        // attacker relays: the home relay is asked too, as when nothing is cached. A stale one is never used itself: the
        // refreshed descriptor must verify under the current pins to replace it.
        if let bound = try await peers.agent(aceId) { return try await fetchAgent(aceId, routes: bound.descriptor.relays) }
        return try await fetchAgent(aceId, routes: routes(of: try await peers.heldRelays(aceId)))
    }

    /// The descriptor of `aceId` from the first route that serves one that verifies and pins: a route replaying an older
    /// revision (`stale_peer_binding`) is passed over like any other failing route.
    private func fetchAgent(_ aceId: String, routes: [String]) async throws -> VerifiedAgent {
        try await onRoutes(routes) { try await self.adoptFetched(try await $0.descriptor(aceId)) }
    }

    /// Pin a fetched descriptor. An older revision refused under the same KEL never stands in for the cached one: that
    /// one is returned only while usable (unexpired and bound to the current pins), else `stale_peer_binding`.
    private func adoptFetched(_ agent: VerifiedAgent) async throws -> VerifiedAgent {
        try await peers.adoptOrUsable(agent, live: true) ?? agent
    }

    // MARK: Invitations (05 § Invitations)

    /// Invite one peer (an ACE ID or `@name@relay-host`; import a PublishedAgent shared out of band first) to contact this
    /// identity: the peer is recorded `admitted` for `profile` (an explicit local decision, which clears a block) and the
    /// invitation carries this identity's PublishedAgent and a permit issued to exactly that peer.
    public func createInvitation(peer: String, profile: String = ProfileManifest.text.id) async throws -> Invitation {
        guard let mine = profiles.manifest(profile), mine.id != ProfileManifest.core.id else {
            throw ACEError(.invalidArgument, "\(profile) is not installed")
        }
        let agent = try await lookup(peer)
        guard agent.aceId != me else { throw ACEError(.invalidArgument, "cannot invite this identity") }
        let permit = try createPermit(identity: identity, subject: agent.aceId, now: try now())
        try await admit(agent.aceId, profile: profile, clearsBlock: true)
        let source = try await publish()
        try admission.noteIssued(agent.aceId, permit: permit)  // handed to the host for the out-of-band channel
        return Invitation(agent: source.source, permit: permit)
    }

    /// Import an invitation addressed to this identity: verify and pin its agent and hold its permit (so `connect`
    /// reaches a `closed` inviter). Never admits the inviter. A permit not issued by the agent to us is
    /// `invalid_authorization`.
    @discardableResult
    public func importInvitation(_ invitation: Invitation) async throws -> VerifiedAgent {
        let agent = try await importAgent(invitation.agent)
        _ = try verifyPermit(invitation.permit, issuer: agent.state, subject: me, now: try now())
        try await holdTheirPermit(invitation.permit, from: agent.aceId)
        return agent
    }

    /// Hold `permit`, issued to us by `from`, when it verifies under `from`'s current pin (`when`: see `holdPermit`). The
    /// held one is kept instead only while it is newer and still verifies under that pin: a permit from a superseded key
    /// never shadows a valid one.
    package func holdTheirPermit(_ permit: JSONValue, from: String, when: ((AdmissionRecord?) -> Bool)? = nil) async throws {
        let now = try now(), me = me
        guard let state = try await peers.pinned(from), let v = try? verifyPermit(permit, issuer: state, subject: me, now: now) else { return }
        try admission.holdPermit(v, when: when) { held in
            guard let h = try? verifyPermit(held, issuer: state, subject: me, now: now) else { return false }
            return h.issuedAt > v.issuedAt
        }
    }

    // MARK: Sending

    /// Stage a message in the Outbox and make the first attempt now. Attempt failures stay on the entry (retried by
    /// `flush` and `maintain`); profile and schema failures throw. A cached descriptor of `to` (expired is enough)
    /// suffices; without one it is resolved first, and when that fails (`unknown_peer`, or a transient error reported as
    /// such) nothing is staged. Without a permit from `to` valid under its current pin it fails with `not_permitted` and
    /// nothing is staged (06 § Outbox). Delivery is confirmed only by the receipt (`onReceipt`, `outbox.entry`).
    @discardableResult
    public func send(to aceId: String, type: String, body: [String: JSONValue], threadId: String? = nil) async throws -> OutboxEntry {
        guard isACEId(aceId), aceId != me else { throw ACEError(.invalidArgument, "to must be another ACE ID") }
        guard let pin = try await peers.pinned(aceId), try validTheirPermit(aceId, pin) != nil else {
            throw ACEError(.notPermitted, "no valid permit from this peer")
        }
        if try await peers.agent(aceId) == nil { _ = try await agent(aceId) }
        let entry = try await outbox.enqueue(to: aceId, type: type, body: body, threadId: threadId)
        return try await outbox.deliver(entry.messageId, via: self)
    }

    /// Attempt every due Outbox message.
    @discardableResult
    public func flush() async throws -> [OutboxEntry] { try await outbox.flush(via: self) }

    /// One attempt of `messageId` now, due or not (TS `outbox.attempt`): nil for an unknown message, a final entry as is,
    /// a pending one after the attempt (unchanged while another attempt holds it).
    @discardableResult
    public func attempt(_ messageId: String) async throws -> OutboxEntry? {
        guard try await outbox.entry(messageId) != nil else { return nil }
        return try await outbox.deliver(messageId, via: self)
    }

    package func prekey(for aceId: String, refresh: Bool) async throws -> Prekey {
        try await agent(aceId, refresh: refresh).descriptor.prekey
    }

    /// One Outbox attempt. It carries the peer's newest permit valid under its current pin; without one it is
    /// `not_permitted` (retried on the schedule until a renewal or refresh) and never falls back to the stranger path
    /// (06 § Outbox step 3).
    package func post(to aceId: String, content: PrivateContent, messageId: String, prekey: Prekey) async throws {
        let agent = try await agent(aceId)
        guard let permit = try validTheirPermit(aceId, agent.state) else {
            throw ACEError(.notPermitted, "no valid permit from this peer")
        }
        let packet = try createPacket(sender: identity, to: aceId, prekey: prekey, content: content, messageId: messageId, timestamp: try now())
        try await onRoutes(agent.descriptor.relays) { try await $0.send(packet, permit: permit) }
    }

    /// The permit `aceId` issued to us, only while it verifies under its current KEL (a bearer credential, never presented
    /// from a superseded key).
    private func validTheirPermit(_ aceId: String, _ state: KelState) throws -> JSONValue? {
        guard let p = try admission.heldPermit(aceId) else { return nil }
        // `JSONValue?` explicitly: a bare `nil` here would be the JSON literal `null`, sent as a permit.
        guard (try? verifyPermit(p, issuer: state, subject: me, now: try now())) != nil else { return nil }
        return p
    }

    /// One attempt of a core packet (receipt or contact): never stored, never retried.
    package func sendCore(to aceId: String, type: String, body: [String: JSONValue], agent: VerifiedAgent? = nil,
                          permit explicit: JSONValue? = nil) async throws {
        let target: VerifiedAgent
        if let agent { target = agent } else { target = try await self.agent(aceId) }
        let content = try profiles.content(type: type, body: body)
        let packet = try createPacket(sender: identity, to: aceId, prekey: target.descriptor.prekey, content: content, timestamp: try now())
        let permit = try explicit ?? validTheirPermit(aceId, target.state)
        try await onRoutes(target.descriptor.relays) { try await $0.send(packet, permit: permit) }
    }

    // MARK: Receiving

    private func receiving() throws -> Inbox {
        guard let inbox else { throw ACEError(.invalidArgument, "this client was opened without the receive role, or is closed") }
        return inbox
    }

    /// Fetch the home relay's inbox: process entries in stream order (receipts, contact requests and messages), send
    /// each receipt, and acknowledge through the last entry with a final disposition. Stops at the first entry without
    /// one (it stays on the relay); repeats while pages are full, at most `maxPages` pages (nil = until drained) — a
    /// bounded pass for a host with a short time or memory budget. Returns the outcomes.
    @discardableResult
    public func pull(limit: Int = ACELimits.maxInboxPage, maxPages: Int? = nil) async throws -> [ReceiveOutcome] {
        try await receiving().pull(limit: limit, maxPages: maxPages)
    }

    /// Follow the home relay's listen stream: each entry is processed and acknowledged before its outcome is yielded.
    /// Ends at an entry without a final disposition (pull again later), on cancellation, or with `relay_unavailable`.
    /// At most 64 outcomes wait for the consumer; a full buffer pauses processing without dropping an outcome.
    public nonisolated func follow() -> AsyncThrowingStream<ReceiveOutcome, Error> {
        AsyncThrowingStream(bufferingPolicy: .bufferingOldest(64)) { continuation in
            let task = Task {
                do {
                    let inbox = try await self.receiving()
                    for try await event in self.relay.listen(self.identity) {
                        try Task.checkCancellation()
                        let outcome = try await inbox.followed(event)
                        try await continuation.yieldWaiting(outcome)
                        guard outcome.isFinal else { break }
                    }
                    continuation.finish()
                } catch {
                    continuation.finish(throwing: error is CancellationError ? nil : error)
                }
            }
            continuation.onTermination = { _ in task.cancel() }
        }
    }

    // MARK: Contacts and admission

    /// Send a contact request about `profile` to `target` (an ACE ID or `@name@relay-host`, resolved and pinned). The
    /// target must list the same profile digest. Without a permit it issued to us, the target's card record must be
    /// `contact: open` (no record is `closed`; 05 § Flow); this identity's own `contact` does not matter. Records the target
    /// as `pending` (unless admitted). A peer held as `blocked` is `not_permitted` and stays blocked: only `unblock` lifts
    /// a block (05 § Blocks).
    public func connect(_ target: String, profile: String, note: String = "") async throws {
        guard let mine = profiles.manifest(profile), mine.id != ProfileManifest.core.id else {
            throw ACEError(.invalidArgument, "\(profile) is not installed")
        }
        guard note.utf8.count <= ACELimits.maxNoteBytes else { throw ACEError(.invalidArgument, "note exceeds \(ACELimits.maxNoteBytes) bytes") }
        let (agent, card) = try await resolve(target)
        let peer = agent.aceId
        guard peer != me else { throw ACEError(.invalidArgument, "cannot connect to this identity") }
        guard agent.descriptor.profiles.contains(mine.ref) else { throw ACEError(.invalidArgument, "no common installed profile") }
        if try admission.get(peer)?.state == .blocked { throw ACEError(.notPermitted, "the peer is blocked; unblock it first") }
        if try validTheirPermit(peer, agent.state) == nil {
            let contact: Contact
            if let card { contact = card.record.contact } else { contact = try await cardOrNone(peer)?.record.contact ?? .closed }
            guard contact == .open else { throw ACEError(.notPermitted, "the peer takes contact requests only from peers it issued a permit") }
        }
        let source = try await publish()
        let now = try now()
        try admission.update(peer) { r in
            guard r?.state != .blocked else { throw ACEError(.notPermitted, "the peer is blocked; unblock it first") }
            var r = r ?? AdmissionRecord(aceId: peer, state: .pending, updatedAt: now)
            if r.state != .admitted {
                r.state = .pending
                r.updatedAt = now  // the pending lifetime runs from the latest request (05 § Flow step 4)
            }
            r.profile = profile
            return r
        }
        try await sendContact("request", to: peer, profile: profile, note: note, source: source, agent: agent)
    }

    /// The peer's verified card record; nil when it has none (`unknown_peer`: closed, unlisted).
    private func cardOrNone(_ aceId: String) async throws -> VerifiedCard? {
        do {
            return try await lookupCard(aceId)
        } catch let e as ACEError where e.code == .unknownPeer {
            return nil
        }
    }

    /// One `ace:contact:1` packet `{kind, profile, note, source, permit?}`; `request` and `accepted` carry a fresh permit,
    /// recorded as issued only once the packet was sent (05 § Delivery permits). `deliveryPermit`: the permit presented to
    /// the relay.
    private func sendContact(_ kind: String, to peer: String, profile: String, note: String = "", source: VerifiedAgent,
                             agent: VerifiedAgent, deliveryPermit: JSONValue? = nil) async throws {
        var body: [String: JSONValue] = ["kind": .string(kind), "profile": .string(profile), "note": .string(note), "source": source.source]
        var permit: JSONValue?  // never the JSON literal `null`
        if kind != "rejected" { permit = try createPermit(identity: identity, subject: peer, now: try now()) }
        if let permit { body["permit"] = permit }
        try await sendCore(to: peer, type: CoreTypes.contact, body: body, agent: agent, permit: deliveryPermit)
        if let permit { try admission.noteIssued(peer, permit: permit) }
    }

    /// Pending incoming contact requests, oldest first: at most `ACELimits.maxPendingContactRequests`, one per sender,
    /// each expiring `contactRequestTTLSeconds` after receipt.
    public func requests() throws -> [ContactRequest] { try admission.requests() }

    /// Explicitly accept `aceId`'s pending contact request: pin its source, hold its permit, admit it
    /// and reply `accepted` with our permit.
    public func accept(_ aceId: String) async throws {
        guard let request = try admission.request(aceId) else { throw ACEError(.invalidArgument, "no pending contact request from this peer") }
        try await accept(request)
    }

    /// Neither path overrides a block registered meanwhile (`not_permitted`).
    private func accept(_ request: ContactRequest) async throws {
        let now = try now()
        let expired = (request.source["descriptor"]?["expiresAt"]?.wireInt ?? 0) <= now
        let fresh = expired ? nil : try verifyPublishedAgent(request.source, now: now, allowLoopback: configuration.allowLoopbackRelays)
        if try admission.get(request.from)?.state == .blocked { throw ACEError(.notPermitted, "blocked peer") }
        let agent: VerifiedAgent
        if let fresh {
            // A source older than the held descriptor never replaces it: the held one is answered while usable (04 § Caching).
            agent = try await peers.adoptOrUsable(fresh) ?? fresh
        } else {
            agent = try await refreshExpiredSource(request, now: now)
        }
        try await admit(request.from, profile: request.profile)
        try await holdTheirPermit(request.permit, from: request.from)
        let source = try await publish()
        try admission.removeRequest(request.from)
        try await sendContact("accepted", to: request.from, profile: request.profile, source: source, agent: agent)
    }

    /// Record `peer` as admitted for `profile`. A block is cleared only by `createInvitation` (`clearsBlock`) and
    /// `unblock` (05 § Blocks): a blocked peer's contact request never reaches `accept`.
    private func admit(_ peer: String, profile: String, clearsBlock: Bool = false) async throws {
        func admitted(_ r: AdmissionRecord?) throws -> AdmissionRecord {
            if r?.state == .blocked, !clearsBlock { throw ACEError(.notPermitted, "the peer is blocked; unblock it first") }
            var r = r ?? AdmissionRecord(aceId: peer, state: .admitted, updatedAt: 0)
            r.state = .admitted
            r.profile = profile
            return r
        }
        guard clearsBlock else {
            try admission.update(peer, admitted)
            return
        }
        if let record = try admission.updateClearingBlock(peer, admitted) { await registerBlock(record) }
    }

    /// The held request (24 h) outlived its source descriptor: pin the source's KEL (05 § Flow step 3), then refresh the
    /// descriptor from the source's routes while the source is bound to the pin (04 § Caching), else through
    /// `agent(_:refresh:)`. A KEL pinned (or advanced) from the source alone is not `kelLive`, as a card bundle's own KEL
    /// is not, until the refreshed descriptor confirms it (04 § Card record).
    private func refreshExpiredSource(_ request: ContactRequest, now: Int) async throws -> VerifiedAgent {
        let events = try (request.source["kel"]?.arrayValue ?? []).map { e -> KelEvent in
            guard let ev = e.objectValue else { throw ACEError(.invalidAuthorization, "the request's source kel is malformed") }
            return ev
        }
        let carried = try ACEKel.verify(events, now: now)
        let pin = try await peers.pin(kel: events).state
        let agent: VerifiedAgent
        if pin.lastHash == carried.lastHash {
            let routes = request.source["descriptor"]?["relays"]?.arrayValue?.compactMap(\.stringValue) ?? []
            agent = try await fetchAgent(request.from, routes: routes)
        } else {
            agent = try await self.agent(request.from, refresh: true)
        }
        return agent
    }

    /// Decline `aceId`'s pending contact request (replies `rejected`, best effort) and forget it.
    public func reject(_ aceId: String) async throws {
        guard let request = try admission.request(aceId) else { return }
        try admission.removeRequest(aceId)
        guard let agent = try? verifyPublishedAgent(request.source, now: try now(), allowLoopback: configuration.allowLoopbackRelays) else { return }
        let source = try await publish()
        try? await sendContact("rejected", to: aceId, profile: request.profile, source: source, agent: agent, deliveryPermit: request.permit)
    }

    /// Block `aceId`: at once locally (the enforcement point; it survives restart) and its held request is dropped, then
    /// at the home relay (its permits stop working there). A relay failure does not throw: `maintain` registers
    /// the block again.
    public func block(_ aceId: String) async throws {
        guard isACEId(aceId), aceId != me else { throw ACEError(.invalidArgument, "invalid peer") }
        let record = try admission.decideBlock(aceId, blocked: true) { r in
            var r = r ?? AdmissionRecord(aceId: aceId, state: .blocked, updatedAt: 0)
            r.state = .blocked
            return r
        }
        await registerBlock(record)
    }

    /// Remove a block (the explicit admission action, 05 § Blocks): the peer becomes a stranger again until contact is
    /// re-established, and `blocked: false` is registered with a higher revision at the home relay.
    public func unblock(_ aceId: String) async throws {
        guard try admission.get(aceId)?.state == .blocked else { return }
        await registerBlock(try admission.decideBlock(aceId, blocked: false) { _ in nil })
    }

    /// Register `record` (exactly its revision) at the home relay; synced once it accepted it. A relay answering
    /// `stale_revision` already holds this or a later decision. Any other failure leaves it unsynced for `maintain`.
    private func registerBlock(_ record: BlockRecord) async {
        do {
            do {
                try await relay.setBlock(identity, peer: record.peer, blocked: record.blocked, revision: record.revision)
            } catch let e as ACEError where e.relayCode == "stale_revision" {}
            try admission.blockSynced(record.peer, revision: record.revision)
        } catch {
            return
        }
    }

    /// Ask the home relay to wake `gateway` with `token` when entries are queued for this identity (07 § Wake hints). A
    /// hint only: delivery still comes from `pull` / `follow`.
    public func setWake(gateway: String, token: String) async throws {
        try await relay.setWake(identity, gateway: gateway, token: token)
    }

    /// Remove the home relay's wake registration.
    public func clearWake() async throws {
        try await relay.clearWake(identity)
    }

    /// The permit to attach to a receipt to `peer` (05 § Renewal): a fresh one when ours has less than
    /// `PERMIT_RENEWAL_SECONDS` left or is no longer valid under our current KEL; nil otherwise or when `peer` is neither
    /// pending nor admitted. The caller records it once the receipt was sent.
    package func renewalPermit(for peer: String) throws -> JSONValue? {
        guard let r = try admission.get(peer), r.state != .blocked else { return nil }
        let now = try now()
        if let p = r.issuedPermit, let state = try? checkUsable(identity, now: now), let v = try? verifyPermit(p, issuer: state, subject: peer, now: now),
           v.expiresAt - now >= ACELimits.permitRenewalSeconds { return nil }
        return try createPermit(identity: identity, subject: peer, now: now)
    }

    /// The Inbox's handling of an authenticated contact packet (core rules already passed).
    package func receivedContact(from: String, body: [String: JSONValue], source: VerifiedAgent) async throws {
        let profile = body["profile"]?.stringValue ?? ""
        switch body["kind"]?.stringValue {
        case "request":
            // The Inbox checked admission before suspending; a block registered since then still wins.
            let state = try admission.get(from)?.state
            guard state != .blocked else { return }
            let request = ContactRequest(from: from, profile: profile, note: body["note"]?.stringValue ?? "", source: source.source,
                                         permit: body["permit"] ?? .null, receivedAt: try now())
            try admission.putRequest(request)
            if state == .admitted || configuration.acceptProfiles.contains(profile) {
                try? await accept(request)  // a failed auto-accept leaves the request for an explicit decision
            }
        case "accepted":
            // Only a peer held as pending for this profile (unexpired), or already admitted (the answer to a permit refresh,
            // which only replaces the held permit); nothing is pinned otherwise.
            guard let r = try admission.get(from), r.acceptsReply(profile: profile) else { return }
            try await peers.adoptOrUsable(source)
            let expected = r.state
            if let permit = body["permit"] { try await holdTheirPermit(permit, from: from) { $0?.state == expected } }
            try admission.update(from) { r in
                guard var r, r.acceptsReply(profile: profile) else { return r }
                r.state = .admitted
                return r
            }
        default:  // rejected
            try admission.update(from) { r in r?.state == .pending && r?.profile == profile ? nil : r }
        }
    }

    // MARK: Upkeep

    /// After a signing-key change, re-send a contact request carrying a fresh permit to every admitted peer whose newest
    /// permit from us predates the current delegation (05 § Delivery permits); the peer accepts it automatically and its
    /// `accepted` refreshes the permit we hold. Best effort per peer: a failed send leaves the peer due at the next
    /// upkeep. Returns the peers sent to.
    @discardableResult
    package func refreshPermits() async throws -> [String] {
        let seq = try identity.getSigningSeq()
        var sent: [String] = []
        var source: VerifiedAgent?  // published once, on the first peer that needs it
        for r in try admission.all() where r.state == .admitted {
            if let issued = r.issuedPermit, issued["signature"]?["seq"]?.wireInt == seq { continue }
            do {
                let agent = try await agent(r.aceId)
                // a profile both sides still list: the recorded one, else the first shared one
                let shared = agent.descriptor.profiles.filter { profiles.manifest($0.id)?.ref == $0 }.map(\.id)
                guard let profile = r.profile.flatMap({ shared.contains($0) ? $0 : nil }) ?? shared.first else { continue }
                let published: VerifiedAgent
                if let source { published = source } else { published = try await publish(); source = published }
                try await sendContact("request", to: r.aceId, profile: profile, source: published, agent: agent)
                sent.append(r.aceId)
            } catch {
                continue
            }
        }
        return sent
    }

    /// Periodic upkeep: publish (renewing descriptor and prekey, re-signing the card record after a new `dlg`,
    /// registering when needed), push fresh permits after a
    /// signing-key change, register blocks a relay missed, retry due Outbox messages and prune settled ones. Every step
    /// runs even when an earlier one fails (an unreachable home relay must not stop Outbox retries to peers' relays); the
    /// first failure is thrown at the end.
    public func maintain() async throws {
        var failure: (any Error)?
        do { _ = try await publish() } catch { failure = failure ?? error }
        do { _ = try await refreshPermits() } catch { failure = failure ?? error }
        do { for record in try admission.unsyncedBlocks() { await registerBlock(record) } } catch { failure = failure ?? error }
        do { _ = try await flush() } catch { failure = failure ?? error }
        do { _ = try await outbox.prune() } catch { failure = failure ?? error }
        if let failure { throw failure }
    }
}
