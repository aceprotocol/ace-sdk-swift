//
//  NetworkClient.swift
//  ACE SDK
//
//  The networking runtime of one identity: publish, discover, look up, import, connect (contact packets), accept /
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
    public var visibility: Visibility
    public var handle: String?
    public var card: AgentCard
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

    public init(profiles: [ProfileManifest] = [.text], acceptProfiles: [String] = [], visibility: Visibility = .private, handle: String? = nil,
                card: AgentCard = AgentCard(), ext: [String: JSONValue]? = nil, delegations: [JSONValue] = [], erc8004: [ERC8004Binding] = [],
                rules: [any ProfileRules] = [], allowLoopbackRelays: Bool = false,
                onMessage: (@Sendable (ReceivedMessage) async throws -> Void)? = nil,
                onReceipt: (@Sendable (String, [String: JSONValue], OutboxEntry?) async -> Void)? = nil) {
        self.profiles = profiles
        self.acceptProfiles = acceptProfiles
        self.visibility = visibility
        self.handle = handle
        self.card = card
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

    /// Try `body` on each route in order; a permanent error other than routing ends at once.
    private func onRoutes<T>(_ routes: [String], _ body: (RelayClient) async throws -> T) async throws -> T {
        var last: any Error = ACEError(.unknownPeer, "no route")
        for url in routes {
            do { return try await body(try client(url)) } catch let e as ACEError where e.category == .permanent && e.code != .unknownPeer {
                throw e
            } catch { last = error }
        }
        throw last
    }

    // MARK: Publishing

    /// This identity's current PublishedAgent, re-signed and posted to the home relay when it is missing, changed,
    /// expiring within an hour or when the prekey rotates (every 24 hours); an unchanged one is posted again only with
    /// `force`. A relay holding no registration (`not_registered`) or an older KEL (`kel_conflict`) gets the current KEL
    /// registered first. Prunes the prekey vault.
    @discardableResult
    public func publish(force: Bool = false) async throws -> VerifiedAgent {
        let now = try now()
        var rotated = false
        var current = try prekeys.current()
        if current == nil || current!.createdAt + ACELimits.prekeyRotationSeconds <= now {
            current = try prekeys.rotate(now: now)
            rotated = true
        }
        try prekeys.prune(now: now)
        let claims = DescriptorClaims(relays: [relay.baseURLString], prekey: current!.prekey, profiles: profiles.refs, visibility: configuration.visibility,
                                      handle: configuration.handle, card: configuration.card, ext: configuration.ext,
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
        do {
            try await relay.publish(agent)
        } catch let e as ACEError where e.code == .notRegistered || e.relayCode == "kel_conflict" {
            try await relay.register(identity)
            try await relay.publish(agent)
        }
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
        return old.source["kel"] == kel && d.relays == c.relays && d.prekey == c.prekey && d.profiles == c.profiles && d.visibility == c.visibility
            && d.handle == c.handle && d.card == c.card && d.ext == c.ext && (old.source["descriptor"]?["delegations"]?.arrayValue ?? []) == c.delegations
            && d.erc8004 == c.erc8004
    }

    // MARK: Discovery

    /// The public directory of the home relay (verified, not pinned).
    public func discover(profile: String? = nil, cursor: String? = nil, limit: Int = ACELimits.defaultPageLimit) async throws -> RelayClient.DirectoryPage {
        try await relay.directory(profile: profile, cursor: cursor, limit: limit)
    }

    /// Verify a PublishedAgent shared out of band against the pin (the descriptor must verify under the newest pinned
    /// state) and pin it. Grants no admission.
    @discardableResult
    public func importAgent(_ source: JSONValue) async throws -> VerifiedAgent {
        try await peers.adopt(source: source, allowLoopback: configuration.allowLoopbackRelays)
    }

    /// An ACE ID (`agent(_:)`), or `@name@relay-host`: the verified, pinned public descriptor holding that handle at
    /// that relay.
    @discardableResult
    public func lookup(_ target: String) async throws -> VerifiedAgent {
        if isACEId(target) { return try await agent(target) }
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
        let own = rest[..<(rest.firstIndex(of: "/") ?? rest.endIndex)] == host ? home : nil
        return try await adoptFetched(try await client(own ?? "https://\(host)").handle(String(parts[1])))
    }

    /// The peer's current descriptor (04 § Caching): the pinned one while it is unexpired, bound to the current pins and
    /// its identity usable (unless `refresh`), else fetched from its relays (`POST /v1/descriptor/resolve` with the permit
    /// it issued to us when we hold one, else the public lookup) and pinned. A failed refresh throws: a stale descriptor
    /// is never used.
    @discardableResult
    public func agent(_ aceId: String, refresh: Bool = false) async throws -> VerifiedAgent {
        guard isACEId(aceId) else { throw ACEError(.invalidArgument, "invalid ACE ID") }
        if !refresh, let a = try await peers.usableAgent(aceId) { return a }
        let cached = try await peers.agent(aceId)
        // A permit is presented only to relays its issuer named in a descriptor bound to the current pin, and only one that
        // verifies under that pin (never one signed by a superseded key); without one, the public lookup at the home relay.
        let permit = try cached.flatMap { try validTheirPermit(aceId, $0.state) }
        let routes = cached?.descriptor.relays ?? [relay.baseURLString]
        let agent = try await onRoutes(routes) { c in
            if let permit { return try await c.resolve(aceId, permit: permit) }
            return try await c.descriptor(aceId)
        }
        return try await adoptFetched(agent)
    }

    /// Pin a fetched descriptor. An older revision refused under the same KEL never stands in for the cached one: that
    /// one is returned only while usable (unexpired and bound to the current pins), else `stale_peer_binding`.
    private func adoptFetched(_ agent: VerifiedAgent) async throws -> VerifiedAgent {
        do {
            try await peers.adopt(agent)
        } catch let e as ACEError where e.code == .stalePeerBinding {
            guard let kept = try await peers.usableAgent(agent.aceId) else { throw e }
            return kept
        }
        return agent
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
    /// reaches a private inviter). Never admits the inviter. A permit not issued by the agent to us is
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
    /// one (it stays on the relay); repeats while pages are full. Returns the outcomes.
    @discardableResult
    public func pull(limit: Int = ACELimits.maxInboxPage) async throws -> [ReceiveOutcome] {
        try await receiving().pull(limit: limit)
    }

    /// Follow the home relay's listen stream: each entry is processed and acknowledged before its outcome is yielded.
    /// Ends at an entry without a final disposition (pull again later), on cancellation, or with `relay_unavailable`.
    public nonisolated func follow() -> AsyncThrowingStream<ReceiveOutcome, Error> {
        AsyncThrowingStream { continuation in
            let task = Task {
                do {
                    let inbox = try await self.receiving()
                    for try await event in self.relay.listen(self.identity) {
                        let outcome = try await inbox.followed(event)
                        continuation.yield(outcome)
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
    /// target must list the same profile digest; a non-public target needs a permit it issued to us. Records the target
    /// as `pending` (unless admitted). A peer held as `blocked` is `not_permitted` and stays blocked: only `unblock` lifts
    /// a block (05 § Blocks).
    public func connect(_ target: String, profile: String, note: String = "") async throws {
        guard let mine = profiles.manifest(profile), mine.id != ProfileManifest.core.id else {
            throw ACEError(.invalidArgument, "\(profile) is not installed")
        }
        guard note.utf8.count <= ACELimits.maxNoteBytes else { throw ACEError(.invalidArgument, "note exceeds \(ACELimits.maxNoteBytes) bytes") }
        let agent = try await lookup(target)
        let peer = agent.aceId
        guard peer != me else { throw ACEError(.invalidArgument, "cannot connect to this identity") }
        guard agent.descriptor.profiles.contains(mine.ref) else { throw ACEError(.invalidArgument, "no common installed profile") }
        if try admission.get(peer)?.state == .blocked { throw ACEError(.notPermitted, "the peer is blocked; unblock it first") }
        if agent.descriptor.visibility != .public, try validTheirPermit(peer, agent.state) == nil {
            throw ACEError(.notPermitted, "a private agent can only be reached with a permit it issued")
        }
        let source = try await publish()
        let now = try now()
        try admission.update(peer) { r in
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
            try await peers.adopt(fresh)
            agent = fresh
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
        guard clearsBlock, try admission.get(peer)?.state == .blocked else {
            try admission.update(peer, admitted)
            return
        }
        await registerBlock(try admission.decideBlock(peer, blocked: false, admitted))
    }

    /// The held request (24 h) outlived its source descriptor: pin the source's KEL (05 § Flow step 3), then refresh the
    /// descriptor from the source's routes with the requester's permit while the source is bound to the pin (04 §
    /// Caching), else through `agent(_:refresh:)`.
    private func refreshExpiredSource(_ request: ContactRequest, now: Int) async throws -> VerifiedAgent {
        let events = try (request.source["kel"]?.arrayValue ?? []).map { e -> KelEvent in
            guard let ev = e.objectValue else { throw ACEError(.invalidAuthorization, "the request's source kel is malformed") }
            return ev
        }
        let carried = try ACEKel.verify(events, now: now)
        let pin = try await peers.pin(kel: events).state
        guard pin.lastHash == carried.lastHash else { return try await agent(request.from, refresh: true) }
        let permit = (try? verifyPermit(request.permit, issuer: pin, subject: me, now: now))?.value
        let routes = request.source["descriptor"]?["relays"]?.arrayValue?.compactMap(\.stringValue) ?? []
        let agent = try await onRoutes(routes) { c in
            if let permit { return try await c.resolve(request.from, permit: permit) }
            return try await c.descriptor(request.from)
        }
        return try await adoptFetched(agent)
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
            try await peers.adopt(source)
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

    /// Periodic upkeep: publish (renewing descriptor and prekey, registering when needed), push fresh permits after a
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
