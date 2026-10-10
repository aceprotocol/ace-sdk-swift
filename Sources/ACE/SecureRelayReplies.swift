import Foundation

/// Read-only reply cursor for a sending process while another process owns the Inbox.
/// Relay reads are non-destructive. This never dispatches an application message or advances
/// the receiving process's durable cursor; the owner continues handling incoming handshakes.
public actor SecureRelayReplies {
    private let identity: any ACEIdentity
    private let secure: SecureTransport
    private let relay: RelayClient
    private let peer: VerifiedPeer
    private let send: SecureMailbox.Send
    private var cursor: String?
    public private(set) var path: DeliveryPath = .relay
    public init(identity: any ACEIdentity, secure: SecureTransport, relay: RelayClient, peer: VerifiedPeer,
                since: String? = nil, send: @escaping SecureMailbox.Send) {
        self.identity = identity; self.secure = secure; self.relay = relay; self.peer = peer; self.send = send; cursor = since
    }
    public func exchange(_ packet: ACEMessage, expected: SecureTransport.Route) async throws -> ACEMessage {
        let deadline = ContinuousClock.now.advanced(by: .seconds(ACELimits.secureAttemptSeconds))
        path = try await send(packet, peer)
        while ContinuousClock.now < deadline {
            try Task.checkCancellation()
            let page = try await relay.fetchInbox(identity, since: cursor)
            for entry in page.entries {
                cursor = entry.streamId
                guard let message = try? decodeEnvelope(entry.message), message.from == peer.aceId,
                      let route = try? await secure.route(message, peer: peer), route.attempt == expected.attempt,
                      route.kind == expected.kind else { continue }
                return message
            }
            if page.entries.count < ACELimits.maxInboxPage { try await Task.sleep(for: .seconds(1)) }
        }
        throw MLSError("delivery_expired")
    }
}
