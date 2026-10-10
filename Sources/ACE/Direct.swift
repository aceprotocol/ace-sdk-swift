//
//  Direct.swift
//  ACE SDK
//
//  Direct delivery, sender side (08-relay § Direct Delivery): the transport for secure
//  delivery frames. The receiver side is `SecureMailbox.receiveDirect`.
//

import Foundation

/// The path that delivered a secure delivery frame (`deliverDirectOrRelay`).
public enum DeliveryPath: String, Sendable {
    case direct, relay
}

/// The largest direct-delivery reply body read; anything longer is `direct_unavailable`.
private let maxDirectReplyBytes = 64 << 10

/// POST `{"message": envelope}` to a peer's direct endpoint (08 § Direct Delivery, Sender).
/// `envelope` is a secure delivery frame (`SecureTransport`); the receiver's
/// `SecureMailbox.receiveDirect` refuses static application envelopes.
///
/// - `endpoint` must be an ACE HTTPS URL; its host is resolved and refused when any
///   address is blocked (`isBlockedAddress`). Either failure is `invalid_argument`.
/// - Redirects are not followed; the default timeout is 5 seconds.
/// - Success iff the status is 2xx and the body is a JSON object with `"ok": true`.
/// - 400 or 413 is `direct_rejected` (permanent; `remoteCode` carries the receiver's
///   `error` string when it matches `^[a-z0-9_]{1,64}$`): do not retry directly and do
///   not fall back to the relay.
/// - Anything else (DNS or network failure, timeout, 429, 503, other status or body) is
///   `direct_unavailable` (transient): fall back to the relay.
///
/// Limitation: `URLSession` cannot connect to a pre-validated IP address, so it resolves
/// the host again when connecting. A resolver that answers differently after the check
/// (DNS rebinding) is not excluded by the address check alone; because only HTTPS with
/// certificate validation is used, a rebind to an internal address fails the TLS handshake
/// (no valid certificate for the endpoint's host) before any request bytes are sent.
public func postDirect(endpoint: String, envelope: ACEMessage, timeout: TimeInterval = 5) async throws {
    try await postDirect(endpoint: endpoint, envelope: envelope, timeout: timeout, session: nil, resolve: resolveAddresses)
}

/// `postDirect` with an injectable session and resolver (tests).
func postDirect(endpoint: String, envelope: ACEMessage, timeout: TimeInterval, session: URLSession?,
                resolve: @Sendable (String) -> [[UInt8]]?) async throws {
    guard timeout > 0, timeout.isFinite else { throw ACEError(.invalidArgument, "timeout must be positive") }
    guard isHTTPSURL(endpoint), let url = URL(string: endpoint), let host = url.host(percentEncoded: false), !host.isEmpty else {
        throw ACEError(.invalidArgument, "endpoint must match the ACE HTTPS URL grammar")
    }
    guard let addresses = resolve(host) else {
        throw ACEError(.directUnavailable, "DNS resolution failed for \(String(host.prefix(100)))")
    }
    if addresses.contains(where: isBlockedRaw) {
        throw ACEError(.invalidArgument, "endpoint \(String(host.prefix(100))) resolves to a blocked address")
    }

    var request = URLRequest(url: url)
    request.httpMethod = "POST"
    request.timeoutInterval = timeout
    request.setValue("application/json", forHTTPHeaderField: "Content-Type")
    request.setValue("application/json", forHTTPHeaderField: "Accept")
    request.httpBody = JSONWriter.serialize(.object(["message": envelope.jvalue]))

    let owned: URLSession?
    if session == nil {
        let config = URLSessionConfiguration.ephemeral
        config.timeoutIntervalForRequest = timeout
        config.timeoutIntervalForResource = timeout
        owned = URLSession(configuration: config)
    } else {
        owned = nil
    }
    defer { owned?.finishTasksAndInvalidate() }
    guard let session = session ?? owned else { throw ACEError(.directUnavailable, "no session") }

    let status: Int
    var body = Data()
    do {
        let (bytes, response) = try await session.bytes(for: request, delegate: NoRedirectDelegate())
        guard let http = response as? HTTPURLResponse else { throw ACEError(.directUnavailable, "not an HTTP response") }
        status = http.statusCode
        for try await b in bytes {
            body.append(b)
            if body.count > maxDirectReplyBytes { break }
        }
    } catch let e as ACEError {
        throw e
    } catch {
        if error is CancellationError || (Task.isCancelled && (error as? URLError)?.code == .cancelled) {
            throw CancellationError()
        }
        throw ACEError(.directUnavailable, "direct delivery failed: \(error.localizedDescription)")
    }
    let reply = body.count <= maxDirectReplyBytes ? (try? JSONParser.parse(body))?.objectValue : nil
    if status == 400 || status == 413 {
        // Peer-controlled text: kept only when it looks like an error code.
        let code = reply?["error"]?.stringValue.flatMap { isRemoteCode($0) ? $0 : nil }
        throw ACEError(.directRejected, "the receiver rejected the envelope: \(code ?? "HTTP \(status)")",
                       status: status, remoteCode: code)
    }
    guard (200..<300).contains(status), reply?["ok"] == .bool(true) else {
        throw ACEError(.directUnavailable, "direct endpoint answered HTTP \(status)", status: status)
    }
}

/// A transport for `SecureRelayReplies` / secure delivery frames (the `send` of
/// `SecureMailbox.open` and `SecureRelayReplies`): the peer's direct endpoint first, relay
/// fallback (08 § Direct Delivery, Sender):
///
/// - no `endpoint` → relay;
/// - `postDirect` succeeds → `.direct`;
/// - `direct_unavailable` or `invalid_argument` (unsafe or malformed endpoint) → relay;
/// - `direct_rejected` is thrown: the recipient rejected this frame, so it is not sent
///   again through the relay.
///
/// Returns the path that delivered the frame, e.g.
/// `SecureMailbox.open(…, send: { packet, peer in try await deliverDirectOrRelay(relay: relay, endpoint: peer.profile?.endpoint)(packet) })`.
public func deliverDirectOrRelay(relay: RelayClient, endpoint: String?,
                                 timeout: TimeInterval = 5) -> @Sendable (ACEMessage) async throws -> DeliveryPath {
    deliverDirectOrRelay(send: { try await relay.send($0) }, endpoint: endpoint) {
        try await postDirect(endpoint: $0, envelope: $1, timeout: timeout)
    }
}

/// `deliverDirectOrRelay` over injectable senders (tests).
func deliverDirectOrRelay(send: @escaping @Sendable (ACEMessage) async throws -> Void, endpoint: String?,
                          direct: @escaping @Sendable (String, ACEMessage) async throws -> Void)
    -> @Sendable (ACEMessage) async throws -> DeliveryPath {
    { envelope in
        if let endpoint {
            do {
                try await direct(endpoint, envelope)
                return .direct
            } catch let e as ACEError where e.code == .directUnavailable || e.code == .invalidArgument {
                // fall back to the relay
            }
        }
        try await send(envelope)
        return .relay
    }
}

/// A receiver `error` string kept as `remoteCode`: `^[a-z0-9_]{1,64}$` (08 § Direct Delivery, Sender).
func isRemoteCode(_ s: String) -> Bool {
    let u = s.utf8
    return (1...64).contains(u.count)
        && u.allSatisfy { ($0 >= 0x61 && $0 <= 0x7A) || ($0 >= 0x30 && $0 <= 0x39) || $0 == 0x5F }
}
