import Foundation
import Network
import Security

/// A single-use byte sequence. The pinned transport reads only when its consumer asks for more;
/// it does not introduce an unbounded stream between the socket and the SSE parser.
struct RelayResponseBytes: AsyncSequence, Sendable {
    typealias Element = UInt8
    let sessionBytes: URLSession.AsyncBytes?
    let body: PinnedHTTPBody?
    let cancel: @Sendable () -> Void

    init(_ bytes: URLSession.AsyncBytes) {
        sessionBytes = bytes
        body = nil
        cancel = { bytes.task.cancel() }
    }

    init(_ body: PinnedHTTPBody, connection: PinnedRelayConnection) {
        sessionBytes = nil
        self.body = body
        cancel = { connection.cancel() }
    }

    struct AsyncIterator: AsyncIteratorProtocol {
        var session: URLSession.AsyncBytes.AsyncIterator?
        let body: PinnedHTTPBody?
        var chunk = Data()
        var offset = 0

        mutating func next() async throws -> UInt8? {
            if session != nil { return try await session!.next() }
            if offset == chunk.count {
                guard let next = try await body?.nextChunk() else { return nil }
                chunk = next
                offset = 0
            }
            defer { offset += 1 }
            return chunk[chunk.startIndex + offset]
        }
    }

    func makeAsyncIterator() -> AsyncIterator {
        AsyncIterator(session: sessionBytes?.makeAsyncIterator(), body: body)
    }
}

/// Foreign relays have two separate names: a vetted numeric connection endpoint, and the
/// original HTTP/TLS authority. Never hand the authority back to a resolving connection API.
enum PinnedRelayTransport {
    typealias Resolver = @Sendable (String) async throws -> [String]

    static func open(_ request: URLRequest, allowLoopback: Bool, timeout: TimeInterval,
                     streaming: Bool, resolver: @escaping Resolver = resolveAddresses) async throws
        -> (RelayResponseBytes, HTTPURLResponse) {
        guard timeout.isFinite, timeout > 0 else { throw ACEError(.invalidArgument, "invalid relay timeout") }
        // Plain `http` only with the development flag (loopback relays); everything else is `https`.
        guard let url = request.url, url.scheme == "https" || (allowLoopback && url.scheme == "http"), let rawHost = url.host(percentEncoded: false),
              let portNumber = UInt16(exactly: url.port ?? (url.scheme == "https" ? 443 : 80)),
              let port = NWEndpoint.Port(rawValue: portNumber) else {
            throw ACEError(.invalidArgument, "invalid relay request URL")
        }
        let host = rawHost.hasPrefix("[") ? String(rawHost.dropFirst().dropLast()) : rawHost
        let started = ContinuousClock.now
        // Bound the caller's DNS wait as well as I/O. A cancelled getaddrinfo call may still finish
        // on its system worker, but its late result cannot initiate a connection.
        let addresses = try await withRelayTimeout(timeout) { try await resolver(host) }
        guard !addresses.isEmpty else { throw ACEError(.relayUnavailable, "relay host does not resolve") }
        for address in addresses where isBlockedAddress(address) && !(allowLoopback && isLoopbackAddress(address)) {
            throw ACEError(.blockedAddress, "relay host resolves to a blocked address")
        }
        let endpoints: [NWEndpoint.Host] = try addresses.map { address in
            if let value = IPv4Address(address) { return .ipv4(value) }
            if let value = IPv6Address(address), !address.contains("%") { return .ipv6(value) }
            throw ACEError(.blockedAddress, "resolver did not return a numeric address")
        }
        var connected: PinnedRelayConnection?
        var lastError: Error = ACEError(.relayUnavailable, "relay request timed out")
        // Fall back only between vetted addresses, before sending any HTTP request. Replaying a
        // request after a send/read failure could duplicate a mutation at the relay.
        for (index, endpoint) in endpoints.enumerated() {
            try Task.checkCancellation()
            let elapsed = started.duration(to: .now).components
            let remaining = timeout - Double(elapsed.seconds) - Double(elapsed.attoseconds) / 1e18
            guard remaining > 0 else { break }
            let candidate = PinnedRelayConnection(endpoint: endpoint, port: port, serverName: host,
                                                   tls: url.scheme == "https", timeout: remaining, streaming: streaming)
            do {
                try await candidate.start(connectTimeout: remaining / Double(endpoints.count - index))
                connected = candidate
                break
            } catch {
                candidate.cancel()
                if error is CancellationError { throw error }
                lastError = error
            }
        }
        guard let connection = connected else { throw lastError }
        do {
            try await connection.send(try requestBytes(request, host: host.contains(":") ? "[\(host)]" : host))
            let body = PinnedHTTPBody(connection: connection)
            let response = try await body.readResponse(url: url)
            if streaming, response.statusCode == 200,
               response.value(forHTTPHeaderField: "Content-Type")?.split(separator: ";").first?
                   .trimmingCharacters(in: .whitespaces).lowercased() == "text/event-stream" {
                connection.headersReceived()
            }
            return (RelayResponseBytes(body, connection: connection), response)
        } catch {
            connection.cancel()
            if Task.isCancelled { throw CancellationError() }
            throw error
        }
    }

    private static func requestBytes(_ request: URLRequest, host: String) throws -> Data {
        let url = request.url!
        let components = URLComponents(url: url, resolvingAgainstBaseURL: false)!
        let path = components.percentEncodedPath.isEmpty ? "/" : components.percentEncodedPath
        let target = path + (components.percentEncodedQuery.map { "?" + $0 } ?? "")
        let method = request.httpMethod ?? "GET"
        guard isHTTPToken(method), !target.utf8.contains(where: { $0 <= 32 || $0 == 127 }) else {
            throw ACEError(.invalidArgument, "invalid HTTP request target")
        }
        var authority = host
        if let port = url.port { authority += ":\(port)" }
        var head = "\(method) \(target) HTTP/1.1\r\nHost: \(authority)\r\nConnection: close\r\nAccept-Encoding: identity\r\n"
        for (name, value) in request.allHTTPHeaderFields ?? [:] {
            if ["host", "connection", "accept-encoding", "content-length", "transfer-encoding"].contains(name.lowercased()) { continue }
            guard isHTTPToken(name), !value.utf8.contains(where: { $0 < 32 && $0 != 9 || $0 == 127 }) else {
                throw ACEError(.invalidArgument, "invalid HTTP request header")
            }
            head += "\(name): \(value)\r\n"
        }
        if let body = request.httpBody { head += "Content-Length: \(body.count)\r\n" }
        var bytes = Data((head + "\r\n").utf8)
        if let body = request.httpBody { bytes.append(body) }
        return bytes
    }
}

/// Completion, cancellation and timeout can race. Exactly one of them resumes the waiter.
final class RelayIOResult<Value: Sendable>: @unchecked Sendable {
    private let lock = NSLock()
    private var continuation: CheckedContinuation<Value, Error>?
    private var result: Result<Value, Error>?

    func install(_ continuation: CheckedContinuation<Value, Error>) {
        lock.lock()
        if let result { lock.unlock(); continuation.resume(with: result) }
        else { self.continuation = continuation; lock.unlock() }
    }

    func finish(_ result: Result<Value, Error>) {
        lock.lock()
        guard self.result == nil else { lock.unlock(); return }
        self.result = result
        let waiter = continuation
        continuation = nil
        lock.unlock()
        waiter?.resume(with: result)
    }
}

private func withRelayTimeout<T: Sendable>(_ seconds: Double, _ operation: @escaping @Sendable () async throws -> T) async throws -> T {
    let result = RelayIOResult<T>()
    let task = Task {
        do { result.finish(.success(try await operation())) }
        catch { result.finish(.failure(error)) }
    }
    let timer = Task {
        do {
            try await Task.sleep(for: .seconds(seconds))
            result.finish(.failure(ACEError(.relayUnavailable, "relay request timed out")))
            task.cancel()
        } catch { }
    }
    defer { task.cancel(); timer.cancel() }
    return try await withTaskCancellationHandler {
        try await withCheckedThrowingContinuation { result.install($0) }
    } onCancel: {
        result.finish(.failure(CancellationError()))
        task.cancel()
        timer.cancel()
    }
}

/// Network.framework supplies TLS, including certificate and hostname validation. No custom trust
/// callback, cookies, credentials, redirects, DNS fallback, or connection reuse is involved. A system-configured
/// proxy is used only when a direct connection fails (`preferNoProxies`), and it still targets the validated address.
final class PinnedRelayConnection: @unchecked Sendable {
    private let connection: NWConnection
    private let queue = DispatchQueue(label: "org.aceprotocol.pinned-relay")
    private let timeout: Double
    private let streaming: Bool
    private let lock = NSLock()
    private var timedOut = false
    private var readEnded = false
    private var timer: DispatchWorkItem?

    init(endpoint: NWEndpoint.Host, port: NWEndpoint.Port, serverName: String, tls: Bool,
         timeout: Double, streaming: Bool) {
        let tlsOptions: NWProtocolTLS.Options? = tls ? NWProtocolTLS.Options() : nil
        if let options = tlsOptions?.securityProtocolOptions {
            sec_protocol_options_set_tls_server_name(options, serverName)
            sec_protocol_options_set_peer_authentication_required(options, true)
            sec_protocol_options_set_min_tls_protocol_version(options, .TLSv12)
            sec_protocol_options_add_tls_application_protocol(options, "http/1.1")
        }
        let parameters = NWParameters(tls: tlsOptions, tcp: NWProtocolTCP.Options())
        parameters.preferNoProxies = true
        connection = NWConnection(host: endpoint, port: port, using: parameters)
        self.timeout = timeout
        self.streaming = streaming
    }

    deinit { timer?.cancel(); connection.cancel() }

    func headersReceived() {
        lock.lock()
        let deadline = timer
        timer = nil
        lock.unlock()
        deadline?.cancel()
    }

    func cancel() { headersReceived(); connection.cancel() }

    private func failure(_ error: Error?) -> Error {
        if Task.isCancelled { return CancellationError() }
        lock.lock()
        let expired = timedOut
        lock.unlock()
        return ACEError(.relayUnavailable, expired ? "relay request timed out" : "relay connection failed: \(error?.localizedDescription ?? "closed")")
    }

    func start(connectTimeout: Double) async throws {
        let result = RelayIOResult<Void>()
        try Task.checkCancellation()
        let timer = DispatchWorkItem { [weak self] in
            guard let self else { return }
            lock.lock()
            guard self.timer != nil else { lock.unlock(); return }
            timedOut = true
            lock.unlock()
            connection.cancel()
        }
        lock.withLock { self.timer = timer }
        // The total deadline covers headers even for SSE. Only a successful stream handshake
        // switches to the per-read idle deadline.
        queue.asyncAfter(deadline: .now() + timeout, execute: timer)
        try await withRelayTimeout(connectTimeout) { [self] in
            try await withTaskCancellationHandler {
                try await withCheckedThrowingContinuation { result.install($0)
                    connection.stateUpdateHandler = { [weak self] state in
                        guard let self else { return }
                        switch state {
                        case .ready: result.finish(.success(()))
                        case .failed(let error), .waiting(let error): result.finish(.failure(self.failure(error)))
                        case .cancelled: result.finish(.failure(self.failure(nil)))
                        default: break
                        }
                    }
                    connection.start(queue: queue)
                }
            } onCancel: { [self] in result.finish(.failure(CancellationError())); cancel() }
        }
    }

    func send(_ data: Data) async throws {
        try Task.checkCancellation()
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (c: CheckedContinuation<Void, Error>) in
                connection.send(content: data, completion: .contentProcessed { [self] error in
                    if let error { c.resume(throwing: failure(error)) } else { c.resume() }
                })
            }
        } onCancel: { [self] in cancel() }
    }

    func read() async throws -> Data? {
        try Task.checkCancellation()
        let (expired, ended) = lock.withLock { (timedOut, readEnded) }
        if expired { throw failure(nil) }
        if ended { return nil }
        // A stream has no total lifetime limit; each actual socket read has an idle deadline.
        // Consumer backpressure does not run an idle timer while no read is outstanding.
        return try await withRelayTimeout(streaming ? RelayClient.idleTimeoutSeconds : timeout) { [self] in
            try await withTaskCancellationHandler {
                try await withCheckedThrowingContinuation { (c: CheckedContinuation<Data?, Error>) in
                    connection.receive(minimumIncompleteLength: 1, maximumLength: 16 * 1024) { [self] data, _, complete, error in
                        // EOF may accompany the final data, so remember it before returning that data.
                        // Receiving again after this point yields ENODATA rather than a second EOF on Network.framework.
                        if complete { lock.withLock { readEnded = true } }
                        if lock.withLock({ timedOut }) { c.resume(throwing: failure(nil)) }
                        else if let error { c.resume(throwing: failure(error)) }
                        else if let data, !data.isEmpty { c.resume(returning: data) }
                        else if complete { c.resume(returning: nil) }
                        else { c.resume(throwing: failure(nil)) }
                    }
                }
            } onCancel: { [self] in cancel() }
        }
    }
}

/// Strict, bounded HTTP/1.1 framing for the relay binding. One response per connection means
/// malformed or ambiguous framing can fail closed without desynchronizing a subsequent request.
actor PinnedHTTPBody {
    private let connection: PinnedRelayConnection
    private var buffer = Data()
    private var offset = 0
    private var length: Int?
    private var chunked = false
    private var chunkRemaining = 0
    private var chunkCRLF = false
    private var ended = false
    private static let maxHeaders = 64 * 1024

    init(connection: PinnedRelayConnection) { self.connection = connection }

    private func more() async throws -> Bool {
        if offset < buffer.count { return true }
        guard let bytes = try await connection.read() else { return false }
        buffer = bytes
        offset = 0
        return true
    }

    private func line(limit: Int) async throws -> Data {
        var line = Data()
        while try await more() {
            let byte = buffer[buffer.startIndex + offset]
            offset += 1
            if byte == 10 {
                guard line.last == 13 else { throw bad("HTTP line is not CRLF terminated") }
                line.removeLast()
                return line
            }
            line.append(byte)
            guard line.count <= limit else { throw bad("HTTP headers exceed their limit") }
        }
        throw bad("truncated HTTP headers")
    }

    func readResponse(url: URL) async throws -> HTTPURLResponse {
        let statusLine = try await line(limit: Self.maxHeaders)
        guard let text = String(data: statusLine, encoding: .ascii),
              !statusLine.contains(where: { $0 < 32 || $0 == 127 }) else { throw bad("invalid HTTP status") }
        let parts = text.split(separator: " ", maxSplits: 2, omittingEmptySubsequences: false)
        guard parts.count >= 2, ["HTTP/1.0", "HTTP/1.1"].contains(parts[0]), parts[1].count == 3,
              parts[1].utf8.allSatisfy({ (48...57).contains($0) }), let status = Int(parts[1]), status >= 100 else {
            throw bad("invalid HTTP status")
        }
        var headers: [String: String] = [:]
        var size = statusLine.count + 2
        while true {
            let bytes = try await line(limit: Self.maxHeaders - size)
            size += bytes.count + 2
            guard size <= Self.maxHeaders else { throw bad("HTTP headers exceed their limit") }
            if bytes.isEmpty { break }
            let (name, value) = try header(bytes)
            if headers[name] != nil {
                guard !["content-length", "transfer-encoding", "content-type", "content-encoding"].contains(name) else {
                    throw bad("duplicate HTTP framing header")
                }
                headers[name]! += ", " + value
            } else { headers[name] = value }
        }
        if let encoding = headers["content-encoding"], encoding.lowercased() != "identity" { throw bad("unexpected content encoding") }
        if let transfer = headers["transfer-encoding"] {
            guard transfer.lowercased() == "chunked", headers["content-length"] == nil else { throw bad("ambiguous HTTP framing") }
            chunked = true
        } else if let text = headers["content-length"] {
            guard !text.isEmpty, text.utf8.allSatisfy({ (48...57).contains($0) }), let count = Int(text) else { throw bad("invalid Content-Length") }
            length = count
        }
        if (100..<200).contains(status) || status == 204 || status == 304 { length = 0; chunked = false }
        guard let response = HTTPURLResponse(url: url, statusCode: status, httpVersion: String(parts[0]), headerFields: headers) else {
            throw bad("invalid HTTP response")
        }
        return response
    }

    func nextChunk() async throws -> Data? {
        guard !ended else { return nil }
        if chunked {
            if chunkRemaining == 0 {
                if chunkCRLF {
                    guard try await line(limit: 2).isEmpty else { throw bad("invalid chunk terminator") }
                }
                let bytes = try await line(limit: 8192)
                guard let text = String(data: bytes, encoding: .ascii),
                      !bytes.contains(where: { $0 < 32 && $0 != 9 || $0 == 127 }) else { throw bad("invalid chunk size") }
                let digits = text.split(separator: ";", maxSplits: 1, omittingEmptySubsequences: false)[0]
                guard !digits.isEmpty, digits.utf8.allSatisfy({ (48...57).contains($0) || (65...70).contains($0) || (97...102).contains($0) }),
                      let count = Int(digits, radix: 16) else { throw bad("invalid chunk size") }
                chunkRemaining = count
                chunkCRLF = true
                if count == 0 {
                    var total = 0
                    while true {
                        let trailer = try await line(limit: Self.maxHeaders - total)
                        total += trailer.count + 2
                        guard total <= Self.maxHeaders else { throw bad("HTTP trailers exceed their limit") }
                        if trailer.isEmpty { break }
                        let (name, _) = try header(trailer)
                        guard !["content-length", "transfer-encoding", "content-encoding"].contains(name) else { throw bad("framing header in HTTP trailers") }
                    }
                    ended = true
                    connection.cancel()
                    return nil
                }
            }
        } else if length == 0 {
            ended = true
            connection.cancel()
            return nil
        }
        guard try await more() else {
            guard !chunked, length == nil else { throw bad("truncated HTTP body") }
            ended = true
            connection.cancel()
            return nil
        }
        let count = min(buffer.count - offset, chunked ? chunkRemaining : (length ?? Int.max))
        let bytes = buffer.subdata(in: (buffer.startIndex + offset)..<(buffer.startIndex + offset + count))
        offset += count
        if chunked { chunkRemaining -= count } else if length != nil { length! -= count }
        return bytes
    }

    private func header(_ bytes: Data) throws -> (String, String) {
        guard let text = String(data: bytes, encoding: .isoLatin1), let colon = text.firstIndex(of: ":") else { throw bad("invalid HTTP header") }
        let name = String(text[..<colon]).lowercased()
        let value = String(text[text.index(after: colon)...]).trimmingCharacters(in: CharacterSet(charactersIn: " \t"))
        guard isHTTPToken(name), !value.utf8.contains(where: { $0 < 32 && $0 != 9 || $0 == 127 }) else { throw bad("invalid HTTP header") }
        return (name, value)
    }

    private func bad(_ message: String) -> ACEError { ACEError(.relayProtocolError, message) }
}

private func isHTTPToken(_ value: String) -> Bool {
    !value.isEmpty && value.utf8.allSatisfy { byte in
        (48...57).contains(byte) || (65...90).contains(byte) || (97...122).contains(byte) || "!#$%&'*+-.^_`|~".utf8.contains(byte)
    }
}
