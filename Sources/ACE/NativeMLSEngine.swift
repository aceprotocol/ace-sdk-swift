import Foundation
import ACESessionCore

/// The statically linked, source-built common MLS engine (`SessionCoreEngine` from the
/// ace-session-core package) as an `MLSEngine`. Calls into Rust serialize natively. Close
/// every `PairwiseMLS` context before closing the engine; a forked child must exec first.
public final class NativeMLSEngine: ClosableMLSEngine, @unchecked Sendable {
    private let core: SessionCoreEngine

    public init() throws {
        do { core = try SessionCoreEngine() } catch let error as SessionCoreError { throw MLSError(error.code) }
    }

    public func execute(_ command: Data) throws -> Data {
        do { return try core.execute(command) } catch let error as SessionCoreError { throw MLSError(error.code) }
    }

    /// Frees the engine; idempotent.
    public func close() { core.close() }
}
