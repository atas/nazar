import Foundation
import LocalAuthentication

/// An authenticated context behind an approval ref: an LAContext on the
/// real platform, a scripted stand-in in tests.
public protocol AuthContext: AnyObject {
    /// The LAContext CryptoKit should use, or nil for a software context.
    var laContext: LAContext? { get }
    /// Ends the context; later uses of its LAContext fail.
    func invalidate()
}

/// An LAContext kept for one approval (spec 4.3/4.7, spike S1).
public final class LAAuthContext: AuthContext, @unchecked Sendable {
    public let context: LAContext
    public init(_ context: LAContext) { self.context = context }
    public var laContext: LAContext? { context }
    public func invalidate() { context.invalidate() }
}

/// Approval refs (core/platform ApprovalRef contract): a ref is never 0,
/// never reused within the process, and an unknown or released ref has no
/// context. Releasing 0, an unknown ref or a released ref is a no-op.
public final class ApprovalStore: @unchecked Sendable {
    private let lock = NSLock()
    private var next: UInt64 = 1
    private var live: [UInt64: AuthContext] = [:]

    public init() {}

    /// Registers ctx and returns its new ref, or nil once the counter is
    /// exhausted (fail closed rather than wrap around and reuse a ref).
    public func issue(_ ctx: AuthContext) -> UInt64? {
        lock.lock()
        defer { lock.unlock() }
        guard next < UInt64.max else { return nil }
        let ref = next
        next += 1
        live[ref] = ctx
        return ref
    }

    /// The context of a live ref, or nil.
    public func context(_ ref: UInt64) -> AuthContext? {
        lock.lock()
        defer { lock.unlock() }
        return ref == 0 ? nil : live[ref]
    }

    /// Ends ref and invalidates its context.
    public func release(_ ref: UInt64) {
        lock.lock()
        let ctx = live.removeValue(forKey: ref)
        lock.unlock()
        ctx?.invalidate()
    }

    public var liveCount: Int {
        lock.lock()
        defer { lock.unlock() }
        return live.count
    }

    /// Test hook: start issuing at n (to exercise exhaustion).
    func setNextForTesting(_ n: UInt64) {
        lock.lock()
        next = n
        lock.unlock()
    }
}
