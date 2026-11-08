import Foundation
import LocalAuthentication

/// A scripted login prompt for tests, the seamed conformance run and the
/// smoke host. Never used by Nazar.app. Answers queued with
/// `push` are used in order, then `defaultAnswer`.
public final class ScriptedLoginEvaluator: LoginEvaluator, @unchecked Sendable {
    private let lock = NSLock()
    private var answers: [Bool] = []
    private var _defaultAnswer: Bool
    private var _reasons: [String] = []
    private var active = 0
    private var _maxConcurrent = 0
    private var _delay: TimeInterval = 0

    public init(defaultAnswer: Bool = false) { _defaultAnswer = defaultAnswer }

    /// The answer when nothing is queued.
    public var defaultAnswer: Bool {
        get { lock.lock(); defer { lock.unlock() }; return _defaultAnswer }
        set { lock.lock(); _defaultAnswer = newValue; lock.unlock() }
    }

    /// Every reason shown, in order.
    public var reasons: [String] {
        lock.lock()
        defer { lock.unlock() }
        return _reasons
    }

    /// The most evaluations ever in flight at once (1 when serialised).
    public var maxConcurrent: Int {
        lock.lock()
        defer { lock.unlock() }
        return _maxConcurrent
    }

    /// How long each evaluation takes (to observe serialisation).
    public var delay: TimeInterval {
        get { lock.lock(); defer { lock.unlock() }; return _delay }
        set { lock.lock(); _delay = newValue; lock.unlock() }
    }

    public func push(_ allow: Bool) {
        lock.lock()
        answers.append(allow)
        lock.unlock()
    }

    public func evaluate(reason: String, timeout: TimeInterval) throws -> AuthContext {
        lock.lock()
        active += 1
        _maxConcurrent = max(_maxConcurrent, active)
        _reasons.append(reason)
        let allow = answers.isEmpty ? _defaultAnswer : answers.removeFirst()
        let pause = _delay
        lock.unlock()
        if pause > 0 { Thread.sleep(forTimeInterval: pause) }
        lock.lock()
        active -= 1
        lock.unlock()
        guard allow else { throw PlatformError.denied }
        return ScriptedAuthContext()
    }
}

/// The context a scripted approval holds (no LAContext).
public final class ScriptedAuthContext: AuthContext, @unchecked Sendable {
    private let lock = NSLock()
    private var _invalidated = false

    public init() {}

    public var invalidated: Bool {
        lock.lock()
        defer { lock.unlock() }
        return _invalidated
    }

    public var laContext: LAContext? { nil }

    public func invalidate() {
        lock.lock()
        _invalidated = true
        lock.unlock()
    }
}
