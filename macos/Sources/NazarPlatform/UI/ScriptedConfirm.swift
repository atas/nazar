import Foundation

/// A scripted `dialog` gate for tests, the seamed conformance run and the
/// smoke host. Never used by Nazar.app.
public final class ScriptedConfirmer: Confirmer, @unchecked Sendable {
    private let lock = NSLock()
    private var answers: [Bool] = []
    private var _defaultAnswer: Bool
    private var _prompts: [PromptSpec] = []

    public init(defaultAnswer: Bool = false) { _defaultAnswer = defaultAnswer }

    /// The answer once the pushed ones are used up.
    public var defaultAnswer: Bool {
        get { lock.lock(); defer { lock.unlock() }; return _defaultAnswer }
        set { lock.lock(); _defaultAnswer = newValue; lock.unlock() }
    }

    /// Every prompt confirm() was asked, in order.
    public var prompts: [PromptSpec] {
        lock.lock()
        defer { lock.unlock() }
        return _prompts
    }

    public func push(_ allow: Bool) {
        lock.lock()
        answers.append(allow)
        lock.unlock()
    }

    public func confirm(_ prompt: PromptSpec) throws -> Bool {
        lock.lock()
        defer { lock.unlock() }
        _prompts.append(prompt)
        return answers.isEmpty ? _defaultAnswer : answers.removeFirst()
    }
}
