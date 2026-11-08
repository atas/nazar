import Foundation
import LocalAuthentication

/// Shows the system authentication prompt (Touch ID, Apple Watch or the Mac
/// password) and returns the authenticated context, or throws .denied when
/// the user cancels or the timeout passes.
public protocol LoginEvaluator: AnyObject {
    func evaluate(reason: String, timeout: TimeInterval) throws -> AuthContext
}

/// How the real evaluator authenticates. `.devicePolicy` is the spec's
/// `LAContext.evaluatePolicy(.deviceOwnerAuthentication)` (spec 4.4).
/// `.accessControl` evaluates the user-presence access control for
/// `.useKeySign`, the mode spike S1 measured reusing one context for six
/// minutes of signatures. Which one a user-presence key accepts without a
/// second prompt needs a person to check: on a real Mac `.devicePolicy`
/// gave one prompt per login. Switching is this one value in NazarApp.
public enum LoginEvaluation: Sendable {
    case devicePolicy
    case accessControl
}

/// The real login gate (needs a person; never run in automated tests).
public final class LAEvaluator: LoginEvaluator, @unchecked Sendable {
    let mode: LoginEvaluation

    public init(mode: LoginEvaluation = .devicePolicy) { self.mode = mode }

    /// The reply of one evaluation, written by LocalAuthentication's reply
    /// block and read once the semaphore fires.
    private final class Reply: @unchecked Sendable {
        private let lock = NSLock()
        private var outcome: Result<Void, Error> = .failure(PlatformError.denied)
        let done = DispatchSemaphore(value: 0)

        func finish(_ ok: Bool, _ err: Error?) {
            lock.lock()
            outcome = ok ? .success(()) : .failure(err ?? PlatformError.denied)
            lock.unlock()
            done.signal()
        }

        var result: Result<Void, Error> {
            lock.lock()
            defer { lock.unlock() }
            return outcome
        }
    }

    public func evaluate(reason: String, timeout: TimeInterval) throws -> AuthContext {
        let ctx = LAContext()
        ctx.localizedCancelTitle = "Deny"
        let reply = Reply()
        switch mode {
        case .devicePolicy:
            ctx.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason) { ok, err in
                reply.finish(ok, err)
            }
        case .accessControl:
            let ac = try SecureEnclaveBackend.accessControl(userPresence: true, whileLocked: false)
            ctx.evaluateAccessControl(ac, operation: .useKeySign, localizedReason: reason) { ok, err in
                reply.finish(ok, err)
            }
        }
        if reply.done.wait(timeout: .now() + timeout) == .timedOut {
            ctx.invalidate() // dismisses the prompt; the reply then reports appCancel
            _ = reply.done.wait(timeout: .now() + 5)
            throw PlatformError.denied
        }
        switch reply.result {
        case .success:
            // From now on this context may never show UI: once the chip's
            // reuse window (S1: 6-10 min) has passed, a signature fails
            // with ErrAuthRequired instead of prompting out of context.
            ctx.interactionNotAllowed = true
            return LAAuthContext(ctx)
        case .failure(let err):
            throw Self.map(err)
        }
    }

    /// Cancel, fallback, failed authentication and system cancels are a
    /// denial; anything else (no password set, LocalAuthentication
    /// unavailable) is an error. LocalAuthentication's reply block hands
    /// over an NSError in LAErrorDomain, so the domain is checked rather
    /// than relying on a bridge to the Swift LAError value.
    public static func map(_ error: Error) -> PlatformError {
        if let p = error as? PlatformError { return p }
        let ns = error as NSError
        if ns.domain == LAErrorDomain, let code = LAError.Code(rawValue: ns.code) {
            switch code {
            case .userCancel, .appCancel, .systemCancel, .authenticationFailed, .userFallback, .notInteractive:
                return .denied
            default:
                return .failed("login gate: \(ns.localizedDescription)")
            }
        }
        return .failed("login gate: \(error)")
    }
}

/// Platform.Authenticate: the `login` gate (spec 4.4). One prompt is on
/// screen at a time; a caller still waiting for its turn when its own
/// timeout passes is denied without a prompt. Each success gets a fresh
/// approval ref holding its own LAContext (S1, spec 4.3).
public final class LoginGate: @unchecked Sendable {
    private let evaluator: LoginEvaluator
    private let approvals: ApprovalStore
    private let turn = DispatchSemaphore(value: 1)

    public static let defaultReason = "nazar needs your approval"
    /// The longest reason LocalAuthentication is given, in characters.
    static let maxReasonLength = 200

    public init(evaluator: LoginEvaluator, approvals: ApprovalStore) {
        self.evaluator = evaluator
        self.approvals = approvals
    }

    /// policy is platform.AuthPolicy (0 = none, 1 = user presence); both
    /// prompt, the value only has to be one the contract defines.
    public func authenticate(policy: Int32, prompt: PromptSpec) throws -> UInt64 {
        guard policy == 0 || policy == 1 else { throw PlatformError.invalid("auth policy \(policy)") }
        let deadline = Date().addingTimeInterval(prompt.timeout)
        guard turn.wait(timeout: .now() + prompt.timeout) == .success else { throw PlatformError.denied }
        defer { turn.signal() }
        let left = deadline.timeIntervalSinceNow
        guard left > 0 else { throw PlatformError.denied }
        let ctx = try evaluator.evaluate(reason: Self.reasonText(prompt), timeout: left)
        guard let ref = approvals.issue(ctx) else {
            ctx.invalidate() // an authenticated context is never left alive unowned
            throw PlatformError.failed("approval refs exhausted")
        }
        return ref
    }

    /// The text LocalAuthentication shows: the prompt's reason, else its
    /// title; LAContext refuses an empty reason. One line (caller-chosen
    /// text such as a destination must not add lines to the system sheet,
    /// so every Unicode line break becomes a space) and bounded in
    /// characters, never splitting a grapheme.
    public static func reasonText(_ p: PromptSpec) -> String {
        let raw = p.reason.isEmpty ? p.title : p.reason
        var s = String(String.UnicodeScalarView(raw.unicodeScalars.map { CharacterSet.newlines.contains($0) ? " " : $0 }))
        s = s.trimmingCharacters(in: .whitespacesAndNewlines)
        if s.isEmpty { s = defaultReason }
        return s.count > maxReasonLength ? String(s.prefix(maxReasonLength - 1)) + "…" : s
    }
}
