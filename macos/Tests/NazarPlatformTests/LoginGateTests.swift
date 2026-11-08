import Foundation
import LocalAuthentication
import Testing
@testable import NazarPlatform

// The `login` gate (Platform.Authenticate), spec 4.3/4.4/4.7, S1/S2.
// LAEvaluator.evaluate needs a person and is never called here (it is
// checked by hand); every behaviour of the gate runs through the
// LoginEvaluator seam.

/// A context the recording evaluator hands out (no LAContext).
fileprivate final class RecordedContext: AuthContext, @unchecked Sendable {
    private let lock = NSLock()
    private var _invalidated = false
    var invalidated: Bool { lock.lock(); defer { lock.unlock() }; return _invalidated }
    var laContext: LAContext? { nil }
    func invalidate() { lock.lock(); _invalidated = true; lock.unlock() }
}

/// A LoginEvaluator that records every call's reason and timeout and the
/// contexts it returned, and answers with `answer` after `delay`.
fileprivate final class RecordingEvaluator: LoginEvaluator, @unchecked Sendable {
    private let lock = NSLock()
    var answer: () throws -> Bool
    var delay: TimeInterval = 0
    private(set) var calls: [(reason: String, timeout: TimeInterval)] = []
    private(set) var contexts: [RecordedContext] = []

    init(answer: @escaping () throws -> Bool = { true }) { self.answer = answer }

    func evaluate(reason: String, timeout: TimeInterval) throws -> AuthContext {
        lock.lock()
        calls.append((reason, timeout))
        lock.unlock()
        if delay > 0 { Thread.sleep(forTimeInterval: delay) }
        guard try answer() else { throw PlatformError.denied }
        let c = RecordedContext()
        lock.lock()
        contexts.append(c)
        lock.unlock()
        return c
    }

    var timeouts: [TimeInterval] { lock.lock(); defer { lock.unlock() }; return calls.map(\.timeout) }
    var callCount: Int { lock.lock(); defer { lock.unlock() }; return calls.count }
}

/// Polls cond (up to 5 s) so a test does not depend on thread start-up timing.
fileprivate func waitUntil(_ cond: () -> Bool) {
    let end = Date().addingTimeInterval(5)
    while !cond() && Date() < end { Thread.sleep(forTimeInterval: 0.005) }
}

@Suite struct LoginGateTests {
    let prompt = PromptSpec(title: "iTerm2 wants to use key \"github\"", lines: ["login to github.com"],
                            reason: "use key github for github.com", timeoutMillis: 5000)

    // MARK: approvals issued by the gate

    @Test func allowIssuesALiveRefWithItsOwnContext() throws {
        let ev = ScriptedLoginEvaluator(), store = ApprovalStore()
        let g = LoginGate(evaluator: ev, approvals: store)
        ev.push(true)
        ev.push(true)
        let a = try g.authenticate(policy: 1, prompt: prompt)
        let b = try g.authenticate(policy: 1, prompt: prompt)
        #expect(a != 0 && b != 0 && a != b)
        #expect(store.context(a) !== store.context(b))
        #expect(ev.reasons == ["use key github for github.com", "use key github for github.com"])
        let ca = try #require(store.context(a) as? ScriptedAuthContext)
        store.release(a)
        #expect(ca.invalidated == true)
        #expect(store.context(a) == nil)
        #expect((try #require(store.context(b) as? ScriptedAuthContext)).invalidated == false)
    }

    @Test func theRefHoldsExactlyTheContextTheEvaluatorAuthenticated() throws {
        let ev = RecordingEvaluator(), store = ApprovalStore()
        let g = LoginGate(evaluator: ev, approvals: store)
        let r = try g.authenticate(policy: 1, prompt: prompt)
        #expect(ev.contexts.count == 1)
        #expect(store.context(r) === ev.contexts[0])
        #expect(store.liveCount == 1)
        #expect(ev.contexts[0].invalidated == false)
    }

    @Test func denyIssuesNothing() {
        let ev = ScriptedLoginEvaluator(), store = ApprovalStore()
        let g = LoginGate(evaluator: ev, approvals: store)
        ev.push(false)
        #expect(throws: PlatformError.denied) { try g.authenticate(policy: 1, prompt: prompt) }
        #expect(store.liveCount == 0)
        #expect(ev.reasons.count == 1)
    }

    @Test func aDenialLeavesEarlierApprovalsAloneAndTheGateUsable() throws {
        let ev = ScriptedLoginEvaluator(), store = ApprovalStore()
        let g = LoginGate(evaluator: ev, approvals: store)
        ev.push(true)
        ev.push(false)
        ev.push(true)
        let a = try g.authenticate(policy: 1, prompt: prompt)
        #expect(throws: PlatformError.denied) { try g.authenticate(policy: 1, prompt: prompt) }
        let c = try g.authenticate(policy: 1, prompt: prompt) // the turn was handed back after the denial
        #expect(store.liveCount == 2)
        #expect(c != a && c != 0)
        #expect((try #require(store.context(a) as? ScriptedAuthContext)).invalidated == false)
    }

    @Test func scriptedAnswersAreUsedInOrderThenTheDefault() throws {
        let ev = ScriptedLoginEvaluator(defaultAnswer: false), store = ApprovalStore()
        let g = LoginGate(evaluator: ev, approvals: store)
        ev.push(false)
        ev.push(true)
        #expect(throws: PlatformError.denied) { try g.authenticate(policy: 1, prompt: prompt) }
        #expect(try g.authenticate(policy: 1, prompt: prompt) != 0)
        #expect(throws: PlatformError.denied) { try g.authenticate(policy: 1, prompt: prompt) }
        #expect(ev.reasons.count == 3)
        #expect(store.liveCount == 1)
    }

    @Test func evaluatorErrorsPassThroughIssueNothingAndFreeTheTurn() throws {
        var fail = true
        let ev = RecordingEvaluator(answer: { if fail { throw PlatformError.failed("boom") }; return true })
        let store = ApprovalStore()
        let g = LoginGate(evaluator: ev, approvals: store)
        #expect(throws: PlatformError.failed("boom")) { try g.authenticate(policy: 1, prompt: prompt) }
        #expect(store.liveCount == 0)
        fail = false
        #expect(try g.authenticate(policy: 1, prompt: prompt) != 0)
        #expect(store.liveCount == 1)
    }

    @Test func exhaustedRefsFailClosedAndInvalidateTheFreshContext() {
        let ev = RecordingEvaluator(), store = ApprovalStore()
        store.setNextForTesting(UInt64.max)
        let g = LoginGate(evaluator: ev, approvals: store)
        do {
            let r = try g.authenticate(policy: 1, prompt: prompt)
            Issue.record("exhausted store issued ref \(r)")
        } catch PlatformError.failed {
        } catch {
            Issue.record("want .failed, got \(error)")
        }
        #expect(store.liveCount == 0)
        #expect(ev.contexts.count == 1)
        #expect(ev.contexts.first?.invalidated == true) // an authenticated context is never left alive unowned
    }

    // MARK: policy

    @Test func outOfRangePolicyIsRefusedWithoutAPrompt() {
        let ev = ScriptedLoginEvaluator(defaultAnswer: true)
        let store = ApprovalStore()
        let g = LoginGate(evaluator: ev, approvals: store)
        for p: Int32 in [2, 3, -1, .max, .min] {
            #expect(throws: PlatformError.invalid("auth policy \(p)")) { try g.authenticate(policy: p, prompt: prompt) }
        }
        #expect(ev.reasons.isEmpty)
        #expect(store.liveCount == 0)
    }

    @Test(arguments: [Int32(0), 1])
    func bothValidPoliciesAlwaysPrompt(_ policy: Int32) throws {
        // AuthNone is never a shortcut to an approval without the user.
        let ev = ScriptedLoginEvaluator(defaultAnswer: false)
        let g = LoginGate(evaluator: ev, approvals: ApprovalStore())
        #expect(throws: PlatformError.denied) { try g.authenticate(policy: policy, prompt: prompt) }
        ev.push(true)
        #expect(try g.authenticate(policy: policy, prompt: prompt) != 0)
        #expect(ev.reasons.count == 2)
    }

    // MARK: one prompt at a time, timeouts

    @Test func onePromptAtATimeAndRefsStayUnique() throws {
        let ev = ScriptedLoginEvaluator(defaultAnswer: true)
        ev.delay = 0.02
        let store = ApprovalStore()
        let g = LoginGate(evaluator: ev, approvals: store)
        let lock = NSLock()
        var refs: [UInt64] = []
        DispatchQueue.concurrentPerform(iterations: 8) { _ in
            if let r = try? g.authenticate(policy: 1, prompt: prompt) {
                lock.lock(); refs.append(r); lock.unlock()
            }
        }
        #expect(refs.count == 8 && Set(refs).count == 8 && !refs.contains(0))
        #expect(ev.maxConcurrent == 1)
        #expect(store.liveCount == 8)
    }

    @Test func concurrentDenialsAreSerialisedAndIssueNothing() {
        let ev = ScriptedLoginEvaluator(defaultAnswer: false)
        ev.delay = 0.01
        let store = ApprovalStore()
        let g = LoginGate(evaluator: ev, approvals: store)
        let lock = NSLock()
        var denied = 0
        DispatchQueue.concurrentPerform(iterations: 6) { _ in
            do { _ = try g.authenticate(policy: 1, prompt: prompt) } catch PlatformError.denied {
                lock.lock(); denied += 1; lock.unlock()
            } catch {}
        }
        #expect(denied == 6)
        #expect(ev.maxConcurrent == 1)
        #expect(store.liveCount == 0)
    }

    @Test func aCallerStillQueuedAtItsTimeoutIsDeniedWithoutAPrompt() throws {
        let ev = ScriptedLoginEvaluator(defaultAnswer: true)
        // Windows scaled with the load (at most 5x: the first prompt's own
        // timeout is 5 s), so a stall doesn't let the first prompt finish
        // before the second caller queues.
        let f = min(loadFactor(), 5)
        ev.delay = 0.8 * f
        let store = ApprovalStore()
        let g = LoginGate(evaluator: ev, approvals: store)
        let first = DispatchSemaphore(value: 0)
        DispatchQueue.global().async {
            _ = try? g.authenticate(policy: 1, prompt: prompt)
            first.signal()
        }
        waitUntil { ev.reasons.count == 1 } // the first prompt is on screen
        let short = PromptSpec(title: "t", reason: "r", timeoutMillis: Int64(100 * f))
        let started = Date()
        #expect(throws: PlatformError.denied) { try g.authenticate(policy: 1, prompt: short) }
        #expect(Date().timeIntervalSince(started) < 0.5 * f) // denied at its own timeout, not after the other prompt
        first.wait()
        #expect(ev.reasons.count == 1)
        #expect(store.liveCount == 1)
        // The timed-out waiter did not take or leak the turn.
        ev.delay = 0
        #expect(try g.authenticate(policy: 1, prompt: prompt) != 0)
        #expect(ev.reasons.count == 2)
    }

    @Test func aQueuedCallerGetsOnlyWhatIsLeftOfItsOwnTimeout() throws {
        let ev = RecordingEvaluator()
        let f = min(loadFactor(), 5) // as above
        ev.delay = 0.6 * f
        let g = LoginGate(evaluator: ev, approvals: ApprovalStore())
        let first = DispatchSemaphore(value: 0)
        DispatchQueue.global().async {
            _ = try? g.authenticate(policy: 1, prompt: prompt)
            first.signal()
        }
        waitUntil { ev.callCount == 1 } // the first prompt is on screen
        let p = PromptSpec(title: "t", reason: "r", timeoutMillis: Int64(1500 * f))
        _ = try g.authenticate(policy: 1, prompt: p)
        first.wait()
        let t = ev.timeouts
        #expect(t.count == 2)
        #expect(t[0] > 0 && t[0] <= 5)
        // It waited ~0.6 s for its turn: the prompt must not get a fresh 1.5 s.
        #expect(t[1] > 0 && t[1] < 1.3 * f)
    }

    @Test func theEvaluatorTimeoutFollowsThePromptAndIsBounded() throws {
        let ev = RecordingEvaluator()
        let g = LoginGate(evaluator: ev, approvals: ApprovalStore())
        _ = try g.authenticate(policy: 1, prompt: PromptSpec(title: "t", reason: "r", timeoutMillis: 2000))
        _ = try g.authenticate(policy: 1, prompt: PromptSpec(title: "t", reason: "r", timeoutMillis: 0))
        _ = try g.authenticate(policy: 1, prompt: PromptSpec(title: "t", reason: "r", timeoutMillis: -5))
        _ = try g.authenticate(policy: 1, prompt: PromptSpec(title: "t", reason: "r", timeoutMillis: .max))
        let t = ev.timeouts
        #expect(t.count == 4)
        #expect(t[0] > 1.5 && t[0] <= 2)
        #expect(t[1] > 59 && t[1] <= 60)   // no timeout: the 60 s default (spec 4.4)
        #expect(t[2] > 59 && t[2] <= 60)
        #expect(t[3] > 599 && t[3] <= 600) // never longer than 10 minutes
    }

    // MARK: reason text (what the system sheet shows)

    @Test func reasonTextIsNeverEmptyAndStaysOneBoundedLine() {
        #expect(LoginGate.reasonText(PromptSpec(title: "T", reason: "")) == "T")
        #expect(LoginGate.reasonText(PromptSpec(title: "", reason: " \n ")) == LoginGate.defaultReason)
        #expect(LoginGate.reasonText(PromptSpec(title: "", reason: "a\nb")) == "a b")
        #expect(LoginGate.reasonText(PromptSpec(title: "", reason: String(repeating: "x", count: 500))).count == 200)
    }

    @Test func reasonTextPrefersTheReasonAndTrims() {
        #expect(LoginGate.reasonText(PromptSpec(title: "title", reason: "reason")) == "reason")
        #expect(LoginGate.reasonText(PromptSpec(title: "  title  ", reason: "")) == "title")
        #expect(LoginGate.reasonText(PromptSpec(title: "", reason: "")) == LoginGate.defaultReason)
        #expect(!LoginGate.defaultReason.isEmpty)
        #expect(LoginGate.reasonText(PromptSpec(title: "", reason: String(repeating: "x", count: 200))).count == 200)
        let long = LoginGate.reasonText(PromptSpec(title: "", reason: String(repeating: "x", count: 201)))
        #expect(long.count == 200 && long.hasSuffix("…"))
    }

    /// A destination or command line chosen by the caller ends up in the
    /// reason; it must not be able to add lines to the system sheet (for
    /// example a fake "approved by your administrator" line).
    @Test(arguments: ["github.com\r\nApproved by IT", "github.com\rApproved by IT",
                      "github.com\u{2028}Approved by IT", "github.com\u{2029}Approved by IT",
                      "github.com\u{85}Approved by IT", "github.com\u{0B}Approved by IT",
                      "github.com\u{0C}Approved by IT"])
    func reasonTextHasNoLineBreaksOfAnyKind(_ hostile: String) {
        let s = LoginGate.reasonText(PromptSpec(title: "", reason: "use key github for " + hostile))
        #expect(!s.unicodeScalars.contains { CharacterSet.newlines.contains($0) }, "line break in \(s.debugDescription)")
        #expect(s.hasPrefix("use key github for github.com"))
        #expect(s.hasSuffix("Approved by IT"))
    }

    @Test func reasonTextBoundCountsCharactersNotBytes() {
        let s = LoginGate.reasonText(PromptSpec(title: "", reason: String(repeating: "🧿", count: 500)))
        #expect(s.count == 200)
        #expect(s.hasSuffix("…"))
        #expect(s.dropLast().allSatisfy { $0 == "🧿" }) // never a split grapheme
    }

    // MARK: the real evaluator (construction and error mapping only)

    @Test func theRealEvaluatorDefaultsToTheSpecsDevicePolicy() {
        #expect(LAEvaluator().mode == .devicePolicy) // spec 4.4: deviceOwnerAuthentication
        #expect(LAEvaluator(mode: .accessControl).mode == .accessControl)
    }

    @Test func laErrorsMapToDeniedOrFailed() {
        for c: LAError.Code in [.userCancel, .appCancel, .systemCancel, .authenticationFailed, .userFallback, .notInteractive] {
            #expect(LAEvaluator.map(LAError(c)) == .denied)
        }
        if case .failed = LAEvaluator.map(LAError(.passcodeNotSet)) {} else { Issue.record("passcodeNotSet must be an error") }
        if case .failed = LAEvaluator.map(NSError(domain: "x", code: 1)) {} else { Issue.record("foreign error must be an error") }
    }

    /// LocalAuthentication's reply hands over an NSError in LAErrorDomain,
    /// not a Swift LAError value.
    @Test func laErrorsArrivingAsNSErrorMapTheSame() {
        for c: LAError.Code in [.userCancel, .appCancel, .systemCancel, .authenticationFailed, .userFallback, .notInteractive] {
            #expect(LAEvaluator.map(NSError(domain: LAErrorDomain, code: c.rawValue)) == .denied)
        }
        if case .failed = LAEvaluator.map(NSError(domain: LAErrorDomain, code: LAError.Code.passcodeNotSet.rawValue)) {} else {
            Issue.record("passcodeNotSet as NSError must be an error")
        }
    }

    @Test func platformErrorsPassThroughTheMapping() {
        #expect(LAEvaluator.map(PlatformError.denied) == .denied)
        #expect(LAEvaluator.map(PlatformError.failed("x")) == .failed("x"))
        #expect(LAEvaluator.map(PlatformError.authRequired) == .authRequired)
    }

    // MARK: the scripted stand-ins

    @Test func scriptedContextHasNoLAContextAndRecordsInvalidation() {
        let c = ScriptedAuthContext()
        #expect(c.laContext == nil)
        #expect(c.invalidated == false)
        c.invalidate()
        #expect(c.invalidated == true)
    }
}
