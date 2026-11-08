import CNazarBridge
import Foundation
import Testing
@testable import NazarPlatform

// Milestone 5: how a `dialog` gate ended reaches the Go core (and the
// audit log) through confirm's `allowed` output: 1 allows, 2 Deny, 3 Esc,
// 4 timed out, 5 closed without an answer. Nothing here shows a window,
// posts an event or turns on Secure Event Input (fakes from DialogGateTests).

/// A confirmer that answers with a fixed outcome.
final class OutcomeConfirmer: Confirmer, @unchecked Sendable {
    let outcome: ConfirmOutcome
    init(_ o: ConfirmOutcome) { outcome = o }
    func confirm(_ prompt: PromptSpec) throws -> Bool { outcome == .allowed }
    func answer(_ prompt: PromptSpec) throws -> ConfirmOutcome { outcome }
}

@Suite(.serialized) struct DialogOutcomeTests {
    let q = DispatchQueue(label: "test.ui.outcome")

    func gate(_ keys: FakeKeys, _ views: Box<[FakeView]>) -> DialogGate {
        DialogGate(makeView: { _, a in let v = FakeView(a); views.value.append(v); return v },
                   keys: keys, secureInput: FakeSecureInput(), uiQueue: q, armDelay: 0)
    }

    /// A dialog that acts on nothing times out, possibly before it opened on
    /// a stalled machine, which is the same outcome: then there is no view
    /// and nothing to act on.
    func run(_ timeoutMillis: Int64 = 30000, _ act: (FakeView, FakeKeys) -> Void) -> ConfirmOutcome? {
        let keys = FakeKeys(), views = Box<[FakeView]>([])
        let g = gate(keys, views)
        let done = DispatchSemaphore(value: 0), out = Box<ConfirmOutcome?>(nil)
        DispatchQueue.global().async { out.value = try? g.answer(PromptSpec(title: "t", timeoutMillis: timeoutMillis)); done.signal() }
        let end = Date().addingTimeInterval(openWait)
        var answered = false
        while !keys.active && !answered && Date() < end {
            answered = done.wait(timeout: .now() + 0.005) == .success
        }
        if let v = q.sync(execute: { views.value.last }) {
            act(v, keys)
        } else if !answered {
            Issue.record("the dialog neither opened nor answered in \(openWait) s")
            return nil
        }
        if !answered { done.wait() }
        return out.value
    }

    @Test func denyButton() {
        #expect(run { v, _ in v.deny(on: q) } == .denyButton)
    }

    @Test func escape() {
        #expect(run { _, k in k.press(escapePress, on: q) } == .escape)
    }

    @Test func timedOut() {
        #expect(run(300) { _, _ in } == .timedOut)
    }

    @Test func allowed() {
        #expect(run { v, _ in v.key(true, on: q); v.clickNow(on: q) } == .allowed)
    }

    /// confirm() stays the Bool contract: true only for .allowed.
    @Test func confirmIsAllowedOnly() {
        for o: ConfirmOutcome in [.denied, .denyButton, .escape, .timedOut, .closed] {
            #expect((try? OutcomeConfirmer(o).confirm(PromptSpec(title: "t"))) == false)
        }
        #expect((try? OutcomeConfirmer(.allowed).confirm(PromptSpec(title: "t"))) == true)
        #expect(ConfirmOutcome.allowed.rawValue == 1 && ConfirmOutcome.denied.rawValue == 0)
        #expect([ConfirmOutcome.denyButton, .escape, .timedOut, .closed].map(\.rawValue) == [2, 3, 4, 5])
    }

    /// A confirmer that only answers Bool (ScriptedConfirmer) reports 0/1.
    @Test func boolOnlyConfirmerAnswersDeniedOrAllowed() throws {
        let s = ScriptedConfirmer()
        s.push(false)
        s.push(true)
        #expect(try s.answer(PromptSpec(title: "t")) == .denied)
        #expect(try s.answer(PromptSpec(title: "t")) == .allowed)
    }

    /// The first way the dialog ended is the answer: a late Esc after Deny
    /// (or a late Deny after Esc) does not change it.
    @Test func firstWayWins() {
        #expect(run { v, k in v.deny(on: q); k.press(escapePress, on: q) } == .denyButton)
        #expect(run { v, k in k.press(escapePress, on: q); v.deny(on: q) } == .escape)
    }

    /// Esc denies even when Allow is armed.
    @Test func escapeWhileArmedIsEscape() {
        #expect(run { v, k in v.key(true, on: q); k.press(escapePress, on: q) } == .escape)
    }

    /// A caller queued behind another dialog whose deadline passes before
    /// its turn timed out (it never saw a dialog); the open dialog still
    /// reports its own way.
    @Test func queuedCallerThatNeverGetsItsTurnTimesOut() {
        let keys = FakeKeys(), views = Box<[FakeView]>([])
        let g = gate(keys, views)
        let d1 = DispatchSemaphore(value: 0), o1 = Box<ConfirmOutcome?>(nil)
        DispatchQueue.global().async { o1.value = try? g.answer(PromptSpec(title: "first", timeoutMillis: 30000)); d1.signal() }
        let end = Date().addingTimeInterval(openWait)
        while !keys.active && Date() < end { Thread.sleep(forTimeInterval: 0.005) }
        guard let v1 = q.sync(execute: { views.value.last }) else {
            Issue.record("the first dialog did not open in \(openWait) s")
            return
        }
        let d2 = DispatchSemaphore(value: 0), o2 = Box<ConfirmOutcome?>(nil)
        DispatchQueue.global().async { o2.value = try? g.answer(PromptSpec(title: "second", timeoutMillis: scaled(200))); d2.signal() }
        d2.wait()
        #expect(o2.value == .timedOut)
        #expect(q.sync { views.value.count } == 1)
        v1.deny(on: q)
        d1.wait()
        #expect(o1.value == .denyButton)
    }

    /// A stuck UI queue: the caller gives up after the bounded wait and the
    /// dialog counts as closed without an answer (never allowed); when the
    /// queue comes back no dialog is shown for it.
    @Test func stuckUIQueueIsClosed() {
        let keys = FakeKeys(), views = Box<[FakeView]>([])
        let g = gate(keys, views)
        let release = DispatchSemaphore(value: 0)
        q.async { release.wait() } // the UI queue is stuck
        let done = DispatchSemaphore(value: 0), out = Box<ConfirmOutcome?>(nil)
        DispatchQueue.global().async { out.value = try? g.answer(PromptSpec(title: "t", timeoutMillis: scaled(300))); done.signal() }
        done.wait()
        #expect(out.value == .closed)
        release.signal()
        q.sync {}
        #expect(views.value.isEmpty && !keys.active)
    }

    /// answer() refuses the main thread like confirm() and shows nothing.
    @Test func answerRefusesTheMainThread() async {
        let keys = FakeKeys(), views = Box<[FakeView]>([])
        let g = gate(keys, views)
        await MainActor.run {
            #expect(throws: PlatformError.failed("confirm called on the main thread")) { try g.answer(PromptSpec(title: "t")) }
        }
        q.sync {}
        #expect(views.value.isEmpty && keys.starts == 0)
    }

    /// The default answer() of a confirmer that throws throws too: an
    /// error is never turned into an outcome (least of all .allowed).
    @Test func aThrowingConfirmerStillThrows() {
        let c = ThrowingConfirmer(.failed("x"))
        #expect(throws: PlatformError.failed("x")) { try c.answer(PromptSpec(title: "t")) }
        #expect(c.calls == 1)
    }
}

extension BridgeTests {
    /// The outcome crosses the table as its raw value.
    @Test func confirmWritesHowTheDialogEnded() {
        for o: ConfirmOutcome in [.allowed, .denied, .denyButton, .escape, .timedOut, .closed] {
            var parts = Env.Parts()
            parts.dialog = OutcomeConfirmer(o)
            let e = Env(parts)
            var allowed: Int32 = -7
            #expect(call(Self.prompt) { e.cb.confirm($0, $1, &allowed) } == NZ_OK)
            #expect(allowed == o.rawValue)
        }
    }
}
