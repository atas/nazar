import AppKit
import CoreGraphics
import Foundation
import Testing
@testable import NazarPlatform

// The `dialog` gate (spec 4.4, 8; spikes S2, S4). Nothing here posts an
// event, turns on Secure Event Input or puts a window on screen: CGEvents and
// NSEvents are built in memory only, DialogGate runs on a private UI queue
// with a fake view (the test reports key changes and clicks through the
// view's actions, as the real panel would), a fake key source and fake
// Secure Event Input, and ConfirmPanel is inspected with a recording
// presenter. Whether WindowServer lets a synthetic click through the
// hardware filter, the real mouse, the front-most window, the arming delay
// on screen and Secure Event Input are checked by hand (spec 10).

/// System uptime, the clock of NSEvent.timestamp and of the gate.
func uptime() -> TimeInterval { ProcessInfo.processInfo.systemUptime }

/// How long a test waits for something that should happen: it stops as soon
/// as it does, so this only costs time when the test is failing.
let openWait: TimeInterval = 30

/// How busy the machine is now: 1 plus twice the load per core, at most 30.
/// A dialog test whose steps must fit inside a short timeout gets that much
/// longer on a loaded machine; otherwise a stall ends the dialog first and
/// the test fails with nothing wrong.
func loadFactor() -> Double {
    var load = [0.0]
    guard getloadavg(&load, 1) == 1 else { return 30 }
    return min(30, 1 + 2 * load[0] / Double(ProcessInfo.processInfo.activeProcessorCount))
}

/// A timeout in milliseconds, scaled by loadFactor.
func scaled(_ millis: Int64) -> Int64 { Int64(Double(millis) * loadFactor()) }

final class FakeView: ConfirmView, @unchecked Sendable {
    let actions: ConfirmActions
    var shown = 0, closed = 0
    var lastIgnored = 0
    /// Every setAllowEnabled call, in order.
    var allowCalls: [Bool] = []
    /// System uptime of each setAllowEnabled(true).
    var enabledAt: [TimeInterval] = []
    init(_ actions: ConfirmActions) { self.actions = actions }
    var allowEnabled: Bool { allowCalls.last ?? false }
    func show() { shown += 1 }
    func update(remaining: TimeInterval, ignoredSynthetic: Int) { lastIgnored = ignoredSynthetic }
    func setAllowEnabled(_ enabled: Bool) {
        allowCalls.append(enabled)
        if enabled { enabledAt.append(uptime()) }
    }
    func close() { closed += 1 }

    // Hooks: deliver on the UI queue, as AppKit would on main.
    func key(_ isKey: Bool, at t: TimeInterval? = nil, on q: DispatchQueue) {
        q.async { self.actions.keyChanged(isKey, t ?? uptime()) }
    }
    func click(_ c: Click, on q: DispatchQueue) { q.async { self.actions.allow(c) } }
    /// A hardware click whose button went down now (when the UI queue runs it).
    func clickNow(on q: DispatchQueue) { q.async { self.actions.allow(Click(hardware: true, downAt: uptime())) } }
    func deny(on q: DispatchQueue) { q.async { self.actions.deny() } }
}

final class FakeKeys: KeySource, @unchecked Sendable {
    private let lock = NSLock()
    private var handler: ((KeyPress) -> Void)?
    var starts = 0, stops = 0
    func start(_ h: @escaping (KeyPress) -> Void) { lock.lock(); handler = h; starts += 1; lock.unlock() }
    func stop() { lock.lock(); handler = nil; stops += 1; lock.unlock() }
    var active: Bool { lock.lock(); defer { lock.unlock() }; return handler != nil }
    /// Delivers a press on the UI queue, as AppKit would.
    func press(_ p: KeyPress, on q: DispatchQueue) {
        q.async { self.lock.lock(); let h = self.handler; self.lock.unlock(); h?(p) }
    }
}

final class FakeSecureInput: SecureInput, @unchecked Sendable {
    var enabled = 0, disabled = 0
    func enable() { enabled += 1 }
    func disable() { disabled += 1 }
}

final class RecordingPresenter: WindowPresenter {
    var presented: [NSWindow] = [], dismissed: [NSWindow] = []
    func present(_ w: NSWindow) { presented.append(w) }
    func dismiss(_ w: NSWindow) { dismissed.append(w) }
}

let escapePress = KeyPress(keyCode: KeyPress.escapeKeyCode)

@Suite struct HardwareInputTests {
    @Test func onlyHIDSourceWithNoPosterCounts() throws {
        #expect(HardwareInput.isHardware(sourcePID: 0, sourceStateID: 1))
        #expect(!HardwareInput.isHardware(sourcePID: 4242, sourceStateID: 1))
        #expect(!HardwareInput.isHardware(sourcePID: 0, sourceStateID: 0))   // private state
        #expect(!HardwareInput.isHardware(sourcePID: 0, sourceStateID: -1))  // combined session
        // A CGEvent built in memory (never posted) carries the fields we read.
        let e = try #require(CGEvent(mouseEventSource: nil, mouseType: .leftMouseDown, mouseCursorPosition: .zero,
                                     mouseButton: .left))
        e.setIntegerValueField(.eventSourceUnixProcessID, value: 0)
        e.setIntegerValueField(.eventSourceStateID, value: 1)
        #expect(HardwareInput.isHardware(e))
        e.setIntegerValueField(.eventSourceUnixProcessID, value: Int64(getpid()))
        #expect(!HardwareInput.isHardware(e))
    }

    @Test func anyPosterPIDOrOtherStateIsSynthetic() {
        for pid: Int64 in [1, -1, Int64(getpid()), Int64(Int32.max), Int64.min] {
            #expect(!HardwareInput.isHardware(sourcePID: pid, sourceStateID: 1), "pid \(pid)")
        }
        for state: Int64 in [2, 0x7fff_ffff, Int64.max, Int64.min] {
            #expect(!HardwareInput.isHardware(sourcePID: 0, sourceStateID: state), "state \(state)")
        }
    }

    /// What an injector gets without forging the PID field: an event from a
    /// hidSystemState source carries sourceStateID 1 (S4) and the poster's
    /// PID, so it is refused. Built in memory, never posted.
    @Test func eventFromAHIDStateSourceInThisProcessIsSynthetic() throws {
        let src = try #require(CGEventSource(stateID: .hidSystemState))
        for type: CGEventType in [.leftMouseDown, .leftMouseUp] {
            let e = try #require(CGEvent(mouseEventSource: src, mouseType: type, mouseCursorPosition: .zero, mouseButton: .left))
            #expect(e.getIntegerValueField(.eventSourceStateID) == 1)
            #expect(!HardwareInput.isHardware(e))
        }
        let key = try #require(CGEvent(keyboardEventSource: src, virtualKey: 40, keyDown: true))
        #expect(!HardwareInput.isHardware(key))
        let plain = try #require(CGEvent(mouseEventSource: nil, mouseType: .leftMouseDown, mouseCursorPosition: .zero,
                                         mouseButton: .left))
        #expect(!HardwareInput.isHardware(plain))
    }

    @Test func onlyKeyCode53IsEscape() {
        #expect(KeyPress.escapeKeyCode == 53)
        #expect(KeyPress(keyCode: 53).isEscape)
        for code: UInt16 in [0, 36, 40, 48, 49, 51, 117, 126] {
            #expect(!KeyPress(keyCode: code).isEscape, "key code \(code)")
        }
    }

    @Test func clickCarriesItsSourceAndDownTime() {
        let c = Click(hardware: true, downAt: 12.5)
        #expect(c.hardware && c.downAt == 12.5)
        #expect(Click(hardware: false, downAt: nil) != Click(hardware: true, downAt: nil))
    }
}

@Suite(.serialized) struct DialogGateTests {
    let q = DispatchQueue(label: "test.ui")

    /// armDelay 0 unless a test is about arming.
    func gate(_ keys: FakeKeys, _ si: FakeSecureInput, _ views: Box<[FakeView]>, armDelay: TimeInterval = 0) -> DialogGate {
        DialogGate(makeView: { _, a in let v = FakeView(a); views.value.append(v); return v },
                   keys: keys, secureInput: si, uiQueue: q, armDelay: armDelay)
    }

    func answer(_ g: DialogGate, _ p: PromptSpec) -> (DispatchSemaphore, Box<Bool?>) {
        let done = DispatchSemaphore(value: 0), out = Box<Bool?>(nil)
        DispatchQueue.global().async { out.value = try? g.confirm(p); done.signal() }
        return (done, out)
    }

    func waitActive(_ k: FakeKeys) {
        let end = Date().addingTimeInterval(openWait)
        while !k.active && Date() < end { Thread.sleep(forTimeInterval: 0.005) }
    }

    /// Waits for the dialog to be open and returns its view.
    func opened(_ keys: FakeKeys, _ views: Box<[FakeView]>) -> FakeView {
        waitActive(keys)
        if let v = q.sync(execute: { views.value.last }) { return v }
        Issue.record("the dialog did not open in \(openWait) s")
        return FakeView(ConfirmActions(deny: {}, allow: { _ in }, keyChanged: { _, _ in }))
    }

    /// Waits for `cond` (read on the UI queue) for at most `seconds`.
    func eventually(_ seconds: TimeInterval = openWait, _ cond: () -> Bool) -> Bool {
        let end = Date().addingTimeInterval(seconds)
        while Date() < end {
            if q.sync(execute: cond) { return true }
            Thread.sleep(forTimeInterval: 0.01)
        }
        return q.sync(execute: cond)
    }

    @Test func hardwareClickAfterArmingAllowsAndEverythingIsTornDown() {
        let keys = FakeKeys(), si = FakeSecureInput(), views = Box<[FakeView]>([])
        let g = gate(keys, si, views)
        let (done, out) = answer(g, PromptSpec(title: "t", timeoutMillis: 30000))
        let v = opened(keys, views)
        v.key(true, on: q)
        v.click(Click(hardware: false, downAt: uptime()), on: q) // synthetic: ignored
        q.sync {}
        #expect(out.value == nil)
        v.clickNow(on: q)
        done.wait()
        #expect(out.value == true)
        q.sync {}
        #expect(si.enabled == 1 && si.disabled == 1 && keys.stops == 1 && !keys.active)
        #expect(views.value.count == 1 && v.shown == 1 && v.closed == 1)
        #expect(v.lastIgnored == 1)
        #expect(v.allowCalls.first == false) // told Allow is off before anything else
    }

    /// Allow stays disabled until the panel has been key for armDelay: not
    /// while the panel is up but not key, and not before keySince + armDelay;
    /// then it is enabled without waiting for a click.
    @Test func allowIsDisabledUntilKeyForTheArmDelay() {
        let keys = FakeKeys(), si = FakeSecureInput(), views = Box<[FakeView]>([])
        let g = gate(keys, si, views, armDelay: 0.4)
        let (done, out) = answer(g, PromptSpec(title: "t", timeoutMillis: 30000))
        let v = opened(keys, views)
        Thread.sleep(forTimeInterval: 0.6) // up, never key: longer than armDelay
        #expect(q.sync { !v.allowEnabled && v.enabledAt.isEmpty })
        let since = uptime()
        v.key(true, at: since, on: q)
        Thread.sleep(forTimeInterval: 0.15)
        #expect(q.sync { !v.allowEnabled })
        #expect(eventually { v.allowEnabled })
        #expect(q.sync { v.enabledAt.allSatisfy { $0 >= since + 0.4 } }, "enabled at \(v.enabledAt), key since \(since)")
        keys.press(escapePress, on: q)
        done.wait()
        #expect(out.value == false)
    }

    /// The default arming delay is 1 second.
    @Test func defaultArmDelayIsOneSecond() {
        let g = DialogGate(makeView: { _, a in FakeView(a) }, keys: FakeKeys(), secureInput: FakeSecureInput())
        #expect(g.armDelay == 1.0)
        let neg = DialogGate(makeView: { _, a in FakeView(a) }, keys: FakeKeys(), secureInput: FakeSecureInput(), armDelay: -1)
        #expect(neg.armDelay == 0)
    }

    /// Losing key disables Allow at once and drops the clock: after the panel
    /// is key again, Allow stays off for a full armDelay, and a click that
    /// went down before that is ignored, even one after the first arming.
    @Test func resignKeyDisablesAllowAndRestartsTheClock() {
        let keys = FakeKeys(), si = FakeSecureInput(), views = Box<[FakeView]>([])
        let g = gate(keys, si, views, armDelay: 0.3)
        let (done, out) = answer(g, PromptSpec(title: "t", timeoutMillis: 30000))
        let v = opened(keys, views)
        let first = uptime()
        v.key(true, at: first, on: q)
        #expect(eventually { v.allowEnabled })
        v.key(false, on: q)
        #expect(q.sync { !v.allowEnabled })
        v.clickNow(on: q) // not key: ignored
        q.sync {}
        #expect(out.value == nil)
        let again = uptime()
        v.key(true, at: again, on: q)
        q.sync {}
        #expect(q.sync { !v.allowEnabled })
        v.clickNow(on: q) // key again, but not yet for armDelay
        v.click(Click(hardware: true, downAt: first + 0.31), on: q) // armed by the first clock only
        q.sync {}
        #expect(out.value == nil && q.sync { v.closed } == 0)
        #expect(eventually { v.allowEnabled })
        #expect(q.sync { v.enabledAt.last! >= again + 0.3 })
        v.clickNow(on: q)
        done.wait()
        #expect(out.value == true)
        #expect(q.sync { v.lastIgnored } == 0) // hardware clicks are never counted as synthetic
    }

    /// A repeated "became key" while already key does not restart the clock.
    @Test func aRepeatedKeyReportKeepsTheClock() {
        let keys = FakeKeys(), si = FakeSecureInput(), views = Box<[FakeView]>([])
        let g = gate(keys, si, views, armDelay: 0.4)
        let (done, out) = answer(g, PromptSpec(title: "t", timeoutMillis: 30000))
        let v = opened(keys, views)
        let since = uptime()
        v.key(true, at: since, on: q)
        v.key(true, at: since + 0.2, on: q)
        #expect(eventually { v.allowEnabled })
        // Went down after the first report's arming, before the second's.
        v.click(Click(hardware: true, downAt: since + 0.41), on: q)
        done.wait()
        #expect(out.value == true)
    }

    /// A hardware click counts only if its button went down after arming:
    /// one stamped before the panel was key (in flight while it appeared),
    /// or after it became key but inside armDelay, is ignored even when the
    /// UI queue handles it late; so is a hardware click with no down time.
    @Test func aClickThatWentDownBeforeArmingIsIgnored() {
        let keys = FakeKeys(), si = FakeSecureInput(), views = Box<[FakeView]>([])
        let g = gate(keys, si, views, armDelay: 0.3)
        let (done, out) = answer(g, PromptSpec(title: "t", timeoutMillis: 30000))
        let v = opened(keys, views)
        let since = uptime()
        v.key(true, at: since, on: q)
        Thread.sleep(forTimeInterval: 0.5) // armed by the time the clicks are handled
        #expect(eventually { v.allowEnabled })
        for down: TimeInterval? in [since - 1, since - 0.001, since, since + 0.1, since + 0.299, nil, 0] {
            v.click(Click(hardware: true, downAt: down), on: q)
        }
        q.sync {}
        #expect(out.value == nil && q.sync { v.closed } == 0)
        #expect(q.sync { v.lastIgnored } == 0)
        v.click(Click(hardware: true, downAt: since + 0.3), on: q) // exactly armed
        done.wait()
        #expect(out.value == true)
    }

    /// While the panel is not key, no click allows, even with armDelay 0;
    /// the dialog runs into its timeout.
    @Test func aClickWhileNotKeyIsIgnored() {
        let keys = FakeKeys(), si = FakeSecureInput(), views = Box<[FakeView]>([])
        let g = gate(keys, si, views)
        let (done, out) = answer(g, PromptSpec(title: "t", timeoutMillis: scaled(700)))
        let v = opened(keys, views)
        v.clickNow(on: q) // never key
        v.key(true, on: q)
        v.key(false, on: q)
        v.clickNow(on: q) // was key, is not now
        done.wait()
        #expect(out.value == false)
        q.sync {}
        #expect(v.lastIgnored == 0 && v.closed == 1 && si.disabled == 1)
    }

    /// A click that did not come from the mouse or trackpad (performClick,
    /// an Accessibility press, an injected event) is ignored and counted,
    /// even with the panel key and armed, and the countdown row reports it.
    @Test func syntheticClicksAreIgnoredAndCounted() {
        let keys = FakeKeys(), si = FakeSecureInput(), views = Box<[FakeView]>([])
        let g = gate(keys, si, views)
        let (done, out) = answer(g, PromptSpec(title: "t", timeoutMillis: scaled(800)))
        let v = opened(keys, views)
        v.key(true, at: uptime() - 10, on: q)
        #expect(eventually { v.allowEnabled })
        v.click(Click(hardware: false, downAt: uptime()), on: q)
        v.click(Click(hardware: false, downAt: nil), on: q)
        v.click(Click(hardware: false, downAt: uptime() + 100), on: q)
        q.sync {}
        #expect(out.value == nil)
        #expect(q.sync { v.lastIgnored } == 3) // reported at once, not at the next tick
        done.wait()
        #expect(out.value == false) // the timeout
        #expect(q.sync { v.lastIgnored } == 3)
    }

    /// Escape denies at once, from any source (the key source does not tell
    /// them apart: denying is always safe), before the panel is key or armed.
    @Test func escapeDeniesAtOnce() {
        let keys = FakeKeys(), si = FakeSecureInput(), views = Box<[FakeView]>([])
        let g = gate(keys, si, views, armDelay: 5)
        for armed in [false, true] {
            let start = Date()
            let (done, out) = answer(g, PromptSpec(title: "t", timeoutMillis: 30000))
            let v = opened(keys, views)
            if armed { v.key(true, at: uptime() - 10, on: q) }
            keys.press(escapePress, on: q)
            done.wait()
            // Half the timeout, whatever the load: a gate that ignored
            // Escape would answer no too, but only when the 30 s ran out.
            #expect(out.value == false && Date().timeIntervalSince(start) < 15, "armed \(armed)")
        }
        q.sync {}
        #expect(si.enabled == 2 && si.disabled == 2 && !keys.active && views.value.allSatisfy { $0.closed == 1 })
    }

    /// Every key but Escape does nothing: it neither allows nor denies, and
    /// the dialog runs into its timeout.
    @Test func otherKeysAreIgnoredAndRunIntoTheTimeout() {
        let keys = FakeKeys(), si = FakeSecureInput(), views = Box<[FakeView]>([])
        let g = gate(keys, si, views)
        let (done, out) = answer(g, PromptSpec(title: "t", timeoutMillis: scaled(700)))
        let v = opened(keys, views)
        v.key(true, on: q)
        for code: UInt16 in [36, 49, 40, 0, 48, 126, 76, 51, 117] { // Return, Space, k, a, Tab, ↑, Enter, ⌫, ⌦
            keys.press(KeyPress(keyCode: code), on: q)
        }
        q.sync {}
        #expect(out.value == nil && keys.active)
        done.wait()
        #expect(out.value == false)
        q.sync {}
        #expect(v.lastIgnored == 0 && si.enabled == 1 && si.disabled == 1 && !keys.active)
    }

    /// Type-through (spec 8): a burst of typing that lands in the dialog,
    /// before or after Allow is armed, never allows: keys cannot press a
    /// button, and the monitor swallows them.
    @Test func aTypingBurstNeverAllows() {
        let keys = FakeKeys(), si = FakeSecureInput(), views = Box<[FakeView]>([])
        let g = gate(keys, si, views, armDelay: 0.2)
        let (done, out) = answer(g, PromptSpec(title: "t", timeoutMillis: scaled(900)))
        let v = opened(keys, views)
        let burst: [UInt16] = [8, 45, 3, 15, 46, 36, 49, 40, 0, 36]
        for c in burst { keys.press(KeyPress(keyCode: c), on: q) }
        v.key(true, on: q)
        for c in burst { keys.press(KeyPress(keyCode: c), on: q) }
        #expect(eventually { v.allowEnabled })
        for c in burst { keys.press(KeyPress(keyCode: c), on: q) }
        done.wait()
        #expect(out.value == false)
        q.sync {}
        #expect(si.enabled == si.disabled && !keys.active)
    }

    /// Deny answers no at once, armed or not; the timeout answers no.
    @Test func denyAndTimeoutAnswerNo() {
        let keys = FakeKeys(), si = FakeSecureInput(), views = Box<[FakeView]>([])
        let g = gate(keys, si, views)
        for armed in [false, true] {
            let (done, out) = answer(g, PromptSpec(title: "t", timeoutMillis: 30000))
            let v = opened(keys, views)
            if armed { v.key(true, on: q); #expect(eventually { v.allowEnabled }) }
            v.deny(on: q)
            done.wait()
            #expect(out.value == false, "armed \(armed)")
        }
        let start = Date()
        let (done, out) = answer(g, PromptSpec(title: "t", timeoutMillis: scaled(300)))
        done.wait()
        #expect(out.value == false && Date().timeIntervalSince(start) < 2 * loadFactor())
        q.sync {}
        #expect(si.enabled == 3 && si.disabled == 3 && views.value.allSatisfy { $0.closed == 1 })
    }

    @Test func oneDialogAtATime() {
        let keys = FakeKeys(), si = FakeSecureInput(), views = Box<[FakeView]>([])
        let g = gate(keys, si, views)
        let (d1, o1) = answer(g, PromptSpec(title: "first", timeoutMillis: 30000))
        let v1 = opened(keys, views)
        let (d2, o2) = answer(g, PromptSpec(title: "second", timeoutMillis: scaled(200))) // times out while queued
        d2.wait()
        #expect(o2.value == false && q.sync { views.value.count } == 1)
        #expect(q.sync { si.enabled } == 1) // the queued caller never turned Secure Event Input on
        v1.key(true, on: q)
        v1.clickNow(on: q)
        d1.wait()
        #expect(o1.value == true)
        // The gate is free again: the next caller gets its own dialog.
        let (d3, o3) = answer(g, PromptSpec(title: "third", timeoutMillis: 30000))
        let v3 = opened(keys, views)
        #expect(v3 !== v1)
        v3.key(true, on: q)
        v3.clickNow(on: q)
        d3.wait()
        #expect(o3.value == true && q.sync { views.value.count } == 2)
        q.sync {}
        #expect(si.enabled == 2 && si.disabled == 2)
    }

    @Test func refusesTheMainThread() async {
        let keys = FakeKeys(), si = FakeSecureInput(), views = Box<[FakeView]>([])
        let g = gate(keys, si, views)
        await MainActor.run {
            #expect(throws: PlatformError.failed("confirm called on the main thread")) { try g.confirm(PromptSpec(title: "t")) }
        }
        q.sync {}
        #expect(views.value.isEmpty && si.enabled == 0 && keys.starts == 0)
    }

    /// Arming is per dialog: the previous dialog's key state does not carry
    /// over, and its late actions do not answer the next one.
    @Test func eachDialogArmsOnItsOwn() {
        let keys = FakeKeys(), si = FakeSecureInput(), views = Box<[FakeView]>([])
        let g = gate(keys, si, views)
        var (done, out) = answer(g, PromptSpec(title: "t", timeoutMillis: 30000))
        let v1 = opened(keys, views)
        v1.key(true, on: q)
        v1.clickNow(on: q)
        done.wait()
        #expect(out.value == true)
        (done, out) = answer(g, PromptSpec(title: "t", timeoutMillis: scaled(600)))
        let v2 = opened(keys, views)
        v1.key(true, on: q)  // the old panel's actions
        v1.clickNow(on: q)
        v2.clickNow(on: q)   // the new panel was never key
        done.wait()
        #expect(out.value == false)
        #expect(q.sync { !v2.allowEnabled })
    }

    /// The prompt reaches the view unchanged.
    @Test func viewGetsThePrompt() {
        let keys = FakeKeys(), si = FakeSecureInput(), got = Box<[PromptSpec]>([]), views = Box<[FakeView]>([])
        let g = DialogGate(makeView: { p, a in got.value.append(p); let v = FakeView(a); views.value.append(v); return v },
                           keys: keys, secureInput: si, uiQueue: q, armDelay: 0)
        let p = PromptSpec(title: "iTerm2 wants to use key \"github\"", lines: ["login to github.com"], unknown: true,
                           reason: "r", timeoutMillis: 30000)
        let (done, _) = answer(g, p)
        opened(keys, views).deny(on: q)
        done.wait()
        #expect(q.sync { got.value } == [p])
    }

    /// Secure Event Input is on, the key source listening and Allow off
    /// before the dialog is shown, and every piece of UI work runs on the UI
    /// queue, never on the caller's thread.
    @Test func secureInputIsOnWhileShownAndAllUIWorkIsOnTheUIQueue() {
        let tag = DispatchSpecificKey<Bool>()
        q.setSpecific(key: tag, value: true)
        defer { q.setSpecific(key: tag, value: nil) }
        let probe = QueueProbe(tag: tag)
        let g = DialogGate(makeView: { _, a in probe.note("makeView"); probe.actions = a; return probe },
                           keys: probe, secureInput: probe, uiQueue: q, armDelay: 0)
        let (done, out) = answer(g, PromptSpec(title: "t", timeoutMillis: 30000))
        let end = Date().addingTimeInterval(openWait)
        while !probe.listening && Date() < end { Thread.sleep(forTimeInterval: 0.005) }
        q.async { probe.actions?.keyChanged(true, uptime()) }
        q.async { probe.actions?.allow(Click(hardware: true, downAt: uptime())) }
        done.wait()
        #expect(out.value == true)
        q.sync {}
        #expect(probe.offQueue.isEmpty, "UI work off the UI queue: \(probe.offQueue)")
        #expect(probe.secureOnAtShow == [true] && probe.listeningAtShow == [true] && probe.allowAtShow == [false])
        #expect(probe.secureOn == false && probe.listening == false && probe.closed == 1)
    }

    /// Many callers at once: never more than one dialog on screen, each
    /// gets its own answer, and Secure Event Input is balanced.
    @Test func concurrentCallersSeeOneDialogAtATime() {
        let keys = FakeKeys(), si = FakeSecureInput()
        let open = Box(0), maxOpen = Box(0), made = Box(0), latest = Box<ConfirmActions?>(nil)
        let g = DialogGate(makeView: { _, a in
            made.value += 1
            latest.value = a
            return CountingView(onShow: { open.value += 1; maxOpen.value = max(maxOpen.value, open.value) },
                                onClose: { open.value -= 1 })
        }, keys: keys, secureInput: si, uiQueue: q, armDelay: 0)
        let n = 4
        let calls = (0..<n).map { i in answer(g, PromptSpec(title: "c\(i)", timeoutMillis: 30000)) }
        for _ in 0..<n {
            waitActive(keys)
            q.async {
                latest.value?.keyChanged(true, uptime())
                latest.value?.allow(Click(hardware: true, downAt: uptime()))
            }
            q.sync {}
            let end = Date().addingTimeInterval(openWait)
            while keys.active && Date() < end { Thread.sleep(forTimeInterval: 0.005) }
        }
        for (done, out) in calls {
            done.wait()
            #expect(out.value == true)
        }
        q.sync {}
        #expect(made.value == n && maxOpen.value == 1 && open.value == 0)
        #expect(si.enabled == n && si.disabled == n && keys.starts == n && keys.stops == n)
    }

    /// A caller's deadline counts from its call, not from when its dialog
    /// opens: waiting in the queue uses up its time.
    @Test func queuedCallersDeadlineCountsFromTheCall() {
        let keys = FakeKeys(), si = FakeSecureInput(), views = Box<[FakeView]>([])
        let g = gate(keys, si, views)
        let second = scaled(1200)
        let (d1, o1) = answer(g, PromptSpec(title: "first", timeoutMillis: max(30000, 3 * second)))
        let v1 = opened(keys, views)
        let start = Date()
        let (d2, o2) = answer(g, PromptSpec(title: "second", timeoutMillis: second))
        // In the queue for 5/6 of its timeout, scaled with it: counted from
        // the call it ends at 1x the timeout, counted from the dialog opening
        // at about 1.8x, whatever the load. Where the caller's own 5 s margin
        // cuts that short, its dialog is still open when it returns, which
        // the last check catches.
        Thread.sleep(forTimeInterval: Double(second) / 1200)
        v1.key(true, on: q)
        v1.clickNow(on: q)
        d1.wait()
        #expect(o1.value == true)
        d2.wait()
        let took = Date().timeIntervalSince(start)
        #expect(o2.value == false)
        #expect(took < 1.5 * Double(second) / 1000, "second caller took \(took) s; its 1.2 s ran from its call")
        q.sync {}
        #expect(si.enabled == si.disabled)
    }

    /// Once answered, nothing changes the answer: a Deny click, Allow
    /// clicks, key changes and key presses that arrive late (a monitor still
    /// delivering after stop) are no-ops, and teardown happens once.
    @Test func answerIsFinalAndTeardownHappensOnce() {
        let keys = LateKeys(), si = FakeSecureInput(), views = Box<[FakeView]>([])
        let g = DialogGate(makeView: { _, a in let v = FakeView(a); views.value.append(v); return v },
                           keys: keys, secureInput: si, uiQueue: q, armDelay: 0)
        let (done, out) = answer(g, PromptSpec(title: "t", timeoutMillis: 30000))
        let end = Date().addingTimeInterval(openWait)
        while q.sync(execute: { keys.last == nil }) && Date() < end { Thread.sleep(forTimeInterval: 0.005) }
        let v = q.sync { views.value[0] }
        v.key(true, on: q)
        v.clickNow(on: q)
        q.async { keys.last?(escapePress) }
        v.deny(on: q)
        v.key(false, on: q)
        v.key(true, on: q)
        v.clickNow(on: q)
        v.click(Click(hardware: false, downAt: nil), on: q)
        done.wait()
        #expect(out.value == true)
        Thread.sleep(forTimeInterval: 0.4) // a few timer ticks
        q.sync {}
        #expect(si.enabled == 1 && si.disabled == 1 && keys.stops == 1)
        #expect(views.value.count == 1 && v.shown == 1 && v.closed == 1)
        #expect(v.lastIgnored == 0)
        let calls = v.allowCalls.count
        Thread.sleep(forTimeInterval: 0.3)
        #expect(q.sync { v.allowCalls.count } == calls) // nothing touches a closed view
    }

    /// A stuck UI queue answers "no" (bounded wait), and when the queue
    /// comes back the late dialog cleans up: Secure Event Input is never
    /// left on.
    @Test func stuckUIQueueAnswersNoAndNeverLeavesSecureInputOn() {
        let keys = FakeKeys(), si = FakeSecureInput(), views = Box<[FakeView]>([])
        let g = gate(keys, si, views)
        let release = DispatchSemaphore(value: 0)
        q.async { release.wait() } // the UI queue is stuck
        let start = Date()
        let (done, out) = answer(g, PromptSpec(title: "t", timeoutMillis: scaled(300)))
        done.wait()
        let took = Date().timeIntervalSince(start)
        #expect(out.value == false)
        #expect(took < 8 * loadFactor(), "confirm took \(took) s with a stuck UI queue")
        release.signal()
        #expect(eventually { si.enabled == si.disabled && !keys.active && views.value.allSatisfy { $0.closed == $0.shown } })
    }

    /// The countdown the view shows is positive and never more than the
    /// prompt's timeout.
    @Test func remainingTimeShownIsWithinTheTimeout() {
        let keys = FakeKeys(), si = FakeSecureInput()
        let remaining = Box<[TimeInterval]>([])
        let g = DialogGate(makeView: { _, _ in RemainingView(remaining) },
                           keys: keys, secureInput: si, uiQueue: q, armDelay: 0)
        let timeout = scaled(800)
        let (done, out) = answer(g, PromptSpec(title: "t", timeoutMillis: timeout))
        done.wait()
        #expect(out.value == false)
        q.sync {}
        #expect(!remaining.value.isEmpty)
        #expect(remaining.value.allSatisfy { $0 > 0 && $0 <= Double(timeout) / 1000 }, "remaining \(remaining.value)")
    }
}

/// A view, key source and Secure Event Input in one, recording whether each
/// call ran on the UI queue and what was on when the dialog was shown.
final class QueueProbe: ConfirmView, KeySource, SecureInput, @unchecked Sendable {
    let tag: DispatchSpecificKey<Bool>
    private let lock = NSLock()
    private var handler: ((KeyPress) -> Void)?
    var actions: ConfirmActions?
    var offQueue: [String] = []
    var secureOn = false, allowOn = false
    var secureOnAtShow: [Bool] = [], listeningAtShow: [Bool] = [], allowAtShow: [Bool] = []
    var closed = 0
    init(tag: DispatchSpecificKey<Bool>) { self.tag = tag }

    func note(_ what: String) {
        if DispatchQueue.getSpecific(key: tag) != true { lock.lock(); offQueue.append(what); lock.unlock() }
    }
    var listening: Bool { lock.lock(); defer { lock.unlock() }; return handler != nil }

    func show() { note("show"); secureOnAtShow.append(secureOn); listeningAtShow.append(listening); allowAtShow.append(allowOn) }
    func update(remaining: TimeInterval, ignoredSynthetic: Int) { note("update") }
    func setAllowEnabled(_ enabled: Bool) { note("setAllowEnabled"); allowOn = enabled }
    func close() { note("close"); closed += 1 }
    func start(_ h: @escaping (KeyPress) -> Void) { note("keys.start"); lock.lock(); handler = h; lock.unlock() }
    func stop() { note("keys.stop"); lock.lock(); handler = nil; lock.unlock() }
    func enable() { note("secure.enable"); secureOn = true }
    func disable() { note("secure.disable"); secureOn = false }
}

/// A key source that keeps its last handler after stop(), so a test can
/// deliver presses late.
final class LateKeys: KeySource, @unchecked Sendable {
    var last: ((KeyPress) -> Void)?
    var stops = 0
    func start(_ h: @escaping (KeyPress) -> Void) { last = h }
    func stop() { stops += 1 }
}

final class CountingView: ConfirmView, @unchecked Sendable {
    let onShow: () -> Void, onClose: () -> Void
    init(onShow: @escaping () -> Void, onClose: @escaping () -> Void) { self.onShow = onShow; self.onClose = onClose }
    func show() { onShow() }
    func update(remaining: TimeInterval, ignoredSynthetic: Int) {}
    func setAllowEnabled(_ enabled: Bool) {}
    func close() { onClose() }
}

final class RemainingView: ConfirmView, @unchecked Sendable {
    let out: Box<[TimeInterval]>
    init(_ out: Box<[TimeInterval]>) { self.out = out }
    func show() {}
    func update(remaining: TimeInterval, ignoredSynthetic: Int) { out.value.append(remaining) }
    func setAllowEnabled(_ enabled: Bool) {}
    func close() {}
}

/// Records what a ConfirmPanel reports to its gate.
final class PanelRecorder {
    var denied = 0
    var clicks: [Click] = []
    var keyReports: [Bool] = []
    var actions: ConfirmActions {
        ConfirmActions(deny: { self.denied += 1 }, allow: { self.clicks.append($0) },
                       keyChanged: { isKey, _ in self.keyReports.append(isKey) })
    }
}

@Suite @MainActor struct ConfirmPanelTests {
    func panel(_ prompt: PromptSpec = PromptSpec(title: "t"), _ rec: PanelRecorder = PanelRecorder(),
               presenter: RecordingPresenter = RecordingPresenter()) -> ConfirmPanel {
        _ = NSApplication.shared
        return ConfirmPanel(prompt: prompt, presenter: presenter, actions: rec.actions)
    }

    @Test func showsWhoAndWhatThenDenyAndAllow() {
        let pres = RecordingPresenter(), rec = PanelRecorder()
        let p = panel(PromptSpec(title: "iTerm2 wants to use key \"github\"",
                                 lines: ["login to github.com", "chain: iTerm2 → bash → git → ssh"], unknown: true),
                      rec, presenter: pres)
        let text = ViewText.labels(p.panel.contentView!)
        #expect(text.contains { $0.hasPrefix("⚠️ Unknown app") })
        #expect(text.contains("iTerm2 wants to use key \"github\""))
        #expect(text.contains("login to github.com") && text.contains("chain: iTerm2 → bash → git → ssh"))
        #expect(ViewText.buttons(p.panel.contentView!) == ["Deny", "Allow"])
        #expect(p.panel.title == "nazar 🧿")
        p.show()
        #expect(pres.presented.count == 1 && pres.presented[0] === p.panel)
        p.update(remaining: 12.2, ignoredSynthetic: 2)
        #expect(ViewText.labels(p.panel.contentView!).contains { $0.hasPrefix("Denied automatically in 13 s · ignored 2") })
        p.denyPressed()
        #expect(rec.denied == 1 && rec.clicks.isEmpty)
        p.close()
        #expect(pres.dismissed.count == 1)
        let known = panel()
        #expect(!ViewText.labels(known.panel.contentView!).contains { $0.contains("Unknown app") })
    }

    /// No letter challenge and no "Press" instruction anywhere: not in the
    /// labels, the buttons, the title, nor what an Accessibility client reads
    /// (which does see the title, the lines and both buttons).
    @Test func noPressTextAnywhere() {
        let p = panel(PromptSpec(title: "t", lines: ["login to example.com"], unknown: true))
        p.update(remaining: 10, ignoredSynthetic: 1)
        let seen = AXWalk.strings(p.panel.contentView!) + AXWalk.strings(p.panel)
        #expect(seen.contains("t") && seen.contains("login to example.com") && seen.contains("Deny") && seen.contains("Allow"),
                "walk saw \(seen)")
        let all = seen + ViewText.labels(p.panel.contentView!) + ViewText.buttons(p.panel.contentView!) + [p.panel.title]
        for s in all {
            #expect(!s.lowercased().contains("press"), "text \(s.debugDescription)")
            #expect(!s.contains("any other key"), "text \(s.debugDescription)")
        }
    }

    /// The buttons sit in one row, Deny then Allow, with Allow on the right.
    @Test func allowIsRightOfDeny() throws {
        let p = panel()
        let content = try #require(p.panel.contentView)
        content.layoutSubtreeIfNeeded()
        let deny = p.deny.convert(p.deny.bounds, to: content), allow = p.allow.convert(p.allow.bounds, to: content)
        #expect(!deny.isEmpty && !allow.isEmpty)
        #expect(allow.minX >= deny.maxX, "deny \(deny), allow \(allow)")
        #expect(abs(allow.midY - deny.midY) < 1, "deny \(deny), allow \(allow)")
    }

    /// Allow starts disabled and follows setAllowEnabled; close disables it.
    @Test func allowStartsDisabledAndFollowsTheGate() {
        let p = panel()
        #expect(!p.allow.isEnabled && p.deny.isEnabled)
        p.setAllowEnabled(true)
        #expect(p.allow.isEnabled)
        p.setAllowEnabled(false)
        #expect(!p.allow.isEnabled)
        p.setAllowEnabled(true)
        p.close()
        #expect(!p.allow.isEnabled)
    }

    /// Allow cannot be pressed except by the mouse: an Accessibility press
    /// is refused, it never takes keyboard focus, it does not take the click
    /// that activates the panel, and neither button has a key equivalent (so
    /// Return, Space and Escape press nothing).
    @Test func allowRefusesAccessibilityFocusAndKeys() throws {
        let rec = PanelRecorder()
        let p = panel(PromptSpec(title: "t"), rec)
        let buttons = allButtons(p.panel.contentView!)
        #expect(buttons.map(\.title) == ["Deny", "Allow"])
        for b in buttons {
            #expect(b.keyEquivalent == "", "button \(b.title) key \(b.keyEquivalent.debugDescription)")
        }
        #expect(p.allow is HardwareButton)
        #expect(p.allow.refusesFirstResponder && !p.allow.acceptsFirstResponder)
        #expect(!p.allow.acceptsFirstMouse(for: nil))
        p.setAllowEnabled(true)
        #expect(p.allow.accessibilityPerformPress() == false)
        // Whatever the cell does with a press, no hardware click comes of it.
        _ = p.allow.cell?.accessibilityPerformPress()
        #expect(rec.clicks.allSatisfy { !$0.hardware }, "clicks \(rec.clicks)")
    }

    /// performClick, or the action sent any other way than through a
    /// mouse-down on the button, yields a non-hardware click with no down
    /// time, which the gate ignores and counts.
    @Test func performClickOnAllowIsNotAHardwareClick() throws {
        let rec = PanelRecorder()
        let p = panel(PromptSpec(title: "t"), rec)
        p.setAllowEnabled(true)
        p.allow.performClick(nil)
        let action = try #require(p.allow.action)
        #expect(NSApp.sendAction(action, to: p.allow.target, from: p.allow))
        p.allowPressed()
        #expect(rec.clicks.count >= 2, "clicks \(rec.clicks)")
        #expect(rec.clicks.allSatisfy { $0 == Click(hardware: false, downAt: nil) }, "clicks \(rec.clicks)")
        #expect(rec.denied == 0)
    }

    /// The Deny button is wired to the gate's deny.
    @Test func denyButtonIsWired() throws {
        let rec = PanelRecorder()
        let p = panel(PromptSpec(title: "t"), rec)
        let action = try #require(p.deny.action)
        #expect(NSApp.sendAction(action, to: p.deny.target, from: p.deny))
        #expect(rec.denied == 1 && rec.clicks.isEmpty)
    }

    /// Losing key is reported to the gate, until the panel is closed. (Only
    /// the panel's own resign notification is posted here; becoming key
    /// needs a real window on screen, checked by hand.)
    @Test func keyChangesAreReportedUntilClose() {
        let rec = PanelRecorder()
        let p = panel(PromptSpec(title: "t"), rec)
        NotificationCenter.default.post(name: NSWindow.didResignKeyNotification, object: p.panel)
        #expect(rec.keyReports == [false])
        p.show() // a recording presenter: never key
        #expect(rec.keyReports == [false, false])
        p.close()
        NotificationCenter.default.post(name: NSWindow.didResignKeyNotification, object: p.panel)
        #expect(rec.keyReports == [false, false])
    }

    /// The Unknown app header comes first (prominent, spec 4.4).
    @Test func unknownHeaderComesFirst() {
        let p = panel(PromptSpec(title: "? wants to use key \"github\"", lines: ["chain: ? → ssh"], unknown: true))
        let text = ViewText.labels(p.panel.contentView!)
        #expect(text.first?.hasPrefix("⚠️ Unknown app") == true)
        #expect(text.filter { $0.contains("Unknown app") }.count == 1)
    }

    /// The panel is built to be the front-most window (S2):
    /// above normal windows, on every Space and over full-screen apps, and
    /// it does not hide when the app loses focus.
    @Test func panelIsFrontMostOnEverySpace() {
        let p = panel()
        #expect(p.panel.level.rawValue >= NSWindow.Level.modalPanel.rawValue)
        #expect(p.panel.collectionBehavior.contains(.canJoinAllSpaces))
        #expect(p.panel.collectionBehavior.contains(.fullScreenAuxiliary))
        #expect(!p.panel.hidesOnDeactivate)
        #expect(!p.panel.isVisible) // building it never puts it on screen
    }

    @Test func statusLineWithoutIgnoredClicks() {
        let p = panel()
        p.update(remaining: 4.01, ignoredSynthetic: 0)
        let text = ViewText.labels(p.panel.contentView!)
        #expect(text.contains("Denied automatically in 5 s"))
        #expect(!text.contains { $0.contains("ignored") })
        p.update(remaining: 0.1, ignoredSynthetic: 1)
        #expect(ViewText.labels(p.panel.contentView!).contains(
            "Denied automatically in 1 s · ignored 1 click(s) that did not come from the mouse or trackpad"))
    }

    @Test func showAndCloseGoThroughThePresenter() {
        let pres = RecordingPresenter()
        let p = panel(presenter: pres)
        #expect(pres.presented.isEmpty && pres.dismissed.isEmpty)
        p.show()
        p.close()
        #expect(pres.presented.count == 1 && pres.dismissed.count == 1 && pres.dismissed[0] === p.panel)
    }

    /// An NSEvent made in this process (never posted, so synthetic) becomes
    /// a KeyPress by key code: Escape is Escape with any modifiers; other
    /// keys are not.
    @Test func localMonitorTranslatesEvents() throws {
        _ = NSApplication.shared
        func ev(_ flags: NSEvent.ModifierFlags, _ chars: String, code: UInt16, repeat r: Bool = false) throws -> NSEvent {
            try #require(NSEvent.keyEvent(with: .keyDown, location: .zero, modifierFlags: flags, timestamp: 0, windowNumber: 0,
                                          context: nil, characters: chars, charactersIgnoringModifiers: chars,
                                          isARepeat: r, keyCode: code))
        }
        for f: NSEvent.ModifierFlags in [[], .shift, .command, .control, .option] {
            #expect(LocalKeyMonitor.keyPress(try ev(f, "\u{1b}", code: 53)).isEscape, "flags \(f.rawValue)")
        }
        #expect(LocalKeyMonitor.keyPress(try ev([], "\u{1b}", code: 53, repeat: true)).isEscape)
        #expect(LocalKeyMonitor.keyPress(try ev([], "k", code: 40)) == KeyPress(keyCode: 40))
        #expect(!LocalKeyMonitor.keyPress(try ev([], "\r", code: 36)).isEscape)
        #expect(!LocalKeyMonitor.keyPress(try ev([], " ", code: 49)).isEscape)
    }

    @Test func localMonitorStartStopIsIdempotent() {
        _ = NSApplication.shared
        let m = LocalKeyMonitor()
        m.stop()
        m.start { _ in }
        m.start { _ in }
        m.stop()
        m.stop()
    }

    @Test func realSeamsExistWithoutBeingUsed() {
        // Built, never called: CarbonSecureInput would turn on Secure Event
        // Input and AppKitPresenter would activate the app.
        let si: SecureInput = CarbonSecureInput()
        let pres: WindowPresenter = AppKitPresenter()
        let keys: KeySource = LocalKeyMonitor()
        _ = (si, pres, keys)
    }

    private func allButtons(_ v: NSView) -> [NSButton] {
        var out: [NSButton] = []
        if let b = v as? NSButton { out.append(b) }
        for s in v.subviews { out += allButtons(s) }
        return out
    }
}

@Suite struct ScriptedConfirmerTests {
    @Test func answersInOrderThenTheDefaultAndRecordsPrompts() throws {
        let c = ScriptedConfirmer()
        c.push(true)
        c.push(false)
        c.push(true)
        #expect(try c.confirm(PromptSpec(title: "a")) == true)
        #expect(try c.confirm(PromptSpec(title: "b")) == false)
        #expect(try c.confirm(PromptSpec(title: "c")) == true)
        #expect(try c.confirm(PromptSpec(title: "d")) == false) // default: deny
        #expect(c.prompts.map(\.title) == ["a", "b", "c", "d"])
        let yes = ScriptedConfirmer(defaultAnswer: true)
        #expect(try yes.confirm(PromptSpec(title: "x")) == true)
        yes.defaultAnswer = false
        #expect(try yes.confirm(PromptSpec(title: "y")) == false)
    }

    @Test func safeUnderConcurrentCallers() {
        let c = ScriptedConfirmer()
        for i in 0..<100 { c.push(i % 2 == 0) }
        let yes = Box(0)
        let lock = NSLock()
        DispatchQueue.concurrentPerform(iterations: 200) { i in
            let a = (try? c.confirm(PromptSpec(title: "p\(i)"))) ?? false
            if a { lock.lock(); yes.value += 1; lock.unlock() }
        }
        #expect(yes.value == 50)
        #expect(c.prompts.count == 200)
    }
}

/// What an Accessibility client can read under an element: every unignored
/// descendant's value, title, label, help, value description and
/// placeholder, as strings.
enum AXWalk {
    @MainActor static func strings(_ root: NSAccessibilityProtocol) -> [String] {
        var out: [String] = []
        func visit(_ e: NSAccessibilityProtocol, _ depth: Int) {
            guard depth < 32 else { return }
            for v in [e.accessibilityValue(), e.accessibilityTitle(), e.accessibilityLabel(), e.accessibilityHelp(),
                      e.accessibilityValueDescription(), e.accessibilityPlaceholderValue()] as [Any?] {
                if let s = v as? String { out.append(s) } else if let s = v as? NSAttributedString { out.append(s.string) }
            }
            for c in NSAccessibility.unignoredChildren(from: e.accessibilityChildren() ?? []) {
                if let c = c as? NSAccessibilityProtocol { visit(c, depth + 1) }
            }
        }
        for c in NSAccessibility.unignoredChildren(from: root.accessibilityChildren() ?? []) {
            if let c = c as? NSAccessibilityProtocol { visit(c, 1) }
        }
        return out
    }
}

final class Box<T>: @unchecked Sendable {
    var value: T
    init(_ v: T) { value = v }
}
