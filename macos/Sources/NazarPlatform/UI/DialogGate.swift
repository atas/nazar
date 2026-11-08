import AppKit
import Foundation

/// The confirm dialog on screen.
public protocol ConfirmView: AnyObject {
    /// Activates the app and orders the dialog front (S2).
    func show()
    func update(remaining: TimeInterval, ignoredSynthetic: Int)
    /// Enables or disables the Allow button. It starts disabled.
    func setAllowEnabled(_ enabled: Bool)
    func close()
}

/// What the dialog on screen reports to its gate. Every closure is called
/// on the gate's uiQueue.
public struct ConfirmActions {
    /// The Deny button was clicked (from any source: denying is safe).
    public let deny: () -> Void
    /// The Allow button sent its action, with how it was clicked.
    public let allow: (Click) -> Void
    /// The panel became (true) or stopped being (false) the key window of
    /// the active app, at this system uptime.
    public let keyChanged: (_ isKey: Bool, _ at: TimeInterval) -> Void

    public init(deny: @escaping () -> Void, allow: @escaping (Click) -> Void,
                keyChanged: @escaping (_ isKey: Bool, _ at: TimeInterval) -> Void) {
        self.deny = deny
        self.allow = allow
        self.keyChanged = keyChanged
    }
}

/// Delivers key presses while a dialog is up.
public protocol KeySource: AnyObject {
    func start(_ handler: @escaping (KeyPress) -> Void)
    func stop()
}

/// How a `dialog` gate ended (since Milestone 5). The raw values are the
/// `allowed` output of the confirm callback (nazar_bridge.h): 1 is the only
/// one that allows.
public enum ConfirmOutcome: Int32, Sendable {
    case denied = 0      // no reason given
    case allowed = 1
    case denyButton = 2
    case escape = 3
    case timedOut = 4    // the dialog's own countdown ran out (or waiting for its turn did)
    case closed = 5      // closed without an answer: another dialog took its place, or the UI was stuck
}

/// Platform.Confirm (`gate: dialog`).
public protocol Confirmer: AnyObject {
    func confirm(_ prompt: PromptSpec) throws -> Bool
    /// The answer with how the dialog ended; `.allowed` exactly when
    /// confirm would answer true.
    func answer(_ prompt: PromptSpec) throws -> ConfirmOutcome
}

public extension Confirmer {
    /// A confirmer that can't tell how it was denied.
    func answer(_ prompt: PromptSpec) throws -> ConfirmOutcome { try confirm(prompt) ? .allowed : .denied }
}

/// The real dialog gate. One dialog at a time, with two buttons, Deny and
/// Allow. The answer is true only for a hardware click on Allow whose
/// mouse-down came after the panel had been the key window of the active
/// app for `armDelay` without a break; Deny, Esc and the timeout answer
/// false. Secure Event Input is on exactly while the dialog is up. All UI
/// work runs on uiQueue (main in Nazar.app); confirm blocks only its calling
/// thread and must never be called on the main thread. A caller's deadline
/// counts from its call, so time spent waiting for another dialog is used
/// up.
///
/// Click-through and type-through: showing the panel activates the app, so
/// a click or keystrokes the user meant for another window can land in it,
/// and a local process can open a dialog at the moment it sees the user
/// about to click. Three things keep that from allowing. Allow stays
/// disabled until the panel has been key for `armDelay` (1 s), and is
/// disabled again, with the clock restarted, whenever the panel stops being
/// key, so a click in flight never meets an enabled button. The gate checks
/// the same rule itself from the click's mouse-down time, whatever state the
/// button is in (defense in depth). And the key monitor swallows every key,
/// so no keystroke can press a button; Esc denies, every other key does
/// nothing.
public final class DialogGate: Confirmer, @unchecked Sendable {
    public typealias MakeView = (PromptSpec, ConfirmActions) -> ConfirmView

    let makeView: MakeView
    let keys: KeySource
    let secureInput: SecureInput
    let uiQueue: DispatchQueue
    /// How long the panel must have been key, without a break, before Allow
    /// is enabled and a click on it counts.
    let armDelay: TimeInterval
    /// One caller holds the turn from before its dialog opens until after
    /// it is closed.
    private let turn = DispatchSemaphore(value: 1)
    /// The dialog on screen, if any. Touched only on uiQueue.
    private var current: Session?

    public init(makeView: @escaping MakeView, keys: KeySource, secureInput: SecureInput, uiQueue: DispatchQueue = .main,
                armDelay: TimeInterval = 1.0) {
        self.makeView = makeView
        self.keys = keys
        self.secureInput = secureInput
        self.uiQueue = uiQueue
        self.armDelay = max(0, armDelay)
    }

    public func confirm(_ prompt: PromptSpec) throws -> Bool { try answer(prompt) == .allowed }

    public func answer(_ prompt: PromptSpec) throws -> ConfirmOutcome {
        guard !Thread.isMainThread else { throw PlatformError.failed("confirm called on the main thread") }
        let deadline = Date().addingTimeInterval(prompt.timeout)
        // Waiting for another dialog used up the whole deadline.
        guard turn.wait(timeout: .now() + prompt.timeout) == .success else { return .timedOut }
        defer { turn.signal() }
        let remaining = deadline.timeIntervalSinceNow
        guard remaining > 0 else { return .timedOut }

        let done = DispatchSemaphore(value: 0)
        let answer = Answer()
        uiQueue.async { [self] in
            // A UI queue that was stuck: the caller has given up, so no
            // dialog, and Secure Event Input is never turned on for it.
            guard deadline.timeIntervalSinceNow > 0 else {
                answer.value = .timedOut
                done.signal()
                return
            }
            // Never two dialogs, even if a stuck queue let the previous
            // caller's turn lapse before its dialog finished.
            current?.finish(.closed)
            let session = Session(gate: self, prompt: prompt, deadline: deadline) { outcome in
                answer.value = outcome
                done.signal()
            }
            current = session
            session.open()
        }
        // The UI side always finishes by the deadline; the extra margin only
        // guards against a stuck UI queue, which then counts as "no".
        if done.wait(timeout: .now() + remaining + 5) == .timedOut { return .closed }
        return answer.value
    }

    /// The caller's answer; written on uiQueue before `done` is signalled
    /// and read by the caller after it waited, so the semaphore orders it.
    private final class Answer: @unchecked Sendable {
        var value = ConfirmOutcome.denied
    }

    /// One dialog: its view, arming state, countdown timer and teardown.
    /// Every method runs on the gate's uiQueue. finish() runs once; late
    /// clicks, key presses, key changes and timer ticks are no-ops.
    private final class Session {
        let gate: DialogGate
        let prompt: PromptSpec
        let deadline: Date
        let onFinish: (ConfirmOutcome) -> Void
        var view: ConfirmView?
        var timer: DispatchSourceTimer?
        var finished = false
        /// System uptime since which the panel has been key without a
        /// break, or nil while it is not key. Allow is armed from
        /// keySince + armDelay.
        var keySince: TimeInterval?
        /// The one-shot that enables Allow when the arming time is reached.
        var armWork: DispatchWorkItem?
        /// What the view was last told about Allow.
        var allowEnabled = false
        /// Clicks on Allow that did not come from the mouse or trackpad.
        var ignoredSynthetic = 0

        init(gate: DialogGate, prompt: PromptSpec, deadline: Date, onFinish: @escaping (ConfirmOutcome) -> Void) {
            self.gate = gate
            self.prompt = prompt
            self.deadline = deadline
            self.onFinish = onFinish
        }

        /// Secure Event Input on, the key source listening and Allow
        /// disabled before the dialog is shown.
        func open() {
            gate.secureInput.enable()
            let actions = ConfirmActions(
                deny: { [weak self] in self?.finish(.denyButton) },
                allow: { [weak self] click in self?.clicked(click) },
                keyChanged: { [weak self] isKey, at in self?.keyChanged(isKey, at: at) })
            view = gate.makeView(prompt, actions)
            view?.setAllowEnabled(false)
            gate.keys.start { [weak self] press in self?.handle(press) }
            view?.show()
            let t = DispatchSource.makeTimerSource(queue: gate.uiQueue)
            t.schedule(deadline: .now(), repeating: .milliseconds(250))
            t.setEventHandler { [weak self] in self?.tick() }
            timer = t
            t.resume()
        }

        /// The panel became or stopped being key. Becoming key starts the
        /// arming clock (a repeat report while already key keeps it running);
        /// losing it disables Allow at once and drops the clock, so the full
        /// armDelay starts again the next time the panel is key.
        func keyChanged(_ isKey: Bool, at t: TimeInterval) {
            guard !finished else { return }
            if isKey {
                guard keySince == nil else { return }
                keySince = t
                scheduleArming()
            } else {
                keySince = nil
                armWork?.cancel()
                armWork = nil
                setAllow(false)
            }
        }

        /// Enables Allow at keySince + armDelay with a one-shot, rather than
        /// waiting for the next countdown tick (which also re-checks).
        func scheduleArming() {
            armWork?.cancel()
            armWork = nil
            guard let since = keySince else { return }
            let wait = since + gate.armDelay - ProcessInfo.processInfo.systemUptime
            let w = DispatchWorkItem { [weak self] in self?.refreshArming() }
            armWork = w
            gate.uiQueue.asyncAfter(deadline: .now() + max(0, wait), execute: w)
        }

        func refreshArming() {
            guard !finished else { return }
            let armed = isArmed(at: ProcessInfo.processInfo.systemUptime)
            setAllow(armed)
            // Woken a little early (timer slack): try again at the time.
            if !armed && keySince != nil { scheduleArming() }
        }

        func isArmed(at t: TimeInterval) -> Bool {
            guard let since = keySince else { return false }
            return t >= since + gate.armDelay
        }

        func setAllow(_ on: Bool) {
            guard on != allowEnabled else { return }
            allowEnabled = on
            view?.setAllowEnabled(on)
        }

        /// A click on Allow, judged here whatever the button's state: it
        /// allows only if both of its events came from the mouse or trackpad,
        /// the panel is key now, and the button went down after the panel had
        /// been key for armDelay (so a click that was in flight before the
        /// panel appeared or became key never counts). A synthetic click is
        /// ignored and counted; an early hardware click is just ignored.
        func clicked(_ click: Click) {
            guard !finished else { return }
            guard click.hardware else {
                ignoredSynthetic += 1
                tick()
                return
            }
            guard let since = keySince, let down = click.downAt, down >= since + gate.armDelay else { return }
            finish(.allowed)
        }

        /// Esc denies, from any source and with any modifiers: denying is
        /// always safe. Every other key does nothing (the monitor has
        /// already swallowed it).
        func handle(_ press: KeyPress) {
            guard !finished else { return }
            if press.isEscape { finish(.escape) }
        }

        func tick() {
            guard !finished else { return }
            let left = deadline.timeIntervalSinceNow
            if left <= 0 {
                finish(.timedOut)
            } else {
                setAllow(isArmed(at: ProcessInfo.processInfo.systemUptime))
                view?.update(remaining: left, ignoredSynthetic: ignoredSynthetic)
            }
        }

        func finish(_ outcome: ConfirmOutcome) {
            guard !finished else { return }
            finished = true
            timer?.cancel()
            timer = nil
            armWork?.cancel()
            armWork = nil
            gate.keys.stop()
            gate.secureInput.disable()
            view?.close()
            view = nil
            if gate.current === self { gate.current = nil }
            onFinish(outcome)
        }
    }
}

/// NSEvent local monitor for key-down events while the dialog is up. It
/// swallows every key-down the app receives (returns nil), so typing that
/// lands in the panel can never reach a button; the gate only looks for
/// Escape.
public final class LocalKeyMonitor: KeySource {
    private var monitor: Any?
    public init() {}

    /// The KeyPress for a key-down NSEvent: its key code.
    public static func keyPress(_ e: NSEvent) -> KeyPress {
        KeyPress(keyCode: e.keyCode)
    }

    public func start(_ handler: @escaping (KeyPress) -> Void) {
        stop()
        monitor = NSEvent.addLocalMonitorForEvents(matching: [.keyDown]) { e in
            handler(LocalKeyMonitor.keyPress(e))
            return nil // never let the key reach anything else
        }
    }

    public func stop() {
        if let m = monitor { NSEvent.removeMonitor(m) }
        monitor = nil
    }
}

/// The Allow button: only a click with the mouse or trackpad can answer
/// through it. mouseDown(with:) records the down event for the length of
/// AppKit's tracking loop (super sends the action on a mouse-up inside the
/// button), and click() pairs it with the mouse-up AppKit is handling. Any
/// other way to send the action (performClick, an Accessibility press if
/// one got through) finds no recorded mouse-down and yields a non-hardware
/// click, which the gate ignores and counts. An Accessibility client's
/// AXPress is refused outright; the button never takes keyboard focus and
/// has no key equivalent, so Space and Return never press it; and it does
/// not accept the first mouse, so the click that activates the panel is not
/// delivered to it.
final class HardwareButton: NSButton {
    /// The mouse-down being tracked, set only inside mouseDown(with:).
    private var down: NSEvent?

    override func mouseDown(with event: NSEvent) {
        down = event
        defer { down = nil }
        super.mouseDown(with: event)
    }

    /// The click that sent the action now.
    func click() -> Click {
        guard let d = down, d.type == .leftMouseDown else { return Click(hardware: false, downAt: nil) }
        guard let up = NSApp.currentEvent, up.type == .leftMouseUp, up.timestamp >= d.timestamp else {
            return Click(hardware: false, downAt: d.timestamp)
        }
        return Click(hardware: Self.isHardware(d) && Self.isHardware(up), downAt: d.timestamp)
    }

    static func isHardware(_ e: NSEvent) -> Bool { e.cgEvent.map(HardwareInput.isHardware) ?? false }

    override func acceptsFirstMouse(for event: NSEvent?) -> Bool { false }
    override func accessibilityPerformPress() -> Bool { false }
}

/// The AppKit dialog: who is asking and what for, the countdown, then
/// [Deny] [Allow] (Allow on the right, as on macOS). Allow starts disabled;
/// the gate enables it once the panel has been key long enough. The panel
/// reports every change of key status (its own become/resign key, and the
/// app becoming or resigning active) to the gate. Built and used on the
/// main thread (the app's uiQueue); a presenter puts it on screen (S2:
/// activate and order front explicitly).
public final class ConfirmPanel: NSObject, ConfirmView {
    public let panel: NSPanel
    let presenter: WindowPresenter
    let status: NSTextField
    let allow: HardwareButton
    let deny: NSButton
    let actions: ConfirmActions
    private var observers: [NSObjectProtocol] = []

    public init(prompt: PromptSpec, presenter: WindowPresenter, actions: ConfirmActions) {
        self.presenter = presenter
        self.actions = actions
        panel = NSPanel(contentRect: NSRect(x: 0, y: 0, width: 520, height: 240), styleMask: [.titled],
                        backing: .buffered, defer: true)
        panel.title = "nazar 🧿"
        panel.level = .modalPanel
        panel.collectionBehavior = [.canJoinAllSpaces, .fullScreenAuxiliary]
        panel.hidesOnDeactivate = false
        panel.isReleasedWhenClosed = false
        var rows: [NSView] = []
        if prompt.unknown {
            let h = NSTextField(labelWithString: "⚠️ Unknown app: nazar could not tell which app is asking")
            h.textColor = .systemRed
            h.font = .boldSystemFont(ofSize: 15)
            rows.append(h)
        }
        let title = NSTextField(wrappingLabelWithString: prompt.title)
        title.font = .boldSystemFont(ofSize: 14)
        rows.append(title)
        rows.append(contentsOf: CodeBox.rows(prompt.lines, commandLine: prompt.commandLine))
        status = NSTextField(labelWithString: "")
        status.textColor = .secondaryLabelColor
        rows.append(status)
        // No key equivalents: neither Return, Space nor Escape presses a
        // button (Esc reaches the gate through the key monitor).
        deny = NSButton(title: "Deny", target: nil, action: nil)
        deny.keyEquivalent = ""
        allow = HardwareButton(title: "Allow", target: nil, action: nil)
        allow.keyEquivalent = ""
        allow.refusesFirstResponder = true
        allow.isEnabled = false
        let buttons = NSStackView()
        buttons.orientation = .horizontal
        buttons.addView(deny, in: .trailing)
        buttons.addView(allow, in: .trailing)
        rows.append(buttons)
        let stack = NSStackView(views: rows)
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.edgeInsets = NSEdgeInsets(top: 16, left: 20, bottom: 16, right: 20)
        panel.contentView = stack
        buttons.trailingAnchor.constraint(equalTo: stack.trailingAnchor, constant: -20).isActive = true
        super.init()
        deny.target = self
        deny.action = #selector(denyPressed)
        allow.target = self
        allow.action = #selector(allowPressed)
        let nc = NotificationCenter.default
        observers = [
            nc.addObserver(forName: NSWindow.didBecomeKeyNotification, object: panel, queue: nil) { [weak self] _ in
                self?.reportKey()
            },
            nc.addObserver(forName: NSWindow.didResignKeyNotification, object: panel, queue: nil) { [weak self] _ in
                self?.reportKey(false)
            },
            nc.addObserver(forName: NSApplication.didBecomeActiveNotification, object: nil, queue: nil) { [weak self] _ in
                self?.reportKey()
            },
            nc.addObserver(forName: NSApplication.didResignActiveNotification, object: nil, queue: nil) { [weak self] _ in
                self?.reportKey(false)
            },
        ]
        panel.center()
    }

    deinit { removeObservers() }

    private func removeObservers() {
        for o in observers { NotificationCenter.default.removeObserver(o) }
        observers = []
    }

    /// Tells the gate whether the panel is the key window of the active app
    /// now (`isKey` overrides the check, for the resign notifications).
    func reportKey(_ isKey: Bool? = nil) {
        let key = isKey ?? (panel.isKeyWindow && NSApp.isActive)
        actions.keyChanged(key, ProcessInfo.processInfo.systemUptime)
    }

    @objc func denyPressed() { actions.deny() }
    @objc func allowPressed() { actions.allow(allow.click()) }

    public func show() {
        presenter.present(panel)
        reportKey()
    }

    public func update(remaining: TimeInterval, ignoredSynthetic: Int) {
        var s = "Denied automatically in \(Int(remaining.rounded(.up))) s"
        if ignoredSynthetic > 0 { s += " · ignored \(ignoredSynthetic) click(s) that did not come from the mouse or trackpad" }
        status.stringValue = s
    }

    public func setAllowEnabled(_ enabled: Bool) { allow.isEnabled = enabled }

    public func close() {
        removeObservers()
        allow.isEnabled = false
        presenter.dismiss(panel)
    }
}
