import AppKit
import Foundation

/// Where "Copy suggested rule" puts the rule. Injected so tests never touch
/// the real clipboard.
public protocol RuleClipboard: AnyObject {
    func copy(_ s: String)
}

/// What "Open config" opens the config file with. Injected so tests never
/// open a real file.
public protocol URLOpener: AnyObject {
    func open(_ url: URL)
}

/// The real clipboard (never used by a test).
public final class SystemPasteboard: RuleClipboard {
    public init() {}
    public func copy(_ s: String) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(s, forType: .string)
    }
}

/// The real opener (never used by a test).
public final class WorkspaceOpener: URLOpener {
    public init() {}
    public func open(_ url: URL) { NSWorkspace.shared.open(url) }
}

/// Platform.ShowWarning: the block warning (spec 4.4). The requester was
/// refused before this window exists, and nothing in it can allow
/// anything: its only buttons are Copy suggested rule, Open config and
/// Dismiss. It is not modal. A warning whose ID is already on screen
/// updates that window (counter), so repeats never stack windows; at most
/// maxWindows are open, the oldest is closed to make room. The lines shown
/// are bounded (count and length) whatever the caller sent.
///
/// `show` only schedules work on uiQueue and returns at once; `open` is
/// touched on uiQueue only.
public final class WarningCenter: @unchecked Sendable {
    public static let maxWindows = 8
    static let maxLines = 20
    static let maxLineLength = 500

    let configURL: URL
    let presenter: WindowPresenter
    let pasteboard: RuleClipboard
    let opener: URLOpener
    let uiQueue: DispatchQueue
    /// The windows on screen, oldest first.
    private(set) var open: [(id: String, panel: WarningPanel)] = []

    public init(configPath: String, presenter: WindowPresenter, pasteboard: RuleClipboard, opener: URLOpener,
                uiQueue: DispatchQueue = .main) {
        configURL = URL(fileURLWithPath: configPath)
        self.presenter = presenter
        self.pasteboard = pasteboard
        self.opener = opener
        self.uiQueue = uiQueue
    }

    /// Returns at once; the window appears on uiQueue.
    public func show(_ w: WarningSpec) {
        uiQueue.async { self.showNow(w) }
    }

    /// Shows or updates the window for w.id. Call on the UI thread.
    func showNow(_ w: WarningSpec) {
        let w = Self.bounded(w)
        if let existing = open.first(where: { $0.id == w.id }) {
            existing.panel.update(w)
            presenter.present(existing.panel.panel)
            return
        }
        if open.count >= Self.maxWindows {
            let oldest = open.removeFirst()
            presenter.dismiss(oldest.panel.panel)
        }
        let p = WarningPanel(w, onCopy: { [weak self] rule in self?.pasteboard.copy(rule) },
                             onOpen: { [weak self] in if let self { self.opener.open(self.configURL) } },
                             onDismiss: { [weak self] panel in self?.dismissNow(panel) })
        open.append((w.id, p))
        presenter.present(p.panel)
    }

    /// Closes exactly this panel if the center still holds it: a stale
    /// panel (already dismissed or evicted) never closes the window another
    /// warning with the same ID opened since.
    func dismissNow(_ panel: WarningPanel) {
        guard let i = open.firstIndex(where: { $0.panel === panel }) else { return }
        presenter.dismiss(open[i].panel.panel)
        open.remove(at: i)
    }

    /// At most maxLines lines of at most maxLineLength characters each (a
    /// cut line ends in "…"). Cuts by Character, never inside one.
    static func bounded(_ w: WarningSpec) -> WarningSpec {
        var w = w
        w.lines = w.lines.prefix(maxLines).map {
            $0.count > maxLineLength ? String($0.prefix(maxLineLength - 1)) + "…" : $0
        }
        return w
    }
}

/// One block warning window. Built and used on the UI thread; a presenter
/// puts it on screen (S2: activate and order front explicitly). Every text
/// field is a non-editable label, so caller text never becomes an input,
/// and the only controls are the three buttons.
final class WarningPanel: NSObject {
    let panel: NSPanel
    private(set) var spec: WarningSpec
    let titleLabel = NSTextField(wrappingLabelWithString: "")
    let countLabel = NSTextField(labelWithString: "")
    let body = NSStackView()
    let copyButton = NSButton(title: "Copy suggested rule", target: nil, action: nil)
    let onCopy: (String) -> Void
    let onOpen: () -> Void
    let onDismiss: (WarningPanel) -> Void

    init(_ w: WarningSpec, onCopy: @escaping (String) -> Void, onOpen: @escaping () -> Void,
         onDismiss: @escaping (WarningPanel) -> Void) {
        spec = w
        self.onCopy = onCopy
        self.onOpen = onOpen
        self.onDismiss = onDismiss
        panel = NSPanel(contentRect: NSRect(x: 0, y: 0, width: 560, height: 260), styleMask: [.titled, .closable],
                        backing: .buffered, defer: true)
        super.init()
        panel.title = "nazar 🧿 blocked a request"
        panel.level = .floating
        panel.collectionBehavior = [.canJoinAllSpaces, .fullScreenAuxiliary]
        panel.hidesOnDeactivate = false
        panel.isReleasedWhenClosed = false
        titleLabel.font = .boldSystemFont(ofSize: 14)
        countLabel.textColor = .secondaryLabelColor
        body.orientation = .vertical
        body.alignment = .leading
        copyButton.target = self
        copyButton.action = #selector(copyPressed)
        let open = NSButton(title: "Open config", target: self, action: #selector(openPressed))
        let dismiss = NSButton(title: "Dismiss", target: self, action: #selector(dismissPressed))
        let buttons = NSStackView(views: [copyButton, open, dismiss])
        buttons.orientation = .horizontal
        // Every line comes from the core (the reason differs per warning);
        // the panel adds none of its own.
        let stack = NSStackView(views: [titleLabel, body, countLabel, buttons])
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.edgeInsets = NSEdgeInsets(top: 16, left: 20, bottom: 16, right: 20)
        panel.contentView = stack
        update(w)
        panel.center()
    }

    /// Rewrites the window in place: title, lines (none left over), counter
    /// and whether Copy has a rule to copy.
    func update(_ w: WarningSpec) {
        spec = w
        titleLabel.stringValue = "🧿 " + w.title
        for v in body.arrangedSubviews {
            body.removeArrangedSubview(v)
            v.removeFromSuperview()
        }
        for v in CodeBox.rows(w.lines, commandLine: w.commandLine) { body.addArrangedSubview(v) }
        countLabel.stringValue = w.count > 1 ? "blocked \(w.count) times" : ""
        copyButton.isEnabled = !w.suggestedRule.isEmpty
    }

    @objc func copyPressed() { if !spec.suggestedRule.isEmpty { onCopy(spec.suggestedRule) } }
    @objc func openPressed() { onOpen() }
    @objc func dismissPressed() { onDismiss(self) }
}
