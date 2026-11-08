import AppKit

/// Puts a window on screen. Spike S2: from an LSUIElement app started by a
/// LaunchAgent an NSAlert returned without being shown, so every window
/// nazar shows explicitly activates the app and orders the window front.
public protocol WindowPresenter: AnyObject {
    func present(_ window: NSWindow)
    func dismiss(_ window: NSWindow)
}

/// The real presenter: never used by a test (it activates the app).
public final class AppKitPresenter: WindowPresenter {
    public init() {}
    public func present(_ window: NSWindow) {
        NSApp.activate()
        window.makeKeyAndOrderFront(nil)
        window.orderFrontRegardless()
    }
    public func dismiss(_ window: NSWindow) {
        window.orderOut(nil)
    }
}

/// Collects every NSTextField's text and every NSButton's title under a
/// view (tests, and checking by hand what is on screen). This
/// reads the view objects directly, not the Accessibility tree.
public enum ViewText {
    public static func labels(_ v: NSView) -> [String] {
        var out: [String] = []
        if let t = v as? NSTextField { out.append(t.stringValue) }
        for s in v.subviews { out += labels(s) }
        return out
    }

    public static func buttons(_ v: NSView) -> [String] {
        var out: [String] = []
        if let b = v as? NSButton { out.append(b.title) }
        for s in v.subviews { out += buttons(s) }
        return out
    }
}
