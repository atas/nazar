// Nazar UI.app (spec 6.1, Milestone 6): an ordinary Mac app, optional and
// installed separately. A Dock icon while it is open; closing its window or
// Cmd+Q quits it, and nothing of it runs when it is closed: no menu bar
// item, no background process, no login item. Everything it shows and
// does is the nazar CLI's (NazarUI), run only after the CLI's signature is
// checked. Quitting it never affects the agent. Built by `make ui`; never
// started by any automated test.
import AppKit
import NazarUI
import SwiftUI

@main
struct NazarUIApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) var delegate

    var body: some Scene {
        Window("Nazar", id: "nazar") {
            RootView(session: delegate.session)
        }
        .defaultSize(width: 860, height: 560)
    }
}

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {
    let session = UISession.forThisApp()

    /// Closing the window quits the app: nothing stays in the background.
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { true }

    /// Quitting stops every CLI stream first, so no child outlives the app.
    func applicationWillTerminate(_ notification: Notification) { session.stopAll() }
}
