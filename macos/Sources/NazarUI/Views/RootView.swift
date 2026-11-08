import SwiftUI

/// Nazar UI.app's one window (spec 6.1): the Nazar window when a verified
/// CLI was found, otherwise what was found instead and how to install
/// nazar. It tells the session when it is on screen, which is when the
/// live streams run: the hooks sit on the one view that stays while the
/// state changes (UISessionTests.appearanceHooksBelongToOneStableView).
public struct RootView: View {
    @ObservedObject var session: UISession

    public init(session: UISession) { self.session = session }

    // Not a Group: its modifiers apply to each branch, so "Look again"
    // would fire SetupView's onDisappear and windowClosed() for a window
    // that is still open.
    public var body: some View {
        ZStack {
            switch session.state {
            case .ready(let models):
                NazarWindowView(models: models)
            case .noCLI(let reason, let candidates):
                SetupView(reason: reason, candidates: candidates) { session.retry() }
            }
        }
        .onAppear { session.windowOpened() }
        .onDisappear { session.windowClosed() }
    }
}

/// No CLI to run: why, every place looked at with what was wrong there
/// (paths are the user's to write, so they are shown through plain), and
/// how to install nazar.
struct SetupView: View {
    let reason: String
    let candidates: [CLICandidate]
    let retry: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Nazar UI needs nazar").font(.title2).bold()
            plain(reason)
            if !candidates.isEmpty {
                Text("Looked at:").bold()
                ForEach(Array(candidates.enumerated()), id: \.offset) { _, c in
                    VStack(alignment: .leading, spacing: 2) {
                        plain(c.source + ": " + c.path).font(.callout)
                        plain(c.problem ?? "usable").font(.caption).foregroundStyle(.secondary)
                    }
                }
            }
            plain(UISession.installHint).font(.body.monospaced()).textSelection(.enabled)
            Button("Look again") { retry() }
            Spacer()
        }
        .padding(24)
        .frame(minWidth: 560, minHeight: 360, alignment: .topLeading)
    }
}
