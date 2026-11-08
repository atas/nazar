import Foundation

/// What Nazar UI.app shows (spec 6.1, Milestone 6): the window over a
/// verified CLI, or, when no CLI passes the signature check, what it found
/// instead. Nothing runs before a window is open and nothing after it
/// closes.
@MainActor
public final class UISession: ObservableObject {
    public enum State {
        case ready(NazarModels)
        /// Why there is no CLI to run: the places looked at (each with its
        /// problem), or a requirement the app could not form.
        case noCLI(reason: String, candidates: [CLICandidate])
    }

    @Published public private(set) var state: State
    private let requirement: Result<CLIRequirement, CLIRequirement.Problem>
    private let locate: (CLIRequirement) -> CLILocation
    private let makeRunner: (URL, CLIRequirement) -> CLIRunner
    private var windowOpen = false

    /// The install hint the setup view shows.
    public static let installHint = "brew install --cask atas/tap/nazar"

    public init(requirement: Result<CLIRequirement, CLIRequirement.Problem>,
                locate: @escaping (CLIRequirement) -> CLILocation,
                makeRunner: @escaping (URL, CLIRequirement) -> CLIRunner) {
        self.requirement = requirement
        self.locate = locate
        self.makeRunner = makeRunner
        state = .noCLI(reason: "", candidates: [])
        resolve()
    }

    /// The one runner the app wires: the CLI runs only when its running
    /// process satisfies the requirement (ProcessCLIRunner's public init).
    /// Pinned by UISessionTests.verifiedRunnerRunsOnlyTheRequiredCLI and
    /// ContractTests.onlyTheVerifiedRunnerIsWired.
    static let verifiedRunner: (URL, CLIRequirement) -> CLIRunner = { ProcessCLIRunner(cli: $0, requirement: $1) }

    /// The app's session: its own signature's rule, the real locations, and
    /// the verified runner.
    public static func forThisApp() -> UISession {
        UISession(requirement: CLIRequirement.forThisApp(),
                  locate: { CLILocator.locate(requirement: $0) },
                  makeRunner: verifiedRunner)
    }

    private func resolve() {
        switch requirement {
        case .failure(let p):
            state = .noCLI(reason: p.description, candidates: [])
        case .success(let req):
            switch locate(req) {
            case .found(let url, _):
                state = .ready(NazarModels(runner: makeRunner(url, req)))
            case .notFound(let c):
                state = .noCLI(reason: "No nazar CLI signed by this app's developer was found. nazar (the agent and its CLI) is installed separately: \(Self.installHint)", candidates: c)
            }
        }
    }

    /// "Look again" (after installing the agent): finds the CLI again and,
    /// when the window is open, starts its streams. A CLI already verified
    /// is kept: nothing is looked for or swapped under the open window.
    public func retry() {
        if case .ready = state { return }
        resolve()
        if windowOpen, case .ready(let m) = state { m.windowOpened() }
    }

    public func windowOpened() {
        windowOpen = true
        if case .ready(let m) = state { m.windowOpened() }
    }

    public func windowClosed() {
        windowOpen = false
        stopAll()
    }

    /// Stops every stream (the app calls it when it terminates).
    public func stopAll() {
        if case .ready(let m) = state { m.stopAll() }
    }
}
