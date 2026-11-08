import Foundation

/// What became of a change made from the window.
public enum ChangeResult: Equatable, Sendable {
    /// In force: a tightening, or a loosening approved through the gate.
    case done(String)
    /// The login gate was denied or not answered; the change stays staged.
    case notApproved(String)
    /// Staged, and the prompt could not be shown yet (another prompt is
    /// open, or the cooldown after a denied one runs): `config apply` asks.
    case stillStaged(String)
    /// Nazar.app isn't running, or the command failed.
    case failed(String)

    public var text: String {
        switch self {
        case .done(let s), .notApproved(let s), .stillStaged(let s), .failed(let s): return s
        }
    }
}

/// Runs the window's changes the way a person would in the terminal: one
/// command, one Touch ID. A rule edit carries --allow-loosen-access
/// (UIAction), so a loosening is written and the CLI at once asks for the
/// login gate (Touch ID / Watch / password) on Nazar.app's own screen for
/// exactly that change, bound inside the CLI to the change it staged: exit
/// 0 once it is in force, 3 when denied (the change stays staged), 4 when
/// the prompt could not be shown. A change left staged, or one made by
/// hand in config.yaml, is approved from the banner with `nazar config
/// apply` (approve), which shows the gate the same way. The window never
/// answers a gate itself, and never runs `config apply` on its own after
/// an edit (spec 4.8, 6.1).
@MainActor
public final class ChangeRunner: ObservableObject {
    public let client: CLIClient
    @Published public private(set) var busy = false
    /// What the window says while a change may be waiting for the gate.
    @Published public private(set) var waitingForApproval = false
    @Published public private(set) var last: ChangeResult?

    public init(client: CLIClient) { self.client = client }

    /// Runs action; input (secret add's value) goes to that one run's
    /// stdin and nowhere else: never again after a refusal or a failure.
    /// It is wiped when this returns, whatever the outcome.
    @discardableResult
    public func perform(_ action: UIAction, input: CLIInput? = nil, done: String) async -> ChangeResult {
        busy = true
        waitingForApproval = true
        defer {
            busy = false
            waitingForApproval = false
        }
        let r = await outcome(action, input: input, done: done)
        last = r
        return r
    }

    private func outcome(_ action: UIAction, input: CLIInput?, done: String) async -> ChangeResult {
        let out = await client.call(action, input: input)
        input?.wipe() // the run has ended: nothing writes it any more
        return Self.result(of: out, done: done)
    }

    /// `nazar config apply` for the change staged in config.yaml (the one
    /// the banner shows): the CLI shows and binds exactly that change.
    public func approve(done: String = "Approved and applied") async -> ChangeResult {
        busy = true
        waitingForApproval = true
        defer {
            busy = false
            waitingForApproval = false
        }
        let r = Self.result(of: await client.call(.configApply), done: done)
        last = r
        return r
    }

    /// How a run ended, by its exit code: 0 in force; 3 denied at the gate
    /// (the change stays staged); 4 staged with no prompt shown (an edit
    /// whose prompt could not be shown, or a command refused because
    /// config.yaml has a change waiting): the CLI's own words, nothing
    /// approved or retried; else a failure.
    static func result(of out: CLIOutcome, done: String) -> ChangeResult {
        switch out {
        case .ok:
            return .done(done)
        case .staged(let objs):
            return .stillStaged(objs.last { $0.kind == Kind.problem }?.decode(Problem.self)?.message
                ?? "the change is staged; run nazar config apply to approve it")
        case .refused(let p):
            return .notApproved(p.message)
        case .unavailable(let p), .failed(let p):
            return .failed(p.message)
        }
    }
}
