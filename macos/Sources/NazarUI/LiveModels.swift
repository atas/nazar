import Foundation

/// Runs a closure on the main actor in the order the stream delivered them
/// (DispatchQueue.main is FIFO; a Task per line is not ordered).
func onMain(_ body: @escaping @MainActor @Sendable () -> Void) {
    DispatchQueue.main.async { MainActor.assumeIsolated { body() } }
}

/// A weak reference a stream's @Sendable callbacks can hold.
final class Weak<T: AnyObject>: @unchecked Sendable {
    weak var value: T?
    init(_ v: T) { value = v }
}

/// The Approvals tab and the menu bar's count (spec 6.1): what is approved
/// right now, live from `nazar status --follow --json`, plus the config
/// state that stream's first object carries (a staged change, vault items
/// Nazar.app runs without). Revoke one or all.
@MainActor
public final class ApprovalsModel: ObservableObject {
    public let client: CLIClient
    public let changes: ChangeRunner
    @Published public private(set) var approvals: [Approval] = []
    @Published public private(set) var status: Status?
    @Published public private(set) var connected = false
    @Published public private(set) var error: String?
    private var stream: CLIStream?
    /// When set, a stream that ended is started again after this many
    /// seconds (the menu bar's count follows Nazar.app's core from its
    /// start, before the control socket listens, and across hiccups).
    public var reconnectAfter: TimeInterval?
    /// How many times start() ran (tests).
    public private(set) var starts = 0

    public init(client: CLIClient, changes: ChangeRunner) {
        self.client = client
        self.changes = changes
    }

    /// A model let go of stops its stream (SIGTERM to the CLI child): no
    /// `--follow` child outlives the model that started it.
    deinit { stream?.stop() }

    public var count: Int { approvals.count }

    /// Starts following (again). The first object is a Status, then one
    /// Approval per change with event "added" or "removed".
    public func start() {
        stream?.stop()
        starts += 1
        (connected, error) = (true, nil)
        let me = Weak(self), mine = starts
        stream = client.follow(.followStatus, onObject: { o in
            onMain { me.value?.current(mine)?.apply(o) }
        }, onExit: { code in
            onMain { me.value?.current(mine)?.ended(code) }
        })
    }

    /// The model, for the stream started by start() number n; nil once a
    /// later start() replaced that stream (a stopped child exits a little
    /// later, and its exit must not disconnect or restart its successor).
    private func current(_ n: Int) -> ApprovalsModel? { n == starts ? self : nil }

    public func stop() {
        stream?.stop()
        stream = nil
    }

    /// Reads the status once (`nazar status --json`): the stream sends the
    /// config state (a staged change, vault items, the client-side
    /// findings) only in its first object, so the window reads it again
    /// when it is shown and after every change it makes.
    public func refreshStatus() async {
        let out = await client.call(.status)
        if let s = out.first(Kind.status, as: Status.self) {
            status = s
            approvals = s.approvals
        }
    }

    /// What the window re-reads every few seconds while on screen: whether
    /// a change is staged (`nazar config check --json`), so the banner
    /// goes when it is approved elsewhere. Not `nazar status`, whose
    /// client-side checks run ssh (and `Match exec` commands), git and the
    /// other agent: those run only when a person or the window asks.
    public func refreshStaged() async {
        let out = await client.call(.configCheck)
        if let c = out.first(Kind.configCheck, as: ConfigCheck.self) { status?.staged = c.staged }
    }

    func apply(_ o: CLIObject) {
        switch o.kind {
        case Kind.status:
            if let s = o.decode(Status.self) {
                status = s
                approvals = s.approvals
            }
        case Kind.approval:
            guard let a = o.decode(Approval.self) else { return }
            approvals.removeAll { $0.identity == a.identity }
            if a.event == "added" { approvals.append(a) }
        case Kind.problem:
            error = o.decode(Problem.self)?.message
        default:
            break
        }
    }

    func ended(_ code: Int32) {
        connected = false
        if error == nil {
            error = code == 5 ? "nazar-agent isn't running" : "the approval stream ended (status \(code))"
        }
        if let delay = reconnectAfter {
            let me = Weak(self)
            DispatchQueue.main.asyncAfter(deadline: .now() + delay) {
                MainActor.assumeIsolated {
                    if let m = me.value, !m.connected, m.reconnectAfter != nil { m.start() }
                }
            }
        }
    }

    /// The command that revokes one approval: its terminal session, its
    /// app, or else every approval of its key.
    public func revokeAction(_ a: Approval) -> UIAction {
        if a.scopeId.hasPrefix("session:") { return .revokeSession(String(a.scopeId.dropFirst("session:".count))) }
        if a.scopeId.hasPrefix("app:"), let app = a.app, !app.isEmpty { return .revokeApp(app) }
        return .revokeKey(a.target.hasPrefix("ssh:") ? String(a.target.dropFirst(4)) : a.target)
    }

    @discardableResult
    public func revoke(_ a: Approval) async -> ChangeResult {
        await changes.perform(revokeAction(a), done: "Revoked")
    }

    @discardableResult
    public func revokeAll() async -> ChangeResult {
        await changes.perform(.revokeAll, done: "Revoked all approvals")
    }
}

/// The Activity tab (spec 6.1): the audit log, live from `nazar log
/// --follow --json` after the last hour from `nazar log --since 1h`, with
/// filters. Every field is audit-log text: show it through PlainText.
@MainActor
public final class ActivityModel: ObservableObject {
    public let client: CLIClient
    /// Newest first, at most maxEvents.
    @Published public private(set) var events: [AuditEvent] = []
    @Published public private(set) var error: String?
    @Published public var text = ""
    @Published public var decision = ""
    public static let maxEvents = 2000
    private var stream: CLIStream?
    /// Counts start() and stop(): a stream, or the read before it, speaks
    /// only while nothing came after it.
    private var generation = 0

    public init(client: CLIClient) { self.client = client }

    /// As ApprovalsModel's: its stream stops with it.
    deinit { stream?.stop() }

    public func start() async {
        stream?.stop()
        generation += 1
        let mine = generation
        let out = await client.call(.log(since: "1h"))
        guard mine == generation else { return } // stopped or started again meanwhile
        if case .ok(let objs) = out {
            events = objs.compactMap { $0.kind == Kind.auditEvent ? $0.decode(AuditEvent.self) : nil }.reversed()
            trim()
            error = nil
        } else {
            error = out.problem?.message ?? "could not read the log"
        }
        let me = Weak(self)
        stream = client.follow(.followLog, onObject: { o in
            onMain { me.value?.current(mine)?.add(o) }
        }, onExit: { code in
            onMain { me.value?.current(mine)?.streamEnded(code) }
        })
    }

    /// As ApprovalsModel.current: only the latest start()'s stream speaks.
    private func current(_ n: Int) -> ActivityModel? { n == generation ? self : nil }

    public func stop() {
        generation += 1
        stream?.stop()
        stream = nil
    }

    func streamEnded(_ code: Int32) {
        if code != 0 && error == nil { error = "the log stream ended (status \(code))" }
    }

    func add(_ o: CLIObject) {
        guard o.kind == Kind.auditEvent, let e = o.decode(AuditEvent.self) else { return }
        events.insert(e, at: 0)
        trim()
    }

    private func trim() {
        if events.count > Self.maxEvents { events.removeLast(events.count - Self.maxEvents) }
    }

    /// What the Activity list shows: the filtered events, repeats folded.
    public var lines: [ActivityLine] { ActivityLine.fold(filtered) }

    /// The events the filters let through: decision equal, text anywhere in
    /// target, app, chain or reason (case-insensitive).
    public var filtered: [AuditEvent] {
        let needle = text.lowercased()
        return events.filter { e in
            (decision.isEmpty || e.fields["decision"] == decision)
                && (needle.isEmpty || ["target", "app", "chain", "reason", "receiver", "command"].contains { e.fields[$0]?.lowercased().contains(needle) ?? false })
        }
    }
}
