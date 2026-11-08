import AppKit
import SwiftUI

/// The models one window shows, all over one CLIClient.
@MainActor
public final class NazarModels {
    public let client: CLIClient
    public let changes: ChangeRunner
    public let keys: KeysModel
    public let approvals: ApprovalsModel
    public let activity: ActivityModel
    public let apps: AppsModel
    public let secrets: SecretsModel
    public let k8s: K8sModel

    public init(runner: CLIRunner) {
        client = CLIClient(runner: runner)
        changes = ChangeRunner(client: client)
        keys = KeysModel(client: client, changes: changes)
        approvals = ApprovalsModel(client: client, changes: changes)
        activity = ActivityModel(client: client)
        apps = AppsModel(client: client)
        secrets = SecretsModel(client: client, changes: changes)
        k8s = K8sModel(client: client, changes: changes)
    }

    /// The live streams run only while the window is open (spec 6.1,
    /// Milestone 6): the approvals stream (`nazar status --follow`) starts
    /// when it opens and follows the agent across restarts (it reconnects
    /// every few seconds) until it closes. The Activity tab's
    /// `nazar log --follow` runs while that tab is shown.
    public static let reconnectAfter: TimeInterval = 5

    public func windowOpened() {
        approvals.reconnectAfter = Self.reconnectAfter
        approvals.start()
    }

    public func windowClosed() { stopAll() }

    /// Stops every stream and keeps them stopped: no CLI child outlives the
    /// window (or the app: Nazar UI quits when its window closes).
    public func stopAll() {
        approvals.reconnectAfter = nil
        approvals.stop()
        activity.stop()
    }
}

/// The Nazar window (spec 6.1): SSH keys, Secrets, Kubernetes, Approvals, Activity, Apps. Every
/// value it shows came from `nazar … --json`; every button runs a CLI
/// command (UIAction). Loosening changes go through `nazar config apply`
/// and its login gate, like anyone else's.
public struct NazarWindowView: View {
    let m: NazarModels
    @ObservedObject var changes: ChangeRunner
    @ObservedObject var approvals: ApprovalsModel

    public init(models: NazarModels) {
        m = models
        changes = models.changes
        approvals = models.approvals
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            banners
            TabView {
                KeysTab(model: m.keys, apps: m.apps).tabItem { Text("SSH keys") }
                SecretsTab(model: m.secrets, apps: m.apps).tabItem { Text("Secrets") }
                K8sTab(model: m.k8s, apps: m.apps).tabItem { Text("Kubernetes") }
                ApprovalsTab(model: m.approvals).tabItem { Text("Approvals") }
                ActivityTab(model: m.activity).tabItem { Text("Activity") }
                AppsTab(model: m.apps).tabItem { Text("Apps") }
            }
            // The tab bar takes the window's first focus; no blue ring on it.
            .focusEffectDisabled()
            .padding()
        }
        .frame(minWidth: 760, minHeight: 480)
        .task {
            // Runs while the view is on screen (SwiftUI cancels it after).
            await approvals.refreshStatus()
            while !Task.isCancelled {
                try? await Task.sleep(for: .seconds(5))
                if !Task.isCancelled { await approvals.refreshStaged() }
            }
        }
        .onReceive(NotificationCenter.default.publisher(for: NSWindow.didBecomeKeyNotification)) { _ in
            Task { await approvals.refreshStatus() }
        }
        .onChange(of: changes.last) { Task { await approvals.refreshStatus() } }
    }

    /// What needs the person: a change waiting for the gate, vault items
    /// the agent runs without, the client-side findings of `nazar status`,
    /// the result of the last change.
    @ViewBuilder var banners: some View {
        if changes.waitingForApproval {
            Banner(color: .orange) {
                Text("Needs approval: confirm with Touch ID, Apple Watch or your Mac password in the nazar prompt.")
            }
        }
        if let st = approvals.status, let staged = st.staged {
            Banner(color: .orange) {
                VStack(alignment: .leading, spacing: 4) {
                    plain(Presentation.stagedTitle(staged)).bold()
                    plain(Presentation.stagedAdvice)
                    HStack {
                        Button("Approve…") { Task { await changes.approve() } }.disabled(changes.busy)
                        DisclosureGroup {
                            ForEach(Array(Presentation.stagedDetails(staged).enumerated()), id: \.offset) { _, c in
                                plain(c).font(.caption).textSelection(.enabled)
                            }
                        } label: { Text("Details") }
                    }
                }
            }
        }
        if let vault = approvals.status?.vault, !vault.isEmpty {
            Banner(color: .red) {
                VStack(alignment: .leading, spacing: 4) {
                    plain(Presentation.vaultTitle).bold()
                    ForEach(Array(vault.enumerated()), id: \.offset) { _, v in plain(Presentation.vaultLine(v)) }
                    DisclosureGroup {
                        ForEach(Array(vault.enumerated()), id: \.offset) { _, v in
                            plain(v.item + ": " + v.reason).font(.caption)
                            plain("fix: " + v.remedy).font(.caption).textSelection(.enabled)
                        }
                    } label: { Text("How to fix") }
                }
            }
        }
        if let setup = approvals.status?.setup, !setup.isEmpty {
            Banner(color: .yellow) {
                VStack(alignment: .leading, spacing: 4) {
                    plain(Presentation.setupTitle).bold()
                    ForEach(Array(setup.enumerated()), id: \.offset) { _, p in
                        plain(p.message).font(.caption).textSelection(.enabled)
                    }
                }
            }
        }
        if let last = changes.last {
            Banner(color: { if case .done = last { return .green }; return .yellow }()) { plain(last.text) }
        }
    }
}

struct Banner<Content: View>: View {
    let color: Color
    @ViewBuilder let content: () -> Content
    var body: some View {
        HStack { content(); Spacer() }
            .padding(8)
            .background(color.opacity(0.15))
    }
}

// MARK: SSH keys

struct KeysTab: View {
    @ObservedObject var model: KeysModel
    @ObservedObject var apps: AppsModel
    @State private var selection: String?

    init(model: KeysModel, apps: AppsModel, selection: String? = nil) {
        self.model = model
        self.apps = apps
        _selection = State(initialValue: selection)
    }
    @State private var creating = false
    @State private var editing: RuleEdit?
    @State private var confirmDelete: SSHKey?

    var body: some View {
        HSplitView {
            // Left: every key, and the actions that are about the list.
            VStack(alignment: .leading, spacing: 8) {
                Text("List of SSH keys").font(.headline)
                List(selection: $selection) {
                    ForEach(model.keys) { k in
                        VStack(alignment: .leading) {
                            plain(k.name).bold()
                            let state = Presentation.keyState(k)
                            if !state.isEmpty { plain(state).font(.caption) }
                            let badge = Presentation.keyBadge(k)
                            if !badge.isEmpty { plain(badge).font(.caption).foregroundStyle(.secondary) }
                            let lock = Presentation.lockBadge(k)
                            if !lock.isEmpty { plain(lock).font(.caption).foregroundStyle(.secondary) }
                        }
                        .tag(k.name)
                    }
                }
                HStack {
                    Button("New key…") { creating = true }
                    Button("Refresh") { Task { await model.refresh() } }
                }
                if let e = model.error { plain(e).font(.caption).foregroundStyle(.red) }
            }
            .padding(.trailing, 8)
            // The key list stays narrow; the details take the rest.
            .frame(minWidth: 180, idealWidth: 220, maxWidth: 280)
            // Right: the selected key, framed so it reads as that key's page.
            VStack(alignment: .leading, spacing: 8) {
                if let k = model.keys.first(where: { $0.name == selection }) {
                    GroupBox {
                        KeyDetail(key: k, since: model.since, model: model, editing: $editing, confirmDelete: $confirmDelete)
                            .padding(6)
                            .frame(maxWidth: .infinity, alignment: .topLeading)
                    } label: {
                        plain("Key: " + k.name).font(.headline)
                    }
                } else {
                    Text("Select a key on the left").foregroundStyle(.secondary)
                }
                Spacer()
            }
            .padding(.leading)
            .frame(minWidth: 480, maxWidth: .infinity, alignment: .topLeading)
        }
        .task { await model.refresh(); await apps.refresh() }
        .sheet(isPresented: $creating) { NewKeySheet(model: model) }
        .sheet(item: $editing) { e in RuleSheet(edit: e, apps: apps.apps) }
        .alert("Delete this key?", isPresented: Binding(get: { confirmDelete != nil }, set: { if !$0 { confirmDelete = nil } })) {
            Button("Delete", role: .destructive) {
                if let k = confirmDelete { Task { await model.delete(k) } }
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("The key is destroyed in the Secure Enclave; nazar asks for Touch ID / Watch / password first. This can't be undone.")
        }
    }
}

/// What the rule sheet edits: a new rule, an existing one, or the key's
/// own gate (the sheet's layout), and how to save it (the page's model:
/// the sheet itself knows none).
struct RuleEdit: Identifiable {
    enum Kind { case add, change(Int), keyGate }
    let id = UUID()
    let kind: Kind
    var draft: RuleDraft
    /// Whether the sheet offers a receiver (to:). A context's rules take none.
    var receivers = true
    let save: @MainActor (RuleDraft) async -> Void
}

/// A key's, a secret's or a context's rules: each with Edit… (only when the
/// sheet writes it back unchanged) and Remove, then what everyone
/// else gets. One view for the three tabs.
struct RuleRows: View {
    let policy: SSHKeyRules
    /// The command for a rule the sheet can't edit ("nazar ssh-key rule set").
    let setCommand: String
    @Binding var editing: RuleEdit?
    let edit: (RuleInfo) -> RuleEdit
    let remove: (Int) -> Void

    var body: some View {
        if policy.staged { Text("These rules are a staged change, not in force until approved.").foregroundStyle(.orange) }
        ForEach(policy.rules, id: \.index) { r in
            let canEdit = Presentation.editable(r)
            HStack {
                plain("\(r.index). " + Presentation.rule(r)).layoutPriority(1)
                Spacer()
                Button("Edit…") {
                    guard canEdit else { return }
                    editing = edit(r)
                }
                .disabled(!canEdit)
                .fixedSize()
                Button("Remove") { remove(r.index) }
                    .fixedSize()
            }
            if !canEdit {
                plain("edit this rule in config.yaml or with " + setCommand).font(.caption).foregroundStyle(.secondary)
            }
        }
        plain(Presentation.others(policy)).foregroundStyle(.secondary)
    }
}

/// A page's audit lines of the last 24 hours (TargetActivity), newest
/// first: the Secrets and Kubernetes tabs' one log view.
struct RecentActivity: View {
    @ObservedObject var log: TargetActivity
    let target: String

    var body: some View {
        Divider()
        Text("Last 24 hours").bold()
        if let events = log.events(for: target) {
            if events.isEmpty { Text("Nothing in the log.").foregroundStyle(.secondary) }
            ForEach(Array(events.enumerated()), id: \.offset) { _, e in
                VStack(alignment: .leading) {
                    plain(Presentation.targetEvent(e))
                    plain(e.time.formatted()).font(.caption).foregroundStyle(.secondary)
                }
            }
        } else if let err = log.error {
            plain(err).font(.caption).foregroundStyle(.red)
        } else {
            Text("Reading the log…").foregroundStyle(.secondary)
        }
    }
}

struct KeyDetail: View {
    let key: SSHKey
    let since: Date?
    let model: KeysModel
    @Binding var editing: RuleEdit?
    @Binding var confirmDelete: SSHKey?

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            plain(key.fingerprint ?? "").font(.system(.caption, design: .monospaced)).textSelection(.enabled)
            HStack {
                ForEach([Presentation.keyBadge(key), Presentation.lockBadge(key)].filter { !$0.isEmpty }, id: \.self) { badge in
                    plain(badge).font(.caption).bold()
                        .padding(.horizontal, 6).padding(.vertical, 2)
                        .background(Color.accentColor.opacity(0.15), in: Capsule())
                }
            }
            if !key.usable {
                plain(key.unusableReason ?? "").foregroundStyle(.red)
                plain("fix: " + (key.remedy ?? "")).font(.caption).textSelection(.enabled)
            }
            ForEach(Array(key.warnings.enumerated()), id: \.offset) { _, w in plain(w).font(.caption).foregroundStyle(.orange) }
            if let p = key.policy {
                RuleRows(policy: p, setCommand: "nazar ssh-key rule set", editing: $editing,
                         edit: { r in RuleEdit(kind: .change(r.index), draft: RuleDraft(r)) { _ = await model.updateRule(of: key, index: r.index, $0) } },
                         remove: { i in Task { await model.removeRule(of: key, index: i) } })
            }
            HStack {
                Button("Add rule…") { editing = RuleEdit(kind: .add, draft: RuleDraft(apps: [])) { _ = await model.addRule(to: key, $0) } }
                Button("Key's own gate…") {
                    let own = key.policy?.own
                    editing = RuleEdit(kind: .keyGate, draft: RuleDraft(apps: [], scope: own?.scope ?? "use",
                                                                        gate: own?.gate ?? "login", expire: own?.expire ?? "")) {
                        _ = await model.setKeyGate(of: key, scope: $0.scope, gate: $0.gate, expire: $0.expire)
                    }
                }
                Button("Copy public key") {
                    Task {
                        if let pub = await model.publicKey(key) {
                            NSPasteboard.general.clearContents()
                            NSPasteboard.general.setString(pub, forType: .string)
                        }
                    }
                }
                Button("Delete…", role: .destructive) { confirmDelete = key }
            }
        }
    }
}

struct NewKeySheet: View {
    let model: KeysModel
    @Environment(\.dismiss) var dismiss
    @State private var name = ""
    @State private var alwaysAsk = false
    @State private var onlyWhenUnlocked = false

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("New SSH key").font(.headline)
            Grid(alignment: .leadingFirstTextBaseline, horizontalSpacing: 12, verticalSpacing: 10) {
                GridRow {
                    Text("Name").gridColumnAlignment(.trailing)
                    TextField("", text: $name, prompt: Text("github"))
                }
            }
            VStack(alignment: .leading, spacing: 2) {
                Toggle(isOn: $alwaysAsk) { plain(Presentation.alwaysAskLabel) }
                plain(Presentation.alwaysAskHelp).font(.caption).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            VStack(alignment: .leading, spacing: 2) {
                // Forced on, and disabled, while "always ask" is on.
                Toggle(isOn: Binding(get: { alwaysAsk || onlyWhenUnlocked }, set: { onlyWhenUnlocked = $0 })) {
                    plain(Presentation.onlyWhenUnlockedLabel)
                }
                .disabled(alwaysAsk)
                plain(alwaysAsk ? Presentation.onlyWhenUnlockedForced : Presentation.onlyWhenUnlockedHelp)
                    .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            }
            if alwaysAsk {
                Text("nazar asks for Touch ID / Watch / password once. The key starts blocked for every app; add rules on its page next, each with gate login and scope use.")
                    .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            } else {
                Text("nazar asks for Touch ID / Watch / password once. The key starts blocked for every app; add rules on its page next.")
                    .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            }
            HStack {
                Spacer()
                Button("Cancel") { dismiss() }.keyboardShortcut(.cancelAction)
                Button("Create") {
                    Task { await model.create(name: name, alwaysAsk: alwaysAsk, onlyWhenUnlocked: alwaysAsk || onlyWhenUnlocked); dismiss() }
                }
                    .keyboardShortcut(.defaultAction)
                    .disabled(name.isEmpty)
            }
        }
        .padding(20)
        .frame(width: 480)
    }
}

struct RuleSheet: View {
    let edit: RuleEdit
    let apps: [AppEntry]
    @Environment(\.dismiss) var dismiss
    @State private var appsField = ""
    @State private var toField = ""
    @State private var scope = "session"
    @State private var gate = "login"
    @State private var expire = ""

    var isKeyGate: Bool { if case .keyGate = edit.kind { return true }; return false }

    /// block and none ignore scope and expire, so the sheet hides them.
    var prompts: Bool { gate == "login" || gate == "dialog" }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            if isKeyGate {
                Text("Default for callers no rule matches").font(.headline)
            } else {
                Text("Who may use it, and how they are asked.").font(.headline)
            }
            Grid(alignment: .leadingFirstTextBaseline, horizontalSpacing: 12, verticalSpacing: 10) {
                if !isKeyGate {
                    GridRow {
                        Text("Apps").gridColumnAlignment(.trailing)
                        VStack(alignment: .leading, spacing: 4) {
                            TextField("", text: $appsField, prompt: Text("app:com.googlecode.iterm2"))
                            Text("app:<bundle-id>, signed:<team>[:<id>], path:<path>, any or unknown; separate several with commas")
                                .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                            if !namedApps.isEmpty {
                                plain("Named in config.yaml: " + namedApps.joined(separator: ", "))
                                    .font(.caption).foregroundStyle(.secondary)
                            }
                        }
                    }
                }
                if !isKeyGate && edit.receivers {
                    GridRow {
                        Text("Receiver")
                        VStack(alignment: .leading, spacing: 4) {
                            TextField("", text: $toField, prompt: Text("optional"))
                            Text("Only when the result goes to this program (to:)").font(.caption).foregroundStyle(.secondary)
                        }
                    }
                }
                GridRow {
                    Text("Gate")
                    Picker("", selection: $gate) {
                        ForEach(isKeyGate ? Presentation.keyGates : Presentation.gates, id: \.self) { plain($0) }
                    }
                    .labelsHidden().fixedSize()
                }
                if prompts {
                    GridRow {
                        Text("Scope")
                        VStack(alignment: .leading, spacing: 4) {
                            Picker("", selection: $scope) { ForEach(Presentation.scopes, id: \.self) { plain($0) } }
                                .labelsHidden().fixedSize()
                            plain(Presentation.scopeHelp(scope)).font(.caption).foregroundStyle(.secondary)
                        }
                    }
                    GridRow {
                        Text("Expires")
                        VStack(alignment: .leading, spacing: 4) {
                            TextField("", text: $expire, prompt: Text("never"))
                            Text("e.g. 8h or 7d").font(.caption).foregroundStyle(.secondary)
                        }
                    }
                }
            }
            Text("A change that loosens access asks for Touch ID, Apple Watch or your password before it takes effect.")
                .font(.caption).foregroundStyle(.secondary)
            HStack {
                Spacer()
                Button("Cancel") { dismiss() }.keyboardShortcut(.cancelAction)
                Button("Save") { Task { await save(); dismiss() } }
                    .keyboardShortcut(.defaultAction)
                    .disabled(!isKeyGate && Presentation.refs(appsField).isEmpty)
            }
        }
        .padding(20)
        .frame(width: 560)
        .onAppear {
            appsField = edit.draft.apps.joined(separator: ", ")
            toField = edit.draft.to.joined(separator: ", ")
            (scope, gate, expire) = (edit.draft.scope, edit.draft.gate, edit.draft.expire)
        }
    }

    /// The top-level apps: names (inline matchers have none).
    var namedApps: [String] { apps.map(\.name).filter { !$0.isEmpty } }

    func save() async {
        let (scope, expire) = prompts ? (scope, expire) : ("use", "")
        // The key's own gate has no apps or receivers; a context's rule no
        // receivers (the program that runs the plugin is).
        let d = isKeyGate
            ? RuleDraft(apps: [], scope: scope, gate: gate, expire: expire)
            : RuleDraft(apps: Presentation.refs(appsField), to: edit.receivers ? Presentation.refs(toField) : [],
                        scope: scope, gate: gate, expire: expire)
        await edit.save(d)
    }
}

// MARK: Approvals

struct ApprovalsTab: View {
    @ObservedObject var model: ApprovalsModel

    var body: some View {
        VStack(alignment: .leading) {
            HStack {
                plain(Presentation.approvalsLine(model.count)).bold()
                Spacer()
                Button("Revoke all") { Task { await model.revokeAll() } }.disabled(model.count == 0)
                if !model.connected { Button("Reconnect") { model.start() } }
            }
            if let e = model.error { plain(e).foregroundStyle(.red) }
            List(model.approvals, id: \.identity) { a in
                HStack {
                    VStack(alignment: .leading) {
                        plain(a.target + " · rule " + a.rule + " · " + a.scope + " · for " + a.covers).bold()
                        plain(a.chain).font(.caption)
                        if let exp = a.expires { plain("until " + exp.formatted()).font(.caption) }
                    }
                    Spacer()
                    Button("Revoke") { Task { await model.revoke(a) } }
                }
            }
        }
    }
}

// MARK: Activity

struct ActivityTab: View {
    @ObservedObject var model: ActivityModel

    var body: some View {
        VStack(alignment: .leading) {
            HStack {
                TextField("Filter (target, app, chain, reason)", text: $model.text)
                Picker("Decision", selection: $model.decision) {
                    Text("all").tag("")
                    ForEach(["allowed", "approved", "denied", "timeout", "blocked", "error"], id: \.self) { plain($0).tag($0) }
                }
                .frame(width: 200)
            }
            if let e = model.error { plain(e).foregroundStyle(.red) }
            List(Array(model.lines.enumerated()), id: \.offset) { _, l in
                VStack(alignment: .leading) {
                    plain(Presentation.activityLine(l))
                    plain(Presentation.activityTime(l)).font(.caption).foregroundStyle(.secondary)
                }
            }
        }
        .task { await model.start() }
        .onDisappear { model.stop() }
    }
}

// MARK: Apps

struct AppsTab: View {
    @ObservedObject var model: AppsModel

    var body: some View {
        VStack(alignment: .leading) {
            HStack {
                Spacer()
                Button("Refresh") { Task { await model.refresh() } }
            }
            if let e = model.error { plain(e).foregroundStyle(.red) }
            List(model.apps) { a in
                VStack(alignment: .leading) {
                    plain(a.name.isEmpty ? Presentation.matcher(a.matcher) : a.name + " · " + Presentation.matcher(a.matcher)).bold()
                    if let team = a.pinnedTeam { plain("pinned team " + team).font(.caption) }
                    if !a.usedBy.isEmpty { plain("used by " + a.usedBy.joined(separator: ", ")).font(.caption) }
                    if let p = a.problem { plain(p).font(.caption).foregroundStyle(.orange) }
                    if let f = a.fix { plain("fix: " + f).font(.caption).textSelection(.enabled) }
                }
            }
        }
        .task { await model.refresh() }
    }
}
