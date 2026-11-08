import SwiftUI

// MARK: Secrets (Milestone 11)

/// The Secrets tab, laid out like SSH keys: the secrets on the left, the
/// selected one's page on the right. Names, state, delivery, rules,
/// warnings and recent audit lines; never a value. The only value in the
/// window is the Add sheet's hidden field, until Add.
struct SecretsTab: View {
    @ObservedObject var model: SecretsModel
    @ObservedObject var apps: AppsModel
    @ObservedObject var changes: ChangeRunner
    @State private var selection: String?
    @State private var adding = false
    @State private var editing: RuleEdit?
    @State private var confirmDelete: Secret?

    init(model: SecretsModel, apps: AppsModel) {
        self.model = model
        self.apps = apps
        changes = model.changes
    }

    var body: some View {
        HSplitView {
            // Left: every secret, and the actions that are about the list.
            VStack(alignment: .leading, spacing: 8) {
                Text("Secrets").font(.headline)
                List(selection: $selection) {
                    ForEach(model.secrets) { s in
                        VStack(alignment: .leading) {
                            plain(s.name).bold()
                            let state = Presentation.secretState(s)
                            if !state.isEmpty { plain(state).font(.caption) }
                            let lock = Presentation.lockBadge(s)
                            if !lock.isEmpty { plain(lock).font(.caption).foregroundStyle(.secondary) }
                        }
                        .tag(s.name)
                    }
                }
                HStack {
                    Button("Add secret…") { adding = true }.disabled(changes.busy)
                    Button("Refresh") { Task { await model.refresh() } }
                }
                if let e = model.error { plain(e).font(.caption).foregroundStyle(.red) }
            }
            .padding(.trailing, 8)
            .frame(minWidth: 180, idealWidth: 220, maxWidth: 280)
            // Right: the selected secret's page.
            VStack(alignment: .leading, spacing: 8) {
                if let s = model.secrets.first(where: { $0.name == selection }) {
                    GroupBox {
                        SecretDetail(secret: s, model: model, editing: $editing, confirmDelete: $confirmDelete)
                            .padding(6)
                            .frame(maxWidth: .infinity, alignment: .topLeading)
                    } label: {
                        plain("Secret: " + s.name).font(.headline)
                    }
                } else {
                    Text("Select a secret on the left").foregroundStyle(.secondary)
                }
                Spacer()
            }
            .padding(.leading)
            .frame(minWidth: 480, maxWidth: .infinity, alignment: .topLeading)
        }
        .task { await model.refresh(); await apps.refresh() }
        .task(id: selection) { if let n = selection { await model.loadActivity(n) } }
        .sheet(isPresented: $adding) { AddSecretSheet(model: model) { added($0) } }
        .sheet(item: $editing) { e in RuleSheet(edit: e, apps: apps.apps) }
        .alert("Delete this secret?", isPresented: Binding(get: { confirmDelete != nil }, set: { if !$0 { confirmDelete = nil } })) {
            Button("Delete", role: .destructive) {
                if let s = confirmDelete { Task { await model.delete(s) } }
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("The value is erased for good; nazar asks for Touch ID / Watch / password first. config.yaml keeps its entry. This can't be undone.")
        }
    }

    /// After an Add: select the secret and, as it has no rule yet (the
    /// window is not a terminal), open its rule sheet. Opening
    /// it changes nothing; saving a rule is a loosening with its own prompt.
    func added(_ name: String) {
        selection = name
        if let s = model.ruleless(name) {
            editing = RuleEdit(kind: .add, draft: RuleDraft(apps: [])) { _ = await model.addRule(to: s, $0) }
        }
    }
}

/// One secret's page: why it can't be used, when it was added, how it is
/// delivered, its warnings, its rules (the SSH keys tab's RuleRows), and
/// its audit lines of the last 24 hours.
struct SecretDetail: View {
    let secret: Secret
    @ObservedObject var model: SecretsModel
    @Binding var editing: RuleEdit?
    @Binding var confirmDelete: Secret?

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            if secret.broken {
                plain(secret.unusableReason ?? "").foregroundStyle(.red)
                plain("fix: " + (secret.remedy ?? "")).font(.caption).textSelection(.enabled)
            } else if !secret.stored {
                Text("No value is stored under this name; config.yaml keeps its entry. Add the secret again to store one.")
                    .foregroundStyle(.orange)
            }
            if let c = secret.created { plain("Added " + c.formatted()).font(.caption) }
            let lock = Presentation.lockBadge(secret)
            if !lock.isEmpty { plain(lock + ": the chip refuses it while the Mac is locked").font(.caption) }
            plain(Presentation.delivery(secret.deliver)).font(.caption)
            ForEach(Array(secret.warnings.enumerated()), id: \.offset) { _, w in plain(w).font(.caption).foregroundStyle(.orange) }
            if let p = secret.policy {
                if Presentation.blocksEveryApp(p) { Text("Blocked for every app until you add a rule.").foregroundStyle(.orange) }
                RuleRows(policy: p, setCommand: "nazar secret rule set", editing: $editing,
                         edit: { r in RuleEdit(kind: .change(r.index), draft: RuleDraft(r)) { _ = await model.updateRule(of: secret, index: r.index, $0) } },
                         remove: { i in Task { await model.removeRule(of: secret, index: i) } })
            }
            HStack {
                Button("Add rule…") { editing = RuleEdit(kind: .add, draft: RuleDraft(apps: [])) { _ = await model.addRule(to: secret, $0) } }
                Button("Delete…", role: .destructive) { confirmDelete = secret }.disabled(!secret.stored)
            }
            RecentActivity(log: model.activityLog, target: SecretsModel.target(secret.name))
        }
    }
}

/// Add a secret: a name and a hidden value. The value lives only in this
/// sheet's hidden field: on Add it becomes a CLIInput (written to `nazar
/// secret add NAME`'s stdin, then wiped) and the field is emptied in the
/// next statement; Cancel and closing the sheet empty it too. No content
/// type is set, so nothing asks the system to fill or save it.
struct AddSecretSheet: View {
    let model: SecretsModel
    let added: (String) -> Void
    @Environment(\.dismiss) var dismiss
    @State private var name = ""
    @State private var value = ""
    @State private var onlyWhenUnlocked = false

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("New secret").font(.headline)
            Grid(alignment: .leadingFirstTextBaseline, horizontalSpacing: 12, verticalSpacing: 10) {
                GridRow {
                    Text("Name").gridColumnAlignment(.trailing)
                    TextField("", text: $name, prompt: Text("GH_TOKEN"))
                }
                GridRow {
                    Text("Value")
                    SecureField("", text: $value)
                }
            }
            VStack(alignment: .leading, spacing: 2) {
                Toggle(isOn: $onlyWhenUnlocked) { plain(Presentation.onlyWhenUnlockedLabel) }
                plain(Presentation.onlyWhenUnlockedHelp).font(.caption).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Text("nazar asks for Touch ID / Watch / password once. The secret starts blocked for every app; you add who may use it next. The value is never shown again.")
                .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            HStack {
                Spacer()
                Button("Cancel") { value = ""; dismiss() }.keyboardShortcut(.cancelAction)
                Button("Add") { add() }
                    .keyboardShortcut(.defaultAction)
                    .disabled(name.isEmpty || value.isEmpty)
            }
        }
        .padding(20)
        .frame(width: 480)
        .onDisappear { value = "" }
    }

    func add() {
        let input = CLIInput(value)
        value = ""
        let n = name
        dismiss()
        let unlocked = onlyWhenUnlocked
        Task { if case .done = await model.add(name: n, value: input, onlyWhenUnlocked: unlocked) { added(n) } }
    }
}
