import SwiftUI

// MARK: Kubernetes (Milestone 13)

/// The Kubernetes tab, laid out like Secrets: the contexts on the left,
/// the selected one's page on the right. Cluster, CA, identity,
/// warnings, rules (the shared RuleRows and RuleSheet, without a receiver
/// field) and recent audit lines (the shared RecentActivity); Forget…
/// after an alert. No set-up: with no context the tab shows the CLI steps.
struct K8sTab: View {
    @ObservedObject var model: K8sModel
    @ObservedObject var apps: AppsModel
    @State private var selection: String?
    @State private var editing: RuleEdit?
    @State private var confirmForget: K8sContext?

    // Explicit: the private @State properties make the memberwise init private.
    init(model: K8sModel, apps: AppsModel) {
        self.model = model
        self.apps = apps
    }

    var body: some View {
        HSplitView {
            // Left: every context, and the actions that are about the list.
            VStack(alignment: .leading, spacing: 8) {
                Text("Contexts").font(.headline)
                List(selection: $selection) {
                    ForEach(model.contexts) { c in
                        VStack(alignment: .leading) {
                            plain(c.name).bold()
                            let state = Presentation.k8sState(c)
                            if !state.isEmpty { plain(state).font(.caption) }
                        }
                        .tag(c.name)
                    }
                }
                Button("Refresh") { Task { await model.refresh() } }
                if let e = model.error { plain(e).font(.caption).foregroundStyle(.red) }
            }
            .padding(.trailing, 8)
            .frame(minWidth: 180, idealWidth: 220, maxWidth: 280)
            // Right: the selected context's page, or how to make one.
            VStack(alignment: .leading, spacing: 8) {
                if let c = model.contexts.first(where: { $0.name == selection }) {
                    GroupBox {
                        K8sDetail(context: c, model: model, editing: $editing, confirmForget: $confirmForget)
                            .padding(6)
                            .frame(maxWidth: .infinity, alignment: .topLeading)
                    } label: {
                        plain("Context: " + c.name).font(.headline)
                    }
                } else if model.contexts.isEmpty && model.error == nil {
                    K8sSetupSteps()
                } else {
                    Text("Select a context on the left").foregroundStyle(.secondary)
                }
                Spacer()
            }
            .padding(.leading)
            .frame(minWidth: 480, maxWidth: .infinity, alignment: .topLeading)
        }
        .task { await model.refresh(); await apps.refresh() }
        .task(id: selection) { if let n = selection { await model.loadActivity(n) } }
        .sheet(item: $editing) { e in RuleSheet(edit: e, apps: apps.apps) }
        .alert("Forget this context?", isPresented: Binding(get: { confirmForget != nil }, set: { if !$0 { confirmForget = nil } })) {
            Button("Forget", role: .destructive) {
                if let c = confirmForget { Task { await model.forget(c) } }
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            plain(Presentation.forgetK8sMessage)
        }
    }
}

/// One context's page: what is wrong and its fix, the cluster, the CA, the
/// identity and certificate lifetime, its warnings, its rules (no
/// receiver: the program that runs the plugin is) and its audit lines.
struct K8sDetail: View {
    let context: K8sContext
    @ObservedObject var model: K8sModel
    @Binding var editing: RuleEdit?
    @Binding var confirmForget: K8sContext?

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            let problem = Presentation.k8sProblem(context)
            if !problem.isEmpty {
                plain(problem).foregroundStyle(context.caBroken ? .red : .orange)
                if let r = context.remedy, !r.isEmpty { plain("fix: " + r).font(.caption).textSelection(.enabled) }
            }
            if let cl = context.cluster { plain(Presentation.k8sCluster(cl)).textSelection(.enabled) }
            if let ca = context.ca { plain(Presentation.k8sCA(ca)).font(.system(.caption, design: .monospaced)).textSelection(.enabled) }
            if let id = context.identity { plain(Presentation.k8sIdentity(id, ttl: context.ttlCert)).font(.caption) }
            ForEach(Array(context.warnings.enumerated()), id: \.offset) { _, w in plain(w).font(.caption).foregroundStyle(.orange) }
            if let p = context.policy {
                if Presentation.blocksEveryApp(p) { Text("Blocked for every app until you add a rule.").foregroundStyle(.orange) }
                RuleRows(policy: p, setCommand: "nazar k8s rule set", editing: $editing,
                         edit: { r in RuleEdit(kind: .change(r.index), draft: RuleDraft(r), receivers: false) { _ = await model.updateRule(of: context, index: r.index, $0) } },
                         remove: { i in Task { await model.removeRule(of: context, index: i) } })
            }
            HStack {
                // A context config.yaml doesn't have takes no rule (the agent
                // refuses one): the fix line says how to set it up.
                if context.policy != nil {
                    Button("Add rule…") { editing = RuleEdit(kind: .add, draft: RuleDraft(apps: []), receivers: false) { _ = await model.addRule(to: context, $0) } }
                }
                Button("Forget…", role: .destructive) { confirmForget = context }
            }
            RecentActivity(log: model.activityLog, target: K8sModel.target(context.name))
        }
    }
}

/// No context yet: the CLI steps (docs/CLI.md, Kubernetes). The window
/// doesn't set a context up: that asks at a terminal and touches the
/// kubeconfig, which it never reads.
struct K8sSetupSteps: View {
    @State private var hints = false
    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("No Kubernetes contexts yet.").bold()
            Text("Set one up in a terminal.").foregroundStyle(.secondary)
            Button { hints.toggle() } label: { Label("Hints", systemImage: "lightbulb") }
                .popover(isPresented: $hints, arrowEdge: .bottom) {
                    VStack(alignment: .leading, spacing: 10) {
                        ForEach(Presentation.k8sSetup, id: \.command) { s in
                            VStack(alignment: .leading, spacing: 2) {
                                plain(s.title).font(.callout.weight(.semibold))
                                plain(s.command).font(.system(.callout, design: .monospaced)).textSelection(.enabled)
                            }
                        }
                    }
                    .padding()
                }
        }
    }
}
