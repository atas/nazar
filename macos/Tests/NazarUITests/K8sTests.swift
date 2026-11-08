import Foundation
import Testing
@testable import NazarUI

// The Kubernetes tab through its model, against a FakeCLIRunner
// that answers with the real CLI's recorded output (Fixtures/k8s-*.jsonl).
// Nothing is run, nothing is put on screen, no keychain is touched. The tab
// runs k8s list, k8s rule add|set|remove (never with a receiver), k8s
// forget and log --target k8s:NAME, and nothing else of k8s.
@MainActor
@Suite(.serialized) struct K8sTests {
    func world() -> (FakeCLIRunner, K8sModel) {
        let r = FakeCLIRunner()
        let c = CLIClient(runner: r)
        return (r, K8sModel(client: c, changes: ChangeRunner(client: c)))
    }

    @Test func refreshShowsEachContextsStateAndRules() async throws {
        let (r, m) = world()
        r.on(["k8s", "list"], try Fixture.result("k8s-list", exit: 0))
        await m.refresh()
        #expect(m.contexts.map(\.name) == ["hydra", "hydra.eks", "loose"] && m.error == nil)
        try #require(m.contexts.count == 3)
        #expect(m.contexts.map(\.state) == ["ok", "no-ca", "no-entry"])
        #expect(m.contexts[0].policy?.rules.count == 1 && m.contexts[1].policy?.rules.isEmpty == true && m.contexts[2].policy == nil)
        #expect(r.calls == [["--json", "k8s", "list"]])
    }

    @Test func unavailableIsShown() async throws {
        let (r, m) = world()
        r.on(["k8s", "list"], try Fixture.result("unavailable", exit: 5))
        await m.refresh()
        #expect(m.contexts.isEmpty && (m.error ?? "").contains("isn't running"))
    }

    /// A context's rules are edited with the key's commands under `k8s`: a
    /// new rule (a loosening) is written and approved on the gate in the one
    /// run (--allow-loosen-access, exit 0); a change and a removal as the
    /// CLI answers them. Every edit carries the hash of the config the rules
    /// were read from and the flag; none carries --to or --no-to, not even
    /// from a draft that names a receiver; no edit has input; no `config
    /// apply` runs.
    @Test func ruleEditsAreTheK8sRuleCommands() async throws {
        let (r, m) = world()
        r.on(["k8s", "list"], try Fixture.result("k8s-list", exit: 0))
        r.on(["k8s", "rule", "add"], try Fixture.result("k8s-rule-approved", exit: 0))
        r.on(["k8s", "rule", "set"], try Fixture.result("k8s-rule-applied", exit: 0))
        r.on(["k8s", "rule", "remove"], try Fixture.result("k8s-rule-applied", exit: 0))
        await m.refresh()
        let hydra = try #require(m.contexts.first)
        let rule = RuleDraft(apps: ["signed:Q6L2SF6YDW:com.anthropic.claude-code"], to: ["kubectl"], scope: "use", gate: "login")
        #expect(await m.addRule(to: hydra, rule) == .done("Rule added to hydra"))
        let first = try #require(m.contexts.first?.policy?.rules.first)
        #expect(await m.updateRule(of: m.contexts[0], index: 1, RuleDraft(first)) == .done("Rule 1 of hydra changed"))
        #expect(await m.removeRule(of: m.contexts[0], index: 1) == .done("Rule 1 of hydra removed"))
        #expect(r.calls == [
            ["--json", "k8s", "list"],
            ["--json", "k8s", "rule", "add", "hydra", "--apps", "signed:Q6L2SF6YDW:com.anthropic.claude-code",
             "--scope", "use", "--gate", "login", "--if-hash", "HASH", "--allow-loosen-access"],
            ["--json", "k8s", "list"],
            ["--json", "k8s", "rule", "set", "hydra", "1", "--apps", "iterm", "--scope", "session", "--gate", "login",
             "--expire", "8h", "--if-hash", "HASH", "--allow-loosen-access"],
            ["--json", "k8s", "list"],
            ["--json", "k8s", "rule", "remove", "hydra", "1", "--if-hash", "HASH", "--allow-loosen-access"],
            ["--json", "k8s", "list"],
        ])
        #expect(!r.calls.joined().contains { $0 == "--to" || $0 == "--no-to" })
        #expect(r.inputs.allSatisfy { $0 == nil })
    }

    /// Forget runs `nazar k8s forget NAME`; the agent asks on its own
    /// screen. A denial is reported, never retried; refused while a change
    /// waits for approval (exit 4 with nothing to approve), it approves
    /// nothing: no config apply runs.
    @Test func forgetRunsK8sForgetAndApprovesNothing() async throws {
        let cases: [(String, Int32, ChangeResult)] = [
            ("k8s-forget-denied", 3, .notApproved("not forgotten: user denied")),
            ("k8s-forget-staged", 4, .stillStaged("config.yaml has changes that aren't approved yet; run `nazar config check`")),
            ("k8s-forget", 0, .done("Forgot hydra")),
        ]
        for (fixture, exit, want) in cases {
            let (r, m) = world()
            r.on(["k8s", "list"], try Fixture.result("k8s-list", exit: 0))
            r.on(["k8s", "forget"], try Fixture.result(fixture, exit: exit))
            await m.refresh()
            let hydra = try #require(m.contexts.first, "\(fixture)")
            #expect(await m.forget(hydra) == want, "\(fixture)")
            #expect(r.calls == [["--json", "k8s", "list"], ["--json", "k8s", "forget", "hydra"], ["--json", "k8s", "list"]], "\(fixture)")
            #expect(!m.changes.busy && !m.changes.waitingForApproval, "\(fixture)")
        }
    }

    /// Recent activity is the context's own audit lines (`nazar log --since
    /// 24h --target k8s:NAME`), newest first, shown only under the target it
    /// was read for: never under hydra.eks, nor a secret named hydra.
    @Test func activityIsTheContextsOwnLog() async throws {
        let (r, m) = world()
        r.on(["log"], try Fixture.result("k8s-log", exit: 0))
        #expect(m.activity(for: "hydra") == nil)
        await m.loadActivity("hydra")
        #expect(r.calls == [["--json", "log", "--since", "24h", "--target", "k8s:hydra"]])
        let events = try #require(m.activity(for: "hydra"))
        try #require(events.count == 2)
        #expect(events.allSatisfy { $0.fields["target"] == "k8s:hydra" })
        #expect(events[0].fields["decision"] == "blocked" && events[1].fields["decision"] == "approved")
        #expect(m.activity(for: "hydra.eks") == nil && m.activityLog.events(for: "secret:hydra") == nil && m.activityLog.error == nil)
    }

    // MARK: Edge and attack cases (test author)

    /// The shared reader keys its lines by the full target: a secret and a
    /// context of the same name never share a page's lines, and a target is
    /// the owner's prefix plus the exact name (no trimming, no folding).
    @Test func targetActivityKeysByTheFullTarget() async throws {
        #expect(K8sModel.target("hydra") == "k8s:hydra" && SecretsModel.target("hydra") == "secret:hydra")
        #expect(K8sModel.target("hydra.eks") == "k8s:hydra.eks" && K8sModel.target("Hydra") == "k8s:Hydra")
        #expect(TargetActivity.since == "24h" && TargetActivity.maxEvents == 50)
        let r = FakeCLIRunner()
        let log = TargetActivity(client: CLIClient(runner: r))
        r.on(["log"], try Fixture.result("k8s-log", exit: 0))
        #expect(log.events(for: "k8s:hydra") == nil)
        await log.load("k8s:hydra")
        #expect(log.events(for: "k8s:hydra")?.count == 2 && log.error == nil)
        #expect(log.events(for: "secret:hydra") == nil && log.events(for: "k8s:hydra.eks") == nil && log.events(for: "hydra") == nil)
        #expect(r.calls == [["--json", "log", "--since", "24h", "--target", "k8s:hydra"]])
    }

    /// A read that started earlier and ends later never replaces a later
    /// one: the slow read of hydra.eks can't put its lines (or hydra's) under
    /// the context now selected.
    @Test func theLatestActivityReadWins() async throws {
        let (r, m) = world()
        r.on(["log"], try Fixture.result("k8s-log", exit: 0))
        r.callDelay = .milliseconds(200)
        let slow = Task { await m.loadActivity("hydra.eks") }
        #expect(await eventually { r.calls.count == 1 })
        r.callDelay = .zero
        await m.loadActivity("hydra")
        await slow.value
        #expect(m.activity(for: "hydra") != nil && m.activity(for: "hydra.eks") == nil)
    }

    /// Edge: a log that can't be read shows why and keeps no lines.
    @Test func unreadableActivityShowsWhy() async throws {
        let (r, m) = world()
        r.on(["log"], try Fixture.result("unavailable", exit: 5))
        await m.loadActivity("hydra")
        #expect(m.activity(for: "hydra") == nil && (m.activityLog.error ?? "").contains("isn't running"))
        #expect(r.calls == [["--json", "log", "--since", "24h", "--target", "k8s:hydra"]])
    }

    /// Attack: a stale page. Each edit carries the hash its own context was
    /// read with, so an edit made from a page read before config.yaml
    /// changed is refused by the CLI (`--if-hash`), never applied to rules
    /// the user did not see.
    @Test func editsCarryTheHashTheirRulesWereReadFrom() async throws {
        let (r, m) = world()
        r.on(["k8s", "list"], try Fixture.result("k8s-list", exit: 0))
        r.on(["k8s", "rule", "remove"], CLIResult(exitCode: 1, stdout: Data("{\"apiVersion\":\"nazar/v1\",\"kind\":\"Problem\",\"code\":\"error\",\"message\":\"config.yaml changed since it was read; read it again (`nazar k8s list`)\"}\n".utf8)))
        await m.refresh()
        var hydra = try #require(m.contexts.first)
        hydra.policy?.configHash = "OLD"
        let got = await m.removeRule(of: hydra, index: 1)
        guard case .failed(let why) = got else { Issue.record("a refused edit is a failure: \(got)"); return }
        #expect(why.contains("changed since it was read"))
        #expect(r.calls.dropFirst().first == ["--json", "k8s", "rule", "remove", "hydra", "1", "--if-hash", "OLD", "--allow-loosen-access"])
        #expect(!r.calls.contains { $0.starts(with: ["--json", "config", "apply"]) })
    }

    /// Attack: the window holds no credential. A context decodes only public
    /// facts: no field could carry a key, a certificate, the CA file's path
    /// or the context's credential provider, even when the CLI's object has
    /// such fields (k8s list prints certFile, caSHA256, credential and the
    /// rule summaries; they are left out).
    @Test func aContextHoldsNoCredentialMaterial() throws {
        let l = try #require(CLIClient.outcome(try Fixture.result("k8s-list", exit: 0)).first(Kind.k8sContextList, as: K8sContextList.self))
        let hydra = try #require(l.items.first)
        func labels(_ v: Any) -> [String] { Mirror(reflecting: v).children.compactMap(\.label) }
        let ca = try #require(hydra.ca), cluster = try #require(hydra.cluster), id = try #require(hydra.identity)
        for (what, fields) in [("K8sContext", labels(hydra)), ("K8sCA", labels(ca)), ("K8sCluster", labels(cluster)), ("K8sIdentity", labels(id))] {
            for never in ["certPEM", "certFile", "caSHA256", "credential", "key", "privateKey", "token", "kubeconfig", "rules"] {
                #expect(!fields.contains(never), "\(what) has \(never)")
            }
        }
    }

    /// Attack: a context name is one argument in its place, never a flag or
    /// a second command, and a draft's receiver never leaves for a context,
    /// in add or set.
    @Test func k8sValuesStayInPlace() {
        #expect(UIAction.forgetK8s(name: "--all").argv == ["--json", "k8s", "forget", "--all"])
        #expect(UIAction.forgetK8s(name: "hydra; nazar k8s credential hydra").argv.count == 4)
        let hostile = RuleDraft(apps: ["path:/a b,c"], to: ["--gate", "none"], scope: "use", gate: "login")
        for a in [UIAction.addRule(.k8s("x y"), rule: hostile, ifHash: "h"), .setRule(.k8s("x y"), index: 1, rule: hostile, ifHash: "h")] {
            #expect(a.argv[4] == "x y" && a.argv.contains("path:/a b,c"), "\(a)")
            #expect(!a.argv.contains("--to") && !a.argv.contains("--no-to") && !a.argv.contains("none"), "\(a)")
            #expect(a.argv.filter { $0 == "--gate" }.count == 1, "\(a)")
        }
    }
}
