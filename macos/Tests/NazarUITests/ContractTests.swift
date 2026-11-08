import Foundation
import Testing
@testable import NazarUI

// The window runs the CLI and nothing else (spec 6.1). Every command line
// it can produce has a template here, Fixtures/ui-actions.json pins the
// list, and cmd/nazar's TestUIActionsAreRealCommands runs each template
// against the real CLI and core: a window action that is not a CLI command
// fails one side or the other.
@Suite struct ContractTests {
    static let file = "ui-actions.json"

    @Test func templatesArePinned() throws {
        let templates = UIAction.samples.map(\.template)
        if ProcessInfo.processInfo.environment["NAZAR_UPDATE_FIXTURES"] == "1" {
            var out = "[\n"
            out += templates.map { t in
                "  [" + t.map { "\"\($0)\"" }.joined(separator: ", ") + "]"
            }.joined(separator: ",\n")
            out += "\n]\n"
            try Data(out.utf8).write(to: Fixture.dir.appendingPathComponent(Self.file))
        }
        let pinned = try JSONDecoder().decode([[String]].self, from: Fixture.data(Self.file))
        #expect(pinned == templates, "UIAction changed: run NAZAR_UPDATE_FIXTURES=1 swift test --filter ContractTests, then go test ./cmd/nazar -run TestUIActionsAreRealCommands")
    }

    /// argv is the template with values filled in: same length, same
    /// literal words, --json first; every value is its own argument (no
    /// shell, no splitting).
    @Test func argvFitsItsTemplate() {
        for a in UIAction.samples {
            let argv = a.argv, t = a.template
            #expect(argv.count == t.count && argv.first == "--json", "\(a)")
            for (w, p) in zip(argv, t) where !p.hasPrefix("<") {
                #expect(w == p, "\(a): \(w) vs \(p)")
            }
        }
    }

    /// Hostile values stay single arguments, and a value that starts with
    /// "-" can't turn into a flag where the CLI takes positionals.
    @Test func valuesAreSingleArguments() {
        let a = UIAction.addRule(.key("github"), rule: RuleDraft(apps: ["path:/a b,c; rm -rf ~", "iterm"], gate: "login"), ifHash: "h")
        #expect(a.argv.contains("path:/a b,c; rm -rf ~"))
        #expect(a.argv.filter { $0 == "--apps" }.count == 2)
    }

    /// Every edit carries --allow-loosen-access once, at the end, and
    /// nothing else does: the window makes the change the person asked for
    /// (the gate is the agent's), and never runs `config apply` with a hash
    /// (the CLI binds the approval itself).
    @Test func editsCarryTheFlagAndNothingElseDoes() {
        for a in UIAction.samples {
            let t = a.template
            let edit = ["rule", "set"].contains(t.dropFirst(2).first ?? "") && ["ssh-key", "secret", "k8s"].contains(t[1])
            #expect(t.filter { $0 == "--allow-loosen-access" }.count == (edit ? 1 : 0), "\(t)")
            if edit { #expect(t.last == "--allow-loosen-access", "\(t)") }
            #expect(!t.contains("--hash"), "\(t)")
        }
        #expect(UIAction.configApply.argv == ["--json", "config", "apply"])
    }

    /// Every case appears in samples (a new case must get a template).
    @Test func samplesCoverEveryCase() {
        func name(_ a: UIAction) -> String { String(describing: a).split(separator: "(").first.map(String.init) ?? "" }
        let names = Set(UIAction.samples.map(name))
        #expect(names.count == 25, "\(names.sorted())")
    }

    // MARK: Edge and attack cases (test author)

    /// The Secrets tab's commands. Add sends the name only (its value
    /// goes to stdin, and it is the one action that reads stdin); a secret's
    /// rule edits are the key's words under `secret`, so a key and a secret
    /// of the same name are never confused; the window runs no value
    /// command (get, run).
    @Test func secretActions() {
        #expect(UIAction.listSecrets.argv == ["--json", "secret", "list"])
        #expect(UIAction.addSecret(name: "GH_TOKEN").argv == ["--json", "secret", "add", "GH_TOKEN"])
        #expect(UIAction.addSecret(name: "GH_TOKEN", onlyWhenUnlocked: true).argv == ["--json", "secret", "add", "GH_TOKEN", "--only-when-unlocked"])
        #expect(UIAction.removeSecret(name: "GH_TOKEN").argv == ["--json", "secret", "rm", "GH_TOKEN"])
        #expect(UIAction.samples.filter(\.readsInput) == [.addSecret(name: "GH_TOKEN"), .addSecret(name: "GH_TOKEN", onlyWhenUnlocked: true)])
        #expect(!UIAction.samples.contains { ["get", "run"].contains($0.template.dropFirst().first ?? "") })
        #expect(UIAction.removeRule(.secret("github"), index: 1, ifHash: "h").argv
            == ["--json", "secret", "rule", "remove", "github", "1", "--if-hash", "h", "--allow-loosen-access"])
        #expect(UIAction.removeRule(.key("github"), index: 1, ifHash: "h").argv
            == ["--json", "ssh-key", "rule", "remove", "github", "1", "--if-hash", "h", "--allow-loosen-access"])
        let r = RuleDraft(apps: ["iterm"], to: ["git-https"], scope: "use", gate: "login", expire: "1h")
        #expect(UIAction.addRule(.secret("github"), rule: r, ifHash: "h").argv.dropFirst(5)
            == UIAction.addRule(.key("github"), rule: r, ifHash: "h").argv.dropFirst(5))
        #expect(UIAction.setRule(.secret("github"), index: 2, rule: r, ifHash: "h").template.prefix(6)
            == ["--json", "secret", "rule", "set", "<secret>", "<n>"])
        #expect(UIAction.log(since: "24h", target: "secret:GH_TOKEN").argv == ["--json", "log", "--since", "24h", "--target", "secret:GH_TOKEN"])
        #expect(UIAction.log(since: "1h").argv == ["--json", "log", "--since", "1h"])
        #expect(UIAction.log(since: "24h", target: "secret:x --follow").argv.last == "secret:x --follow")
    }

    /// The Kubernetes tab's commands: list, a context's rule edits
    /// (the key's words under `k8s`, never --to or --no-to: the program that
    /// runs the plugin is the receiver, and the CLI refuses both), forget. It runs
    /// no k8s ca or credential command (nor the import that is gone), and
    /// none reads stdin.
    @Test func k8sActions() {
        #expect(UIAction.listK8s.argv == ["--json", "k8s", "list"])
        #expect(UIAction.forgetK8s(name: "hydra").argv == ["--json", "k8s", "forget", "hydra"])
        let r = RuleDraft(apps: ["iterm"], to: ["kubectl"], scope: "session", gate: "login", expire: "8h")
        #expect(UIAction.addRule(.k8s("hydra"), rule: r, ifHash: "h").argv
            == ["--json", "k8s", "rule", "add", "hydra", "--apps", "iterm", "--scope", "session", "--gate", "login", "--expire", "8h", "--if-hash", "h", "--allow-loosen-access"])
        #expect(UIAction.setRule(.k8s("hydra"), index: 2, rule: RuleDraft(apps: ["iterm"]), ifHash: "h").argv
            == ["--json", "k8s", "rule", "set", "hydra", "2", "--apps", "iterm", "--scope", "session", "--gate", "login", "--no-expire", "--if-hash", "h", "--allow-loosen-access"])
        #expect(UIAction.removeRule(.k8s("hydra"), index: 1, ifHash: "h").argv == ["--json", "k8s", "rule", "remove", "hydra", "1", "--if-hash", "h", "--allow-loosen-access"])
        #expect(UIAction.removeRule(.secret("hydra"), index: 1, ifHash: "h").argv[1] == "secret"
            && UIAction.removeRule(.key("hydra"), index: 1, ifHash: "h").argv[1] == "ssh-key")
        #expect(RuleOwner.key("a").receivers && RuleOwner.secret("a").receivers && !RuleOwner.k8s("a").receivers)
        let k8s = UIAction.samples.filter { $0.template.dropFirst().first == "k8s" }
        #expect(k8s.map { $0.template[2] } == ["list", "rule", "rule", "rule", "rule", "rule", "forget"])
        #expect(!k8s.flatMap(\.template).contains { ["--to", "--no-to", "ca", "import", "credential"].contains($0) })
        #expect(!k8s.contains { $0.readsInput })
        #expect(UIAction.log(since: "24h", target: "k8s:hydra").argv == ["--json", "log", "--since", "24h", "--target", "k8s:hydra"])
    }

    /// The window creates a key by name alone; nazar-agent decides
    /// its entry and protection, so no gate or scope is ever sent (the agent
    /// refuses them with a usage error). The choices are --always-ask (the
    /// sheet's checkbox): a key the chip asks for on every use, and
    /// --only-when-unlocked: a key the chip refuses while the Mac is locked,
    /// which --always-ask implies (so it is not sent with it).
    @Test func createKeySendsTheNameAndAtMostOneFlag() {
        #expect(UIAction.createKey(name: "github").argv == ["--json", "ssh-key", "create", "github"])
        #expect(UIAction.createKey(name: "prod", alwaysAsk: true).argv == ["--json", "ssh-key", "create", "prod", "--always-ask"])
        #expect(UIAction.createKey(name: "prod", alwaysAsk: true, onlyWhenUnlocked: true).argv == ["--json", "ssh-key", "create", "prod", "--always-ask"])
        #expect(UIAction.createKey(name: "laptop", onlyWhenUnlocked: true).argv == ["--json", "ssh-key", "create", "laptop", "--only-when-unlocked"])
        #expect(UIAction.samples.filter { $0.template.starts(with: ["--json", "ssh-key", "create"]) }.map(\.template)
            == [["--json", "ssh-key", "create", "<key>"], ["--json", "ssh-key", "create", "<key>", "--always-ask"],
                ["--json", "ssh-key", "create", "<key>", "--only-when-unlocked"]])
    }

    /// Only the two --follow actions stream, and they are exactly the
    /// templates with --follow.
    @Test func followsMatchesTheTemplate() {
        for a in UIAction.samples {
            #expect(a.follows == a.template.contains("--follow"), "\(a)")
        }
        #expect(UIAction.samples.filter(\.follows) == [.followStatus, .followLog])
    }

    /// Values from the CLI's own output or from config.yaml (paths, session
    /// ids, bundle ids, durations) are each exactly one argument, in place.
    @Test func hostileValuesStayInPlace() {
        let id = "com.x b; $(rm -rf ~) `id` \n--all"
        #expect(UIAction.revokeApp(id).argv == ["--json", "revoke", "--app", id])
        #expect(UIAction.revokeSession("--all").argv == ["--json", "revoke", "--session", "--all"])
        #expect(UIAction.revokeApp("x --all").argv == ["--json", "revoke", "--app", "x --all"])
        #expect(UIAction.log(since: "1h --follow").argv == ["--json", "log", "--since", "1h --follow"])
        #expect(!UIAction.log(since: "1h --follow").follows)
        let r = RuleDraft(apps: ["a,b"], to: ["path:/x y"], scope: "use", gate: "none", expire: "1h")
        let argv = UIAction.setRule(.key("github"), index: 3, rule: r, ifHash: "--x").argv
        #expect(argv == ["--json", "ssh-key", "rule", "set", "github", "3", "--apps", "a,b", "--to", "path:/x y",
                         "--scope", "use", "--gate", "none", "--expire", "1h", "--if-hash", "--x", "--allow-loosen-access"])
    }

    /// Editing an existing rule starts from what the CLI listed: matcher
    /// references, scope, gate, no expiry; a set without to/expire clears them.
    @Test func ruleDraftOfAnExistingRule() throws {
        let l = try #require(CLIClient.outcome(try Fixture.result("ssh-key-list", exit: 0)).first(Kind.sshKeyList, as: SSHKeyList.self))
        let rules = try #require(l.items.first?.policy?.rules)
        #expect(RuleDraft(rules[0]) == RuleDraft(apps: ["iterm"], to: [], scope: "session", gate: "dialog", expire: ""))
        #expect(RuleDraft(rules[1]) == RuleDraft(apps: ["kubectl"], to: [], scope: "use", gate: "login", expire: ""))
        #expect(UIAction.setRule(.key("github"), index: 2, rule: RuleDraft(rules[1]), ifHash: "HASH").argv
            == ["--json", "ssh-key", "rule", "set", "github", "2", "--apps", "kubectl", "--no-to", "--scope", "use",
                "--gate", "login", "--no-expire", "--if-hash", "HASH", "--allow-loosen-access"])
        // add has no --no-to / --no-expire (nothing to clear).
        #expect(!UIAction.addRule(.key("github"), rule: RuleDraft(rules[1]), ifHash: "HASH").argv.contains { $0.hasPrefix("--no-") })
    }

    /// Spec 6.1: the app only ever runs a CLI whose running process passed
    /// the signature check. Outside CLIRunner.swift every ProcessCLIRunner
    /// is made with a requirement (the unchecked init is for the tests'
    /// shell scripts), and the app's session is wired to that one factory.
    @Test func onlyTheVerifiedRunnerIsWired() throws {
        let src = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
            .appendingPathComponent("../../Sources/NazarUI").standardizedFileURL
        let files = try #require(FileManager.default.enumerator(at: src, includingPropertiesForKeys: nil)?
            .compactMap { $0 as? URL }.filter { $0.pathExtension == "swift" && $0.lastPathComponent != "CLIRunner.swift" })
        var calls = 0
        for f in files {
            let text = try String(contentsOf: f, encoding: .utf8)
            for part in text.components(separatedBy: "ProcessCLIRunner(").dropFirst() {
                calls += 1
                let args = part.prefix { $0 != ")" }
                #expect(args.contains("requirement:"), "\(f.lastPathComponent): ProcessCLIRunner(\(args)) is not the checked runner")
            }
        }
        #expect(calls == 1, "\(calls) ProcessCLIRunner calls outside CLIRunner.swift; the app has one, UISession.verifiedRunner")
        let session = try String(contentsOf: src.appendingPathComponent("UISession.swift"), encoding: .utf8)
        #expect(session.contains("static let verifiedRunner: (URL, CLIRequirement) -> CLIRunner = { ProcessCLIRunner(cli: $0, requirement: $1) }"))
        #expect(session.contains("makeRunner: verifiedRunner)"), "forThisApp does not wire verifiedRunner")
    }

    /// Spec 6.1: NazarUI is a thin client of the installed agent's CLI. Its
    /// sources import only Foundation, the UI frameworks and Security (for
    /// code-signature checks only: no Keychain call, no NazarPlatform, no
    /// CNazarBridge/CNazarCore, no sockets), and only CLIRunner.swift
    /// starts a process.
    @Test func sourcesStayAThinClient() throws {
        let src = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
            .appendingPathComponent("../../Sources/NazarUI").standardizedFileURL
        let files = try #require(FileManager.default.enumerator(at: src, includingPropertiesForKeys: nil)?
            .compactMap { $0 as? URL }.filter { $0.pathExtension == "swift" })
        #expect(!files.isEmpty)
        let allowed: Set<String> = ["Foundation", "SwiftUI", "AppKit", "Combine", "Observation", "Security"]
        for f in files {
            let text = try String(contentsOf: f, encoding: .utf8)
            for line in text.split(separator: "\n") {
                let t = line.trimmingCharacters(in: .whitespaces)
                guard t.hasPrefix("import ") || t.hasPrefix("@testable import ") || t.hasPrefix("@_exported import ") else { continue }
                let module = t.split(separator: " ").last.map(String.init) ?? ""
                #expect(allowed.contains(module), "\(f.lastPathComponent): \(t)")
            }
            let code = text.split(separator: "\n").filter { !$0.trimmingCharacters(in: .whitespaces).hasPrefix("//") }.joined(separator: "\n")
            for never in ["NazarPlatform", "CNazarBridge", "CNazarCore", "socket(", "connect(", "SecItem", "SecKeychain", "SecTrustedApplication", "SecAccess",
                          "LAContext", "/usr/bin/env", "launchPath", "contentsOfFile: \"", "config.yaml\")",
                          // The Kubernetes tab never reads the kubeconfig.
                          ".kube/", "KUBECONFIG",
                          // Nothing is logged or dumped (a value must never reach a log).
                          "print(", "NSLog(", "os_log(", "Logger(", "dump("] {
                #expect(!code.contains(never), "\(f.lastPathComponent) uses \(never)")
            }
            if f.lastPathComponent != "CLIRunner.swift" {
                #expect(!code.contains("Process()"), "\(f.lastPathComponent) starts a process")
            }
        }
    }
}
