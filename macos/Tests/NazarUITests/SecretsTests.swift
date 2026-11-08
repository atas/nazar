import Foundation
import Testing
@testable import NazarUI

// The Secrets tab through its model, against a FakeCLIRunner that
// answers with the real CLI's recorded output (Fixtures/secret-*.jsonl).
// Nothing is run, nothing is put on screen, no keychain is touched. A value
// exists here only as a CLIInput: it goes to the stdin of `nazar secret add
// NAME` and nowhere else, and is wiped when the call returns.
@MainActor
@Suite(.serialized) struct SecretsTests {
    static let value = "m11-02-test-value-7c1d"

    func world() -> (FakeCLIRunner, SecretsModel) {
        let r = FakeCLIRunner()
        let c = CLIClient(runner: r)
        return (r, SecretsModel(client: c, changes: ChangeRunner(client: c)))
    }

    /// No argument of any run carries the value.
    func argsHoldNoValue(_ r: FakeCLIRunner) -> Bool { !r.calls.joined().contains { $0.contains(Self.value) } }

    @Test func refreshShowsEachSecretsStateDeliveryAndRules() async throws {
        let (r, m) = world()
        r.on(["secret", "list"], try Fixture.result("secret-list", exit: 0))
        await m.refresh()
        #expect(m.secrets.map(\.name) == ["GH_TOKEN", "NOTES"] && m.error == nil)
        try #require(m.secrets.count == 2)
        let gh = m.secrets[0], notes = m.secrets[1]
        #expect(gh.stored && !gh.broken && gh.deliver == ["helper", "stdout"] && gh.policy?.rules.count == 1 && gh.warnings.count == 1)
        #expect(notes.stored && notes.policy?.rules.isEmpty == true && notes.policy?.fallbackSource == "secret-gate")
        #expect(m.ruleless("NOTES")?.name == "NOTES" && m.ruleless("GH_TOKEN") == nil && m.ruleless("NOPE") == nil)
        #expect(r.calls == [["--json", "secret", "list"]])
    }

    @Test func unavailableIsShown() async throws {
        let (r, m) = world()
        r.on(["secret", "list"], try Fixture.result("unavailable", exit: 5))
        await m.refresh()
        #expect(m.secrets.isEmpty && (m.error ?? "").contains("isn't running"))
    }

    /// Add: the name is the only argument; the value is that one run's
    /// stdin, no other run gets input, no argument holds it, and the input
    /// is wiped when add returns.
    @Test func addSendsTheValueOnStdinOnly() async throws {
        let (r, m) = world()
        r.on(["secret", "add"], try Fixture.result("secret-add-window", exit: 0))
        r.on(["secret", "list"], try Fixture.result("secret-list", exit: 0))
        let input = CLIInput(Self.value)
        #expect(await m.add(name: "NOTES", value: input) == .done("Added NOTES"))
        #expect(r.calls == [["--json", "secret", "add", "NOTES"], ["--json", "secret", "list"]])
        #expect(r.inputs == [Data(Self.value.utf8), nil])
        #expect(input.isWiped && argsHoldNoValue(r))
        // Added from the window: no rule yet, so the tab opens the rule sheet.
        #expect(m.ruleless("NOTES") != nil)
        // The sheet's checkbox adds --only-when-unlocked; the value still
        // goes on stdin only.
        let again = CLIInput(Self.value)
        #expect(await m.add(name: "NOTES", value: again, onlyWhenUnlocked: true) == .done("Added NOTES"))
        #expect(r.calls.suffix(2) == [["--json", "secret", "add", "NOTES", "--only-when-unlocked"], ["--json", "secret", "list"]])
        #expect(again.isWiped && argsHoldNoValue(r))
    }

    /// secret add without its value runs nothing (CLIClient's guard).
    @Test func addNeedsItsValue() async {
        let (r, m) = world()
        let out = await m.client.call(.addSecret(name: "NOTES"))
        #expect(out.problem == Problem(code: "usage", message: "nazar secret add needs its value") && r.calls.isEmpty)
    }

    /// Refused at the prompt (exit 3), or refused before it because
    /// config.yaml has a change waiting (exit 4 with nothing to approve):
    /// the result is the CLI's own words, nothing is retried or approved,
    /// and the input is wiped.
    @Test func aRefusedAddIsNeverRetried() async throws {
        let cases: [(String, Int32, ChangeResult)] = [
            ("secret-add-denied", 3, .notApproved("not added: user denied")),
            ("secret-add-staged", 4, .stillStaged("config.yaml has changes that aren't approved yet; run `nazar config check`")),
        ]
        for (fixture, exit, want) in cases {
            let (r, m) = world()
            r.on(["secret", "add"], try Fixture.result(fixture, exit: exit))
            r.on(["secret", "list"], try Fixture.result("secret-list", exit: 0))
            let input = CLIInput(Self.value)
            #expect(await m.add(name: "LATER", value: input) == want, "\(fixture)")
            #expect(r.calls == [["--json", "secret", "add", "LATER"], ["--json", "secret", "list"]], "\(fixture)")
            #expect(r.inputs == [Data(Self.value.utf8), nil] && input.isWiped && argsHoldNoValue(r), "\(fixture)")
            #expect(!m.changes.busy && !m.changes.waitingForApproval)
        }
    }

    /// Edge (test author): Nazar.app not running, or the CLI failing,
    /// during an Add: reported as a failure, never retried, and the input
    /// is wiped all the same.
    @Test func aFailedAddIsReportedAndWiped() async throws {
        for (fixture, exit) in [("unavailable", Int32(5)), ("secret-add-denied", Int32(1))] {
            let (r, m) = world()
            r.on(["secret", "add"], try Fixture.result(fixture, exit: exit))
            r.on(["secret", "list"], try Fixture.result("secret-list", exit: 0))
            let input = CLIInput(Self.value)
            let got = await m.add(name: "LATER", value: input)
            guard case .failed(let msg) = got else { Issue.record("\(fixture): \(got)"); continue }
            #expect(!msg.isEmpty && !msg.contains(Self.value), "\(fixture)")
            #expect(r.calls == [["--json", "secret", "add", "LATER"], ["--json", "secret", "list"]], "\(fixture)")
            #expect(r.inputs == [Data(Self.value.utf8), nil] && input.isWiped && argsHoldNoValue(r), "\(fixture)")
        }
    }

    /// A secret's rules are edited with the key's commands under `secret`:
    /// a new rule (a loosening) is written and approved on the login gate in
    /// the one run (--allow-loosen-access, exit 0); a change and a removal
    /// of a rule as the CLI answers them. Every edit carries the hash of the
    /// config the rules were read from and the flag, no edit has input, and
    /// no `config apply` runs.
    @Test func ruleEditsAreTheSecretRuleCommands() async throws {
        let (r, m) = world()
        r.on(["secret", "list"], try Fixture.result("secret-list", exit: 0))
        r.on(["secret", "rule", "add"], try Fixture.result("secret-rule-approved", exit: 0))
        r.on(["secret", "rule", "set"], try Fixture.result("secret-rule-applied", exit: 0))
        r.on(["secret", "rule", "remove"], try Fixture.result("secret-rule-applied", exit: 0))
        await m.refresh()
        let notes = try #require(m.ruleless("NOTES"))
        let rule = RuleDraft(apps: ["iterm"], to: ["git-https"], scope: "session", gate: "login", expire: "8h")
        #expect(await m.addRule(to: notes, rule) == .done("Rule added to NOTES"))
        let gh = try #require(m.secrets.first)
        let first = try #require(gh.policy?.rules.first)
        #expect(await m.updateRule(of: gh, index: 1, RuleDraft(first)) == .done("Rule 1 of GH_TOKEN changed"))
        #expect(await m.removeRule(of: gh, index: 1) == .done("Rule 1 of GH_TOKEN removed"))
        #expect(r.calls == [
            ["--json", "secret", "list"],
            ["--json", "secret", "rule", "add", "NOTES", "--apps", "iterm", "--to", "git-https", "--scope", "session",
             "--gate", "login", "--expire", "8h", "--if-hash", "HASH", "--allow-loosen-access"],
            ["--json", "secret", "list"],
            ["--json", "secret", "rule", "set", "GH_TOKEN", "1", "--apps", "app:com.googlecode.iterm2", "--no-to",
             "--scope", "session", "--gate", "login", "--expire", "8h", "--if-hash", "HASH", "--allow-loosen-access"],
            ["--json", "secret", "list"],
            ["--json", "secret", "rule", "remove", "GH_TOKEN", "1", "--if-hash", "HASH", "--allow-loosen-access"],
            ["--json", "secret", "list"],
        ])
        #expect(r.inputs.allSatisfy { $0 == nil })
    }

    /// Delete runs `nazar secret rm NAME`; the agent asks on its own screen.
    /// A denial is reported, never retried.
    @Test func deleteRunsSecretRm() async throws {
        let (r, m) = world()
        r.on(["secret", "list"], try Fixture.result("secret-list", exit: 0))
        r.on(["secret", "rm"], try Fixture.result("secret-rm-denied", exit: 3))
        await m.refresh()
        #expect(await m.delete(try #require(m.secrets.first)) == .notApproved("not deleted: user denied"))
        #expect(r.calls.filter { $0.contains("rm") } == [["--json", "secret", "rm", "GH_TOKEN"]])
        let (r2, m2) = world()
        r2.on(["secret", "list"], try Fixture.result("secret-list", exit: 0))
        r2.on(["secret", "rm"], try Fixture.result("secret-rm", exit: 0))
        await m2.refresh()
        #expect(await m2.delete(try #require(m2.secrets.last)) == .done("Deleted NOTES"))
        #expect(r2.calls == [["--json", "secret", "list"], ["--json", "secret", "rm", "NOTES"], ["--json", "secret", "list"]])
    }

    /// Recent activity is the secret's own audit lines (`nazar log --since
    /// 24h --target secret:NAME`), newest first, shown only under the secret
    /// it was read for; a read that started earlier and ends later never
    /// replaces a later one.
    @Test func activityIsTheSecretsOwnLog() async throws {
        let (r, m) = world()
        r.on(["log"], try Fixture.result("secret-log", exit: 0))
        #expect(m.activity(for: "GH_TOKEN") == nil)
        await m.loadActivity("GH_TOKEN")
        #expect(r.calls == [["--json", "log", "--since", "24h", "--target", "secret:GH_TOKEN"]])
        let events = try #require(m.activity(for: "GH_TOKEN"))
        try #require(events.count == 2)
        #expect(events.allSatisfy { $0.fields["target"] == "secret:GH_TOKEN" })
        #expect(events[0].fields["decision"] == "blocked" && events[1].fields["decision"] == "allowed")
        #expect(m.activity(for: "NOTES") == nil && m.activityError == nil)
        r.callDelay = .milliseconds(200)
        let slow = Task { await m.loadActivity("OLD") }
        #expect(await eventually { r.calls.count == 2 })
        r.callDelay = .zero
        await m.loadActivity("NOTES")
        await slow.value
        #expect(m.activity(for: "NOTES") != nil && m.activity(for: "OLD") == nil)
    }

    /// Edge (test author): a log that can't be read shows why and keeps no
    /// lines; nothing else is run for it.
    @Test func unreadableActivityShowsWhy() async throws {
        let (r, m) = world()
        r.on(["log"], try Fixture.result("unavailable", exit: 5))
        await m.loadActivity("GH_TOKEN")
        #expect(m.activity(for: "GH_TOKEN") == nil && (m.activityError ?? "").contains("isn't running"))
        #expect(r.calls == [["--json", "log", "--since", "24h", "--target", "secret:GH_TOKEN"]])
    }

    /// The one place a value exists in the window: the Add sheet's hidden
    /// field. It becomes a CLIInput once, on Add, and the field is emptied in
    /// the next statement; Cancel and closing the sheet empty it too. No
    /// other source makes a CLIInput or a SecureField, the model has no
    /// String value, and the tab has no way to copy, store or show one.
    @Test func aValueLivesOnlyInTheAddSheetsHiddenField() throws {
        let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
            .appendingPathComponent("../../Sources/NazarUI").standardized
        let files = try #require(FileManager.default.enumerator(at: root, includingPropertiesForKeys: nil)?
            .compactMap { $0 as? URL }.filter { $0.pathExtension == "swift" })
        var code: [String: [String]] = [:]
        for f in files {
            code[f.lastPathComponent] = try String(contentsOf: f, encoding: .utf8).split(separator: "\n")
                .map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.hasPrefix("//") }
        }
        let tab = try #require(code["SecretsTab.swift"])
        for (name, lines) in code where name != "SecretsTab.swift" && name != "CLIRunner.swift" {
            #expect(!lines.contains { $0.contains("CLIInput(") || $0.contains("SecureField(") }, "\(name)")
        }
        let makes = tab.indices.filter { tab[$0].contains("CLIInput(") }
        #expect(makes.count == 1, "\(makes.count) CLIInput( in SecretsTab.swift")
        if let i = makes.first {
            #expect(tab[i] == "let input = CLIInput(value)")
            #expect(i + 1 < tab.count && tab[min(i + 1, tab.count - 1)] == "value = \"\"")
        }
        #expect(tab.filter { $0.contains("SecureField(") } == ["SecureField(\"\", text: $value)"])
        #expect(tab.filter { $0.contains("$value") }.count == 1)
        #expect(tab.contains("Button(\"Cancel\") { value = \"\"; dismiss() }.keyboardShortcut(.cancelAction)"))
        #expect(tab.contains(".onDisappear { value = \"\" }"))
        for never in ["NSPasteboard", "AppStorage", "SceneStorage", "UserDefaults", "TextEditor(", "textContentType"] {
            #expect(!tab.contains { $0.contains(never) }, "SecretsTab.swift uses \(never)")
        }
        let model = try #require(code["SecretsModel.swift"])
        #expect(!model.contains { $0.contains("value: String") || $0.contains("CLIInput(") })
        #expect(model.contains { $0.contains("public func add(name: String, value: CLIInput, onlyWhenUnlocked: Bool = false) async -> ChangeResult") })
    }
}
