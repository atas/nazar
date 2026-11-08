import Foundation
import Testing
@testable import NazarUI

// The window's models decode what the real CLI prints (the fixtures come
// from cmd/nazar's TestUIFixtures: the real core on the fake platform, the
// real CLI's encoders). A field the window needs that the CLI renamed,
// retyped or dropped fails here.
@Suite struct FixtureTests {
    func objects(_ name: String, exit: Int32 = 0) throws -> CLIOutcome {
        CLIClient.outcome(try Fixture.result(name, exit: exit))
    }

    @Test func keyList() throws {
        let l = try #require(try objects("ssh-key-list").first(Kind.sshKeyList, as: SSHKeyList.self))
        #expect(l.items.map(\.name) == ["github", "old", "prod"])
        let gh = l.items[0], old = l.items[1], prod = l.items[2]
        // `ssh-key create prod --always-ask` from the iTerm2 tab: the chip
        // asks on every use; its one rule is the tab's, login with scope use.
        #expect(prod.userPresence && !gh.userPresence && !old.userPresence)
        // Made with the new default, gh works while the Mac is locked;
        // prod (--always-ask) only while it is unlocked; old is broken.
        #expect(gh.whileLocked && !prod.whileLocked && !old.whileLocked)
        #expect(prod.policy?.rules.map(\.policy) == [PolicyInfo(scope: "use", gate: "login", expire: nil)] && prod.policy?.own?.gate == "block")
        #expect(gh.usable && gh.fingerprint == "SHA256:FINGERPRINT" && gh.lastUsed?.decision == "approved"
            && gh.lastUsed?.app == "com.googlecode.iterm2" && gh.warnings.isEmpty)
        let p = try #require(gh.policy)
        #expect(p.fallbackSource == "key-gate" && p.own?.gate == "dialog" && p.rules.count == 2 && p.configHash == "HASH")
        #expect(p.rules[0].apps.first?.ref == "iterm" && p.rules[1].apps.first?.kind == "signed")
        #expect(!old.usable && old.broken && (old.unusableReason ?? "").contains("old") && (old.remedy ?? "").contains("nazar ssh-key create old"))
    }

    @Test func keyRulesAndCreate() throws {
        let r = try #require(try objects("ssh-key-rules").first(Kind.sshKeyRules, as: SSHKeyRules.self))
        #expect(r.name == "github" && r.configured && !r.staged && r.rules.map(\.index) == [1, 2])
        #expect(r.rules[0].policy == PolicyInfo(scope: "session", gate: "dialog", expire: nil))
        let k = try #require(try objects("ssh-key-create").first(Kind.sshKey, as: SSHKey.self))
        // Created from a terminal tab, the key has the tab's login rule and is blocked otherwise.
        #expect(k.name == "github" && k.usable && !k.userPresence && k.whileLocked && k.policy?.rules.count == 1
            && k.policy?.rules.first?.apps.first?.kind == "app" && k.policy?.rules.first?.policy == PolicyInfo(scope: "session", gate: "login", expire: "8h")
            && k.policy?.own?.gate == "block" && k.policy?.fallbackSource == "key-gate")
        let pub = try #require(try objects("ssh-key-pubkey").first(Kind.sshKey, as: SSHKey.self))
        #expect(pub.publicKey?.hasPrefix("ecdsa-sha2-nistp256 ") == true)
    }

    /// An edit made with --allow-loosen-access: approved in the one run
    /// (exit 0: the ConfigEdit of the staged change, then the ConfigDiff
    /// that applied it), denied (exit 3: the ConfigEdit, then the Problem),
    /// or written but not asked about yet (exit 4: the ConfigEdit, then the
    /// Problem with code staged); a tightening in force; `config apply` of
    /// a change left staged, approved and denied.
    @Test func edits() throws {
        let approved = try objects("config-edit-approved")
        let e = try #require(approved.first(Kind.configEdit, as: ConfigEdit.self))
        #expect(e.changed && !e.applied && e.staged?.loosens == true && e.op == "rule.add")
        let ad = try #require(approved.first(Kind.configDiff, as: ConfigDiff.self))
        #expect(ad.applied && ad.loosens && !ad.changes.isEmpty && ad.hash == e.staged?.hash)
        let denied = try objects("config-edit-denied", exit: 3)
        #expect(denied == .refused(Problem(code: "refused", message: "the config change was not approved; it stays staged")))
        let staged = try objects("config-edit-staged", exit: 4)
        guard case .staged = staged else { Issue.record("exit 4 is staged: \(staged)"); return }
        #expect(staged.first(Kind.configEdit, as: ConfigEdit.self)?.staged?.loosens == true)
        #expect(staged.objects.last?.decode(Problem.self)?.code == "staged")
        let applied = try #require(try objects("config-edit-applied").first(Kind.configEdit, as: ConfigEdit.self))
        #expect(applied.applied && applied.staged == nil && applied.op == "rule.remove")
        let d = try #require(try objects("config-apply").first(Kind.configDiff, as: ConfigDiff.self))
        #expect(d.applied && !d.changes.isEmpty)
        let applyDenied = try objects("config-apply-denied", exit: 3)
        #expect(applyDenied == .refused(Problem(code: "refused", message: "the config change was not approved; it stays staged")))
        let check = try #require(try objects("config-check").first(Kind.configCheck, as: ConfigCheck.self))
        #expect(check.valid && check.staged == nil)
    }

    @Test func statusAndStream() throws {
        let s = try #require(try objects("status").first(Kind.status, as: Status.self))
        #expect(s.approvals.count == 1 && s.approvals[0].scopeId.hasPrefix("session:") && s.agentSocket.hasSuffix("agent.sock"))
        #expect(s.approvals[0].op == "sign:git" && s.approvals[0].covers == "git commits and tags")
        let lines = try Fixture.stdout("status-follow").split(separator: 0x0A).map { Data($0) }
        let objs = lines.compactMap(CLIObject.parse)
        #expect(objs.map(\.kind) == [Kind.status, Kind.approval, Kind.approval])
        let added = try #require(objs[1].decode(Approval.self)), removed = try #require(objs[2].decode(Approval.self))
        #expect(added.event == "added" && removed.event == "removed" && removed.reason == "session ended" && added.identity == removed.identity)
    }

    /// The client-side findings the CLI adds to the status (ssh
    /// config, git signing) decode as config problems; a status with none
    /// has no field.
    @Test func statusSetupFindings() throws {
        let s = try #require(try objects("status-setup").first(Kind.status, as: Status.self))
        let setup = try #require(s.setup)
        #expect(setup.count == 2)
        #expect(setup.allSatisfy { !$0.message.isEmpty && ($0.severity == "error" || $0.severity == "warning") })
        #expect(setup.contains { $0.path == "~/.ssh/config" } && setup.contains { $0.path == "git config --global" })
        let plain = try #require(try objects("status").first(Kind.status, as: Status.self))
        #expect(plain.setup == nil)
    }

    @Test func appsRevokeLog() throws {
        let apps = try #require(try objects("apps-list").first(Kind.appList, as: AppList.self))
        #expect(apps.items.map(\.name) == ["iterm", "kubectl", ""])
        #expect(apps.items[0].pinnedTeam == "H7V7XYVQ7D" && apps.items[0].usedBy == ["github rule 1"])
        // The inline matcher of prod's rule (`ssh-key create prod --always-ask` in the iTerm2 tab).
        #expect(apps.items[2].matcher.ref == "app:com.googlecode.iterm2" && apps.items[2].usedBy == ["prod rule 1"])
        #expect(apps.items[1].matcher.kind == "signed" && apps.items[1].problem == nil && apps.items[1].fix == nil)
        let r = try #require(try objects("revoke").first(Kind.revokeResult, as: RevokeResult.self))
        #expect(r.revoked == 1)
        let log = try objects("log").objects.compactMap { $0.decode(AuditEvent.self) }
        #expect(log.count == 2 && log[0].fields["decision"] == "approved" && log[1].fields["rule"] == "fallback")
        #expect(log[0].fields["chain"]?.contains("claude-code (file deleted)") == true)
    }

    /// What the Secrets tab decodes, from the real core.
    @Test func secrets() throws {
        let l = try #require(try objects("secret-list").first(Kind.secretList, as: SecretList.self))
        #expect(l.items.map(\.name) == ["GH_TOKEN", "NOTES"])
        let gh = l.items[0], notes = l.items[1]
        #expect(gh.stored && !gh.broken && gh.configured && gh.created != nil && gh.deliver == ["helper", "stdout"])
        #expect(gh.policy?.rules.first?.apps.first?.ref == "app:com.googlecode.iterm2" && gh.policy?.fallbackSource == "secret-gate"
            && gh.policy?.configHash == "HASH" && gh.warnings.count == 1 && gh.warnings[0].contains("no to:"))
        // Added from the window: blocked, no rule.
        #expect(notes.stored && notes.policy?.rules.isEmpty == true && notes.policy?.own?.gate == "block" && notes.warnings.isEmpty)
        let added = try #require(try objects("secret-add-window").first(Kind.secret, as: Secret.self))
        #expect(added.name == "NOTES" && added.policy?.rules.isEmpty == true)
        // NOTES was added with the sheet's "only while unlocked" checkbox.
        #expect(gh.whileLocked && !notes.whileLocked && !added.whileLocked)
        let rm = try #require(try objects("secret-rm").first(Kind.secret, as: Secret.self))
        #expect(rm.name == "NOTES" && !rm.stored)
        #expect(try objects("secret-rm-denied", exit: 3) == .refused(Problem(code: "refused", message: "not deleted: user denied")))
        #expect(try objects("secret-add-denied", exit: 3) == .refused(Problem(code: "refused", message: "not added: user denied")))
        let staged = try objects("secret-add-staged", exit: 4)
        #expect(staged.first(Kind.problem, as: Problem.self)?.message == "config.yaml has changes that aren't approved yet; run `nazar config check`")
        #expect(staged.first(Kind.configEdit, as: ConfigEdit.self) == nil)
        let e = try #require(try objects("secret-rule-approved").first(Kind.configEdit, as: ConfigEdit.self))
        #expect(e.secret == "GH_TOKEN" && e.key == "" && e.staged?.loosens == true)
        #expect(try objects("secret-rule-approved").first(Kind.configDiff, as: ConfigDiff.self)?.applied == true)
        let log = try objects("secret-log").objects.compactMap { $0.decode(AuditEvent.self) }
        #expect(log.count == 2 && log.allSatisfy { $0.fields["target"] == "secret:GH_TOKEN" })
    }

    /// What the Kubernetes tab decodes, from the real core.
    @Test func k8s() throws {
        let l = try #require(try objects("k8s-list").first(Kind.k8sContextList, as: K8sContextList.self))
        #expect(l.items.map(\.name) == ["hydra", "hydra.eks", "loose"])
        try #require(l.items.count == 3)
        let hydra = l.items[0], eks = l.items[1], loose = l.items[2]
        #expect(hydra.state == "ok" && hydra.configured && !hydra.caBroken && (hydra.remedy ?? "").isEmpty && hydra.warnings.isEmpty)
        #expect(hydra.cluster?.server == "https://hydra.example:16443" && hydra.cluster?.tlsServerName == "hydra.internal" && hydra.cluster?.proxyURL == nil)
        #expect(hydra.identity == K8sIdentity(user: "admin", groups: ["system:masters"]) && hydra.ttlCert == "15m0s")
        #expect(hydra.ca?.fingerprint == "SHA256:FINGERPRINT")
        let p = try #require(hydra.policy)
        #expect(p.fallbackSource == "context-gate" && p.own?.gate == "block" && p.fallback.gate == "block" && p.configHash == "HASH" && !p.staged)
        #expect(p.rules.count == 1 && p.rules[0].apps.first?.ref == "iterm" && p.rules[0].to.isEmpty
            && p.rules[0].policy == PolicyInfo(scope: "session", gate: "login", expire: "8h"))
        #expect(eks.state == "no-ca" && eks.ca == nil && eks.remedy == "nazar k8s forget hydra.eks, then nazar k8s ca create hydra.eks"
            && eks.warnings.count == 1 && eks.warnings[0].contains("managed clusters") && eks.policy?.rules.isEmpty == true)
        #expect(loose.state == "no-entry" && !loose.configured && loose.policy == nil && loose.ca != nil && loose.cluster == nil
            && loose.warnings.isEmpty && loose.remedy == "nazar k8s forget loose, then nazar k8s ca create loose")
        let staged = try #require(try objects("k8s-rule-approved").first(Kind.configEdit, as: ConfigEdit.self))
        #expect(staged.context == "hydra" && staged.key == "" && staged.staged?.loosens == true)
        #expect(try objects("k8s-rule-approved").first(Kind.configDiff, as: ConfigDiff.self)?.applied == true)
        let applied = try #require(try objects("k8s-rule-applied").first(Kind.configEdit, as: ConfigEdit.self))
        #expect(applied.context == "hydra" && applied.applied && applied.op == "rule.remove")
        #expect(try objects("k8s-forget-denied", exit: 3) == .refused(Problem(code: "refused", message: "not forgotten: user denied")))
        let held = try objects("k8s-forget-staged", exit: 4)
        #expect(held.first(Kind.problem, as: Problem.self)?.code == "staged" && held.first(Kind.configEdit, as: ConfigEdit.self) == nil)
        let gone = try #require(try objects("k8s-forget").first(Kind.k8sContext, as: K8sContext.self))
        #expect(gone.name == "hydra" && gone.state == "absent" && gone.ca == nil && !gone.configured && gone.policy == nil)
        let log = try objects("k8s-log").objects.compactMap { $0.decode(AuditEvent.self) }
        #expect(log.count == 2 && log.allSatisfy { $0.fields["target"] == "k8s:hydra" })
        // A key's and a secret's edits name no context.
        #expect(try objects("config-edit-applied").first(Kind.configEdit, as: ConfigEdit.self)?.context == nil)
        #expect(try objects("secret-rule-approved").first(Kind.configEdit, as: ConfigEdit.self)?.context == nil)
    }

    @Test func problems() throws {
        #expect(try objects("unavailable", exit: 5).problem?.code == "unavailable")
        #expect(try objects("ssh-key-delete-denied", exit: 3) == .refused(Problem(code: "refused", message: "not deleted: user denied")))
    }

    /// Go writes times with up to nine fractional digits.
    @Test func goTimesDecode() throws {
        for s in ["2026-10-11T00:00:00Z", "2026-10-11T00:00:00.123456789+00:00", "0001-01-01T00:00:00Z"] {
            let j = Data("{\"time\":\"\(s)\",\"decision\":\"allowed\"}".utf8)
            #expect((try? CLIJSON.decoder().decode(KeyUse.self, from: j)) != nil, "\(s)")
        }
    }

    /// Lines that are not nazar/v1 objects never count as output.
    @Test func foreignOutputIsAFailure() {
        let r = CLIResult(exitCode: 0, stdout: Data("{\"apiVersion\":\"other/v1\",\"kind\":\"SSHKeyList\"}\nnot json\n".utf8))
        guard case .failed = CLIClient.outcome(r) else { Issue.record("accepted foreign output"); return }
        #expect(CLIObject.parse(Data("{\"kind\":\"SSHKey\"}".utf8)) == nil)
        #expect(CLIObject.parse(Data("{\"apiVersion\":\"nazar/v1\",\"kind\":\"\"}".utf8)) == nil)
    }

    // MARK: Edge and attack cases (test author)

    static func problemLine(_ code: String, _ message: String) -> Data {
        Data("{\"apiVersion\":\"nazar/v1\",\"kind\":\"Problem\",\"code\":\"\(code)\",\"message\":\"\(message)\"}\n".utf8)
    }

    func caseName(_ o: CLIOutcome) -> String {
        switch o {
        case .ok: return "ok"
        case .staged: return "staged"
        case .refused: return "refused"
        case .unavailable: return "unavailable"
        case .failed: return "failed"
        }
    }

    /// The exit code decides the outcome (spec 6); the message comes from the
    /// Problem object on stdout, else stderr, else the status. Only exit 0
    /// (and 4, staged) is ever a success; a killed or crashed CLI, or an exit
    /// code the CLI never uses, is a failure.
    @Test func exitCodesClassify() {
        #expect(CLIClient.outcome(CLIResult(exitCode: 0)) == .ok([]))
        let stale = CLIClient.outcome(CLIResult(exitCode: 1, stdout: Self.problemLine("error", "config.yaml changed since it was read")))
        #expect(stale == .failed(Problem(code: "error", message: "config.yaml changed since it was read")))
        let usage = CLIClient.outcome(CLIResult(exitCode: 2, stderr: "nazar: unknown flag --bogus\n"))
        #expect(caseName(usage) == "failed" && usage.problem?.message.contains("--bogus") == true)
        let refused = CLIClient.outcome(CLIResult(exitCode: 3))
        #expect(caseName(refused) == "refused" && !(refused.problem?.message ?? "").isEmpty)
        let down = CLIClient.outcome(CLIResult(exitCode: 5, stderr: "Nazar.app isn't running"))
        #expect(down == .unavailable(Problem(code: "error", message: "Nazar.app isn't running")))
        for code: Int32 in [-1, 6, 9, 127, 137, 255] {
            let o = CLIClient.outcome(CLIResult(exitCode: code))
            #expect(caseName(o) == "failed" && o.problem != nil, "exit \(code): \(o)")
        }
    }

    /// A command that did not succeed exposes no objects: the window can't
    /// mistake a refusal's output for a result.
    @Test func noObjectsUnlessOkOrStaged() {
        let result = Data("{\"apiVersion\":\"nazar/v1\",\"kind\":\"RevokeResult\",\"revoked\":1}\n".utf8)
        for code: Int32 in [1, 2, 3, 5, 137] {
            let o = CLIClient.outcome(CLIResult(exitCode: code, stdout: result))
            #expect(o.objects.isEmpty && o.first(Kind.revokeResult, as: RevokeResult.self) == nil, "exit \(code)")
        }
        #expect(CLIClient.outcome(CLIResult(exitCode: 4, stdout: result)).objects.count == 1)
    }

    /// Lines that are not one nazar/v1 object with a kind never parse.
    @Test func parseRejectsWhatIsNotAnObject() {
        for s in ["[]", "\"nazar/v1\"", "null", "42", "{}", "{\"apiVersion\":\"nazar/v1\"}",
                  "{\"apiVersion\":\"nazar/v1\",\"kind\":7}", "{\"apiVersion\":7,\"kind\":\"SSHKey\"}",
                  "{\"apiVersion\":\"nazar/v2\",\"kind\":\"SSHKey\"}", "{\"apiVersion\":\"Nazar/v1\",\"kind\":\"SSHKey\"}", ""] {
            #expect(CLIObject.parse(Data(s.utf8)) == nil, "\(s)")
        }
        let o = CLIObject.parse(Data("{\"apiVersion\":\"nazar/v1\",\"kind\":\"RevokeResult\",\"revoked\":2}".utf8))
        #expect(o?.kind == Kind.revokeResult && o?.decode(RevokeResult.self)?.revoked == 2)
        // The right kind with the wrong shape decodes to nil, not a crash.
        #expect(CLIObject.parse(Data("{\"apiVersion\":\"nazar/v1\",\"kind\":\"RevokeResult\",\"revoked\":\"x\"}".utf8))?
            .decode(RevokeResult.self) == nil)
    }

    /// A time that is not RFC 3339 fails the decode (never a made-up date).
    @Test func badTimesDoNotDecode() {
        for s in ["yesterday", "2026-10-11", "1791072000", ""] {
            let j = Data("{\"time\":\"\(s)\",\"decision\":\"allowed\"}".utf8)
            #expect((try? CLIJSON.decoder().decode(KeyUse.self, from: j)) == nil, "\(s)")
        }
    }
}
