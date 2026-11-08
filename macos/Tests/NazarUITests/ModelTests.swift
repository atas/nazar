import Foundation
import Testing
@testable import NazarUI

// The tabs' view models against a FakeCLIRunner that answers with the real
// CLI's recorded output. Nothing is run and nothing is put on screen.
@MainActor
@Suite(.serialized) struct ModelTests {
    func world() -> (FakeCLIRunner, CLIClient, ChangeRunner) {
        let r = FakeCLIRunner()
        let c = CLIClient(runner: r)
        return (r, c, ChangeRunner(client: c))
    }

    @Test func keysRefreshShowsKeysAndWhyOneIsUnusable() async throws {
        let (r, c, ch) = world()
        r.on(["ssh-key", "list"], try Fixture.result("ssh-key-list", exit: 0))
        let m = KeysModel(client: c, changes: ch)
        await m.refresh()
        #expect(m.keys.map(\.name) == ["github", "old", "prod"] && m.error == nil && m.since != nil)
        #expect(!m.keys[1].usable && m.keys[1].remedy != nil)
        #expect(r.calls == [["--json", "ssh-key", "list"]])
    }

    /// The New key sheet's checkbox is the one choice at creation: checked,
    /// the CLI runs `ssh-key create <name> --always-ask`; unchecked, the
    /// name alone.
    @Test func createKeyWithAndWithoutAlwaysAsk() async throws {
        let (r, c, ch) = world()
        r.on(["ssh-key", "create"], try Fixture.result("ssh-key-create", exit: 0))
        r.on(["ssh-key", "list"], try Fixture.result("ssh-key-list", exit: 0))
        let m = KeysModel(client: c, changes: ch)
        #expect(await m.create(name: "prod", alwaysAsk: true) == .done("Created prod"))
        #expect(await m.create(name: "work") == .done("Created work"))
        // The sheet's "only while unlocked" checkbox; with "always ask" it is
        // forced on and --always-ask alone says so.
        #expect(await m.create(name: "laptop", onlyWhenUnlocked: true) == .done("Created laptop"))
        #expect(await m.create(name: "root", alwaysAsk: true, onlyWhenUnlocked: true) == .done("Created root"))
        #expect(r.calls.filter { $0.contains("create") } == [["--json", "ssh-key", "create", "prod", "--always-ask"],
                                                             ["--json", "ssh-key", "create", "work"],
                                                             ["--json", "ssh-key", "create", "laptop", "--only-when-unlocked"],
                                                             ["--json", "ssh-key", "create", "root", "--always-ask"]])
    }

    @Test func unavailableIsShown() async throws {
        let (r, c, ch) = world()
        r.on(["ssh-key", "list"], try Fixture.result("unavailable", exit: 5))
        let m = KeysModel(client: c, changes: ch)
        await m.refresh()
        #expect(m.keys.isEmpty && (m.error ?? "").contains("isn't running"))
    }

    /// A rule that loosens access is written and approved in the one run:
    /// the edit carries --allow-loosen-access, the CLI shows the login gate
    /// for exactly that change and answers 0 once it is in force (the
    /// ConfigEdit, then the ConfigDiff). The window runs no `config apply`
    /// and never answers the gate itself.
    @Test func addRuleIsApprovedInOneRun() async throws {
        let (r, c, ch) = world()
        r.on(["ssh-key", "list"], try Fixture.result("ssh-key-list", exit: 0))
        r.on(["ssh-key", "rule", "add"], try Fixture.result("config-edit-approved", exit: 0))
        let m = KeysModel(client: c, changes: ch)
        await m.refresh()
        let rule = RuleDraft(apps: ["app:com.googlecode.iterm2"], scope: "use", gate: "none")
        let res = await m.addRule(to: m.keys[0], rule)
        #expect(res == .done("Rule added to github"))
        let calls = r.calls.map { $0.prefix(5).joined(separator: " ") }
        #expect(calls == ["--json ssh-key list", "--json ssh-key rule add github", "--json ssh-key list"])
        let add = r.calls[1]
        #expect(add.suffix(3) == ["--if-hash", "HASH", "--allow-loosen-access"])
        #expect(!r.calls.contains { $0.contains("apply") })
        #expect(!ch.busy && !ch.waitingForApproval)
    }

    /// Denied at the gate (exit 3): the change stays staged, the window
    /// says so with the CLI's words, and runs no `config apply` for it (the
    /// banner's Approve… is the person's choice).
    @Test func deniedEditKeepsTheChangeStaged() async throws {
        let (r, c, ch) = world()
        r.on(["ssh-key", "list"], try Fixture.result("ssh-key-list", exit: 0))
        r.on(["ssh-key", "rule", "add"], try Fixture.result("config-edit-denied", exit: 3))
        let m = KeysModel(client: c, changes: ch)
        await m.refresh()
        let res = await m.addRule(to: m.keys[0], RuleDraft(apps: ["iterm"], gate: "none"))
        guard case .notApproved(let why) = res else { Issue.record("\(res)"); return }
        #expect(why.contains("not approved") && why.contains("stays staged"))
        #expect(!r.calls.contains { $0.contains("apply") })
        #expect(!ch.busy && !ch.waitingForApproval)
    }

    /// A tightening is in force at once: no config apply.
    @Test func removeRuleNeedsNoApproval() async throws {
        let (r, c, ch) = world()
        r.on(["ssh-key", "list"], try Fixture.result("ssh-key-list", exit: 0))
        r.on(["ssh-key", "rule", "remove"], try Fixture.result("config-edit-applied", exit: 0))
        let m = KeysModel(client: c, changes: ch)
        await m.refresh()
        #expect(await m.removeRule(of: m.keys[0], index: 1) == .done("Rule 1 of github removed"))
        #expect(!r.calls.contains { $0.contains("apply") })
        #expect(r.calls[1] == ["--json", "ssh-key", "rule", "remove", "github", "1", "--if-hash", "HASH", "--allow-loosen-access"])
    }

    @Test func deleteDeniedIsReported() async throws {
        let (r, c, ch) = world()
        r.on(["ssh-key", "list"], try Fixture.result("ssh-key-list", exit: 0))
        r.on(["ssh-key", "delete"], try Fixture.result("ssh-key-delete-denied", exit: 3))
        let m = KeysModel(client: c, changes: ch)
        await m.refresh()
        #expect(await m.delete(m.keys[0]) == .notApproved("not deleted: user denied"))
    }

    @Test func publicKeyForTheClipboard() async throws {
        let (r, c, ch) = world()
        r.on(["ssh-key", "pubkey"], try Fixture.result("ssh-key-pubkey", exit: 0))
        r.on(["ssh-key", "list"], try Fixture.result("ssh-key-list", exit: 0))
        let m = KeysModel(client: c, changes: ch)
        await m.refresh()
        #expect(await m.publicKey(m.keys[0])?.hasPrefix("ecdsa-sha2-nistp256 ") == true)
    }

    @Test func approvalsFollowTheStream() async throws {
        let (r, c, ch) = world()
        let lines = try Fixture.stdout("status-follow").split(separator: 0x0A).map { Data($0) }
        r.streamLines = ["status --follow": Array(lines.prefix(2))]
        let m = ApprovalsModel(client: c, changes: ch)
        m.start()
        #expect(await eventually { m.count == 1 && m.status != nil })
        #expect(m.approvals[0].target == "ssh:github")
        // The removal event takes it away again.
        r.streamLines = ["status --follow": lines]
        m.start()
        #expect(await eventually { m.status != nil && m.count == 0 && !m.connected })
        #expect(r.stopped >= 1)
    }

    /// The stream carries the config state only in its first object, so the
    /// window reads `nazar status` again: a banner never outlives its cause.
    @Test func refreshStatusReplacesTheStreamsFirstObject() async throws {
        let (r, c, ch) = world()
        let lines = try Fixture.stdout("status-follow").split(separator: 0x0A).map { Data($0) }
        r.streamLines = ["status --follow": Array(lines.prefix(1))]
        let m = ApprovalsModel(client: c, changes: ch)
        m.start()
        #expect(await eventually { m.status != nil })
        r.on(["status"], try Fixture.result("status", exit: 0))
        await m.refreshStatus()
        #expect(r.calls.last == ["--json", "status"])
        let want = try #require(CLIClient.outcome(try Fixture.result("status", exit: 0)).first(Kind.status, as: Status.self))
        #expect(m.status == want)
        #expect(m.approvals == want.approvals)
    }

    /// The window's timer reads only whether a change is staged (`nazar
    /// config check`), never `nazar status`: its client-side checks run ssh
    /// with the user's `Match exec` commands and ask another agent for its
    /// keys, which must not happen every few seconds.
    @Test func timerRefreshReadsConfigCheckNotStatus() async throws {
        let (r, c, ch) = world()
        r.on(["status"], try Fixture.result("status-setup", exit: 0))
        let m = ApprovalsModel(client: c, changes: ch)
        await m.refreshStatus()
        var want = try #require(m.status)
        #expect(want.setup?.isEmpty == false)
        let staged = #"{"apiVersion":"nazar/v1","kind":"ConfigCheck","path":"/Users/u/.nazar/config/config.yaml","valid":true,"problems":[],"staged":{"hash":"H","loosens":true,"applied":false,"changes":["c"]}}"#
        r.on(["config", "check"], CLIResult(exitCode: 4, stdout: Data((staged + "\n").utf8)))
        let before = r.calls.count
        await m.refreshStaged()
        #expect(Array(r.calls.dropFirst(before)) == [["--json", "config", "check"]])
        want.staged = ConfigDiff(hash: "H", loosens: true, applied: false, changes: ["c"], loosening: nil)
        #expect(m.status == want, "only staged changes; the setup findings stay")
    }

    /// With reconnectAfter set, a stream that ended starts again.
    @Test func approvalsReconnect() async throws {
        let (r, c, ch) = world()
        r.streamExit = 5 // Nazar.app's control socket isn't listening yet
        let m = ApprovalsModel(client: c, changes: ch)
        m.reconnectAfter = 0.05
        m.start()
        #expect(await eventually { m.starts >= 3 })
        m.reconnectAfter = nil
        #expect(await eventually { !m.connected && m.error == "nazar-agent isn't running" })
    }

    @Test func revokeOneUsesItsScope() async throws {
        let (r, c, ch) = world()
        r.on(["revoke"], try Fixture.result("revoke", exit: 0))
        let m = ApprovalsModel(client: c, changes: ch)
        let s = try #require(CLIClient.outcome(try Fixture.result("status", exit: 0)).first(Kind.status, as: Status.self))
        let a = s.approvals[0]
        #expect(m.revokeAction(a) == .revokeSession(String(a.scopeId.dropFirst("session:".count))))
        #expect(await m.revoke(a) == .done("Revoked"))
        #expect(await m.revokeAll() == .done("Revoked all approvals"))
        #expect(r.calls.last == ["--json", "revoke", "--all"])
        var app = a
        app.scopeId = "app:H7V7XYVQ7D:com.googlecode.iterm2"
        #expect(m.revokeAction(app) == .revokeApp("com.googlecode.iterm2"))
        app.scopeId = ""
        #expect(m.revokeAction(app) == .revokeKey("github"))
    }

    /// Two approvals of one tab that differ only in what they cover are two
    /// rows (Milestone 7): what an approval covers is part of its identity.
    @Test func approvalsDifferingInWhatTheyCoverAreDistinct() throws {
        let s = try #require(CLIClient.outcome(try Fixture.result("status", exit: 0)).first(Kind.status, as: Status.self))
        let a = s.approvals[0]
        var b = a
        b.op = "login:SHA256:gh"
        b.covers = "github.com"
        #expect(b.identity != a.identity && !a.op.isEmpty && !a.covers.isEmpty)
    }

    @Test func activityLoadsThenFollowsAndFilters() async throws {
        let (r, c, _) = world()
        r.on(["log", "--since"], try Fixture.result("log", exit: 0))
        let more = try Fixture.stdout("log").split(separator: 0x0A).map { Data($0) }
        r.streamLines = ["log --follow": [more[0]]]
        let m = ActivityModel(client: c)
        await m.start()
        #expect(await eventually { m.events.count == 3 })
        // Newest first: the streamed line, then the loaded ones newest first.
        #expect(m.events[1].fields["decision"] == "blocked")
        m.decision = "blocked"
        #expect(m.filtered.count == 1)
        m.decision = ""
        m.text = "CLAUDE-CODE"
        #expect(m.filtered.count == 2)
    }

    /// The log stream stopped when the Activity tab was hidden exits a
    /// little later (status 143), after the tab, shown again, loaded the log
    /// and started a new stream: that is not the new stream's error.
    @Test func aStoppedLogStreamsExitIsNotTheNewStreamsError() async throws {
        let (r, c, _) = world()
        r.on(["log", "--since"], try Fixture.result("log", exit: 0))
        r.exitOnStop = true
        let m = ActivityModel(client: c)
        await m.start()
        m.stop()
        await m.start()
        try? await Task.sleep(nanoseconds: 200_000_000)
        #expect(m.error == nil, "\(m.error ?? "")")
        #expect(m.events.count == 2)
    }

    /// A model let go of while its stream runs stops it (SIGTERM to the
    /// CLI child through the runner's handle): no `--follow` child outlives
    /// the model that started it.
    @Test func aModelLetGoStopsItsStream() async throws {
        let (r, c, ch) = world()
        r.on(["log", "--since"], try Fixture.result("log", exit: 0))
        r.exitOnStop = true // the streams run until stopped, as the real ones do
        var approvals: ApprovalsModel? = ApprovalsModel(client: c, changes: ch)
        var activity: ActivityModel? = ActivityModel(client: c)
        weak var approvalsGone = approvals, activityGone = activity
        approvals?.start()
        await activity?.start()
        #expect(r.calls.filter { $0.contains("--follow") }.count == 2)
        #expect(r.stopped == 0)
        approvals = nil
        activity = nil
        #expect(approvalsGone == nil && activityGone == nil, "a model was kept alive")
        #expect(r.stopped == 2, "stopped \(r.stopped) of 2 streams")
    }

    /// start() reads the last hour before it follows; a stop() during that
    /// read (the tab hidden, the window closed, the app quitting) means no
    /// stream starts afterwards: no child outlives the window.
    @Test func aStopDuringTheLogReadStartsNoStream() async throws {
        let (r, c, _) = world()
        r.on(["log", "--since"], try Fixture.result("log", exit: 0))
        r.callDelay = .milliseconds(100)
        let m = ActivityModel(client: c)
        let starting = Task { await m.start() }
        #expect(await eventually { r.calls == [["--json", "log", "--since", "1h"]] }, "the read never started")
        m.stop()
        await starting.value
        try await Task.sleep(for: .milliseconds(50))
        #expect(!r.calls.contains { $0.contains("--follow") }, "a stream started after stop(): \(r.calls)")
    }

    /// The Apps tab only reads: it lists the matchers and runs nothing else.
    @Test func appsTabOnlyReads() async throws {
        let (r, c, _) = world()
        r.on(["apps", "list"], try Fixture.result("apps-list", exit: 0))
        let m = AppsModel(client: c)
        await m.refresh()
        #expect(m.apps.map(\.name) == ["iterm", "kubectl", ""])
        #expect(m.error == nil)
        #expect(r.calls == [["--json", "apps", "list"]])
    }

    // MARK: Edge and attack cases (test author)

    static func problem(_ exit: Int32, _ message: String) -> CLIResult {
        CLIResult(exitCode: exit, stdout: Data("{\"apiVersion\":\"nazar/v1\",\"kind\":\"Problem\",\"code\":\"error\",\"message\":\"\(message)\"}\n".utf8))
    }

    /// An edit aimed at a rule that moved is refused by the core (stale
    /// --if-hash). The window reports it, runs no config apply and reads the
    /// keys again.
    @Test func staleEditFailsWithoutApply() async throws {
        let (r, c, ch) = world()
        r.on(["ssh-key", "list"], try Fixture.result("ssh-key-list", exit: 0))
        r.on(["ssh-key", "rule", "set"], Self.problem(1, "config.yaml changed since it was read"))
        let m = KeysModel(client: c, changes: ch)
        await m.refresh()
        let rule = RuleDraft(try #require(m.keys[0].policy?.rules[1]))
        let res = await m.updateRule(of: m.keys[0], index: 2, rule)
        #expect(res == .failed("config.yaml changed since it was read"))
        #expect(!r.calls.contains { $0.contains("apply") })
        #expect(r.calls[1] == ["--json", "ssh-key", "rule", "set", "github", "2", "--apps", "kubectl", "--no-to",
                               "--scope", "use", "--gate", "login", "--no-expire", "--if-hash", "HASH", "--allow-loosen-access"])
        #expect(r.calls.last == ["--json", "ssh-key", "list"])
        #expect(!ch.busy && !ch.waitingForApproval && ch.last == res)
    }

    /// A key's own gate is an edit like the others: --if-hash and
    /// --allow-loosen-access, approved in the one run.
    @Test func setKeyGateSendsTheHash() async throws {
        let (r, c, ch) = world()
        r.on(["ssh-key", "list"], try Fixture.result("ssh-key-list", exit: 0))
        r.on(["ssh-key", "set"], try Fixture.result("config-edit-applied", exit: 0))
        let m = KeysModel(client: c, changes: ch)
        await m.refresh()
        #expect(await m.setKeyGate(of: m.keys[0], scope: "session", gate: "login", expire: "8h") == .done("Gate of github changed"))
        #expect(r.calls[1] == ["--json", "ssh-key", "set", "github", "--scope", "session", "--gate", "login", "--expire", "8h", "--if-hash", "HASH", "--allow-loosen-access"])
        #expect(!r.calls.contains { $0.contains("apply") })
    }

    /// An edit whose prompt can't be shown yet (a prompt is already open, or
    /// the cooldown after a denied one runs) is written and left staged
    /// (exit 4: the ConfigEdit, then the Problem); the window says so with
    /// the CLI's words and runs no `config apply` on its own.
    @Test func editThatCannotAskYetLeavesItStaged() async throws {
        let (r, c, ch) = world()
        r.on(["ssh-key", "list"], try Fixture.result("ssh-key-list", exit: 0))
        r.on(["ssh-key", "rule", "add"], try Fixture.result("config-edit-staged", exit: 4))
        let m = KeysModel(client: c, changes: ch)
        await m.refresh()
        let res = await m.addRule(to: m.keys[0], RuleDraft(apps: ["iterm"], gate: "none"))
        guard case .stillStaged(let why) = res else { Issue.record("\(res)"); return }
        #expect(why.contains("nazar can ask again") && why.contains("stays staged"))
        #expect(!r.calls.contains { $0.contains("apply") })
        #expect(!ch.busy && !ch.waitingForApproval)
    }

    /// Nazar.app stopping between the list and the edit: a failure, never done.
    @Test func editWhileUnavailableFails() async throws {
        let (r, c, ch) = world()
        r.on(["ssh-key", "list"], try Fixture.result("ssh-key-list", exit: 0))
        r.on(["ssh-key", "rule", "remove"], try Fixture.result("unavailable", exit: 5))
        let m = KeysModel(client: c, changes: ch)
        await m.refresh()
        let res = await m.removeRule(of: m.keys[0], index: 1)
        guard case .failed(let why) = res else { Issue.record("\(res)"); return }
        #expect(why.contains("isn't running"))
    }

    /// The banner's Approve… is the person's choice: it runs `nazar config
    /// apply`, with no hash (the CLI shows and binds the staged change
    /// itself), and reports how that ended: approved, denied (the change
    /// stays staged), or not asked yet.
    @Test func approveRunsConfigApply() async throws {
        let (r, c, ch) = world()
        r.on(["config", "apply"], try Fixture.result("config-apply", exit: 0))
        #expect(await ch.approve() == .done("Approved and applied"))
        #expect(r.calls == [["--json", "config", "apply"]])
        #expect(!ch.busy && !ch.waitingForApproval && ch.last == .done("Approved and applied"))
        let (r2, c2, ch2) = world()
        r2.on(["config", "apply"], try Fixture.result("config-apply-denied", exit: 3))
        #expect(await ch2.approve() == .notApproved("the config change was not approved; it stays staged"))
        #expect(r2.calls == [["--json", "config", "apply"]])
        let (r3, c3, ch3) = world()
        r3.on(["config", "apply"], Self.problem(4, "an approval prompt is already open"))
        #expect(await ch3.approve() == .stillStaged("an approval prompt is already open"))
        #expect(r3.calls.count == 1)
        _ = (c2, c3)
    }

    /// A staged reply with no objects at all (exit 4 and nothing on stdout)
    /// is reported as staged with the window's own words; nothing is
    /// approved or retried.
    @Test func bareStagedReplyRunsNoApply() async throws {
        let (r, c, ch) = world()
        r.on(["ssh-key", "list"], try Fixture.result("ssh-key-list", exit: 0))
        r.on(["ssh-key", "rule", "add"], CLIResult(exitCode: 4))
        let m = KeysModel(client: c, changes: ch)
        await m.refresh()
        let res = await m.addRule(to: m.keys[0], RuleDraft(apps: ["iterm"], gate: "none"))
        #expect(res == .stillStaged("the change is staged; run nazar config apply to approve it"))
        #expect(!r.calls.contains { $0.contains("apply") })
        #expect(!ch.busy && !ch.waitingForApproval)
    }

    /// A Problem on the status stream is shown; objects that are not
    /// nazar/v1 are ignored; a removal of an approval never seen adds nothing.
    @Test func approvalsIgnoreForeignObjectsAndShowProblems() async throws {
        let (r, c, ch) = world()
        let lines = try Fixture.stdout("status-follow").split(separator: 0x0A).map { Data($0) }
        let foreign = Data(String(decoding: lines[1], as: UTF8.self).replacingOccurrences(of: "nazar/v1", with: "evil/v1").utf8)
        r.streamLines = ["status --follow": [lines[0], foreign, Data("not json".utf8), lines[2],
                                             try Fixture.stdout("unavailable").split(separator: 0x0A).map { Data($0) }[0]]]
        r.streamExit = 5
        let m = ApprovalsModel(client: c, changes: ch)
        m.start()
        #expect(await eventually { m.status != nil && !m.connected })
        #expect(m.count == 0)
        #expect((m.error ?? "").hasPrefix("nazar-agent isn't running (cannot connect"))
        m.stop()
        #expect(r.stopped >= 1)
    }

    /// The Activity list keeps the newest maxEvents and skips objects that
    /// are not audit events.
    @Test func activityIsBoundedAndSkipsOtherObjects() async throws {
        let (r, c, _) = world()
        r.on(["log", "--since"], CLIResult(exitCode: 0))
        let log = try Fixture.stdout("log").split(separator: 0x0A).map { Data($0) }
        let revoke = try Fixture.stdout("revoke").split(separator: 0x0A).map { Data($0) }[0]
        r.streamLines = ["log --follow": Array(repeating: log[0], count: ActivityModel.maxEvents + 5)
            + [revoke, Data("not json".utf8), log[1]]]
        let m = ActivityModel(client: c)
        await m.start()
        #expect(await eventually { m.events.first?.fields["decision"] == "blocked" })
        #expect(m.events.count == ActivityModel.maxEvents)
        m.stop()
    }

    /// Revoking an approval of an app with no app recorded falls back to its
    /// key, never to "revoke everything".
    @Test func revokeFallsBackToTheKey() throws {
        let (_, c, ch) = world()
        let m = ApprovalsModel(client: c, changes: ch)
        let s = try #require(CLIClient.outcome(try Fixture.result("status", exit: 0)).first(Kind.status, as: Status.self))
        var a = s.approvals[0]
        a.scopeId = "app:H7V7XYVQ7D:com.googlecode.iterm2"
        a.app = nil
        #expect(m.revokeAction(a) == .revokeKey("github"))
        a.app = ""
        #expect(m.revokeAction(a) == .revokeKey("github"))
        #expect(m.revokeAction(a) != .revokeAll)
    }
}
