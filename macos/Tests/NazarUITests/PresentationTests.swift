import Foundation
import SwiftUI
import Testing
@testable import NazarUI

// What the window shows, tested without putting anything on screen: the
// strings it derives from CLI objects, and a scan of the view sources for
// the one rule about untrusted text (shown verbatim and cleaned, through
// plain(), never as a Markdown-parsed literal with a value in it). No view
// is instantiated, no window, status item or NSApp run loop is touched, and
// nothing here reaches a keychain.
@Suite struct PresentationTests {
    @Test func scopeHelpSaysHowLongAnApprovalLasts() {
        #expect(Presentation.scopeHelp("use") == "Asks every time")
        #expect(Presentation.scopeHelp("session") == "Once per terminal tab or tool run")
        #expect(Presentation.scopeHelp("app") == "Until the app quits")
        #expect(Presentation.scopes.allSatisfy { !Presentation.scopeHelp($0).isEmpty })
        #expect(Presentation.scopeHelp("other") == "")
    }

    @Test func menuLine() {
        #expect(Presentation.approvalsLine(0) == "No current approvals")
        #expect(Presentation.approvalsLine(1) == "1 current approval")
        #expect(Presentation.approvalsLine(3) == "3 current approvals")
    }

    @Test func rulesAndKeys() throws {
        let l = try #require(CLIClient.outcome(try Fixture.result("ssh-key-list", exit: 0)).first(Kind.sshKeyList, as: SSHKeyList.self))
        let p = try #require(l.items[0].policy)
        #expect(Presentation.rule(p.rules[0]) == "iterm · session · dialog")
        #expect(Presentation.rule(p.rules[1]) == "kubectl · use · login")
        #expect(Presentation.others(p) == "Everyone else: session · dialog (the key's own gate)")
        #expect(Presentation.keyState(l.items[1]) == "can't be used")
        #expect(Presentation.lastUsed(l.items[0], since: l.since).hasPrefix("approved "))
        #expect(Presentation.lastUsed(l.items[1], since: l.since).hasPrefix("not used since Nazar started"))
        let r = RuleInfo(index: 1, apps: [MatcherInfo(name: nil, kind: "app", team: nil, id: "x", path: nil, command: nil, ref: "app:x")],
                         to: [MatcherInfo(name: nil, kind: "signed", team: "apple", id: nil, path: nil, command: nil, ref: "signed:apple")],
                         policy: PolicyInfo(scope: "app", gate: "none", expire: nil))
        #expect(Presentation.rule(r) == "app:x → signed:apple · none")
    }

    /// The scope is shown only where it means something (login, dialog);
    /// an expiry is spelled out; an empty one is no expiry.
    @Test func policyLine() {
        #expect(Presentation.policy(PolicyInfo(scope: "use", gate: "block")) == "block")
        #expect(Presentation.policy(PolicyInfo(scope: "session", gate: "none")) == "none")
        #expect(Presentation.policy(PolicyInfo(scope: "use", gate: "login")) == "use · login")
        #expect(Presentation.policy(PolicyInfo(scope: "app", gate: "dialog", expire: "")) == "app · dialog")
        #expect(Presentation.policy(PolicyInfo(scope: "session", gate: "login", expire: "8h")) == "session · login · expires after 8h")
    }

    /// Several apps and receivers, in order; a matcher with no reference
    /// shows its kind (any, unknown).
    @Test func ruleWithSeveralMatchers() {
        func m(_ kind: String, _ ref: String) -> MatcherInfo {
            MatcherInfo(name: nil, kind: kind, team: nil, id: nil, path: nil, command: nil, ref: ref)
        }
        #expect(Presentation.matcher(m("any", "")) == "any")
        #expect(Presentation.matcher(m("app", "iterm")) == "iterm")
        let r = RuleInfo(index: 3, apps: [m("app", "claude"), m("app", "iterm")], to: [m("signed", "signed:apple"), m("unknown", "")],
                         policy: PolicyInfo(scope: "session", gate: "dialog", expire: "7d"))
        #expect(Presentation.rule(r) == "claude, iterm → signed:apple, unknown · session · dialog · expires after 7d")
    }

    /// "Everyone else" names where the policy comes from: the key's own gate
    /// or defaults.fallback (an unconfigured key: block).
    @Test func othersOfAnUnconfiguredKey() throws {
        let l = try #require(CLIClient.outcome(try Fixture.result("ssh-key-list", exit: 0)).first(Kind.sshKeyList, as: SSHKeyList.self))
        let p = try #require(l.items[1].policy)
        #expect(Presentation.others(p) == "Everyone else: block (defaults.fallback)")
    }

    /// Every state a key can be in, unusable first (a broken key is never
    /// shown as protected).
    @Test func keyStates() throws {
        let l = try #require(CLIClient.outcome(try Fixture.result("ssh-key-list", exit: 0)).first(Kind.sshKeyList, as: SSHKeyList.self))
        var k = l.items[0]
        #expect(Presentation.keyState(k) == "")
        k.userPresence = true
        #expect(Presentation.keyState(k) == "")
        k.configured = false
        #expect(Presentation.keyState(k) == "no rules yet: every use is blocked")
        k.usable = false
        #expect(Presentation.keyState(k) == "can't be used")
        var broken = l.items[1]
        broken.userPresence = true
        broken.configured = true
        #expect(Presentation.keyState(broken) == "can't be used")
    }

    /// A key the chip asks for on every use carries a badge (from the
    /// CLI's userPresence, the creation-time record); no other key does. The
    /// New key sheet's checkbox says what it does, in one line under it.
    @Test func alwaysAskBadgeAndCheckbox() throws {
        let l = try #require(CLIClient.outcome(try Fixture.result("ssh-key-list", exit: 0)).first(Kind.sshKeyList, as: SSHKeyList.self))
        #expect(l.items.map { Presentation.keyBadge($0) } == ["", "", "Asks every time (chip)"])
        var k = l.items[2]
        k.userPresence = false
        #expect(Presentation.keyBadge(k) == "")
        #expect(Presentation.alwaysAskLabel == "Ask for Touch ID on every use (enforced by the chip)")
        #expect(Presentation.alwaysAskHelp == "Strongest protection, for keys like production root logins. Can't be loosened later.")
    }

    /// A usable key or stored secret the chip refuses while the Mac is
    /// locked carries the "Only when unlocked" badge (from the CLI's
    /// whileLocked, the creation-time record); a broken key, a secret
    /// without a value and one that works while locked carry none.
    @Test func onlyWhenUnlockedBadgeAndCheckbox() throws {
        let l = try #require(CLIClient.outcome(try Fixture.result("ssh-key-list", exit: 0)).first(Kind.sshKeyList, as: SSHKeyList.self))
        #expect(l.items.map { Presentation.lockBadge($0) } == ["", "", "Only when unlocked"]) // github, old (broken), prod
        let s = try #require(CLIClient.outcome(try Fixture.result("secret-list", exit: 0)).first(Kind.secretList, as: SecretList.self))
        #expect(s.items.map { Presentation.lockBadge($0) } == ["", "Only when unlocked"]) // GH_TOKEN, NOTES
        var notes = s.items[1]
        notes.stored = false
        #expect(Presentation.lockBadge(notes) == "")
        #expect(Presentation.onlyWhenUnlockedLabel == "Only while the Mac is unlocked (enforced by the chip)")
    }

    /// The banners say what a staged change or a missing vault item means,
    /// in plain words; the raw diff and the fix commands are only details.
    @Test func bannersInPlainWords() throws {
        let d = ConfigDiff(hash: "H", loosens: true, applied: false,
                           changes: ["ssh:t: key entry added"], loosening: ["ssh:t: requests that got gate=block can now get gate=dialog"])
        #expect(Presentation.stagedTitle(d).hasPrefix("Your config was changed to allow more access."))
        var t = d
        t.loosens = false
        #expect(Presentation.stagedTitle(t) == "Your config was changed. The change isn't in force until you approve it.")
        #expect(Presentation.stagedDetails(d) == ["ssh:t: key entry added", "allows more: ssh:t: requests that got gate=block can now get gate=dialog"])
        #expect(!Presentation.stagedTitle(d).contains("gate="))
        func v(_ item: String) -> VaultProblem { VaultProblem(item: item, reason: "r", effect: "e", remedy: "fix") }
        #expect(Presentation.vaultLine(v("config/approved")).contains("every key is blocked"))
        #expect(Presentation.vaultLine(v("ssh-key/t-dialog")) == "Key t-dialog can't be used. It was probably made by an earlier build of Nazar; make it again.")
        #expect(Presentation.vaultLine(v("state/trust")) == "Item state/trust: e")
        #expect(Presentation.setupTitle.contains("outside nazar") && !Presentation.setupTitle.contains("ssh -G"))
    }

    /// Last use: decision, when (localized, not checked), by which app.
    @Test func lastUsedLine() throws {
        let l = try #require(CLIClient.outcome(try Fixture.result("ssh-key-list", exit: 0)).first(Kind.sshKeyList, as: SSHKeyList.self))
        var k = l.items[0]
        let now = l.since.addingTimeInterval(7200)
        let s = Presentation.lastUsed(k, since: l.since, now: now)
        #expect(s.hasPrefix("approved "))
        #expect(s.hasSuffix(" by com.googlecode.iterm2"))
        k.lastUsed?.app = nil
        #expect(!Presentation.lastUsed(k, since: l.since, now: now).contains(" by "))
        k.lastUsed?.app = ""
        #expect(!Presentation.lastUsed(k, since: l.since, now: now).contains(" by "))
        k.lastUsed = nil
        #expect(Presentation.lastUsed(k, since: nil, now: now) == "not used")
        #expect(Presentation.lastUsed(k, since: l.since, now: now).hasPrefix("not used since Nazar started "))
    }

    @Test func refsFieldSplitsLikeTheCLI() {
        #expect(Presentation.refs(" claude , iterm ") == ["claude", "iterm"])
        #expect(Presentation.refs("iterm, app:com.x,signed:apple") == ["iterm", "app:com.x", "signed:apple"])
        #expect(Presentation.refs("") == [] && Presentation.refs(" , ") == [])
    }

    /// Empty pieces are dropped; a path: reference is split like any other
    /// (a path with a comma is written in config.yaml).
    @Test func refsEdgeCases() {
        #expect(Presentation.refs("iterm,,claude,") == ["iterm", "claude"])
        #expect(Presentation.refs("path:/Applications/A, B.app/x") == ["path:/Applications/A", "B.app/x"])
        #expect(Presentation.refs("app:com.x, signed:ABCDE12345:com.y") == ["app:com.x", "signed:ABCDE12345:com.y"])
    }

    static func m(_ name: String? = nil, _ kind: String, team: String? = nil, id: String? = nil, path: String? = nil,
                  command: [String]? = nil, ref: String) -> MatcherInfo {
        MatcherInfo(name: name, kind: kind, team: team, id: id, path: path, command: command, ref: ref)
    }

    static func rule(_ apps: [MatcherInfo], to: [MatcherInfo] = []) -> RuleInfo {
        RuleInfo(index: 2, apps: apps, to: to, policy: PolicyInfo(scope: "use", gate: "login", expire: "8h"))
    }

    /// What the rule sheet sends for a list it was opened with: the refs
    /// joined into the field, split again on save.
    static func sheetRoundTrip(_ list: [String]) -> [String] {
        Presentation.refs(list.joined(separator: ", "))
    }

    /// Edit… is offered only for a rule the sheet writes back unchanged
    /// (adversarial review): opening the sheet and changing
    /// only the expire must not drop a matcher or a team pin.
    @Test func editOnlyRulesThatRoundTrip() {
        // An inline path: is editable by its ref, in apps: or to:; one
        // whose path the field would split or trim is not.
        let tool = Self.m(nil, "path", path: "/opt/homebrew/opt/mytool/bin/mytool", ref: "path:/opt/homebrew/opt/mytool/bin/mytool")
        let pathFirst = Self.rule([tool, Self.m("iterm", "app", id: "com.googlecode.iterm2", ref: "iterm")])
        #expect(Presentation.editable(pathFirst))
        #expect(Presentation.editable(Self.rule([Self.m("iterm", "app", ref: "iterm")], to: [tool])))
        #expect(!Presentation.editable(Self.rule([Self.m(nil, "path", path: "/opt/a,b/c", ref: "path:/opt/a,b/c")])))
        #expect(!Presentation.editable(Self.rule([Self.m(nil, "path", path: "/opt/a ", ref: "path:/opt/a ")])))
        #expect(!Presentation.editable(Self.rule([Self.m(nil, "path", path: "/opt/a", ref: "")])))
        #expect(Presentation.matcher(tool) == "path:/opt/homebrew/opt/mytool/bin/mytool")
        #expect(Presentation.matcher(Self.m("mytool", "path", path: "/opt/homebrew/opt/mytool/bin/mytool", ref: "mytool")) == "path:/opt/homebrew/opt/mytool/bin/mytool")
        // A path: ref typed into the field splits at commas like any other.
        #expect(Presentation.refs("path:/opt/a, b, iterm") == ["path:/opt/a", "b", "iterm"])
        // An inline {app: X, team: T}: the ref app:X has no team, so the
        // sheet would write {app: X} and drop the pin.
        let teamPinned = Self.rule([Self.m(nil, "app", team: "ABCDE12345", id: "com.example.tool", ref: "app:com.example.tool")])
        #expect(!Presentation.editable(teamPinned))
        #expect(!Presentation.editable(Self.rule([Self.m("iterm", "app", ref: "iterm")], to: teamPinned.apps)))
        // An inline command: (no ref); a signed team with a colon (signed:a:b
        // reads as team a, id b); a ref that is not what the fields say.
        #expect(!Presentation.editable(Self.rule([Self.m(nil, "command", command: ["npx", "x"], ref: "")])))
        #expect(!Presentation.editable(Self.rule([Self.m(nil, "signed", team: "a:b", ref: "signed:a:b")])))
        #expect(!Presentation.editable(Self.rule([Self.m(nil, "app", id: "com.x", ref: "app:com.y")])))
        #expect(!Presentation.editable(Self.rule([Self.m(nil, "app", id: "a,b", ref: "app:a,b")])))
        // Plain lists round-trip and stay editable: names, any/unknown,
        // app:, signed: with and without an id.
        let named = Self.rule([Self.m("claude", "signed", team: "Q6L2SF6YDW", ref: "claude"),
                               Self.m("iterm", "app", id: "com.googlecode.iterm2", ref: "iterm"),
                               Self.m("any", "any", ref: "any"),
                               Self.m(nil, "app", id: "com.x", ref: "app:com.x"),
                               Self.m(nil, "signed", team: "apple", ref: "signed:apple"),
                               Self.m(nil, "signed", team: "ABCDE12345", id: "com.y", ref: "signed:ABCDE12345:com.y")],
                              to: [Self.m("unknown", "unknown", ref: "unknown")])
        #expect(Presentation.editable(named))
        #expect(Self.sheetRoundTrip(RuleDraft(named).apps) == RuleDraft(named).apps)
        #expect(Self.sheetRoundTrip(RuleDraft(named).to) == RuleDraft(named).to)
        #expect(Presentation.editable(Self.rule([Self.m("iterm", "app", ref: "iterm")])))
    }

    /// The fixture's rules (from the real CLI) are editable, and the
    /// window's Edit… is gated by Presentation.editable.
    @Test func editButtonIsGated() throws {
        let l = try #require(CLIClient.outcome(try Fixture.result("ssh-key-list", exit: 0)).first(Kind.sshKeyList, as: SSHKeyList.self))
        let p = try #require(l.items[0].policy)
        #expect(p.rules.allSatisfy(Presentation.editable))
        let src = try String(contentsOf: Self.views.appendingPathComponent("NazarWindowView.swift"), encoding: .utf8)
        #expect(src.contains("let canEdit = Presentation.editable(r)"))
        #expect(src.contains("guard canEdit else { return }"))
        #expect(src.contains(".disabled(!canEdit)"))
        #expect(src.components(separatedBy: "kind: .change(").count == 2)
        // The Secrets tab shows a secret's rules with the same
        // RuleRows (its gated Edit…), never with rule buttons of its own.
        let secrets = try String(contentsOf: Self.views.appendingPathComponent("SecretsTab.swift"), encoding: .utf8)
        #expect(src.contains("struct RuleRows: View") && secrets.contains("RuleRows(") && !secrets.contains("Button(\"Edit…\")"))
        #expect(secrets.components(separatedBy: "kind: .change(").count == 2)
    }

    /// Exactly the gates each picker may offer: a key's own gate applies to
    /// every caller, so it is never none (the CLI refuses it).
    @Test func pickerValuesAreWhatTheCLIAccepts() {
        #expect(Presentation.gates == ["login", "dialog", "none", "block"])
        #expect(Presentation.keyGates == ["login", "dialog", "block"])
        #expect(!Presentation.keyGates.contains("none"))
        #expect(Presentation.scopes == ["use", "session", "app"])
    }

    private func blocked(_ at: TimeInterval, chain: String = "bash(100) > kubectl(200)", target: String = "k8s:hydra", reason: String = "no rule matched",
                         decision: String = "blocked", session: String = "1@1") -> AuditEvent {
        AuditEvent(time: Date(timeIntervalSince1970: at), fields: ["decision": decision, "target": target, "chain": chain, "reason": reason, "session": session])
    }

    /// One kubectl makes several blocked lines and a retrying caller many:
    /// they fold, across runs (new pids, new session), newest first.
    @Test func blockedRepeatsFold() {
        let lines = ActivityLine.fold([
            blocked(30), blocked(20),
            blocked(10, chain: "bash(101) > kubectl(301)", session: "2@2"),
        ])
        #expect(lines.count == 1)
        #expect(lines[0].count == 3)
        #expect(lines[0].event.time == Date(timeIntervalSince1970: 30))
        #expect(lines[0].oldest == Date(timeIntervalSince1970: 10))
        #expect(Presentation.activityLine(lines[0]) == "blocked ×3 k8s:hydra · bash(100) > kubectl(200) · no rule matched")
        #expect(Presentation.activityTime(lines[0]).contains(" – "))
    }

    /// A fold must never hide a different event: another target, reason or
    /// program stays on its own line, an allowed line never folds, and
    /// neither do repeats with something else between them.
    @Test func differentEventsDoNotFold() {
        #expect(ActivityLine.fold([blocked(3), blocked(2, target: "ssh:github")]).count == 2)
        #expect(ActivityLine.fold([blocked(3), blocked(2, reason: "other")]).count == 2)
        #expect(ActivityLine.fold([blocked(3), blocked(2, chain: "bash(100) > curl(200)")]).count == 2)
        #expect(ActivityLine.fold([blocked(3, decision: "approved"), blocked(2, decision: "approved")]).count == 2)
        #expect(ActivityLine.fold([blocked(3), blocked(2, decision: "approved"), blocked(1)]).count == 3)
        // A pid is only a pid: a team id in the chain still tells callers apart.
        #expect(ActivityLine.fold([blocked(3, chain: "x(1, AAAAAAAAAA:x)"), blocked(2, chain: "x(2, BBBBBBBBBB:x)")]).count == 2)
        let one = ActivityLine.fold([blocked(3)])[0]
        #expect(Presentation.activityLine(one) == Presentation.event(one.event))
        #expect(!Presentation.activityTime(one).contains(" – "))
    }

    @Test func eventLine() throws {
        let e = try #require(CLIClient.outcome(try Fixture.result("log", exit: 0)).objects.first?.decode(AuditEvent.self))
        #expect(Presentation.event(e).hasPrefix("approved ssh:github · com.googlecode.iterm2 · bash(4120)"))
    }

    /// A line with no app: decision, target, chain, reason.
    @Test func eventLineWithoutApp() throws {
        let objs = CLIClient.outcome(try Fixture.result("log", exit: 0)).objects
        let e = try #require(objs.count > 1 ? objs[1].decode(AuditEvent.self) : nil)
        #expect(Presentation.event(e) == "blocked ssh:github · python3(5000) · no rule matched")
    }

    /// Attack: audit fields are caller-controlled. Presentation keeps them
    /// as text (it does not interpret anything); once cleaned for plain()
    /// no value can add a line or reverse the reading order, and link or
    /// emphasis syntax stays literal characters.
    @Test func hostileEventFieldsStayOneCleanLine() {
        let e = AuditEvent(time: Date(timeIntervalSince1970: 0), fields: [
            "decision": "denied", "target": "ssh:github",
            "app": "evil\u{202E}ppa.exe", "chain": "[Allow](https://evil.example) > **ssh**(1)",
            "reason": "ok\napproved ssh:github · trusted\u{2028}x\u{200B}",
        ])
        let line = Presentation.event(e)
        #expect(line.hasPrefix("denied ssh:github · "))
        let shown = PlainText.clean(line)
        for bad in ["\n", "\u{202E}", "\u{2028}", "\u{200B}"] {
            #expect(!shown.contains(bad), "a hostile field survives cleaning: \(bad.unicodeScalars.map { String($0.value, radix: 16) })")
        }
        #expect(shown.contains("[Allow](https://evil.example) > **ssh**(1)"))
    }

    /// A secret's state (only what needs attention, unusable first),
    /// how it is delivered, and who gets the fallback, in plain words.
    @Test func secretLines() throws {
        let l = try #require(CLIClient.outcome(try Fixture.result("secret-list", exit: 0)).first(Kind.secretList, as: SecretList.self))
        var gh = l.items[0]
        #expect(Presentation.secretState(gh) == "")
        #expect(Presentation.secretState(l.items[1]) == "no rules yet: every app is blocked")
        #expect(Presentation.others(try #require(gh.policy)) == "Everyone else: block (the secret's own gate)")
        #expect(Presentation.delivery(gh.deliver) == "Delivered by git's credential helper, nazar get")
        #expect(Presentation.delivery(["late-env", "env", "later"]) == "Delivered by nazar run, nazar run (startup environment), later")
        gh.stored = false
        #expect(Presentation.secretState(gh) == "no value stored")
        gh.broken = true
        #expect(Presentation.secretState(gh) == "can't be used")
    }

    /// No rules is "every app is blocked" only when what the others get
    /// really blocks: a login fallback (defaults.fallback, a hand-written
    /// gate) lets any app have the value after a prompt.
    @Test func noRulesSaysBlockedOnlyWhenTheFallbackBlocks() throws {
        let l = try #require(CLIClient.outcome(try Fixture.result("secret-list", exit: 0)).first(Kind.secretList, as: SecretList.self))
        var notes = l.items[1]
        #expect(Presentation.blocksEveryApp(try #require(notes.policy)))
        notes.policy?.fallback.gate = "login"
        notes.policy?.fallbackSource = "defaults.fallback"
        let p = try #require(notes.policy)
        #expect(!Presentation.blocksEveryApp(p))
        #expect(Presentation.secretState(notes) == "")
        #expect(Presentation.others(p) == "Everyone else: use · login (defaults.fallback)")
        notes.policy = nil
        #expect(Presentation.secretState(notes) == "")
    }

    /// A secret's audit line: decision, who asked (the app, else the chain),
    /// the receiver, the delivery, and the reason.
    @Test func secretEventLine() throws {
        let objs = CLIClient.outcome(try Fixture.result("secret-log", exit: 0)).objects.compactMap { $0.decode(AuditEvent.self) }
        let git = try #require(objs.first), script = try #require(objs.last)
        #expect(Presentation.targetEvent(git)
            == "allowed · com.googlecode.iterm2 → " + (git.fields["receiver"] ?? "?") + " · helper · cached approval")
        #expect(Presentation.targetEvent(script)
            == "blocked · " + (script.fields["chain"] ?? "?") + " → " + (script.fields["receiver"] ?? "?") + " · stdout · no rule matched")
        #expect(Presentation.targetEvent(AuditEvent(time: Date(timeIntervalSince1970: 0), fields: ["decision": "error"])) == "error · unknown caller")
    }

    /// Attack: every field is caller-controlled; cleaned for plain() the
    /// line stays one line in reading order.
    @Test func hostileSecretEventStaysOneCleanLine() {
        let e = AuditEvent(time: Date(timeIntervalSince1970: 0), fields: [
            "decision": "allowed", "app": "evil\u{202E}ppa", "receiver": "x\napproved · trusted\u{2028}", "reason": "**ok**\u{200B}",
        ])
        let shown = PlainText.clean(Presentation.targetEvent(e))
        for bad in ["\n", "\u{202E}", "\u{2028}", "\u{200B}"] { #expect(!shown.contains(bad)) }
        #expect(shown.hasPrefix("allowed · evil") && shown.contains("**ok**"))
    }

    /// A context's state in the list (only what needs attention,
    /// unusable first), its page's lines, and who gets the fallback.
    @Test func k8sLines() throws {
        let l = try #require(CLIClient.outcome(try Fixture.result("k8s-list", exit: 0)).first(Kind.k8sContextList, as: K8sContextList.self))
        try #require(l.items.count == 3)
        var hydra = l.items[0]
        let eks = l.items[1], loose = l.items[2]
        #expect(Presentation.k8sState(hydra) == "" && Presentation.k8sProblem(hydra) == "")
        #expect(Presentation.k8sState(eks) == "no CA yet" && Presentation.k8sProblem(eks) == "No CA for this context: kubectl gets no credential.")
        #expect(Presentation.k8sState(loose) == "no config entry" && Presentation.k8sProblem(loose) == "A CA without a config.yaml entry: kubectl gets no credential.")
        #expect(Presentation.others(try #require(hydra.policy)) == "Everyone else: block (the context's own gate)")
        #expect(Presentation.k8sCluster(try #require(hydra.cluster)) == "Cluster https://hydra.example:16443 · TLS server name hydra.internal")
        #expect(Presentation.k8sCluster(K8sCluster(server: "https://x:6443", tlsServerName: nil, proxyURL: "socks5://127.0.0.1:1080"))
            == "Cluster https://x:6443 · via socks5://127.0.0.1:1080")
        let ca = try #require(hydra.ca)
        #expect(Presentation.k8sCA(ca) == "CA SHA-256 " + ca.fingerprint + " · valid until " + ca.notAfter.formatted(date: .abbreviated, time: .omitted))
        // loose's CA was made with --only-when-unlocked.
        let looseCA = try #require(loose.ca)
        #expect(Presentation.k8sCA(looseCA) == "CA SHA-256 " + looseCA.fingerprint + " · valid until "
            + looseCA.notAfter.formatted(date: .abbreviated, time: .omitted) + " · signs only while the Mac is unlocked")
        #expect(Presentation.k8sIdentity(try #require(hydra.identity), ttl: hydra.ttlCert) == "Certificates for admin (groups system:masters), each valid 15m")
        #expect(Presentation.k8sIdentity(K8sIdentity(user: "dev", groups: []), ttl: "1h0m0s") == "Certificates for dev, each valid 1h")
        for (go, shown) in [("15m0s", "15m"), ("1h0m0s", "1h"), ("1h30m0s", "1h30m"), ("1m30s", "1m30s"), ("45s", "45s")] {
            #expect(Presentation.duration(go) == shown, "\(go)")
        }
        hydra.policy?.rules = []
        #expect(Presentation.k8sState(hydra) == "no rules yet: every app is blocked")
        hydra.state = "ca-unusable"
        hydra.caBroken = true
        hydra.unusableReason = "made by another build of nazar-agent"
        #expect(Presentation.k8sState(hydra) == "can't be used" && Presentation.k8sProblem(hydra) == "made by another build of nazar-agent")
    }

    /// With no context the tab shows the CLI's own setup steps:
    /// each is a line of docs/CLI.md, so the two can't drift, and none runs
    /// the plugin. The forget alert says what forget leaves behind.
    @Test func k8sSetupStepsAndForgetWarning() throws {
        let docs = try String(contentsOf: Self.nazarUI.appendingPathComponent("../../../docs/CLI.md").standardized, encoding: .utf8)
        let lines = docs.split(separator: "\n").map(String.init)
        #expect(Presentation.k8sSetup.map(\.command) == ["nazar k8s ca create", "nazar k8s ca show hydra-nazar --microk8s"])
        for s in Presentation.k8sSetup {
            #expect(lines.contains { $0 == s.command || $0.hasPrefix(s.command + " ") }, "\(s.command)")
            #expect(!s.title.contains("#"), "\(s.title)")
        }
        #expect(!Presentation.k8sSetup.contains { $0.command.contains("k8s credential") || $0.command.contains("import") })
        let w = Presentation.forgetK8sMessage
        #expect(w.contains("Touch ID") && w.contains("kubeconfig entries nazar added") && w.contains("stay valid until they end"))
    }

    /// The three pages share one rule list (its gated Edit…), one
    /// rule sheet and one log view; a context's rule sheet has no receiver
    /// field: every RuleEdit the Kubernetes tab makes says so, and the
    /// sheet hides the row and saves no receiver for it.
    @Test func pagesShareTheRuleEditorAndTheLogView() throws {
        func read(_ f: String) throws -> String { try String(contentsOf: Self.views.appendingPathComponent(f), encoding: .utf8) }
        let window = try read("NazarWindowView.swift"), secrets = try read("SecretsTab.swift"), k8s = try read("K8sTab.swift")
        #expect(window.contains("struct RecentActivity: View") && window.contains("struct RuleRows: View"))
        for (name, src) in [("SecretsTab.swift", secrets), ("K8sTab.swift", k8s)] {
            #expect(src.contains("RecentActivity(log: model.activityLog"), "\(name)")
            #expect(!src.contains("Text(\"Last 24 hours\")") && !src.contains("Button(\"Edit…\")") && !src.contains("struct RuleSheet"), "\(name)")
        }
        #expect(k8s.contains("RuleRows(") && k8s.components(separatedBy: "kind: .change(").count == 2)
        #expect(k8s.components(separatedBy: "RuleEdit(").count == 3
            && k8s.components(separatedBy: "receivers: false)").count == 3)
        #expect(window.contains("if !isKeyGate && edit.receivers {") && window.contains("to: edit.receivers ? Presentation.refs(toField) : []"))
    }

    // MARK: Kubernetes edge and attack cases (test author)

    /// Attack: a context's text comes from config.yaml (a staged,
    /// attacker-writable file) and the agent: every line the page builds
    /// from it, cleaned for plain(), stays one line in reading order.
    @Test func hostileK8sTextStaysOneCleanLine() {
        let bad = ["\n", "\u{202E}", "\u{2028}", "\u{200B}"]
        let lines = [
            Presentation.k8sCluster(K8sCluster(server: "https://x\n· TLS server name trusted", tlsServerName: "a\u{202E}b", proxyURL: "p\u{2028}q")),
            Presentation.k8sIdentity(K8sIdentity(user: "admin\napproved", groups: ["system:masters\u{200B}"]), ttl: "15m0s\n"),
            Presentation.targetEvent(AuditEvent(time: Date(timeIntervalSince1970: 0), fields: [
                "decision": "blocked", "target": "k8s:hydra", "chain": "python3\napproved", "reason": "the program that ran nazar can't be identified\u{202E}",
            ])),
        ]
        for l in lines {
            let shown = PlainText.clean(l)
            #expect(!shown.isEmpty, "\(l)")
            for b in bad { #expect(!shown.contains(b), "\(l)") }
        }
    }

    /// Edge: a state this window doesn't know, or the reply of a forget, is
    /// shown in the CLI's word, never hidden as "fine".
    @Test func unknownK8sStateIsShownAsTheCLISaysIt() throws {
        let l = try #require(CLIClient.outcome(try Fixture.result("k8s-list", exit: 0)).first(Kind.k8sContextList, as: K8sContextList.self))
        var c = try #require(l.items.first)
        c.state = "absent"
        #expect(Presentation.k8sState(c) == "absent")
        c.state = "something-new"
        #expect(Presentation.k8sState(c) == "something-new" && Presentation.k8sProblem(c) == "")
        // A rule-less context in force blocks every app, and says so.
        var eks = l.items[1]
        eks.state = "ok"
        #expect(Presentation.k8sState(eks) == "no rules yet: every app is blocked")
    }

    /// The one way untrusted text reaches the screen.
    @Test func plainIsTheTextOfCleanedText() {
        let t: Text = plain("x\u{202E}y")
        let u: Text = plain(String(repeating: "a", count: 1000), max: 10)
        _ = (t, u)
    }

    /// The window's models: one CLIClient and one ChangeRunner for every
    /// tab, and making them runs nothing (the views and the menu bar start
    /// the streams; a window that is never opened costs no CLI run).
    @MainActor @Test func modelsShareOneClientAndRunNothing() {
        let runner = FakeCLIRunner()
        let m = NazarModels(runner: runner)
        #expect((m.client.runner as AnyObject) === runner)
        #expect(m.changes.client === m.client)
        #expect(m.keys.client === m.client && m.keys.changes === m.changes)
        #expect(m.approvals.client === m.client && m.approvals.changes === m.changes)
        #expect(m.apps.client === m.client)
        #expect(m.activity.client === m.client)
        #expect(m.secrets.client === m.client && m.secrets.changes === m.changes)
        #expect(m.k8s.client === m.client && m.k8s.changes === m.changes && m.k8s.activityLog.client === m.client)
        #expect(m.approvals.starts == 0)
        #expect(runner.calls.isEmpty)
        // The window's initializer exists with this shape; it is not called
        // (no view is made, nothing is put on screen).
        let make: @MainActor (NazarModels) -> NazarWindowView = NazarWindowView.init(models:)
        _ = make
    }

    // MARK: the source scan

    static let nazarUI = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
        .appendingPathComponent("../../Sources/NazarUI").standardized
    static let views = nazarUI.appendingPathComponent("Views")

    func sources(_ dir: URL) throws -> [(String, String)] {
        try FileManager.default.contentsOfDirectory(atPath: dir.path).filter { $0.hasSuffix(".swift") }.sorted().map {
            ($0, try String(contentsOf: dir.appendingPathComponent($0), encoding: .utf8))
        }
    }

    /// Calls whose first argument SwiftUI turns into on-screen text: a
    /// string literal there is a LocalizedStringKey (Markdown in it is
    /// rendered, and a value spliced into it could carry links or
    /// emphasis); a String value there is shown uncleaned. So each of them
    /// takes a plain literal with no interpolation, or a labelled argument
    /// (`action:`, `role:`, …); `Text(verbatim:` is counted (only plain()).
    static let textCalls = ["Text(", "Button(", "Label(", "TextField(", "SecureField(", "Toggle(", "Picker(", "Section(",
                            "Link(", "Menu(", "Tab(", "NavigationLink(", "GroupBox(", "LabeledContent(",
                            ".alert(", ".confirmationDialog(", ".help(", ".navigationTitle("]
    /// Ways around plain() that no view needs.
    static let neverInViews = ["AttributedString(markdown", "LocalizedStringKey(", "Text(attributed", ".init(verbatim:"]

    /// Scans Swift source for text calls that bypass plain(); returns the
    /// problems and how many times `Text(verbatim:` is called.
    static func scan(_ name: String, _ src: String) -> (problems: [String], verbatim: Int) {
        var problems: [String] = []
        var verbatim = 0
        for (i, rawLine) in src.split(separator: "\n", omittingEmptySubsequences: false).enumerated() {
            let line = Substring(stripComment(String(rawLine)))
            let at = "\(name):\(i + 1)"
            for never in neverInViews where line.contains(never) {
                problems.append("\(at) uses \(never): \(rawLine)")
            }
            for call in textCalls {
                var from = line.startIndex
                while let r = line.range(of: call, range: from..<line.endIndex) {
                    from = r.upperBound
                    // Text( must be the call itself, not plainText( or TextField(.
                    if !call.hasPrefix("."), r.lowerBound > line.startIndex {
                        let before = line[line.index(before: r.lowerBound)]
                        if before.isLetter || before.isNumber || before == "_" { continue }
                    }
                    let arg = line[r.upperBound...].drop { $0 == " " }
                    if arg.hasPrefix("\"\"\"") || arg.hasPrefix("#") {
                        problems.append("\(at): \(call) with a multi-line or raw literal: \(rawLine)")
                    } else if arg.hasPrefix("\"") {
                        switch literalEnd(arg.dropFirst()) {
                        case .interpolates:
                            problems.append("\(at) interpolates into a \(call)…\") literal: \(rawLine)")
                        case .unterminated:
                            problems.append("\(at): \(call) literal not closed on its line: \(rawLine)")
                        case .ends(let rest):
                            let next = rest.drop { $0 == " " }
                            if next.hasPrefix("+") {
                                problems.append("\(at) appends a value to a \(call)…\") literal: \(rawLine)")
                            }
                        }
                    } else if arg.hasPrefix("verbatim:") {
                        if call == "Text(" { verbatim += 1 } else { problems.append("\(at): \(call)verbatim: \(rawLine)") }
                    } else if arg.hasPrefix(")") || arg.isEmpty {
                        continue
                    } else if let colon = arg.firstIndex(of: ":"),
                              arg[..<colon].allSatisfy({ $0.isLetter || $0.isNumber || $0 == "_" }), !arg[..<colon].isEmpty {
                        continue // a labelled argument: action:, role:, selection:, isPresented:, item:, …
                    } else {
                        problems.append("\(at): \(call) takes a value, not a literal (use plain()): \(rawLine)")
                    }
                }
            }
        }
        return (problems, verbatim)
    }

    enum LiteralEnd { case interpolates, unterminated, ends(Substring) }

    /// Walks a string literal's body (after its opening quote).
    static func literalEnd(_ s: Substring) -> LiteralEnd {
        var i = s.startIndex
        while i < s.endIndex {
            let c = s[i]
            if c == "\\" {
                let n = s.index(after: i)
                if n < s.endIndex, s[n] == "(" { return .interpolates }
                i = n < s.endIndex ? s.index(after: n) : n
                continue
            }
            if c == "\"" { return .ends(s[s.index(after: i)...]) }
            i = s.index(after: i)
        }
        return .unterminated
    }

    /// The line without a trailing // comment (a // inside a string literal
    /// is kept).
    static func stripComment(_ line: String) -> String {
        var inString = false
        var escaped = false
        var prev: Character = " "
        for (n, c) in line.enumerated() {
            if inString {
                if escaped { escaped = false } else if c == "\\" { escaped = true } else if c == "\"" { inString = false }
            } else if c == "\"" {
                inString = true
            } else if c == "/", prev == "/" {
                return String(line.prefix(n - 1))
            }
            prev = c
        }
        return line
    }

    /// The scanner itself: it finds every way around plain() a view could
    /// take, and passes what the window legitimately writes.
    @Test func scannerCatchesBypasses() {
        let bad = [
            "Text(\"Delete \\(key.name)?\")",
            "Button(\"Revoke \\(a.target)\") { }",
            "Label(\"\\(app.name)\", systemImage: \"lock\")",
            ".alert(\"Delete \\(k.name)?\", isPresented: $x) {",
            "TextField(\"\\(hint)\", text: $s)",
            "Text(\"say \\\"hi\\\" \\(name)\")",
            "Text(key.name)",
            "Button(a.target) { }",
            "Text(\"fix: \" + v.remedy)",
            "Text(#\"\\#(x)\"#)",
            "Text(LocalizedStringKey(x))",
            "Text(AttributedString(markdown: s))",
            "Picker(name, selection: $g) {",
            ".help(app.path)",
            "Toggle(\"Use \\(k.name)\", isOn: $on)",
            "  HStack { Text(\"a\"); Text(\"b \\(c)\") }",
            "Text(verbatim: x) + Text(verbatim: y)",
            "Link(app.name, destination: u)",
        ]
        for (n, src) in bad.enumerated() {
            let r = Self.scan("bad\(n)", src)
            #expect(!r.problems.isEmpty || r.verbatim > 1, "not caught: \(src)")
        }
        let good = """
            Text("SSH keys")
            Button("Delete", role: .destructive) { go() }
            Button { go() } label: { plain(x) }
            Button(action: go) { plain(x) }
            Picker("Gate", selection: $gate) { ForEach(Presentation.gates, id: \\.self) { plain($0) } }
            Text("all").tag("")
            plain("fix: " + v.remedy).font(.caption)
            plain("\\(r.index). " + Presentation.rule(r))
            .alert("Delete this key?", isPresented: $confirm) {
            TextField("Name", text: $name)
            Text("a // b")
            let t = plainText(x) // Text(x) in a comment
            // Text("\\(x)")
            """
        let r = Self.scan("good", good)
        #expect(r.problems.isEmpty, "\(r.problems)")
        #expect(r.verbatim == 0)
        #expect(Self.scan("plain", "    Text(verbatim: PlainText.clean(s, max: max))").verbatim == 1)
    }

    /// Text(verbatim:) only inside plain(); no Text, Button, Label (or any
    /// other text-taking call) interpolates a value into a literal or takes
    /// a String value.
    @Test func untrustedTextGoesThroughPlain() throws {
        let views = try sources(Self.views)
        #expect(views.contains { $0.0 == "Presentation.swift" } && views.contains { $0.0 == "NazarWindowView.swift" })
        var verbatim = 0
        for (name, src) in views {
            let r = Self.scan(name, src)
            verbatim += r.verbatim
            for p in r.problems { Issue.record(Comment(rawValue: p)) }
        }
        #expect(verbatim == 1, "Text(verbatim:) must appear only in plain()")
        // plain() is the one in Presentation.swift, and it cleans.
        let pres = try #require(views.first { $0.0 == "Presentation.swift" }?.1)
        #expect(pres.contains("Text(verbatim: PlainText.clean("))
        // Outside Views, NazarUI calls no Text at all.
        for (name, src) in try sources(Self.nazarUI) {
            #expect(Self.scan(name, src).verbatim == 0, "\(name) calls Text(verbatim:) outside plain()")
        }
    }

    /// The window is a thin client: its views run CLI commands through the
    /// models and put nothing on screen themselves (the app's NazarUIHost
    /// owns the window and the status item); no process, no URL opening.
    @Test func viewsPutNothingOnScreenThemselves() throws {
        for (name, src) in try sources(Self.views) {
            let code = src.split(separator: "\n").map { Self.stripComment(String($0)) }.joined(separator: "\n")
            for never in ["NSStatusBar", "makeKeyAndOrderFront", "NSApp.run", "NSApplication.shared.run",
                          "NSWindow(", "Process(", "NSWorkspace", "openURL", "NSAppleScript", "CGEvent"] {
                #expect(!code.contains(never), "\(name) uses \(never)")
            }
        }
    }
}
