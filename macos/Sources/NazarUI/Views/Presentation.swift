import Foundation
import SwiftUI

/// The one way the window shows text that is not a literal of its own:
/// verbatim (no Markdown, no links, no localization lookup) and cleaned
/// (PlainText). PresentationTests scans the view sources: the verbatim
/// Text initializer is called here and nowhere else, and no Text, Button or
/// Label literal interpolates a value.
public func plain(_ s: String, max: Int = PlainText.defaultMax) -> Text {
    Text(verbatim: PlainText.clean(s, max: max))
}

/// Strings the window derives from CLI objects, kept out of the views so
/// they can be tested without putting anything on screen.
public enum Presentation {
    public static let gates = ["login", "dialog", "none", "block"]
    public static let keyGates = ["login", "dialog", "block"]
    public static let scopes = ["use", "session", "app"]

    /// One line under the scope picker: how long one approval lasts.
    public static func scopeHelp(_ scope: String) -> String {
        switch scope {
        case "use": return "Asks every time"
        case "session": return "Once per terminal tab or tool run"
        case "app": return "Until the app quits"
        default: return ""
        }
    }

    /// The menu bar's line about approvals.
    public static func approvalsLine(_ count: Int) -> String {
        switch count {
        case 0: return "No current approvals"
        case 1: return "1 current approval"
        default: return "\(count) current approvals"
        }
    }

    /// The staged-change banner's headline: what it means, not the diff.
    public static func stagedTitle(_ d: ConfigDiff) -> String {
        d.loosens
            ? "Your config was changed to allow more access. The change isn't in force until you approve it."
            : "Your config was changed. The change isn't in force until you approve it."
    }

    /// Under the headline: approving is a consent, so say whose change it
    /// should be (the change may not have been made in this window).
    public static let stagedAdvice = "Approve only if you made this change. Otherwise revert config.yaml."

    /// The staged change in full, for the Details disclosure: the diff, then
    /// what each loosening allows.
    public static func stagedDetails(_ d: ConfigDiff) -> [String] {
        d.changes + (d.loosening ?? []).map { "allows more: " + $0 }
    }

    /// The vault banner's headline.
    public static let vaultTitle = "Nazar can't read some of what it saved in the Keychain."

    /// One vault item Nazar.app runs without, in plain words. The item name
    /// comes from the Keychain (another program can plant one): it is shown
    /// through plain(), never interpreted.
    public static func vaultLine(_ v: VaultProblem) -> String {
        if v.item == "config/approved" {
            return "It no longer knows which config you approved, so every key is blocked until you approve the config again."
        }
        if v.item.hasPrefix("ssh-key/") {
            let name = String(v.item.dropFirst("ssh-key/".count))
            return "Key " + name + " can't be used. It was probably made by an earlier build of Nazar; make it again."
        }
        return "Item " + v.item + ": " + v.effect
    }

    /// The setup banner's headline: the lines under it are the
    /// CLI's own words, each ending with the fix.
    public static let setupTitle = "Something outside nazar isn't wired to it. Each line says what to change."

    /// A key's state in the list: only what needs attention.
    public static func keyState(_ k: SSHKey) -> String {
        if !k.usable { return "can't be used" }
        if !k.configured { return "no rules yet: every use is blocked" }
        return "" // a working key needs no subtitle
    }

    /// The badge of a key the chip asks for on every use (userPresence, the
    /// CLI's creation-time record); "" for any other key.
    public static func keyBadge(_ k: SSHKey) -> String {
        k.userPresence ? "Asks every time (chip)" : ""
    }

    /// The badge of a usable key the chip refuses while the Mac is locked
    /// (whileLocked false); "" for any other key. A broken key gets none:
    /// its record can't be read.
    public static func lockBadge(_ k: SSHKey) -> String {
        k.usable && !k.whileLocked ? onlyWhenUnlocked : ""
    }

    /// The same for a stored secret.
    public static func lockBadge(_ s: Secret) -> String {
        s.stored && !s.broken && !s.whileLocked ? onlyWhenUnlocked : ""
    }

    static let onlyWhenUnlocked = "Only when unlocked"

    /// The checkbox of the New key and New secret sheets
    /// (`--only-when-unlocked`) and the line under it. With "always ask"
    /// on, the key's checkbox is on and can't be changed.
    public static let onlyWhenUnlockedLabel = "Only while the Mac is unlocked (enforced by the chip)"
    public static let onlyWhenUnlockedHelp = "Off: also works while the Mac is locked, once you have logged in, for jobs that run while you are away. Can't be changed later."
    public static let onlyWhenUnlockedForced = "Always on for a key that asks for Touch ID on every use."

    /// The New key sheet's checkbox (`ssh-key create --always-ask`) and the
    /// line under it.
    public static let alwaysAskLabel = "Ask for Touch ID on every use (enforced by the chip)"
    public static let alwaysAskHelp = "Strongest protection, for keys like production root logins. Can't be loosened later."

    /// When a key was last used, relative to since.
    public static func lastUsed(_ k: SSHKey, since: Date?, now: Date = Date()) -> String {
        guard let u = k.lastUsed else {
            guard let since else { return "not used" }
            return "not used since Nazar started " + relative(since, now: now)
        }
        var s = "\(u.decision) " + relative(u.time, now: now)
        if let app = u.app, !app.isEmpty { s += " by " + app }
        return s
    }

    static func relative(_ t: Date, now: Date) -> String {
        let f = RelativeDateTimeFormatter()
        f.unitsStyle = .full
        return f.localizedString(for: t, relativeTo: now)
    }

    /// A rule as one line: "claude, iterm → signed:apple · session · dialog · 8h".
    public static func rule(_ r: RuleInfo) -> String {
        var s = r.apps.map(matcher).joined(separator: ", ")
        if !r.to.isEmpty { s += " → " + r.to.map(matcher).joined(separator: ", ") }
        return s + " · " + policy(r.policy)
    }

    public static func policy(_ p: PolicyInfo) -> String {
        var parts = [p.gate]
        if p.gate == "login" || p.gate == "dialog" { parts.insert(p.scope, at: 0) }
        if let e = p.expire, !e.isEmpty { parts.append("expires after " + e) }
        return parts.joined(separator: " · ")
    }

    /// A matcher as `--apps` writes it; a path: entry by its path.
    public static func matcher(_ m: MatcherInfo) -> String {
        if m.kind == "path", let p = m.path, !p.isEmpty { return "path:" + p }
        return m.ref.isEmpty ? m.kind : m.ref
    }

    /// What callers no rule matches get.
    public static func others(_ r: SSHKeyRules) -> String {
        let source: String
        switch r.fallbackSource {
        case "key-gate": source = "the key's own gate"
        case "secret-gate": source = "the secret's own gate"
        case "context-gate": source = "the context's own gate"
        default: source = "defaults.fallback"
        }
        return "Everyone else: " + policy(r.fallback) + " (" + source + ")"
    }

    /// Matcher references typed into a field, split at commas, as on the
    /// command line.
    public static func refs(_ field: String) -> [String] {
        var out: [String] = []
        var rest = Substring(field)
        while !rest.isEmpty {
            let trimmed = rest.drop { $0 == " " }
            if let comma = trimmed.firstIndex(of: ",") {
                let r = trimmed[..<comma].trimmingCharacters(in: .whitespaces)
                if !r.isEmpty { out.append(r) }
                rest = trimmed[trimmed.index(after: comma)...]
            } else {
                let r = trimmed.trimmingCharacters(in: .whitespaces)
                if !r.isEmpty { out.append(r) }
                break
            }
        }
        return out
    }

    /// Whether the rule sheet can edit r without changing a matcher the user
    /// did not touch. The sheet shows each list as its refs joined with ", "
    /// and saves refs(field), which sends --apps/--to again in full, so a
    /// rule is editable only when every matcher's ref says exactly what the
    /// matcher is and the joined field splits back into the same refs. Not
    /// editable (Remove still is; edit config.yaml or `nazar ssh-key rule
    /// set`): an inline {app, team} (a ref has no team), an inline command:
    /// matcher (no ref), a signed team with a colon, a path with a comma or
    /// a space at either end (the field splits and trims).
    public static func editable(_ r: RuleInfo) -> Bool {
        roundTrips(r.apps) && roundTrips(r.to)
    }

    static func roundTrips(_ list: [MatcherInfo]) -> Bool {
        let rs = list.map(\.ref)
        guard list.allSatisfy(refIsExact) else { return false }
        return refs(rs.joined(separator: ", ")) == rs
    }

    /// The ref, given to `--apps`/`--to`, writes back this very matcher.
    static func refIsExact(_ m: MatcherInfo) -> Bool {
        let ref = m.ref
        guard !ref.isEmpty, ref.trimmingCharacters(in: .whitespaces) == ref else { return false }
        if let name = m.name, !name.isEmpty { return ref == name }
        let team = m.team ?? "", id = m.id ?? ""
        guard (m.command ?? []).isEmpty else { return false }
        switch m.kind {
        case "app":
            return team.isEmpty && !id.isEmpty && ref == "app:" + id
        case "signed":
            guard !team.isEmpty, !team.contains(":") else { return false }
            return ref == (id.isEmpty ? "signed:" + team : "signed:" + team + ":" + id)
        case "path":
            let path = m.path ?? ""
            return !path.isEmpty && ref == "path:" + path
        default:
            return false
        }
    }

    /// A secret's state in the list: only what needs attention, unusable first.
    public static func secretState(_ s: Secret) -> String {
        if s.broken { return "can't be used" }
        if !s.stored { return "no value stored" }
        if let p = s.policy, blocksEveryApp(p) { return "no rules yet: every app is blocked" }
        return ""
    }

    /// No rule, and what the others get blocks: no app can have the value.
    public static func blocksEveryApp(_ p: SSHKeyRules) -> Bool {
        p.rules.isEmpty && p.fallback.gate == "block"
    }

    /// How a secret reaches a program (its deliver list), in the commands' words.
    public static func delivery(_ deliver: [String]) -> String {
        let words = ["helper": "git's credential helper", "stdout": "nazar get", "late-env": "nazar run",
                     "env": "nazar run (startup environment)"]
        return "Delivered by " + deliver.map { words[$0] ?? $0 }.joined(separator: ", ")
    }

    /// A secret's or a context's audit line on its page: allowed or blocked,
    /// who asked (the app, else the chain), the receiver, the delivery when
    /// there is one, why.
    public static func targetEvent(_ e: AuditEvent) -> String {
        let f = e.fields
        let who = [f["app"], f["chain"]].compactMap { $0 }.first { !$0.isEmpty } ?? "unknown caller"
        var s = (f["decision"] ?? "?") + " · " + who
        if let r = f["receiver"], !r.isEmpty { s += " → " + r }
        if let d = f["delivery"], !d.isEmpty { s += " · " + d }
        if let r = f["reason"], !r.isEmpty, r != f["decision"] { s += " · " + r }
        return s
    }

    // MARK: Kubernetes

    /// A context's state in the list: only what needs attention, unusable first.
    public static func k8sState(_ c: K8sContext) -> String {
        switch c.state {
        case "ok":
            if let p = c.policy, blocksEveryApp(p) { return "no rules yet: every app is blocked" }
            return ""
        case "ca-unusable": return "can't be used"
        case "no-ca": return "no CA yet"
        case "no-entry": return "no config entry"
        default: return c.state // absent, or a state this window doesn't know: the CLI's word
        }
    }

    /// What is wrong with a context, on its page above the fix line ("" when nothing).
    public static func k8sProblem(_ c: K8sContext) -> String {
        switch c.state {
        case "ca-unusable": return c.unusableReason ?? "its CA can't be used"
        case "no-ca": return "No CA for this context: kubectl gets no credential."
        case "no-entry": return "A CA without a config.yaml entry: kubectl gets no credential."
        default: return ""
        }
    }

    /// The recorded cluster: the server, and what else pins it when set.
    public static func k8sCluster(_ c: K8sCluster) -> String {
        var s = "Cluster " + c.server
        if let n = c.tlsServerName, !n.isEmpty { s += " · TLS server name " + n }
        if let p = c.proxyURL, !p.isEmpty { s += " · via " + p }
        return s
    }

    public static func k8sCA(_ ca: K8sCA) -> String {
        "CA SHA-256 " + ca.fingerprint + " · valid until " + ca.notAfter.formatted(date: .abbreviated, time: .omitted)
            + (ca.whileLocked ? "" : " · signs only while the Mac is unlocked")
    }

    /// Who the minted certificates name, and how long each lasts (ttl_cert).
    public static func k8sIdentity(_ i: K8sIdentity, ttl: String?) -> String {
        var s = "Certificates for " + i.user
        if !i.groups.isEmpty { s += " (groups " + i.groups.joined(separator: ", ") + ")" }
        if let t = ttl, !t.isEmpty { s += ", each valid " + duration(t) }
        return s
    }

    /// A Go duration as people write it: 15m0s → 15m, 1h0m0s → 1h.
    static func duration(_ go: String) -> String {
        var s = go
        if s.hasSuffix("m0s") { s.removeLast(2) }
        if s.hasSuffix("h0m") { s.removeLast(2) }
        return s
    }

    /// With no context: the setup steps as (what it does, the command).
    /// Each command starts a line of docs/CLI.md's Kubernetes block
    /// (PresentationTests compares them). The window runs none of them:
    /// they touch the cluster and the kubeconfig.
    public static let k8sSetup: [(title: String, command: String)] = [
        ("Set a context up: it asks for the name, the server and its CA, then Touch ID once", "nazar k8s ca create"),
        ("Make the cluster trust its CA: run the steps it printed on the node (this prints them again)", "nazar k8s ca show hydra-nazar --microk8s"),
    ]

    /// The alert before Forget…: what forget does, and what it leaves.
    public static let forgetK8sMessage = "nazar asks for Touch ID / Watch / password, then destroys the context's CA and removes its config.yaml entry and the kubeconfig entries nazar added for it (those still exactly nazar's; it names any others for you to remove). Certificates already handed out stay valid until they end (15 minutes by default). This can't be undone."

    /// An audit event as one line: decision, target, who.
    public static func event(_ e: AuditEvent) -> String {
        let f = e.fields
        var s = (f["decision"] ?? "?") + " " + (f["target"] ?? "")
        if let app = f["app"], !app.isEmpty { s += " · " + app }
        if let chain = f["chain"], !chain.isEmpty { s += " · " + chain }
        if let r = f["reason"], !r.isEmpty { s += " · " + r }
        return s
    }

    /// An Activity line: the event, its count after the decision when it
    /// stands for several ("blocked ×4 ssh:github · …").
    public static func activityLine(_ l: ActivityLine) -> String {
        let s = event(l.event)
        guard l.count > 1, let d = l.event.fields["decision"], s.hasPrefix(d) else { return s }
        return d + " ×\(l.count)" + s.dropFirst(d.count)
    }

    /// When an Activity line happened: from the oldest to the newest of a run.
    public static func activityTime(_ l: ActivityLine) -> String {
        l.count > 1 && l.oldest != l.event.time ? l.oldest.formatted() + " – " + l.event.time.formatted() : l.event.time.formatted()
    }
}
