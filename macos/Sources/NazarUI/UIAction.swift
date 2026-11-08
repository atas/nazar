import Foundation

/// A rule as the window's rule sheet edits it: matcher references as the
/// CLI takes them (an apps: name, any, unknown, app:<bundle-id> or
/// signed:<team>[:<id>]), scope, gate and expire ("" = none).
public struct RuleDraft: Equatable, Sendable {
    public var apps: [String]
    public var to: [String]
    public var scope: String
    public var gate: String
    public var expire: String
    public init(apps: [String], to: [String] = [], scope: String = "session", gate: String = "login", expire: String = "") {
        self.apps = apps
        self.to = to
        self.scope = scope
        self.gate = gate
        self.expire = expire
    }

    /// The draft of an existing rule (for editing it).
    public init(_ r: RuleInfo) {
        self.init(apps: r.apps.map(\.ref), to: r.to.map(\.ref), scope: r.policy.scope, gate: r.policy.gate,
                  expire: r.policy.expire ?? "")
    }
}

/// Whose rules a rule action edits: an SSH key's (`nazar ssh-key rule …`),
/// a secret's (`nazar secret rule …`) or a Kubernetes context's
/// (`nazar k8s rule …`). One set of words for all three; the owner
/// is a type, so a key, a secret and a context of the same name can't be
/// confused.
public enum RuleOwner: Equatable, Sendable {
    case key(String)
    case secret(String)
    case k8s(String)

    public var name: String {
        switch self { case .key(let n), .secret(let n), .k8s(let n): return n }
    }
    var command: String {
        switch self { case .key: return "ssh-key"; case .secret: return "secret"; case .k8s: return "k8s" }
    }
    var placeholder: String {
        switch self { case .key: return "<key>"; case .secret: return "<secret>"; case .k8s: return "<context>" }
    }
    /// Whether its rules name receivers (to:). A context's don't: the
    /// program that runs the plugin is the receiver, and the CLI and the
    /// agent refuse --to and --no-to for one, so neither is ever sent.
    public var receivers: Bool {
        if case .k8s = self { return false }
        return true
    }
}

/// Every command the window runs, and nothing else (spec 6.1: everything
/// the UI can do, a person or an agent can do in the terminal). argv is
/// what is passed to the bundled CLI; template is argv with every value
/// replaced by a placeholder, and the list of templates is the contract
/// with the CLI: ContractTests pins it to Fixtures/ui-actions.json, and
/// cmd/nazar's TestUIActionsAreRealCommands runs every template against the
/// real CLI and core.
public enum UIAction: Equatable, Sendable {
    case listKeys
    case keyRules(key: String)
    /// A new key: nazar-agent writes its entry (blocked, plus a login rule
    /// for the terminal the CLI was typed in, so none from the window) and
    /// decides its protection from the entry; for a name with an entry
    /// already, the key under that entry (the last step of the fix for an
    /// unusable key). alwaysAsk (the New key sheet's checkbox) adds
    /// --always-ask: the chip asks on every use (from the window, with no
    /// terminal, the key starts blocked and only login/use rules can be
    /// added). onlyWhenUnlocked (the sheet's other checkbox) adds
    /// --only-when-unlocked: the chip refuses the key while the Mac is
    /// locked. --always-ask implies it, so it is not sent with it.
    case createKey(name: String, alwaysAsk: Bool = false, onlyWhenUnlocked: Bool = false)
    case deleteKey(name: String)
    case publicKey(name: String)
    /// A rule edit, or a key's own gate. Each carries --if-hash (refused
    /// when config.yaml changed since the rules were read) and
    /// --allow-loosen-access: a change that loosens access is written and
    /// the CLI asks for the login gate at once, for exactly that change (exit
    /// 0 in force, 3 denied, 4 the prompt could not be shown); without the
    /// flag the CLI would refuse it and only print what it loosens, which is
    /// for agents, not for a person clicking Save.
    case addRule(RuleOwner, rule: RuleDraft, ifHash: String)
    case setRule(RuleOwner, index: Int, rule: RuleDraft, ifHash: String)
    case removeRule(RuleOwner, index: Int, ifHash: String)
    case setKeyGate(key: String, scope: String, gate: String, expire: String, ifHash: String)
    case configCheck
    /// `config apply`: the approval of the change staged in config.yaml (one
    /// made by hand, or one an edit left waiting); the CLI shows it and binds
    /// the approval to exactly it.
    case configApply
    case status
    case followStatus
    case revokeAll
    case revokeKey(String)
    case revokeSession(String)
    case revokeApp(String)
    /// `log --since`, of one target only when target is not empty.
    case log(since: String, target: String = "")
    case followLog
    case listApps
    case listSecrets
    /// A new secret: its value goes to the CLI's stdin as a CLIInput, never
    /// an argument; from the window the agent writes its entry
    /// blocked with no rule. onlyWhenUnlocked adds --only-when-unlocked.
    case addSecret(name: String, onlyWhenUnlocked: Bool = false)
    case removeSecret(name: String)
    case listK8s
    /// `k8s forget`: the agent's login prompt is the confirmation (the CA
    /// is destroyed, the entry removed); the window's alert before it says
    /// what stays.
    case forgetK8s(name: String)

    /// The arguments for the CLI, --json first.
    public var argv: [String] { ["--json"] + words(placeholders: false) }

    /// argv with values replaced by placeholders (<key>, <matcher>, …).
    public var template: [String] { ["--json"] + words(placeholders: true) }

    /// Whether the command reads a value on stdin (CLIInput): only secret
    /// add; CLIClient refuses input to every other action.
    public var readsInput: Bool {
        if case .addSecret = self { return true }
        return false
    }

    /// Whether the command keeps printing until stopped (--follow).
    public var follows: Bool { self == .followStatus || self == .followLog }

    private func words(placeholders p: Bool) -> [String] {
        func v(_ placeholder: String, _ value: String) -> String { p ? placeholder : value }
        /// The tail of every edit: the hash it was read under, and leave to
        /// loosen (approved on the gate in this run).
        func edit(_ h: String) -> [String] { ["--if-hash", v("<hash>", h), "--allow-loosen-access"] }
        func rule(_ r: RuleDraft, set: Bool, receivers: Bool) -> [String] {
            var w: [String] = []
            for a in r.apps { w += ["--apps", v("<matcher>", a)] }
            if receivers {
                if r.to.isEmpty {
                    if set { w.append("--no-to") }
                } else {
                    for t in r.to { w += ["--to", v("<matcher>", t)] }
                }
            }
            w += ["--scope", v("<scope>", r.scope), "--gate", v("<gate>", r.gate)]
            if r.expire.isEmpty {
                if set { w.append("--no-expire") }
            } else {
                w += ["--expire", v("<duration>", r.expire)]
            }
            return w
        }
        switch self {
        case .listKeys: return ["ssh-key", "list"]
        case .keyRules(let k): return ["ssh-key", "rules", v("<key>", k)]
        case let .createKey(n, always, unlocked):
            return ["ssh-key", "create", v("<key>", n)] + (always ? ["--always-ask"] : unlocked ? ["--only-when-unlocked"] : [])
        case .deleteKey(let n): return ["ssh-key", "delete", v("<key>", n)]
        case .publicKey(let n): return ["ssh-key", "pubkey", v("<key>", n)]
        case let .addRule(o, r, h):
            return [o.command, "rule", "add", v(o.placeholder, o.name)] + rule(r, set: false, receivers: o.receivers) + edit(h)
        case let .setRule(o, i, r, h):
            return [o.command, "rule", "set", v(o.placeholder, o.name), v("<n>", String(i))] + rule(r, set: true, receivers: o.receivers) + edit(h)
        case let .removeRule(o, i, h):
            return [o.command, "rule", "remove", v(o.placeholder, o.name), v("<n>", String(i))] + edit(h)
        case let .setKeyGate(k, s, g, e, h):
            var w = ["ssh-key", "set", v("<key>", k), "--scope", v("<scope>", s), "--gate", v("<gate>", g)]
            w += e.isEmpty ? ["--no-expire"] : ["--expire", v("<duration>", e)]
            return w + edit(h)
        case .configCheck: return ["config", "check"]
        case .configApply: return ["config", "apply"]
        case .status: return ["status"]
        case .followStatus: return ["status", "--follow"]
        case .revokeAll: return ["revoke", "--all"]
        case .revokeKey(let k): return ["revoke", "--key", v("<key>", k)]
        case .revokeSession(let s): return ["revoke", "--session", v("<session>", s)]
        case .revokeApp(let a): return ["revoke", "--app", v("<bundle-id>", a)]
        case let .log(since, target):
            return ["log", "--since", v("<duration>", since)] + (target.isEmpty ? [] : ["--target", v("<target>", target)])
        case .followLog: return ["log", "--follow"]
        case .listApps: return ["apps", "list"]
        case .listSecrets: return ["secret", "list"]
        case let .addSecret(n, unlocked): return ["secret", "add", v("<secret>", n)] + (unlocked ? ["--only-when-unlocked"] : [])
        case .removeSecret(let n): return ["secret", "rm", v("<secret>", n)]
        case .listK8s: return ["k8s", "list"]
        case .forgetK8s(let n): return ["k8s", "forget", v("<context>", n)]
        }
    }

    /// One action of every case, with every optional part present, so
    /// their templates cover every argument shape the window can produce.
    public static var samples: [UIAction] {
        let full = RuleDraft(apps: ["claude", "iterm"], to: ["signed:apple"], scope: "session", gate: "dialog", expire: "8h")
        let bare = RuleDraft(apps: ["iterm"], scope: "use", gate: "login")
        return [
            .listKeys, .keyRules(key: "github"), .createKey(name: "github"), .createKey(name: "prod", alwaysAsk: true),
            .createKey(name: "laptop", onlyWhenUnlocked: true),
            .deleteKey(name: "github"), .publicKey(name: "github"),
            .addRule(.key("github"), rule: full, ifHash: "h"), .addRule(.key("github"), rule: bare, ifHash: "h"),
            .setRule(.key("github"), index: 1, rule: full, ifHash: "h"), .setRule(.key("github"), index: 1, rule: bare, ifHash: "h"),
            .removeRule(.key("github"), index: 1, ifHash: "h"),
            .setKeyGate(key: "hydra", scope: "session", gate: "login", expire: "8h", ifHash: "h"),
            .setKeyGate(key: "hydra", scope: "use", gate: "login", expire: "", ifHash: "h"),
            .listSecrets, .addSecret(name: "GH_TOKEN"), .addSecret(name: "GH_TOKEN", onlyWhenUnlocked: true),
            .addRule(.secret("GH_TOKEN"), rule: full, ifHash: "h"), .addRule(.secret("GH_TOKEN"), rule: bare, ifHash: "h"),
            .setRule(.secret("GH_TOKEN"), index: 1, rule: full, ifHash: "h"), .setRule(.secret("GH_TOKEN"), index: 1, rule: bare, ifHash: "h"),
            .removeRule(.secret("GH_TOKEN"), index: 1, ifHash: "h"), .removeSecret(name: "GH_TOKEN"),
            .listK8s, .addRule(.k8s("hydra"), rule: full, ifHash: "h"), .addRule(.k8s("hydra"), rule: bare, ifHash: "h"),
            .setRule(.k8s("hydra"), index: 1, rule: full, ifHash: "h"), .setRule(.k8s("hydra"), index: 1, rule: bare, ifHash: "h"),
            .removeRule(.k8s("hydra"), index: 1, ifHash: "h"), .forgetK8s(name: "hydra"),
            .configCheck, .configApply, .status, .followStatus, .revokeAll, .revokeKey("github"),
            .revokeSession("4120@1791072000"), .revokeApp("com.googlecode.iterm2"), .log(since: "1h"),
            .log(since: "24h", target: "secret:GH_TOKEN"), .followLog,
            .listApps,
        ]
    }
}
