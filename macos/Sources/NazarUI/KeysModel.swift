import Foundation

/// The SSH keys tab (spec 6.1): keys, fingerprints, rules, last use, why a
/// key is unusable; create, delete, copy the public key, add, edit and
/// remove rules, set a key's own gate. Every read and change is a CLI
/// command (UIAction).
@MainActor
public final class KeysModel: ObservableObject {
    public let client: CLIClient
    public let changes: ChangeRunner
    @Published public private(set) var keys: [SSHKey] = []
    /// When Nazar.app started: "last used" covers the time since.
    @Published public private(set) var since: Date?
    @Published public private(set) var error: String?

    public init(client: CLIClient, changes: ChangeRunner) {
        self.client = client
        self.changes = changes
    }

    public func refresh() async {
        let out = await client.call(.listKeys)
        if let l = out.first(Kind.sshKeyList, as: SSHKeyList.self) {
            (keys, since, error) = (l.items, l.since, nil)
        } else {
            error = out.problem?.message ?? "could not read the key list"
        }
    }

    /// The hash of the config the key's rules were read from: an edit is
    /// refused if config.yaml changed since (`--if-hash`).
    func hash(_ key: SSHKey) -> String { key.policy?.configHash ?? "" }

    /// alwaysAsk: the chip asks for Touch ID on every use (--always-ask).
    /// onlyWhenUnlocked: the chip refuses the key while the Mac is locked
    /// (--only-when-unlocked; always so with alwaysAsk).
    @discardableResult
    public func create(name: String, alwaysAsk: Bool = false, onlyWhenUnlocked: Bool = false) async -> ChangeResult {
        await change(.createKey(name: name, alwaysAsk: alwaysAsk, onlyWhenUnlocked: onlyWhenUnlocked), done: "Created \(name)")
    }

    @discardableResult
    public func delete(_ key: SSHKey) async -> ChangeResult {
        await change(.deleteKey(name: key.name), done: "Deleted \(key.name)")
    }

    @discardableResult
    public func addRule(to key: SSHKey, _ rule: RuleDraft) async -> ChangeResult {
        await change(.addRule(.key(key.name), rule: rule, ifHash: hash(key)), done: "Rule added to \(key.name)")
    }

    @discardableResult
    public func updateRule(of key: SSHKey, index: Int, _ rule: RuleDraft) async -> ChangeResult {
        await change(.setRule(.key(key.name), index: index, rule: rule, ifHash: hash(key)), done: "Rule \(index) of \(key.name) changed")
    }

    @discardableResult
    public func removeRule(of key: SSHKey, index: Int) async -> ChangeResult {
        await change(.removeRule(.key(key.name), index: index, ifHash: hash(key)), done: "Rule \(index) of \(key.name) removed")
    }

    @discardableResult
    public func setKeyGate(of key: SSHKey, scope: String, gate: String, expire: String) async -> ChangeResult {
        await change(.setKeyGate(key: key.name, scope: scope, gate: gate, expire: expire, ifHash: hash(key)),
                     done: "Gate of \(key.name) changed")
    }

    /// The OpenSSH public key line, for the clipboard.
    public func publicKey(_ key: SSHKey) async -> String? {
        await client.call(.publicKey(name: key.name)).first(Kind.sshKey, as: SSHKey.self)?.publicKey
    }

    private func change(_ action: UIAction, done: String) async -> ChangeResult {
        let r = await changes.perform(action, done: done)
        await refresh()
        return r
    }
}

/// The Apps tab (spec 6.1): the top-level apps: matchers, pinned teams,
/// what keeps one from matching and the command that fixes it. Read-only.
@MainActor
public final class AppsModel: ObservableObject {
    public let client: CLIClient
    @Published public private(set) var apps: [AppEntry] = []
    @Published public private(set) var error: String?

    public init(client: CLIClient) {
        self.client = client
    }

    public func refresh() async {
        let out = await client.call(.listApps)
        if let l = out.first(Kind.appList, as: AppList.self) {
            (apps, error) = (l.items, nil)
        } else {
            error = out.problem?.message ?? "could not read the apps"
        }
    }
}
