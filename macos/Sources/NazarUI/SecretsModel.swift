import Foundation

/// The Secrets tab (spec 6.1, Milestone 11): each secret's state, delivery,
/// rules and warnings (`nazar secret list`) and its recent audit lines
/// (`nazar log --target secret:NAME`); add, delete, add / edit / remove
/// rules. Every read and change is a CLI command (UIAction). It never holds
/// a value: add takes a CLIInput, which goes to `nazar secret add`'s stdin
/// and is wiped when that run ends.
@MainActor
public final class SecretsModel: ObservableObject {
    public let client: CLIClient
    public let changes: ChangeRunner
    @Published public private(set) var secrets: [Secret] = []
    @Published public private(set) var error: String?
    /// The secret's page's recent audit lines (shared with the Kubernetes tab).
    public let activityLog: TargetActivity

    public init(client: CLIClient, changes: ChangeRunner) {
        self.client = client
        self.changes = changes
        activityLog = TargetActivity(client: client)
    }

    public func refresh() async {
        let out = await client.call(.listSecrets)
        if let l = out.first(Kind.secretList, as: SecretList.self) {
            (secrets, error) = (l.items, nil)
        } else {
            error = out.problem?.message ?? "could not read the secrets"
        }
    }

    /// The secret named name when it has no rule (blocked for every app):
    /// after an Add from the window the tab opens its rule sheet.
    public func ruleless(_ name: String) -> Secret? {
        secrets.first { $0.name == name && ($0.policy?.rules.isEmpty ?? true) }
    }

    /// The hash of the config the secret's rules were read from (--if-hash).
    func hash(_ s: Secret) -> String { s.policy?.configHash ?? "" }

    /// `nazar secret add NAME` with value on its stdin; value is wiped when
    /// this returns, whatever the outcome, and is never sent again.
    /// onlyWhenUnlocked adds --only-when-unlocked.
    @discardableResult
    public func add(name: String, value: CLIInput, onlyWhenUnlocked: Bool = false) async -> ChangeResult {
        await change(.addSecret(name: name, onlyWhenUnlocked: onlyWhenUnlocked), input: value, done: "Added \(name)")
    }

    @discardableResult
    public func delete(_ s: Secret) async -> ChangeResult {
        await change(.removeSecret(name: s.name), done: "Deleted \(s.name)")
    }

    @discardableResult
    public func addRule(to s: Secret, _ rule: RuleDraft) async -> ChangeResult {
        await change(.addRule(.secret(s.name), rule: rule, ifHash: hash(s)), done: "Rule added to \(s.name)")
    }

    @discardableResult
    public func updateRule(of s: Secret, index: Int, _ rule: RuleDraft) async -> ChangeResult {
        await change(.setRule(.secret(s.name), index: index, rule: rule, ifHash: hash(s)), done: "Rule \(index) of \(s.name) changed")
    }

    @discardableResult
    public func removeRule(of s: Secret, index: Int) async -> ChangeResult {
        await change(.removeRule(.secret(s.name), index: index, ifHash: hash(s)), done: "Rule \(index) of \(s.name) removed")
    }

    /// A secret's audit target.
    public static func target(_ name: String) -> String { "secret:" + name }
    public var activityError: String? { activityLog.error }
    /// The audit lines read for name, newest first; nil until read.
    public func activity(for name: String) -> [AuditEvent]? { activityLog.events(for: Self.target(name)) }
    public func loadActivity(_ name: String) async { await activityLog.load(Self.target(name)) }

    private func change(_ action: UIAction, input: CLIInput? = nil, done: String) async -> ChangeResult {
        let r = await changes.perform(action, input: input, done: done)
        await refresh()
        return r
    }
}
