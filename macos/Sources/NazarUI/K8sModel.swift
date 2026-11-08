import Foundation

/// The Kubernetes tab (spec 6.1, Milestone 13): each context's state,
/// cluster, CA, identity, rules and warnings (`nazar k8s list`)
/// and its recent audit lines (`nazar log --target k8s:NAME`); add / edit /
/// remove rules (`nazar k8s rule …`, never with a receiver) and forget
/// (`nazar k8s forget`). Every read and change is a CLI command (UIAction):
/// it never reads config.yaml, the kubeconfig, the CA file or the Vault,
/// and runs no k8s ca or credential command.
@MainActor
public final class K8sModel: ObservableObject {
    public let client: CLIClient
    public let changes: ChangeRunner
    public let activityLog: TargetActivity
    @Published public private(set) var contexts: [K8sContext] = []
    @Published public private(set) var error: String?

    public init(client: CLIClient, changes: ChangeRunner) {
        self.client = client
        self.changes = changes
        activityLog = TargetActivity(client: client)
    }

    /// A context's audit target.
    public static func target(_ name: String) -> String { "k8s:" + name }

    public func refresh() async {
        let out = await client.call(.listK8s)
        if let l = out.first(Kind.k8sContextList, as: K8sContextList.self) {
            (contexts, error) = (l.items, nil)
        } else {
            error = out.problem?.message ?? "could not read the Kubernetes contexts"
        }
    }

    /// The hash of the config the context's rules were read from (--if-hash).
    func hash(_ c: K8sContext) -> String { c.policy?.configHash ?? "" }

    @discardableResult
    public func addRule(to c: K8sContext, _ rule: RuleDraft) async -> ChangeResult {
        await change(.addRule(.k8s(c.name), rule: rule, ifHash: hash(c)), done: "Rule added to \(c.name)")
    }

    @discardableResult
    public func updateRule(of c: K8sContext, index: Int, _ rule: RuleDraft) async -> ChangeResult {
        await change(.setRule(.k8s(c.name), index: index, rule: rule, ifHash: hash(c)), done: "Rule \(index) of \(c.name) changed")
    }

    @discardableResult
    public func removeRule(of c: K8sContext, index: Int) async -> ChangeResult {
        await change(.removeRule(.k8s(c.name), index: index, ifHash: hash(c)), done: "Rule \(index) of \(c.name) removed")
    }

    /// `nazar k8s forget NAME`: the agent's login prompt decides; refused
    /// while config.yaml has a change waiting, it approves nothing.
    @discardableResult
    public func forget(_ c: K8sContext) async -> ChangeResult {
        await change(.forgetK8s(name: c.name), done: "Forgot \(c.name)")
    }

    /// The audit lines read for name, newest first; nil until read.
    public func activity(for name: String) -> [AuditEvent]? { activityLog.events(for: Self.target(name)) }
    public func loadActivity(_ name: String) async { await activityLog.load(Self.target(name)) }

    private func change(_ action: UIAction, done: String) async -> ChangeResult {
        let r = await changes.perform(action, done: done)
        await refresh()
        return r
    }
}
