import Foundation

/// One target's audit lines as a page shows them (`nazar log --since 24h
/// --target T`): newest first, at most maxEvents, and only under the target
/// they were read for; a read that started earlier and ends later never
/// replaces a later one. The Secrets and Kubernetes tabs each have one;
/// the Activity tab has everything else, live.
@MainActor
public final class TargetActivity: ObservableObject {
    public let client: CLIClient
    @Published public private(set) var error: String?
    /// The last lines read, and the target they were read for.
    @Published private var read: (target: String, events: [AuditEvent])?
    /// Counts load calls: only the latest one's answer is kept.
    private var generation = 0
    public static let since = "24h"
    public static let maxEvents = 50

    public init(client: CLIClient) { self.client = client }

    /// The lines read for target, newest first; nil until read.
    public func events(for target: String) -> [AuditEvent]? {
        read?.target == target ? read?.events : nil
    }

    public func load(_ target: String) async {
        generation += 1
        let mine = generation
        error = nil
        let out = await client.call(.log(since: Self.since, target: target))
        guard mine == generation else { return } // a later read replaced this one
        if case .ok(let objs) = out {
            let events = objs.compactMap { $0.kind == Kind.auditEvent ? $0.decode(AuditEvent.self) : nil }.reversed()
            read = (target, Array(events.prefix(Self.maxEvents)))
        } else {
            read = nil
            error = out.problem?.message ?? "could not read the log"
        }
    }
}
