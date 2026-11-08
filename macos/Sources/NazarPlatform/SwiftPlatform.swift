import Foundation

/// platform.Vault as the bridge sees it (KeychainVault in Nazar.app).
public protocol VaultStore: AnyObject {
    func get(_ name: String) throws -> Data
    func put(_ name: String, _ value: Data) throws
    func delete(_ name: String) throws
    func list(prefix: String) throws -> [String]
}

/// audit.Sink as the bridge sees it (OSLogAuditSink in Nazar.app).
public protocol AuditWriter: AnyObject {
    func write(unixNanos: Int64, line: String) throws
}

/// Shows the block warning (WarningCenter in Nazar.app).
public protocol WarningShower: AnyObject {
    func show(_ w: WarningSpec)
}

extension KeychainVault: VaultStore {}
extension OSLogAuditSink: AuditWriter {}
extension WarningCenter: WarningShower {}

/// The Swift implementation of core/platform.Platform: one object per
/// process, assembled from the parts below. Nazar.app builds it with the
/// real parts; the conformance and smoke hosts swap the human-facing ones
/// for scripted stand-ins.
public final class SwiftPlatform: @unchecked Sendable {
    public let enclave: EnclaveStore
    public let approvals: ApprovalStore
    public let login: LoginGate
    public let dialog: Confirmer
    public let resolver: ProcessResolver
    public let installed: InstalledApps
    public let exits: ExitWatcher
    public let screenLocks: ScreenLockWatcher
    public let warnings: WarningShower
    /// platform.Exec; nil leaves the exec callbacks out of the table, so
    /// the daemon refuses late-env (secrets design 6.3, D8).
    public let execs: ExecWatcher?

    public init(enclave: EnclaveStore, approvals: ApprovalStore, login: LoginGate, dialog: Confirmer,
                resolver: ProcessResolver, installed: InstalledApps, exits: ExitWatcher,
                screenLocks: ScreenLockWatcher, warnings: WarningShower, execs: ExecWatcher? = nil) {
        self.enclave = enclave
        self.approvals = approvals
        self.login = login
        self.dialog = dialog
        self.resolver = resolver
        self.installed = installed
        self.exits = exits
        self.screenLocks = screenLocks
        self.warnings = warnings
        self.execs = execs
    }
}
