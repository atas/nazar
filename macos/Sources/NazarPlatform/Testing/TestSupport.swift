import CryptoKit
import Foundation

// Stand-ins for the human-facing and persistent parts of SwiftPlatform.
// Used by unit tests, NazarConformanceHost and NazarSmokeHost.
// NazarApp never uses them; scripts/check-app.sh fails the build if its
// sources mention any of these names.

/// An in-memory VaultStore with the fake Vault's semantics
/// (core/platform/fake/vault.go): a missing name is .notFound on get and
/// delete, put replaces, list is a sorted literal-prefix match.
public final class MemoryVault: VaultStore, @unchecked Sendable {
    private let lock = NSLock()
    private var items: [String: Data] = [:]
    public init() {}
    public func get(_ name: String) throws -> Data {
        lock.lock(); defer { lock.unlock() }
        guard let v = items[name] else { throw PlatformError.notFound }
        return v
    }
    public func put(_ name: String, _ value: Data) throws {
        lock.lock(); defer { lock.unlock() }
        items[name] = value
    }
    public func delete(_ name: String) throws {
        lock.lock(); defer { lock.unlock() }
        guard items.removeValue(forKey: name) != nil else { throw PlatformError.notFound }
    }
    public func list(prefix: String) throws -> [String] {
        lock.lock(); defer { lock.unlock() }
        return items.keys.filter { $0.hasPrefix(prefix) }.sorted()
    }
}

/// Keeps audit lines in memory.
public final class MemoryAudit: AuditWriter, @unchecked Sendable {
    private let lock = NSLock()
    private var _lines: [String] = []
    public init() {}
    public var lines: [String] {
        lock.lock(); defer { lock.unlock() }
        return _lines
    }
    public func write(unixNanos: Int64, line: String) throws {
        lock.lock(); defer { lock.unlock() }
        _lines.append(line)
    }
}

/// Records warnings instead of showing windows.
public final class RecordedWarnings: WarningShower, @unchecked Sendable {
    private let lock = NSLock()
    private var _shown: [WarningSpec] = []
    public init() {}
    public var shown: [WarningSpec] {
        lock.lock(); defer { lock.unlock() }
        return _shown
    }
    public func show(_ w: WarningSpec) {
        lock.lock(); defer { lock.unlock() }
        _shown.append(w)
    }
}

public extension SwiftPlatform {
    /// Real callers, events and LaunchServices; the given enclave backend;
    /// scripted login and dialog gates; recorded warnings. The screen-lock
    /// watcher listens to a test notification name, never the system's.
    static func testPlatform(backend: EnclaveBackend, login: ScriptedLoginEvaluator, confirm: ScriptedConfirmer,
                             warnings: WarningShower = RecordedWarnings(),
                             screenLockName: String = "dev.nazar.test.screenIsLocked.\(UUID().uuidString)") -> SwiftPlatform {
        let approvals = ApprovalStore()
        return SwiftPlatform(enclave: EnclaveStore(backend: backend, approvals: approvals), approvals: approvals,
                             login: LoginGate(evaluator: login, approvals: approvals), dialog: confirm,
                             resolver: ProcessResolver(), installed: InstalledApps(), exits: ExitWatcher(),
                             screenLocks: ScreenLockWatcher(name: screenLockName), warnings: warnings)
    }
}

/// Wraps a backend and refuses to create user-presence keys: automated runs
/// on the real Secure Enclave (the conformance and smoke hosts) must never
/// create one. The refusal happens before the wrapped backend is asked;
/// everything else passes through unchanged, approval contexts included.
public final class NoUserPresenceBackend: EnclaveBackend, @unchecked Sendable {
    let inner: EnclaveBackend
    public init(_ inner: EnclaveBackend) { self.inner = inner }
    public func create(purpose: KeyPurpose, userPresence: Bool, whileLocked: Bool) throws -> (blob: Data, publicKey: Data) {
        guard !userPresence else { throw PlatformError.invalid("user-presence keys are disabled in automated runs") }
        return try inner.create(purpose: purpose, userPresence: false, whileLocked: whileLocked)
    }
    public func isKey(_ blob: Data, purpose: KeyPurpose) -> Bool { inner.isKey(blob, purpose: purpose) }
    public func sign(blob: Data, message: Data, context: AuthContext?) throws -> Data {
        try inner.sign(blob: blob, message: message, context: context)
    }
    public func agree(blob: Data, peer: P256.KeyAgreement.PublicKey, context: AuthContext?) throws -> Data {
        try inner.agree(blob: blob, peer: peer, context: context)
    }
}
