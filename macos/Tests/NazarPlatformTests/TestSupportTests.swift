import CryptoKit
import Foundation
import Testing
@testable import NazarPlatform

// The stand-ins that tests and the automated hosts (conformance, smoke) put
// in place of the human-facing and persistent parts. They must behave like
// the parts they replace (the fake Vault's semantics), and
// NoUserPresenceBackend must make it impossible for an automated run on the
// real Secure Enclave to create a key that would need a person to sign.
// Nothing here touches a Keychain, a prompt or a window.

/// Wraps a software backend and records what it was asked to create.
final class RecordingBackend: EnclaveBackend, @unchecked Sendable {
    let inner = SoftwareEnclaveBackend()
    private let lock = NSLock()
    private var _creates: [Bool] = []
    var creates: [Bool] { lock.lock(); defer { lock.unlock() }; return _creates }
    func create(purpose: KeyPurpose, userPresence: Bool, whileLocked: Bool) throws -> (blob: Data, publicKey: Data) {
        lock.lock()
        _creates.append(userPresence)
        lock.unlock()
        return try inner.create(purpose: purpose, userPresence: userPresence, whileLocked: whileLocked)
    }
    func isKey(_ blob: Data, purpose: KeyPurpose) -> Bool { inner.isKey(blob, purpose: purpose) }
    func sign(blob: Data, message: Data, context: AuthContext?) throws -> Data {
        try inner.sign(blob: blob, message: message, context: context)
    }
    func agree(blob: Data, peer: P256.KeyAgreement.PublicKey, context: AuthContext?) throws -> Data {
        try inner.agree(blob: blob, peer: peer, context: context)
    }
}

@Suite struct NoUserPresenceBackendTests {
    @Test func refusesPresenceKeysAndPassesTheRest() throws {
        let s = EnclaveStore(backend: NoUserPresenceBackend(SoftwareEnclaveBackend()), approvals: ApprovalStore())
        #expect(throws: PlatformError.invalid("user-presence keys are disabled in automated runs")) { try s.createKey(purpose: 1, auth: 1, access: 0) }
        let (h, _) = try s.createKey(purpose: 1, auth: 0, access: 0)
        _ = try s.sign(handle: h, data: Data("x".utf8), approval: 0)
    }

    /// The refusal happens before the wrapped backend is asked: the real
    /// Secure Enclave never even sees a user-presence request.
    @Test func innerBackendNeverSeesAPresenceRequest() throws {
        let rec = RecordingBackend()
        let b = NoUserPresenceBackend(rec)
        for purpose in [KeyPurpose.sign, .keyAgreement] {
            #expect(throws: PlatformError.invalid("user-presence keys are disabled in automated runs")) {
                try b.create(purpose: purpose, userPresence: true, whileLocked: false)
            }
        }
        #expect(rec.creates.isEmpty)
        _ = try b.create(purpose: .sign, userPresence: false, whileLocked: false)
        #expect(rec.creates == [false])
    }

    /// isKey, sign and agree pass through unchanged, context included.
    @Test func operationsPassThrough() throws {
        let inner = SoftwareEnclaveBackend()
        let b = NoUserPresenceBackend(inner)
        let (sk, spub) = try b.create(purpose: .sign, userPresence: false, whileLocked: false)
        #expect(b.isKey(sk, purpose: .sign) && !b.isKey(sk, purpose: .keyAgreement) && !b.isKey(Data([1, 2, 3]), purpose: .sign))
        let ctx = ScriptedAuthContext()
        let msg = Data("pass".utf8)
        let der = try b.sign(blob: sk, message: msg, context: ctx)
        #expect(try P256.Signing.PublicKey(x963Representation: spub)
            .isValidSignature(P256.Signing.ECDSASignature(derRepresentation: der), for: msg))
        #expect((inner.contexts.last ?? nil) === ctx)
        #expect(inner.signCalls == 1)

        let (ka, kpub) = try b.create(purpose: .keyAgreement, userPresence: false, whileLocked: false)
        let peer = P256.KeyAgreement.PrivateKey()
        let secret = try b.agree(blob: ka, peer: peer.publicKey, context: nil)
        let want = try peer.sharedSecretFromKeyAgreement(with: P256.KeyAgreement.PublicKey(x963Representation: kpub))
            .withUnsafeBytes { Data($0) }
        #expect(secret == want && inner.agreeCalls == 1)
        #expect(throws: PlatformError.notFound) { try b.sign(blob: Data([9]), message: msg, context: nil) }
    }
}

@Suite struct MemoryVaultTests {
    /// The fake Vault's semantics (core/platform/fake/vault.go).
    @Test func behavesLikeTheFakeVault() throws {
        let v = MemoryVault()
        #expect(throws: PlatformError.notFound) { try v.get("x") }
        #expect(throws: PlatformError.notFound) { try v.delete("x") }
        #expect(try v.list(prefix: "").isEmpty)
        try v.put("x", Data([1]))
        try v.put("x", Data([2, 0]))
        #expect(try v.get("x") == Data([2, 0]))
        try v.put("empty", Data())
        #expect(try v.get("empty") == Data())
        try v.delete("x")
        #expect(throws: PlatformError.notFound) { try v.get("x") }
        #expect(throws: PlatformError.notFound) { try v.delete("x") }
    }

    /// Sorted, literal prefix match (no pattern syntax).
    @Test func listIsSortedByLiteralPrefix() throws {
        let v = MemoryVault()
        for n in ["ssh-key/b", "ssh-key/a", "ssh-keyX", "ssh-key", "config/approved", "a.b", "aXb", "*"] {
            try v.put(n, Data(n.utf8))
        }
        #expect(try v.list(prefix: "ssh-key/") == ["ssh-key/a", "ssh-key/b"])
        #expect(try v.list(prefix: "ssh-key") == ["ssh-key", "ssh-key/a", "ssh-key/b", "ssh-keyX"])
        #expect(try v.list(prefix: "a.") == ["a.b"])
        #expect(try v.list(prefix: "*") == ["*"])
        #expect(try v.list(prefix: "") == ["*", "a.b", "aXb", "config/approved", "ssh-key", "ssh-key/a", "ssh-key/b", "ssh-keyX"])
        #expect(try v.list(prefix: "zzz").isEmpty)
    }

    @Test func concurrentUseIsSafe() throws {
        let v = MemoryVault()
        DispatchQueue.concurrentPerform(iterations: 200) { i in
            try? v.put("k/\(i)", Data([UInt8(i % 256)]))
            _ = try? v.get("k/\(i / 2)")
            _ = try? v.list(prefix: "k/")
        }
        #expect(try v.list(prefix: "k/").count == 200)
    }
}

@Suite struct RecordingStandInsTests {
    @Test func memoryAuditKeepsLinesInOrder() throws {
        let a = MemoryAudit()
        try a.write(unixNanos: 2, line: "first")
        try a.write(unixNanos: 1, line: "")
        try a.write(unixNanos: 3, line: "third")
        #expect(a.lines == ["first", "", "third"])
    }

    @Test func recordedWarningsKeepEveryWarning() {
        let w = RecordedWarnings()
        let a = WarningSpec(id: "a", title: "A", lines: ["x"], count: 1, suggestedRule: "r")
        let b = WarningSpec(id: "a", title: "A", lines: ["x"], count: 2, suggestedRule: "r")
        w.show(a)
        w.show(b)
        #expect(w.shown == [a, b])
    }
}

@Suite struct TestPlatformTests {
    /// The login gate and the key store share one ApprovalStore: an
    /// approval from login signs a user-presence key until it is released.
    @Test func loginApprovalsReachTheKeyStore() throws {
        let login = ScriptedLoginEvaluator()
        let confirm = ScriptedConfirmer()
        let p = SwiftPlatform.testPlatform(backend: SoftwareEnclaveBackend(), login: login, confirm: confirm)
        let (h, _) = try p.enclave.createKey(purpose: 1, auth: 1, access: 0)
        #expect(throws: PlatformError.authRequired) { try p.enclave.sign(handle: h, data: Data("x".utf8), approval: 1) }
        login.push(true)
        let ref = try p.login.authenticate(policy: 1, prompt: PromptSpec(title: "t", reason: "r", timeoutMillis: 2000))
        #expect(p.approvals.liveCount == 1)
        _ = try p.enclave.sign(handle: h, data: Data("x".utf8), approval: ref)
        p.approvals.release(ref)
        #expect(throws: PlatformError.authRequired) { try p.enclave.sign(handle: h, data: Data("x".utf8), approval: ref) }
        #expect(login.reasons == ["r"])
    }

    /// The scripted gates and recorded warnings are the ones passed in;
    /// warnings default to a RecordedWarnings (never a window).
    @Test func standInsAreWiredIn() throws {
        let login = ScriptedLoginEvaluator()
        let confirm = ScriptedConfirmer()
        let w = RecordedWarnings()
        let p = SwiftPlatform.testPlatform(backend: SoftwareEnclaveBackend(), login: login, confirm: confirm, warnings: w)
        #expect(p.dialog === confirm)
        #expect(p.warnings === w)
        confirm.push(true)
        #expect(try p.dialog.confirm(PromptSpec(title: "c")))
        #expect(confirm.prompts.map(\.title) == ["c"])
        p.warnings.show(WarningSpec(id: "i", title: "t"))
        #expect(w.shown.map(\.id) == ["i"])

        let d = SwiftPlatform.testPlatform(backend: SoftwareEnclaveBackend(), login: login, confirm: confirm)
        #expect(d.warnings is RecordedWarnings)
    }

    /// The screen-lock watcher listens to the name it is given (tests never
    /// post the system's com.apple.screenIsLocked).
    @Test func screenLockNameIsInjectable() {
        let name = "dev.nazar.test.testplatform.\(UUID().uuidString)"
        #expect(name != ScreenLockWatcher.systemName)
        let p = SwiftPlatform.testPlatform(backend: SoftwareEnclaveBackend(), login: ScriptedLoginEvaluator(),
                                           confirm: ScriptedConfirmer(), screenLockName: name)
        let c = Counter()
        p.screenLocks.register { c.hit() }
        DistributedNotificationCenter.default().postNotificationName(Notification.Name(name), object: nil, userInfo: nil,
                                                                    deliverImmediately: true)
        #expect(c.wait(for: 1))
    }

    /// SwiftPlatform keeps exactly the parts it was built from.
    @Test func swiftPlatformKeepsItsParts() {
        let approvals = ApprovalStore()
        let enclave = EnclaveStore(backend: SoftwareEnclaveBackend(), approvals: approvals)
        let login = LoginGate(evaluator: ScriptedLoginEvaluator(), approvals: approvals)
        let dialog = ScriptedConfirmer()
        let resolver = ProcessResolver(gui: NoApps())
        let installed = InstalledApps(locator: FakeLocator(), inspect: { _ in nil }, roots: ["/Applications/"])
        let exits = ExitWatcher()
        let locks = ScreenLockWatcher(name: "dev.nazar.test.parts.\(UUID().uuidString)")
        let warnings = RecordedWarnings()
        let p = SwiftPlatform(enclave: enclave, approvals: approvals, login: login, dialog: dialog, resolver: resolver,
                              installed: installed, exits: exits, screenLocks: locks, warnings: warnings)
        #expect(p.enclave === enclave && p.approvals === approvals && p.login === login && p.dialog === dialog)
        #expect(p.resolver === resolver && p.installed === installed && p.exits === exits && p.screenLocks === locks)
        #expect(p.warnings === warnings)
    }

    /// The production parts satisfy the bridge's protocols (compile-time;
    /// nothing is constructed, so no Keychain, log or window is touched).
    @Test func productionPartsConform() {
        func vault<T: VaultStore>(_: T.Type) -> Bool { true }
        func audit<T: AuditWriter>(_: T.Type) -> Bool { true }
        func shower<T: WarningShower>(_: T.Type) -> Bool { true }
        #expect(vault(KeychainVault.self) && vault(MemoryVault.self))
        #expect(audit(OSLogAuditSink.self) && audit(MemoryAudit.self))
        #expect(shower(WarningCenter.self) && shower(RecordedWarnings.self))
    }
}
