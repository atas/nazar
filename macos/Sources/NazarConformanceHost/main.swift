// NazarConformanceHost: runs core/platform/conformance (Go, linked as
// build/libnazar-conformance.a) against the Swift platform through the real
// C ABI. Never shipped.
//
//   NazarConformanceHost real   [-test.v]   real Secure Enclave (AuthNone keys only), real processes,
//                                           LaunchServices, code signing; no gate is ever shown
//   NazarConformanceHost seamed [-test.v]   software keys + scripted gates, so the approval
//                                           subtests run through the same C ABI
import CNazarBridge
import CNazarConformance
import CoreGraphics
import Foundation
import NazarPlatform
import Security

setvbuf(stdout, nil, _IOLBF, 0)
let args = CommandLine.arguments
guard args.count >= 2, args[1] == "real" || args[1] == "seamed" else {
    FileHandle.standardError.write(Data("usage: NazarConformanceHost real|seamed [go test flags]\n".utf8))
    exit(2)
}
let real = args[1] == "real"
// Belt and braces: nothing in this host touches a keychain (the vault is in
// memory), but an automated run must never be able to show a Keychain dialog.
guard SecKeychainSetUserInteractionAllowed(false) == errSecSuccess else {
    FileHandle.standardError.write(Data("could not turn Keychain dialogs off\n".utf8))
    exit(1)
}
if real && !SecureEnclaveBackend.isAvailable {
    FileHandle.standardError.write(Data("no Secure Enclave on this Mac\n".utf8))
    exit(1)
}
// Diagnostic only: a WhenUnlockedThisDeviceOnly Secure Enclave key cannot be
// generated while the screen is locked (-25308, AKSError -536870174), which
// the Go side sees as a bare NZ_ERR on every keys/* subtest.
if real, let session = CGSessionCopyCurrentDictionary() as? [String: Any],
   (session["CGSSessionScreenIsLocked"] as? Bool) == true {
    FileHandle.standardError.write(Data("warning: the screen is locked; Secure Enclave key generation will fail (unlock and rerun)\n".utf8))
}

/// One answer queue for both gates: conformance's Answer scripts "the next
/// prompt", whichever gate it is. Unscripted prompts are denied.
final class AnswerQueue: LoginEvaluator, Confirmer, @unchecked Sendable {
    private let lock = NSLock()
    private var queue: [Bool] = []
    private(set) var asked = 0
    func push(_ allow: Bool) { lock.lock(); queue.append(allow); lock.unlock() }
    private func next() -> Bool {
        lock.lock(); defer { lock.unlock() }
        asked += 1
        return queue.isEmpty ? false : queue.removeFirst()
    }
    func evaluate(reason: String, timeout: TimeInterval) throws -> AuthContext {
        guard next() else { throw PlatformError.denied }
        return ScriptedAuthContext()
    }
    func confirm(_ prompt: PromptSpec) throws -> Bool { next() }
}

let answers = AnswerQueue()
let ledger = BufferLedger()
let approvals = ApprovalStore()
let backend: EnclaveBackend = real ? NoUserPresenceBackend(SecureEnclaveBackend()) : SoftwareEnclaveBackend()
let resolver = ProcessResolver()
let platform = SwiftPlatform(
    enclave: EnclaveStore(backend: backend, approvals: approvals), approvals: approvals,
    login: LoginGate(evaluator: answers, approvals: approvals), dialog: answers,
    resolver: resolver, installed: InstalledApps(), exits: ExitWatcher(),
    screenLocks: ScreenLockWatcher(name: "dev.nazar.test.screenIsLocked.\(UUID().uuidString)"),
    warnings: RecordedWarnings(), execs: ExecWatcher(resolver: resolver))
let callbacks = NazarBridge.install(NazarBridge.Runtime(
    platform: platform, vault: MemoryVault(), audit: MemoryAudit(), ledger: ledger,
    exitFired: { NazarProcessExited($0) }, screenLocked: { NazarScreenLocked($0) },
    execFired: NazarBridge.execFired { NazarProcessExecd($0, $1, $2) }))

let hooks = UnsafeMutablePointer<NazarHostHooks>.allocate(capacity: 1)
hooks.initialize(to: NazarHostHooks(
    answer: { allow in answers.push(allow != 0) },
    live_buffers: { Int64(ledger.liveCount) },
    bad_frees: { Int64(ledger.badFrees) }))

DispatchQueue.global().async {
    let rc = NazarRunConformance(callbacks, real ? 1 : 2, hooks)
    // Not reached normally (testing.Main exits); a real run must never
    // have shown a gate.
    exit(real && answers.asked > 0 ? 1 : rc)
}
dispatchMain()
