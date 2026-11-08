// nazar-agent (spec 4, Milestone 6): the background service. An app
// bundle (LSUIElement: no Dock icon) that owns the main thread, the dialogs,
// CryptoKit and LocalAuthentication, and runs the Go core
// (build/libnazar-core.a) through the C ABI. Started at login by the
// LaunchAgent dev.nazar.agent that `nazar install` writes. It has no menu
// bar item and no window of its own: the only things it puts on screen are
// the ones a request needs (the login prompt, the Allow/Deny dialog, the
// block warning); the UI is the separate Nazar UI.app. Built by `make
// agent`; never started by any automated test (it uses the login keychain).
import AppKit
import CNazarBridge
import CNazarCore
import Foundation
import NazarPlatform

setvbuf(stderr, nil, _IOLBF, 0)
func fail(_ msg: String) -> Never {
    FileHandle.standardError.write(Data("nazar-agent: \(msg)\n".utf8))
    exit(1)
}

let app = NSApplication.shared
app.setActivationPolicy(.accessory)
let home = NSHomeDirectory()
let presenter = AppKitPresenter()
let approvals = ApprovalStore()

let vault: KeychainVault
do { vault = try KeychainVault.login() } catch { fail("login keychain: \(error)") }

let resolver = ProcessResolver()
let platform = SwiftPlatform(
    enclave: EnclaveStore(backend: SecureEnclaveBackend(), approvals: approvals),
    approvals: approvals,
    // .devicePolicy: checked by hand on a real Mac, one prompt per login;
    // .accessControl is the alternative (LoginGate.swift).
    login: LoginGate(evaluator: LAEvaluator(mode: .devicePolicy), approvals: approvals),
    dialog: DialogGate(
        makeView: { prompt, actions in ConfirmPanel(prompt: prompt, presenter: presenter, actions: actions) },
        keys: LocalKeyMonitor(), secureInput: CarbonSecureInput()),
    resolver: resolver,
    installed: InstalledApps(),
    exits: ExitWatcher(),
    screenLocks: ScreenLockWatcher(),
    warnings: WarningCenter(configPath: home + "/.nazar/config/config.yaml", presenter: presenter,
                            pasteboard: SystemPasteboard(), opener: WorkspaceOpener()),
    execs: ExecWatcher(resolver: resolver))

let callbacks = NazarBridge.install(NazarBridge.Runtime(
    platform: platform, vault: vault, audit: OSLogAuditSink(),
    exitFired: { NazarProcessExited($0) }, screenLocked: { NazarScreenLocked($0) },
    execFired: NazarBridge.execFired { NazarProcessExecd($0, $1, $2) }))

var homeBytes = Array(home.utf8)
let started = homeBytes.withUnsafeMutableBufferPointer { NazarCoreStart(callbacks, $0.baseAddress, $0.count) }
guard started == 0 else { fail("the core did not start (status \(started))") }

signal(SIGTERM, SIG_IGN)
let term = DispatchSource.makeSignalSource(signal: SIGTERM, queue: .main)
term.setEventHandler {
    NazarCoreStop()
    exit(0)
}
term.resume()
app.run()
