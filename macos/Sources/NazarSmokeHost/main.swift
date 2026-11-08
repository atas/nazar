// NazarSmokeHost: the real Go core (build/libnazar-core.a) on the real Swift
// platform, for end-to-end tests. Never shipped. Differences from
// Nazar.app, each so that nothing needs a person or touches the user's data:
//   - the Vault is a temporary keychain in --keychain-dir (deleted on exit;
//     never under a Library/Keychains folder, never on the search list),
//   - the login and dialog gates are scripted to allow,
//   - Secure Enclave keys are real but user presence is refused,
//   - audit lines go to the unified log under --log-subsystem, which must be
//     dev.nazar.test.*, never the real dev.nazar,
//   - block warnings are recorded, not shown.
// Every argument is checked before anything is created, so a refusal leaves
// no keychain, no socket and no folder behind.
//
//   NazarSmokeHost --home DIR --keychain-dir DIR --log-subsystem dev.nazar.test.X
import CNazarBridge
import CNazarCore
import Foundation
import NazarPlatform
import Security

setvbuf(stderr, nil, _IOLBF, 0)
let usage = "usage: NazarSmokeHost --home DIR --keychain-dir DIR --log-subsystem dev.nazar.test.X (absolute DIRs)"
func fail(_ m: String) -> Never {
    FileHandle.standardError.write(Data("NazarSmokeHost: \(m)\n".utf8))
    exit(2)
}

var opts: [String: String] = [:]
var it = CommandLine.arguments.dropFirst().makeIterator()
while let k = it.next() {
    guard k.hasPrefix("--"), let v = it.next() else { fail(usage) }
    opts[String(k.dropFirst(2))] = v
}
guard let home = opts["home"], home.hasPrefix("/"),
      let kcDir = opts["keychain-dir"], kcDir.hasPrefix("/"),
      let sub = opts["log-subsystem"], sub.hasPrefix("dev.nazar.test."), sub != OSLogAuditSink.productionSubsystem
else { fail(usage) }

// Keychain dialogs off before the first Keychain call of this process, and
// proven off (AGENTS.md, hard rules). TemporaryKeychain and KeychainVault
// do the same; this is the host's own assertion.
guard SecKeychainSetUserInteractionAllowed(false) == errSecSuccess else { fail("could not turn Keychain dialogs off") }
var dialogs: DarwinBoolean = true
guard SecKeychainGetUserInteractionAllowed(&dialogs) == errSecSuccess, !dialogs.boolValue else {
    fail("Keychain dialogs are still on")
}
guard SecureEnclaveBackend.isAvailable else { fail("no Secure Enclave on this Mac") }

let keychain: TemporaryKeychain
do { keychain = try TemporaryKeychain(directory: URL(fileURLWithPath: kcDir)) } catch { fail("keychain: \(error)") }
let vault: KeychainVault
do { vault = try KeychainVault(keychain: keychain.keychain, service: "dev.nazar.smoke") } catch {
    keychain.destroy()
    fail("vault: \(error)")
}

let platform = SwiftPlatform.testPlatform(
    backend: NoUserPresenceBackend(SecureEnclaveBackend()),
    login: ScriptedLoginEvaluator(defaultAnswer: true), confirm: ScriptedConfirmer(defaultAnswer: true))
let callbacks = NazarBridge.install(NazarBridge.Runtime(
    platform: platform, vault: vault, audit: OSLogAuditSink(subsystem: sub),
    exitFired: { NazarProcessExited($0) }, screenLocked: { NazarScreenLocked($0) }))

var homeBytes = Array(home.utf8)
let rc = homeBytes.withUnsafeMutableBufferPointer { NazarCoreStart(callbacks, $0.baseAddress, $0.count) }
guard rc == 0 else {
    keychain.destroy()
    fail("the core did not start (status \(rc))")
}

// SIGINT and SIGTERM: stop the core, then delete the keychain and its folder.
var signalSources: [DispatchSourceSignal] = []
for sig in [SIGTERM, SIGINT] {
    signal(sig, SIG_IGN)
    let src = DispatchSource.makeSignalSource(signal: sig, queue: .main)
    src.setEventHandler {
        NazarCoreStop()
        keychain.destroy()
        exit(0)
    }
    src.resume()
    signalSources.append(src)
}
dispatchMain()
