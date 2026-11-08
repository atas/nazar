import AppKit
import CryptoKit
import Foundation
import LocalAuthentication
import Security

let dir = URL(fileURLWithPath: NSHomeDirectory()).appendingPathComponent(".nazar/spike")
try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true,
                                         attributes: [.posixPermissions: 0o700])
// createDirectory(withIntermediateDirectories:) left the leaf at 0755 on macOS 27; spec wants 0700.
try? FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: dir.path)
func handleURL(_ name: String) -> URL { dir.appendingPathComponent("\(name).handle") }

func accessControl(presence: Bool) -> SecAccessControl {
    var err: Unmanaged<CFError>?
    let flags: SecAccessControlCreateFlags = presence ? [.privateKeyUsage, .userPresence] : [.privateKeyUsage]
    guard let ac = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, flags, &err)
    else { fatalError("access control: \(err!.takeRetainedValue())") }
    return ac
}

func wait(_ start: (@escaping (Bool, Error?) -> Void) -> Void) -> (Bool, Error?) {
    let sem = DispatchSemaphore(value: 0)
    var result: (Bool, Error?) = (false, nil)
    start { ok, err in result = (ok, err); sem.signal() }
    sem.wait()
    return result
}

func stamp() -> String { ISO8601DateFormatter().string(from: Date()) }

let args = Array(CommandLine.arguments.dropFirst())
switch args.first {
case "create":
    let name = args[1]
    let presence = !args.contains("--no-presence")
    let key = try SecureEnclave.P256.Signing.PrivateKey(compactRepresentable: true,
                                                         accessControl: accessControl(presence: presence))
    try key.dataRepresentation.write(to: handleURL(name))
    print("created \(name) presence=\(presence) handleBytes=\(key.dataRepresentation.count)")

case "loop":
    // loop <name> <policy|access|none> <everySeconds> <count>
    let name = args[1], mode = args[2]
    let every = Double(args[3])!, count = Int(args[4])!
    let handle = try Data(contentsOf: handleURL(name))
    let ctx = LAContext()
    switch mode {
    case "policy":
        let r = wait { ctx.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: "S1 policy mode", reply: $0) }
        print("\(stamp()) pre-auth policy ok=\(r.0) err=\(String(describing: r.1))")
    case "access":
        let r = wait { ctx.evaluateAccessControl(accessControl(presence: true), operation: .useKeySign,
                                                 localizedReason: "S1 access mode", reply: $0) }
        print("\(stamp()) pre-auth access ok=\(r.0) err=\(String(describing: r.1))")
    default:
        print("\(stamp()) no pre-auth")
    }
    for i in 1...count {
        let t = Date()
        do {
            let key = try SecureEnclave.P256.Signing.PrivateKey(
                dataRepresentation: handle, authenticationContext: mode == "none" ? nil : ctx)
            _ = try key.signature(for: Data("s1 tick \(i)".utf8))
            let ms = Int(Date().timeIntervalSince(t) * 1000)
            print("\(stamp()) tick \(i) ok \(ms)ms\(ms > 500 ? "  <-- likely prompted" : "")")
        } catch {
            print("\(stamp()) tick \(i) ERROR \(error)")
        }
        if i < count { Thread.sleep(forTimeInterval: every) }
    }

case "prompt-test":
    // S2: run as an LSUIElement app started by a LaunchAgent.
    let out = dir.appendingPathComponent("s2-result.txt")
    func log(_ s: String) {
        let line = "\(stamp()) \(s)\n"
        if let h = try? FileHandle(forWritingTo: out) { h.seekToEndOfFile(); h.write(Data(line.utf8)); try? h.close() }
        else { try? line.write(to: out, atomically: true, encoding: .utf8) }
    }
    let app = NSApplication.shared
    app.setActivationPolicy(.accessory)
    DispatchQueue.main.asyncAfter(deadline: .now() + 5) {
        log("starting LA prompt, parent pid \(getppid())")
        LAContext().evaluatePolicy(.deviceOwnerAuthentication, localizedReason: "S2: prompt from a LaunchAgent app") { ok, err in
            log("LA result ok=\(ok) err=\(String(describing: err))")
            DispatchQueue.main.async {
                NSApp.activate()
                let alert = NSAlert()
                alert.messageText = "S2: AppKit alert from a LaunchAgent app"
                alert.informativeText = "Click OK. The result is logged to s2-result.txt."
                let resp = alert.runModal()
                log("NSAlert shown, response=\(resp.rawValue)")
                exit(0)
            }
        }
    }
    app.run()

case "store":
    // S5: put a handle into the login Keychain with an access list trusting only this binary.
    let name = args[1]
    let handle = try Data(contentsOf: handleURL(name))
    var selfApp: SecTrustedApplication?
    guard SecTrustedApplicationCreateFromPath(nil, &selfApp) == errSecSuccess, let selfApp else { fatalError("trusted app") }
    var access: SecAccess?
    guard SecAccessCreate("nazar spike handle \(name)" as CFString, [selfApp] as CFArray, &access) == errSecSuccess,
          let access else { fatalError("SecAccessCreate") }
    let base: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
                               kSecAttrService as String: "dev.nazar.spike.s5",
                               kSecAttrAccount as String: name]
    SecItemDelete(base as CFDictionary)
    var add = base
    add[kSecValueData as String] = handle
    add[kSecAttrAccess as String] = access
    print("store status=\(SecItemAdd(add as CFDictionary, nil))")

case "load":
    let name = args[1]
    let q: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
                            kSecAttrService as String: "dev.nazar.spike.s5",
                            kSecAttrAccount as String: name,
                            kSecReturnData as String: true]
    var out: CFTypeRef?
    let status = SecItemCopyMatching(q as CFDictionary, &out)
    print("load status=\(status) bytes=\((out as? Data)?.count ?? 0)")

default:
    print("usage: S1Enclave create|loop|prompt-test|store|load …")
    exit(2)
}
