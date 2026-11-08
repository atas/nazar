import CryptoKit
import Foundation
import Security

// A different binary (different ad-hoc signature, no shared code identity) — plays "malware".
let args = Array(CommandLine.arguments.dropFirst())
switch args.first {
case "sign":
    let url = URL(fileURLWithPath: NSHomeDirectory()).appendingPathComponent(".nazar/spike/\(args[1]).handle")
    do {
        let handle = try Data(contentsOf: url)
        let t = Date()
        let key = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: handle)
        _ = try key.signature(for: Data("s5 other process".utf8))
        print("OTHER PROCESS SIGNED with \(args[1]) in \(Int(Date().timeIntervalSince(t) * 1000))ms")
    } catch {
        print("other process could NOT sign with \(args[1]): \(error)")
    }
case "keychain":
    let q: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
                            kSecAttrService as String: "dev.nazar.spike.s5",
                            kSecAttrAccount as String: args[1],
                            kSecReturnData as String: true]
    var out: CFTypeRef?
    let status = SecItemCopyMatching(q as CFDictionary, &out)
    print("other process keychain read status=\(status) bytes=\((out as? Data)?.count ?? 0)")
default:
    print("usage: S5Other sign <name> | keychain <name>")
}
