import Foundation
import Security
import Testing
@testable import NazarPlatform

// Milestone 6 (spec 4): the vault knows the agent by its signature, never
// by its path. Homebrew installs every version of nazar-agent.app into a
// new Caskroom folder, so an item the agent made at one path must be its
// own item at the next; a program at the same path with another signature
// is another program.
//
// No test here creates, reads, writes or deletes a keychain item, and none
// opens a keychain: the in-memory store (FakeKeychainStore) holds the items,
// and the real part only builds SecTrustedApplication objects from files
// (SecTrustedApplicationCreateFromPath reads a code signature from disk)
// and compares the identities the vault would compare. Keychain dialogs are
// off for the process first (requireKeychainDialogsOff), as everywhere in
// this target.

/// `id` under another recorded path: what an access list made by the same
/// build at its previous install location reads back as.
func moved(_ id: AppIdentity, to path: String) -> AppIdentity {
    AppIdentity(path: Data((path + "\0").utf8), requirement: id.requirement)
}

/// A folder under the temporary directory, removed by the caller.
func scratchFolder() throws -> URL {
    let u = FileManager.default.temporaryDirectory.appendingPathComponent("nz-ident-\(UUID().uuidString)")
    try FileManager.default.createDirectory(at: u, withIntermediateDirectories: true)
    return u
}

/// Copies /usr/bin/true to `dir/name/tool` and signs it ad hoc with
/// `identifier` (never a real identity): two copies signed alike are one
/// signature (ad-hoc signing is deterministic), at two paths.
func adHocTool(_ dir: URL, _ name: String, identifier: String) throws -> URL {
    let folder = dir.appendingPathComponent(name)
    try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
    let tool = folder.appendingPathComponent("tool")
    try? FileManager.default.removeItem(at: tool)
    try FileManager.default.copyItem(at: URL(fileURLWithPath: "/usr/bin/true"), to: tool)
    try resignAdHoc(tool, identifier: identifier)
    return tool
}

func resignAdHoc(_ tool: URL, identifier: String) throws {
    let p = Process()
    p.executableURL = URL(fileURLWithPath: "/usr/bin/codesign")
    p.arguments = ["--force", "--sign", "-", "--identifier", identifier, tool.path]
    p.standardOutput = FileHandle.nullDevice
    p.standardError = FileHandle.nullDevice
    try p.run()
    p.waitUntilExit()
    try #require(p.terminationStatus == 0, "codesign --sign - \(tool.path)")
}

/// The identity the vault records for the program at `url`.
func identity(of url: URL) throws -> AppIdentity {
    var app: SecTrustedApplication?
    try #require(SecTrustedApplicationCreateFromPath(url.path, &app) == errSecSuccess, "\(url.path)")
    return try AppIdentity(try #require(app))
}

@Suite(.serialized, .timeLimit(.minutes(1))) struct IdentityBySignatureTests {
    // The rule itself: one requirement is one program wherever it was
    // recorded; one path under two requirements is two programs.
    @Test func identityIsTheRequirementNotThePath() throws {
        let upgraded = moved(nazarID, to: "/opt/homebrew/Caskroom/nazar/0.2.0/nazar-agent.app/Contents/MacOS/nazar-agent")
        #expect(upgraded == nazarID)
        #expect(Set([upgraded, nazarID]).count == 1)
        #expect(forgedID != nazarID, "Nazar's path with another requirement is another program")
        #expect(Set([forgedID, nazarID]).count == 2)
    }

    // An item the agent made at its old path (every grant names the old
    // path) is the new build's own item when the signature is the same: get
    // reads it, put rewrites it in place, nothing is refused.
    @Test func itemOfTheSameSignatureAtAnotherPathIsAccepted() throws {
        let old = moved(nazarID, to: "/opt/homebrew/Caskroom/nazar/0.1.0/nazar-agent.app/Contents/MacOS/nazar-agent")
        let (v, s) = try fakeVault(trusted: [nazarID])
        let item = s.plant(service: v.service, account: "ssh-key/github", value: Data("handle".utf8),
                           entries: FakeKeychainStore.ownShape(trusted: [old]), creator: "nazar")
        #expect(KeychainVault.refusal(of: item.entries, trusted: [nazarID]) == nil)
        s.clearLog()
        #expect(try v.get("ssh-key/github") == Data("handle".utf8))
        #expect(s.calls == ["find", "accessList", "content"])
        try v.put("ssh-key/github", Data("handle-2".utf8))
        #expect(item.value == Data("handle-2".utf8) && s.allItems.count == 1, "rewritten in place, not added next to it")
        #expect(item.entries == FakeKeychainStore.ownShape(trusted: [old]), "the access list is never changed")
        // The other way round: a vault at the new path reads what one at the old path wrote.
        let (v2, s2) = try fakeVault(trusted: [old])
        try v2.put("config/approved", Data("cfg".utf8))
        let v3 = try KeychainVault(store: s2, service: v2.service, trustedIDs: [nazarID])
        #expect(try v3.get("config/approved") == Data("cfg".utf8))
        try requireKeychainDialogsOff()
    }

    // An item whose grants name the agent's own path with another program's
    // requirement is refused before its value is touched, however many of
    // its entries carry the right path.
    @Test func itemOfAnotherSignatureAtTheSamePathIsRefused() throws {
        let (v, s) = try fakeVault(trusted: [nazarID])
        let planted = s.plant(service: v.service, account: "state/trust", value: Data("forged".utf8),
                              entries: FakeKeychainStore.ownShape(trusted: [forgedID]))
        s.clearLog()
        do {
            _ = try v.get("state/trust")
            Issue.record("get read an item made for another signature at the agent's path")
        } catch let e as PlatformError {
            #expect(e == .failed("vault state/trust: item trusts another application (\(FakeKeychainStore.decryptGroup))"), "\(e)")
        }
        #expect(s.calls == ["find", "accessList"], "the value was touched: \(s.calls)")
        #expect(throws: PlatformError.self) { try v.put("state/trust", Data("mine".utf8)) }
        #expect(planted.value == Data("forged".utf8))
        // Another signature recorded at the agent's old install path is no
        // better, and the agent's own signature (at any path) next to a
        // foreign one does not launder it: an extra application is refused.
        let oldPath = "/opt/homebrew/Caskroom/nazar/0.1.0/nazar-agent.app/Contents/MacOS/nazar-agent"
        let forgedOld = moved(forgedID, to: oldPath)
        #expect(forgedOld != nazarID)
        #expect(KeychainVault.refusal(of: FakeKeychainStore.ownShape(trusted: [forgedOld]), trusted: [nazarID]) != nil)
        #expect(KeychainVault.refusal(of: FakeKeychainStore.ownShape(trusted: [moved(nazarID, to: oldPath), forgedID]),
                                      trusted: [nazarID]) != nil)
        try requireKeychainDialogsOff()
    }

    // The same on real code signatures: two ad-hoc-signed copies of one
    // program at two paths are one identity to the vault, and the program at
    // one of those paths signed again (another identifier, so another
    // cdhash) is another identity. Builds only SecTrustedApplication objects
    // from files: no keychain, no item.
    @Test func realSignaturesDecideNotPaths() throws {
        try requireKeychainDialogsOff()
        let dir = try scratchFolder()
        defer { try? FileManager.default.removeItem(at: dir) }
        let a = try adHocTool(dir, "0.1.0", identifier: "dev.nazar.test.tool")
        let b = try adHocTool(dir, "0.2.0", identifier: "dev.nazar.test.tool")
        let ida = try identity(of: a), idb = try identity(of: b)
        #expect(ida.path != idb.path, "the two copies are recorded under their own paths")
        #expect(ida == idb, "one signature at two paths is one program")
        let own = FakeKeychainStore.ownShape(trusted: [ida])
        #expect(KeychainVault.refusal(of: own, trusted: [idb]) == nil, "the copy at the new path owns the item")

        try resignAdHoc(a, identifier: "dev.nazar.test.other")
        let resigned = try identity(of: a)
        #expect(resigned.path == ida.path, "same path")
        #expect(resigned != ida, "another signature at the same path is another program")
        #expect(KeychainVault.refusal(of: own, trusted: [resigned]) == "item trusts another application (\(FakeKeychainStore.decryptGroup))")
        try requireKeychainDialogsOff()
    }
}
