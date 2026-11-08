import Foundation
import Security
import Testing
@testable import NazarPlatform

// platform.Vault on a Keychain item whose access list trusts only Nazar.app
// (spec 4.5 "Handle storage", 4.8, spike S5).
//
// Two kinds of test, and a hard line between them (AGENTS.md, hard rules;
// drawn after an experiment raised a SecurityAgent password dialog on the
// user's screen):
//
// - REAL keychain: a TemporaryKeychain file in a temporary folder (never the
//   login keychain, never under any `Library/Keychains` folder, never added
//   to the user's search list, never locked, never SecKeychainSetSettings).
//   These tests only ever create items THROUGH THE VAULT, i.e. with the
//   vault's own access list trusting exactly this executable, and only ever
//   read, rewrite or delete those; the one thing they read of an item is
//   its access list (no authorization needed) and the item's value through
//   the vault. Nothing here plants an item with another shape, trusts
//   another application, forges an identity, relabels an entry or changes a
//   stored item's access list (SecKeychainItemSetAccess is confirmed by a
//   prompt-only ChangeACL entry that the dialogs-off flag does NOT suppress:
//   that was the dialog).
// - IN-MEMORY store (FakeKeychainStore, a KeychainStore): every hostile
//   access list, foreign or forged code identity, securityd's managed
//   entries and partition check, a locked keychain and injected statuses.
//   The vault runs its real rules on it, and the store records every call,
//   which proves what a real keychain never could without reaching
//   securityd: get and put never touch a value before the access list has
//   passed, and refuse without ever calling content/replace.
//
// Keychain Services dialogs are turned OFF for the test process before its
// first Keychain call (`keychainDialogsOff`, asserted by every test that
// touches a keychain), no test ever calls
// SecKeychainSetUserInteractionAllowed(true), and the vault's own switch is
// observed through a seam. Everything cross-process or login-shaped in
// reality (a reader that is not Nazar, a planter with another code identity,
// securityd's real Integrity/PartitionID entries and partition check, a
// locked login keychain) is checked by hand, never run by automation. The
// suite's time limit turns a dialog into a failure instead of a hang.

// MARK: - Keychain dialogs are off for this process

/// Evaluated once, before any other Keychain call this file makes: Keychain
/// Services dialogs are OFF for the test process, so a call that would need
/// one fails with errSecInteractionNotAllowed instead of showing it.
let keychainDialogsOff: Bool = {
    guard SecKeychainSetUserInteractionAllowed(false) == errSecSuccess else { return false }
    var allowed: DarwinBoolean = true
    return SecKeychainGetUserInteractionAllowed(&allowed) == errSecSuccess && allowed == false
}()

/// Every keychain-touching test starts here, and the ones that could have
/// changed the switch end here: dialogs are off, and still off.
func requireKeychainDialogsOff(sourceLocation: SourceLocation = #_sourceLocation) throws {
    try #require(keychainDialogsOff, "Keychain dialogs could not be turned off for this process", sourceLocation: sourceLocation)
    var allowed: DarwinBoolean = true
    #expect(SecKeychainGetUserInteractionAllowed(&allowed) == errSecSuccess, sourceLocation: sourceLocation)
    #expect(allowed == false, "something turned Keychain dialogs on", sourceLocation: sourceLocation)
}

// MARK: - Helpers (real keychain)

func userSearchList() -> [String] {
    var list: CFArray?
    SecKeychainCopyDomainSearchList(.user, &list)
    return ((list as? [SecKeychain]) ?? []).map(keychainPath)
}

func keychainPath(_ kc: SecKeychain) -> String {
    var len: UInt32 = 1024
    var buf = [CChar](repeating: 0, count: 1024)
    SecKeychainGetPath(kc, &len, &buf)
    return String(cString: buf)
}

func isInside(_ path: String, _ dir: URL) -> Bool {
    KeychainVault.realPath(path).hasPrefix(KeychainVault.realPath(dir.path) + "/")
}

func userDefaultKeychain() -> String? {
    var kc: SecKeychain?
    guard SecKeychainCopyDomainDefault(.user, &kc) == errSecSuccess, let kc else { return nil }
    return keychainPath(kc)
}

func thisExecutable() throws -> SecTrustedApplication {
    var me: SecTrustedApplication?
    #expect(SecTrustedApplicationCreateFromPath(nil, &me) == errSecSuccess)
    return try #require(me)
}

/// This executable's identity as the vault compares it (path + requirement).
func myIdentity() throws -> AppIdentity {
    try AppIdentity(try thisExecutable())
}

/// The item the vault created for `account` (a reference; no value).
func ownItem(_ v: KeychainVault, _ account: String) throws -> AnyObject {
    try #require(try v.store.find(service: v.service, account: account), "no item \(v.service)/\(account)")
}

/// The access list of an item the vault created, read through the real store.
func ownAccessList(_ v: KeychainVault, _ account: String) throws -> [KeychainVault.Entry] {
    try v.store.accessList(of: try ownItem(v, account))
}

/// Number of generic-password items with this service and account (attributes only).
func itemCount(_ keychain: SecKeychain, service: String, account: String) -> Int {
    let q: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service,
                            kSecAttrAccount as String: account, kSecMatchSearchList as String: [keychain],
                            kSecReturnAttributes as String: true, kSecMatchLimit as String: kSecMatchLimitAll]
    var out: CFTypeRef?
    let st = SecItemCopyMatching(q as CFDictionary, &out)
    if st == errSecItemNotFound { return 0 }
    return (out as? [[String: Any]])?.count ?? -1
}

let decryptAuth = kSecACLAuthorizationDecrypt as String
let encryptAuth = kSecACLAuthorizationEncrypt as String
let changeACLAuth = kSecACLAuthorizationChangeACL as String
let integrityAuth = kSecACLAuthorizationIntegrity as String
let partitionAuth = kSecACLAuthorizationPartitionID as String

/// The vault's guarantee for one item: every entry except the bare ChangeACL
/// entry trusts exactly `trusted` (never "any application", never an extra
/// app), the ChangeACL entry trusts no application outside `trusted`, and a
/// Decrypt entry and an Encrypt entry are present (SecAccessCreate leaves
/// Encrypt open to any application). securityd's managed entries are skipped.
func expectOnlyTrusted(_ entries: [KeychainVault.Entry], _ trusted: Set<AppIdentity>,
                       sourceLocation: SourceLocation = #_sourceLocation) {
    var sawEncrypt = false
    var sawDecrypt = false
    var sawChange = false
    for e in entries {
        if KeychainVault.isManaged(e.auths) { continue }
        guard let apps = e.apps else {
            Issue.record("ACL \(e.auths) is open to any application", sourceLocation: sourceLocation)
            continue
        }
        if KeychainVault.isChangeACLOnly(e.auths) {
            #expect(apps.allSatisfy(trusted.contains), "ChangeACL trusts a foreign application", sourceLocation: sourceLocation)
            sawChange = true
            continue
        }
        #expect(Set(apps) == trusted && apps.count == trusted.count, "ACL \(e.auths) trusts \(apps.count) apps",
                sourceLocation: sourceLocation)
        if e.auths.contains(encryptAuth) { sawEncrypt = true }
        if e.auths.contains(decryptAuth) { sawDecrypt = true }
    }
    #expect(sawEncrypt, "no Encrypt entry", sourceLocation: sourceLocation)
    #expect(sawDecrypt, "no Decrypt entry", sourceLocation: sourceLocation)
    #expect(sawChange, "no bare ChangeACL entry", sourceLocation: sourceLocation)
    #expect(KeychainVault.refusal(of: entries, trusted: trusted) == nil, sourceLocation: sourceLocation)
}

// MARK: - Helpers (in-memory)

/// A made-up application identity for the pure rules and the in-memory store.
func fakeID(_ name: String) -> AppIdentity {
    AppIdentity(path: Data("/Applications/\(name).app/Contents/MacOS/\(name)\0".utf8),
                requirement: Data("requirement-of-\(name)".utf8))
}

let nazarID = fakeID("Nazar")
let evilID = fakeID("Evil")
/// Nazar's path with another program's code requirement
/// (SecTrustedApplicationCreateFromRequirement puts any requirement under any path).
let forgedID = AppIdentity(path: nazarID.path, requirement: Data("requirement-of-Evil".utf8))

typealias Entry = KeychainVault.Entry

/// A KeychainStore in memory, modelled on what the real store reads back
/// (`ownItemsReadBackAsTheFakeModelsThem` pins the match): items with an
/// access list and a creator, securityd's two behaviours on a keychain under
/// Library/Keychains (managed entries, partition check), a locked keychain,
/// injected statuses, and a log of every call.
final class FakeKeychainStore: KeychainStore, @unchecked Sendable {
    final class Item {
        let service: String
        let account: String
        var value: Data
        var entries: [Entry]
        /// The code identity that created the item (what securityd's PartitionID entry names).
        let creator: String

        init(service: String, account: String, value: Data, entries: [Entry], creator: String) {
            self.service = service
            self.account = account
            self.value = value
            self.entries = entries
            self.creator = creator
        }
    }

    /// The Decrypt group SecAccessCreate makes (checked against the real store).
    static let decryptGroup = [kSecACLAuthorizationDecrypt, kSecACLAuthorizationDerive, kSecACLAuthorizationExportClear,
                               kSecACLAuthorizationExportWrapped, kSecACLAuthorizationMAC, kSecACLAuthorizationSign]
        .map { $0 as String }
    /// securityd's own entries on an item in a keychain under Library/Keychains.
    static let managedEntries = [Entry(auths: [integrityAuth], apps: nil), Entry(auths: [partitionAuth], apps: nil)]

    /// The shape the vault creates: the Decrypt group and Encrypt trusting
    /// exactly `trusted`, and the bare ChangeACL owner entry trusting nobody
    /// (a prompt this process never answers).
    static func ownShape(trusted: Set<AppIdentity>) -> [Entry] {
        let apps = Array(trusted)
        return [Entry(auths: decryptGroup, apps: apps), Entry(auths: [encryptAuth], apps: apps),
                Entry(auths: [changeACLAuth], apps: [])]
    }

    private let lock = NSLock()
    private var items: [Item] = []
    /// What `add` trusts (the vault's applications).
    let trusted: Set<AppIdentity>
    /// This process's code identity (securityd's partition for it).
    var me = "nazar"
    /// A keychain under Library/Keychains: every added item carries the managed entries.
    var loginShaped = false
    /// securityd's partition check: reading or rewriting the value of an item
    /// another identity created fails silently with errSecAuthFailed.
    var partitionCheck = false
    /// A locked keychain with dialogs off: reading an access list fails with
    /// errSecAuthFailed (the first call to fail, seen on macOS 27), adding
    /// with errSecInteractionNotAllowed.
    var locked = false
    /// Injected statuses by call: find, accessList, content, replace, add, delete, accounts.
    var failures: [String: OSStatus] = [:]
    /// An injected failure of accessList that is not a status of SecKeychainItemCopyAccess.
    var accessListFailure: KeychainCallFailed?
    private(set) var log: [String] = []

    init(trusted: Set<AppIdentity>) { self.trusted = trusted }

    var calls: [String] { lock.lock(); defer { lock.unlock() }; return log }
    func clearLog() { lock.lock(); log.removeAll(); lock.unlock() }
    var allItems: [Item] { lock.lock(); defer { lock.unlock() }; return items }
    func item(_ service: String, _ account: String) -> Item? {
        lock.lock(); defer { lock.unlock() }
        return items.first { $0.service == service && $0.account == account }
    }

    /// An item the vault did not create (another process got there first).
    @discardableResult
    func plant(service: String, account: String, value: Data, entries: [Entry], creator: String = "evil") -> Item {
        let it = Item(service: service, account: account, value: value, entries: entries, creator: creator)
        lock.lock(); items.append(it); lock.unlock()
        return it
    }

    private func enter(_ call: String, _ sec: String) throws {
        lock.lock(); log.append(call); lock.unlock()
        if let st = failures[call] { throw KeychainCallFailed(call: sec, status: st) }
    }

    func find(service: String, account: String) throws -> AnyObject? {
        try enter("find", "SecItemCopyMatching")
        return item(service, account)
    }

    func accessList(of item: AnyObject) throws -> [Entry] {
        try enter("accessList", "SecKeychainItemCopyAccess")
        if let f = accessListFailure { throw f }
        if locked { throw KeychainCallFailed(call: "SecKeychainItemCopyAccess", status: errSecAuthFailed) }
        return (item as! Item).entries
    }

    func content(of item: AnyObject) throws -> Data {
        try enter("content", "SecKeychainItemCopyContent")
        let it = item as! Item
        if partitionCheck && it.creator != me { throw KeychainCallFailed(call: "SecKeychainItemCopyContent", status: errSecAuthFailed) }
        return it.value
    }

    func replaceContent(of item: AnyObject, with value: Data) throws {
        try enter("replace", "SecKeychainItemModifyAttributesAndData")
        let it = item as! Item
        if partitionCheck && it.creator != me {
            throw KeychainCallFailed(call: "SecKeychainItemModifyAttributesAndData", status: errSecAuthFailed)
        }
        it.value = value
    }

    func add(service: String, account: String, label: String, value: Data) throws {
        try enter("add", "SecItemAdd")
        if locked { throw KeychainCallFailed(call: "SecItemAdd", status: errSecInteractionNotAllowed) }
        guard item(service, account) == nil else { throw KeychainCallFailed(call: "SecItemAdd", status: errSecDuplicateItem) }
        let entries = Self.ownShape(trusted: trusted) + (loginShaped ? Self.managedEntries : [])
        plant(service: service, account: account, value: value, entries: entries, creator: me)
    }

    func delete(service: String, account: String) throws {
        try enter("delete", "SecItemDelete")
        lock.lock(); defer { lock.unlock() }
        guard let i = items.firstIndex(where: { $0.service == service && $0.account == account }) else {
            throw KeychainCallFailed(call: "SecItemDelete", status: errSecItemNotFound)
        }
        items.remove(at: i)
    }

    func accounts(service: String) throws -> [String] {
        try enter("accounts", "SecItemCopyMatching")
        return allItems.filter { $0.service == service }.map(\.account)
    }
}

func fakeVault(trusted: Set<AppIdentity> = [nazarID], service: String = "dev.nazar") throws -> (KeychainVault, FakeKeychainStore) {
    let store = FakeKeychainStore(trusted: trusted)
    return (try KeychainVault(store: store, service: service, trustedIDs: trusted), store)
}

/// A planted access list that is not Nazar's shape, and why the vault refuses it.
struct HostileShape: CustomStringConvertible {
    let name: String
    let entries: [Entry]
    let reason: String
    var description: String { name }

    static let me = nazarID
    static let other = evilID
    static let own = FakeKeychainStore.ownShape(trusted: [me])
    static let group = FakeKeychainStore.decryptGroup
    static let openAny = "item is open to any application"
    static let another = "item trusts another application"

    static let all: [HostileShape] = [
        // What SecAccessCreate gives when a planter does not narrow it: Encrypt open to any application.
        .init(name: "openEncrypt", entries: [Entry(auths: group, apps: [me]), Entry(auths: [encryptAuth], apps: nil),
                                            Entry(auths: [changeACLAuth], apps: [])], reason: openAny),
        .init(name: "openDecrypt", entries: [Entry(auths: group, apps: nil), Entry(auths: [encryptAuth], apps: [me]),
                                            Entry(auths: [changeACLAuth], apps: [])], reason: openAny),
        .init(name: "openChangeACL", entries: [Entry(auths: group, apps: [me]), Entry(auths: [encryptAuth], apps: [me]),
                                              Entry(auths: [changeACLAuth], apps: nil)], reason: openAny),
        .init(name: "extraApp", entries: [Entry(auths: group, apps: [me, other]), Entry(auths: [encryptAuth], apps: [me, other]),
                                         Entry(auths: [changeACLAuth], apps: [])], reason: another),
        .init(name: "extraAppOnEncryptOnly", entries: [Entry(auths: group, apps: [me]), Entry(auths: [encryptAuth], apps: [me, other]),
                                                      Entry(auths: [changeACLAuth], apps: [])], reason: another),
        .init(name: "duplicateApp", entries: [Entry(auths: group, apps: [me, me]), Entry(auths: [encryptAuth], apps: [me]),
                                             Entry(auths: [changeACLAuth], apps: [])], reason: another),
        .init(name: "foreignChangeACL", entries: [Entry(auths: group, apps: [me]), Entry(auths: [encryptAuth], apps: [me]),
                                                 Entry(auths: [changeACLAuth], apps: [other])], reason: another),
        .init(name: "foreignAndSelfChangeACL", entries: [Entry(auths: group, apps: [me]), Entry(auths: [encryptAuth], apps: [me]),
                                                        Entry(auths: [changeACLAuth], apps: [me, other])], reason: another),
        // Nazar's path with another program's code requirement: the path-only comparison's bypass.
        .init(name: "forgedChangeACL", entries: [Entry(auths: group, apps: [me]), Entry(auths: [encryptAuth], apps: [me]),
                                                Entry(auths: [changeACLAuth], apps: [forgedID])], reason: another),
        .init(name: "forgedDecryptEncrypt", entries: [Entry(auths: group, apps: [forgedID]), Entry(auths: [encryptAuth], apps: [forgedID]),
                                                     Entry(auths: [changeACLAuth], apps: [])], reason: another),
        .init(name: "foreignDecryptEncrypt", entries: [Entry(auths: group, apps: [other]), Entry(auths: [encryptAuth], apps: [other]),
                                                      Entry(auths: [changeACLAuth], apps: [])], reason: another),
        // A grant dressed as securityd's own entry (SecACLUpdateAuthorizations can make one).
        .init(name: "mixedManaged", entries: own + [Entry(auths: [partitionAuth, decryptAuth], apps: nil)], reason: openAny),
        .init(name: "mixedManagedEncrypt", entries: own + [Entry(auths: [integrityAuth, encryptAuth], apps: nil)], reason: openAny),
        // ChangeACL bundled with a grant, answered by a password prompt, not an application.
        .init(name: "bundledOnly", entries: [Entry(auths: [changeACLAuth, decryptAuth, encryptAuth], apps: [])], reason: another),
        .init(name: "bundledNextToOwn", entries: own + [Entry(auths: [changeACLAuth, decryptAuth, encryptAuth], apps: [])], reason: another),
        .init(name: "bundledForeign", entries: own + [Entry(auths: [changeACLAuth, decryptAuth], apps: [other])], reason: another),
        .init(name: "bundledEncryptTrustsMeOnly", entries: [Entry(auths: [changeACLAuth, encryptAuth], apps: [me]),
                                                           Entry(auths: [changeACLAuth], apps: [])],
              reason: "item has no Decrypt entry trusting this program"),
        // Missing grants: SecAccessCreate's entries with one removed before the add.
        .init(name: "noDecrypt", entries: [Entry(auths: [encryptAuth], apps: [me]), Entry(auths: [changeACLAuth], apps: [])],
              reason: "item has no Decrypt entry trusting this program"),
        .init(name: "noEncrypt", entries: [Entry(auths: group, apps: [me]), Entry(auths: [changeACLAuth], apps: [])],
              reason: "item has no Encrypt entry trusting this program"),
        .init(name: "bareChangeACLOnly", entries: [Entry(auths: [changeACLAuth], apps: [])],
              reason: "item has no Decrypt entry trusting this program"),
        .init(name: "noEntries", entries: [], reason: "item has no Decrypt entry trusting this program"),
        .init(name: "onlyManaged", entries: FakeKeychainStore.managedEntries, reason: "item has no Decrypt entry trusting this program"),
        .init(name: "emptyAuths", entries: own + [Entry(auths: [], apps: nil)], reason: openAny),
    ]
}

/// Replaces the vault's dialog switch with `fake` for the scope of `body`
/// (restored afterwards). `fake` sees only calls from this thread; calls
/// from other threads (another suite building a vault at the same time)
/// go to the real switch untouched, and every call is checked to be
/// `false`: the real SecKeychainSetUserInteractionAllowed is never given
/// `true` by anything in this process.
func withDialogSwitch(_ fake: @escaping (Bool) -> OSStatus, _ body: () throws -> Void) rethrows {
    let real = KeychainVault.setUserInteractionAllowed
    let here = Thread.current
    KeychainVault.setUserInteractionAllowed = { allowed in
        if allowed { Issue.record("something asked to turn Keychain dialogs ON"); return errSecParam }
        return Thread.current === here ? fake(false) : real(false)
    }
    defer { KeychainVault.setUserInteractionAllowed = real }
    try body()
}

/// A temporary home folder with NOTHING inside it: enough for the login-path
/// logic, which compares paths along their longest existing prefix. No
/// `Library`, no `Keychains`, no keychain is ever created under it.
struct EmptyHome {
    let base: URL
    var home: URL { base.appendingPathComponent("home") }
    /// A symlink to `home`.
    var link: URL { base.appendingPathComponent("link") }
    var loginPath: String { KeychainVault.loginKeychainPath(home: home.path) }

    init() throws {
        base = FileManager.default.temporaryDirectory.appendingPathComponent("nzhome-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: home, withIntermediateDirectories: true,
                                                attributes: [.posixPermissions: 0o700])
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: home)
    }

    /// Nothing was ever created inside the home.
    func expectUntouched(sourceLocation: SourceLocation = #_sourceLocation) {
        #expect((try? FileManager.default.contentsOfDirectory(atPath: home.path)) == [], sourceLocation: sourceLocation)
    }

    func destroy() { try? FileManager.default.removeItem(at: base) }
}

/// Values collected from concurrent work (the shared `Box` is in DialogGateTests).
final class VaultTestErrors: @unchecked Sendable {
    private let lock = NSLock()
    private var v: [String]
    init(_ v: [String]) { self.v = v }
    var value: [String] { lock.lock(); defer { lock.unlock() }; return v }
    func mutate(_ f: (inout [String]) -> Void) { lock.lock(); defer { lock.unlock() }; f(&v) }
}

// MARK: - Real keychain: the vault's own items only

@Suite(.serialized, .timeLimit(.minutes(1))) struct KeychainVaultTests {
    /// A vault on a fresh temporary keychain trusting exactly this executable.
    func vault() throws -> (KeychainVault, TemporaryKeychain) {
        try requireKeychainDialogsOff()
        let tk = try TemporaryKeychain()
        return (try KeychainVault(keychain: tk.keychain, service: "dev.nazar.test.\(UUID().uuidString)"), tk)
    }

    @Test func productionServiceIsDevNazar() {
        #expect(KeychainVault.productionService == "dev.nazar")
    }

    @Test func keychainDialogsAreOffBeforeAnyKeychainCall() throws {
        try requireKeychainDialogsOff()
    }

    @Test func getPutDeleteList() throws {
        try requireKeychainDialogsOff()
        let before = userSearchList()
        let defaultBefore = userDefaultKeychain()
        do {
            let (v, tk) = try vault()
            defer { tk.destroy() }
            #expect(throws: PlatformError.notFound) { try v.get("ssh-key/github") }
            #expect(try v.list(prefix: "") == [])
            try v.put("ssh-key/github", Data("h1".utf8))
            try v.put("ssh-key/work", Data("h2".utf8))
            try v.put("config/approved", Data("cfg".utf8))
            #expect(try v.get("ssh-key/github") == Data("h1".utf8))
            try v.put("ssh-key/github", Data("h3".utf8)) // replace keeps one item
            #expect(try v.get("ssh-key/github") == Data("h3".utf8))
            #expect(itemCount(tk.keychain, service: v.service, account: "ssh-key/github") == 1)
            #expect(try v.list(prefix: "ssh-key/") == ["ssh-key/github", "ssh-key/work"])
            #expect(try v.list(prefix: "") == ["config/approved", "ssh-key/github", "ssh-key/work"])
            try v.delete("ssh-key/github")
            #expect(throws: PlatformError.notFound) { try v.get("ssh-key/github") }
            #expect(throws: PlatformError.notFound) { try v.delete("ssh-key/github") }
            #expect(try v.list(prefix: "ssh-key/") == ["ssh-key/work"])
            try v.put("empty", Data())
            #expect(try v.get("empty") == Data())
            #expect(isInside(keychainPath(tk.keychain), tk.dir))
        }
        // The temporary keychain never joins the user's search list or
        // becomes the default keychain.
        #expect(userSearchList() == before)
        #expect(userDefaultKeychain() == defaultBefore)
        try requireKeychainDialogsOff()
    }

    @Test func binaryValuesRoundTripExactly() throws {
        let (v, tk) = try vault()
        defer { tk.destroy() }
        var big = Data((0..<65536).map { UInt8(truncatingIfNeeded: $0 &* 31 &+ 7) })
        big[0] = 0
        big[big.count - 1] = 0
        try v.put("state/big", big)
        #expect(try v.get("state/big") == big)
        let nuls = Data([0, 0, 0, 0xFF, 0])
        try v.put("state/nuls", nuls)
        #expect(try v.get("state/nuls") == nuls)
        // A shorter value fully replaces a longer one (no stale tail).
        try v.put("state/big", Data("s".utf8))
        #expect(try v.get("state/big") == Data("s".utf8))
    }

    @Test func namesAreValidated() throws {
        let (v, tk) = try vault()
        defer { tk.destroy() }
        let bad = ["", "/abs", ".hidden", "-x", "_x", "a b", "a\nb", "a\tb", "a\0b", "a:b", "a\\b", "a*", "a%b",
                   // ICU's `$` also matches before a final line terminator
                   "ssh-key/github\n", "ssh-key/github\r\n", "abc\r", "abc\u{2028}",
                   // look-alikes outside ASCII
                   "é", "ssh-key/caf\u{E9}", "\u{FF41}", "\u{0661}", "ssh-key/\u{0455}sh",
                   String(repeating: "x", count: 129), "a" + String(repeating: "/", count: 128)]
        for name in bad {
            #expect(throws: PlatformError.invalid("vault name"), "\(name.debugDescription)") {
                try v.put(name, Data("x".utf8))
            }
            #expect(throws: PlatformError.invalid("vault name"), "\(name.debugDescription)") { try v.get(name) }
            #expect(throws: PlatformError.invalid("vault name"), "\(name.debugDescription)") { try v.delete(name) }
        }
        #expect(try v.list(prefix: "") == [], "a rejected name was stored")
        let good = ["a", "0", "A.b_c-d/e", "config/approved", "config/prompts", "state/trust",
                    "ssh-key/" + String(repeating: "k", count: 64), String(repeating: "x", count: 128), "a/../b"]
        for name in good {
            try v.put(name, Data(name.utf8))
            #expect(try v.get(name) == Data(name.utf8))
        }
        #expect(try v.list(prefix: "") == good.sorted())
        for name in good { try v.delete(name) }
        #expect(try v.list(prefix: "") == [])
    }

    @Test func namesAreCaseSensitive() throws {
        let (v, tk) = try vault()
        defer { tk.destroy() }
        try v.put("ssh-key/A", Data("upper".utf8))
        try v.put("ssh-key/a", Data("lower".utf8))
        #expect(try v.get("ssh-key/A") == Data("upper".utf8))
        #expect(try v.get("ssh-key/a") == Data("lower".utf8))
        #expect(try v.list(prefix: "ssh-key/") == ["ssh-key/A", "ssh-key/a"])
        #expect(try v.list(prefix: "SSH-KEY/") == [])
        try v.delete("ssh-key/a")
        #expect(try v.get("ssh-key/A") == Data("upper".utf8))
    }

    // Same semantics as core/platform/fake (TestVaultListIsSortedAndPrefixExact).
    @Test func listIsSortedAndPrefixExact() throws {
        let (v, tk) = try vault()
        defer { tk.destroy() }
        for n in ["ssh-key/b", "state/trust", "ssh-key/a", "ssh-keyring", "config/approved", "ssh-key/c"] {
            try v.put(n, Data("x".utf8))
        }
        #expect(try v.list(prefix: "ssh-key/") == ["ssh-key/a", "ssh-key/b", "ssh-key/c"])
        #expect(try v.list(prefix: "") == ["config/approved", "ssh-key/a", "ssh-key/b", "ssh-key/c", "ssh-keyring",
                                          "state/trust"])
        #expect(try v.list(prefix: "nothing/") == [])
        #expect(try v.list(prefix: "ssh-key/a") == ["ssh-key/a"])
        // The prefix is a literal, never a pattern.
        #expect(try v.list(prefix: "ssh-key.") == [])
        #expect(try v.list(prefix: "*") == [])
        #expect(try v.list(prefix: "%") == [])
    }

    @Test func separateServicesDoNotSeeEachOther() throws {
        let (v, tk) = try vault()
        defer { tk.destroy() }
        let other = try KeychainVault(keychain: tk.keychain, service: "dev.nazar.test.other.\(UUID().uuidString)")
        try v.put("a", Data("1".utf8))
        #expect(try other.list(prefix: "") == [])
        #expect(throws: PlatformError.notFound) { try other.get("a") }
        #expect(throws: PlatformError.notFound) { try other.delete("a") }
        try other.put("a", Data("2".utf8))
        #expect(try v.get("a") == Data("1".utf8))
        #expect(try other.get("a") == Data("2".utf8))
    }

    // The vault reads and writes only its own keychain: an item with the same
    // service and name in another keychain (one an attacker added to the
    // search list, or the login keychain) is invisible to it, and a put never
    // lands there. Both items are the vault's own shape (made by a vault of
    // this executable on the other keychain): nothing foreign is created.
    @Test func otherKeychainsAreNeverConsulted() throws {
        let (v, tk) = try vault()
        defer { tk.destroy() }
        let foreign = try TemporaryKeychain()
        defer { foreign.destroy() }
        let fv = try KeychainVault(keychain: foreign.keychain, service: v.service)
        try fv.put("config/approved", Data("elsewhere".utf8))
        #expect(throws: PlatformError.notFound) { try v.get("config/approved") }
        #expect(try v.list(prefix: "") == [])
        #expect(throws: PlatformError.notFound) { try v.delete("config/approved") }
        try v.put("config/approved", Data("real".utf8))
        #expect(try v.get("config/approved") == Data("real".utf8))
        #expect(try fv.get("config/approved") == Data("elsewhere".utf8))
        #expect(itemCount(foreign.keychain, service: v.service, account: "config/approved") == 1)
        #expect(itemCount(tk.keychain, service: v.service, account: "config/approved") == 1)
    }

    // Every ACL entry except ChangeACL trusts exactly one application: this
    // executable. (That another process gets a dialog is checked by hand.)
    @Test func itemAccessListTrustsOnlyThisExecutable() throws {
        let (v, tk) = try vault()
        defer { tk.destroy() }
        try v.put("ssh-key/acl", Data("h".utf8))
        let me = try myIdentity()
        #expect(v.trustedIDs == [me])
        expectOnlyTrusted(try ownAccessList(v, "ssh-key/acl"), [me])
        // The raw-API spelling of the same check (own item, access list only:
        // no authorization is needed to read it).
        let item = try ownItem(v, "ssh-key/acl") as! SecKeychainItem
        var access: SecAccess?
        #expect(SecKeychainItemCopyAccess(item, &access) == errSecSuccess)
        var acls: CFArray?
        SecAccessCopyACLList(try #require(access), &acls)
        var checked = 0
        for acl in (acls as? [SecACL]) ?? [] {
            let auths = SecACLCopyAuthorizations(acl) as? [String] ?? []
            if auths.contains(changeACLAuth) { continue }
            var apps: CFArray?
            var desc: CFString?
            var prompt = SecKeychainPromptSelector()
            SecACLCopyContents(acl, &apps, &desc, &prompt)
            let list = try #require(apps as? [SecTrustedApplication], "ACL \(auths) is open to any application")
            #expect(list.count == 1, "ACL \(auths)")
            #expect(try list.map(AppIdentity.init) == [me], "ACL \(auths) trusts another application")
            checked += 1
        }
        #expect(checked >= 2) // the decrypt group and encrypt
    }

    // The in-memory store is modelled on what the real store reads back from
    // an item the vault created; this pins the match, so every verdict the
    // fake-store tests reach is a verdict on the real shape: the same entries
    // (as sets of authorizations), the Decrypt group and Encrypt trusting
    // exactly this executable, the bare ChangeACL entry trusting nobody, no
    // managed entries (a temporary keychain is not under Library/Keychains).
    @Test func ownItemsReadBackAsTheFakeModelsThem() throws {
        let (v, tk) = try vault()
        defer { tk.destroy() }
        try v.put("config/approved", Data("x".utf8))
        let me = try myIdentity()
        let real = try ownAccessList(v, "config/approved")
        let modelled = FakeKeychainStore.ownShape(trusted: [me])
        #expect(Set(real.map { Set($0.auths) }) == Set(modelled.map { Set($0.auths) }),
                "real: \(real.map(\.auths)) modelled: \(modelled.map(\.auths))")
        #expect(real.count == modelled.count)
        for e in real {
            if KeychainVault.isChangeACLOnly(e.auths) {
                #expect(e.apps == [], "the owner entry trusts \(e.apps.map { "\($0.count) apps" } ?? "ANY")")
            } else {
                #expect(e.apps == [me], "ACL \(e.auths)")
            }
        }
        #expect(!real.contains { KeychainVault.isManaged($0.auths) })
        #expect(KeychainVault.refusal(of: real, trusted: [me]) == nil)
        #expect(KeychainVault.refusal(of: modelled, trusted: [me]) == nil)
        #expect(real.map { KeychainVault.classify(auths: $0.auths, apps: $0.apps, trusted: [me]) }
                    .allSatisfy { $0 == .trusted })
        // And the real store's own-item read goes through the same calls the
        // fake logs: a reference, the access list, then the content.
        #expect(try v.get("config/approved") == Data("x".utf8))
    }

    // Replacing a value and re-creating a deleted one must not widen the
    // access list.
    @Test func accessListSurvivesReplaceAndRecreate() throws {
        let (v, tk) = try vault()
        defer { tk.destroy() }
        let me = try myIdentity()
        try v.put("config/approved", Data("1".utf8))
        try v.put("config/approved", Data("2".utf8))
        expectOnlyTrusted(try ownAccessList(v, "config/approved"), [me])
        try v.delete("config/approved")
        try v.put("config/approved", Data("3".utf8))
        expectOnlyTrusted(try ownAccessList(v, "config/approved"), [me])
        #expect(try v.get("config/approved") == Data("3".utf8))
        #expect(itemCount(tk.keychain, service: v.service, account: "config/approved") == 1)
    }

    // `trusted:` nil and `trusted: [this executable]` are the same vault:
    // same identity, same access list. (Lists with other applications are
    // exercised on the in-memory store: no real item ever trusts anyone but
    // this process.)
    @Test func explicitSelfEqualsDefaultTrusted() throws {
        try requireKeychainDialogsOff()
        let tk = try TemporaryKeychain()
        defer { tk.destroy() }
        let me = try thisExecutable()
        let myID = try AppIdentity(me)
        let explicit = try KeychainVault(keychain: tk.keychain, service: "dev.nazar.test.explicit", trusted: [me])
        let implicit = try KeychainVault(keychain: tk.keychain, service: "dev.nazar.test.explicit")
        #expect(explicit.trustedIDs == [myID] && implicit.trustedIDs == [myID])
        try explicit.put("ssh-key/one", Data("1".utf8))
        #expect(try implicit.get("ssh-key/one") == Data("1".utf8))
        expectOnlyTrusted(try ownAccessList(implicit, "ssh-key/one"), [myID])
        try implicit.put("ssh-key/one", Data("2".utf8))
        #expect(try explicit.get("ssh-key/one") == Data("2".utf8))
        #expect(throws: PlatformError.self) { try KeychainVault(keychain: tk.keychain, service: "dev.nazar.test.none", trusted: []) }
    }

    // Keychain Services dialogs are off for the whole process from the first
    // vault on (spec 4.5: no prompt out of context). The alternative is a
    // "NazarApp wants to use your confidential information" Allow/Deny dialog
    // from Nazar's own process at login, which is the one click a planted
    // config/approved or state/trust needs. The switch is observed through
    // the seam: this test never turns dialogs on to "prove" the vault turns
    // them off (with dialogs on, a keychain call from any suite running in
    // parallel could prompt).
    @Test func vaultTurnsKeychainDialogsOff() throws {
        try requireKeychainDialogsOff()
        let calls = VaultTestErrors([])
        let real = KeychainVault.setUserInteractionAllowed
        try withDialogSwitch({ allowed in calls.mutate { $0.append("\(allowed)") }; return real(false) }) {
            let tk = try TemporaryKeychain()
            defer { tk.destroy() }
            calls.mutate { $0.removeAll() } // TemporaryKeychain uses the real switch, not the seam
            let v = try KeychainVault(keychain: tk.keychain, service: "dev.nazar.test.\(UUID().uuidString)")
            #expect(calls.value == ["false"], "init must turn dialogs off exactly once, with false")
            try requireKeychainDialogsOff()
            try v.put("ssh-key/a", Data("h".utf8))
            #expect(try v.get("ssh-key/a") == Data("h".utf8)) // nothing of the vault's own needs a dialog
            #expect(calls.value == ["false"])

            // The in-memory seam too.
            calls.mutate { $0.removeAll() }
            _ = try fakeVault()
            #expect(calls.value == ["false"])

            // The login() seam too (it is the production entry point): dialogs
            // go off BEFORE the keychain is opened, and the vault that comes
            // back works on the keychain `open` returned.
            calls.mutate { $0.removeAll() }
            let eh = try EmptyHome()
            defer { eh.destroy() }
            let opened = VaultTestErrors([])
            let lv = try KeychainVault.login(service: "dev.nazar.test.login.\(UUID().uuidString)", home: eh.home.path,
                                             defaultKeychainPath: eh.loginPath) { path in
                #expect(calls.value == ["false"], "login() opened the keychain before turning dialogs off")
                opened.mutate { $0.append(path) }
                return tk.keychain
            }
            #expect(opened.value == [eh.loginPath])
            #expect(calls.value.allSatisfy { $0 == "false" } && !calls.value.isEmpty, "\(calls.value)")
            try lv.put("ssh-key/b", Data("h".utf8))
            #expect(try lv.get("ssh-key/b") == Data("h".utf8))
            #expect(itemCount(tk.keychain, service: lv.service, account: "ssh-key/b") == 1)
            eh.expectUntouched()
            try requireKeychainDialogsOff()
        }
    }

    // If the switch cannot be turned off, no vault exists at all: init (real
    // and in-memory) and login() fail closed before any Keychain call
    // (login() before `open`).
    @Test func vaultCannotExistWithDialogsOn() throws {
        try requireKeychainDialogsOff()
        let tk = try TemporaryKeychain()
        defer { tk.destroy() }
        let expected = PlatformError.failed("SecKeychainSetUserInteractionAllowed: \(errSecInteractionNotAllowed)")
        try withDialogSwitch({ _ in errSecInteractionNotAllowed }) {
            #expect(throws: expected) { try KeychainVault(keychain: tk.keychain, service: "dev.nazar.test.off") }
            #expect(throws: expected) { try fakeVault() }
            let eh = try EmptyHome()
            defer { eh.destroy() }
            let opened = VaultTestErrors([])
            #expect(throws: expected) {
                try KeychainVault.login(service: "dev.nazar.test.off", home: eh.home.path, defaultKeychainPath: eh.loginPath) { path in
                    opened.mutate { $0.append(path) }
                    return tk.keychain
                }
            }
            #expect(opened.value == [], "login() opened a keychain with dialogs still on")
            eh.expectUntouched()
        }
        // The real switch is untouched by the failure and still off.
        try requireKeychainDialogsOff()
    }

    // Production opens the login keychain by its canonical path under the
    // passwd home, and refuses to run when the user-domain default keychain
    // has been pointed elsewhere (a plain preference any process can set).
    // Only paths are compared here, along their longest existing prefix: the
    // "home" is an EMPTY temporary folder (no Library, no Keychains, no file),
    // `open` hands back a plain TemporaryKeychain and records what it was
    // asked to open, and the real login keychain is never opened.
    @Test func loginKeychainIsTheCanonicalFileAndASwappedDefaultIsRefused() throws {
        try requireKeychainDialogsOff()
        let eh = try EmptyHome()
        defer { eh.destroy() }
        let (home, loginPath) = (eh.home, eh.loginPath)
        #expect(loginPath == home.path + "/Library/Keychains/login.keychain-db")
        #expect(KeychainVault.loginKeychainPath(home: home.path + "/") == loginPath)
        #expect(try KeychainVault.homeDirectory() == String(cString: getpwuid(getuid()).pointee.pw_dir))

        let store = try TemporaryKeychain()
        defer { store.destroy() }
        let opened = VaultTestErrors([])
        func open(_ path: String) -> SecKeychain {
            opened.mutate { $0.append(path) }
            return store.keychain
        }

        // A swapped default (another keychain file, a file elsewhere, a
        // near-miss name, another home) is refused before anything is opened.
        let other = try TemporaryKeychain()
        defer { other.destroy() }
        for swapped in [keychainPath(other.keychain), home.appendingPathComponent("evil.keychain-db").path,
                        home.appendingPathComponent("Library/Keychains/login.keychain").path,
                        eh.base.appendingPathComponent("other/Library/Keychains/login.keychain-db").path, "", "/"] {
            #expect(throws: PlatformError.self, "\(swapped)") {
                try KeychainVault.checkedLoginKeychainPath(home: home.path, defaultKeychainPath: swapped)
            }
            do {
                _ = try KeychainVault.login(service: "dev.nazar.test.login", home: home.path, defaultKeychainPath: swapped,
                                            open: open)
                Issue.record("login accepted a default keychain that is not the login keychain: \(swapped)")
            } catch let e as PlatformError {
                guard case .failed(let msg) = e else { Issue.record("\(swapped): \(e)"); continue }
                #expect(msg.contains("not the login keychain"), "\(msg)")
            }
        }
        #expect(opened.value == [], "a swapped default was opened")

        // The real thing: the default names the login keychain (directly,
        // through a symlinked home, through /var -> /private/var, or with a
        // `..` in it), and exactly the canonical path is opened.
        let defaults = [loginPath, eh.link.appendingPathComponent("Library/Keychains/login.keychain-db").path,
                        KeychainVault.realPath(loginPath), home.path + "/Library/Keychains/../Keychains/login.keychain-db"]
        for def in defaults {
            #expect(try KeychainVault.checkedLoginKeychainPath(home: home.path, defaultKeychainPath: def) == loginPath, "\(def)")
            let v = try KeychainVault.login(service: "dev.nazar.test.login.\(UUID().uuidString)", home: home.path,
                                            defaultKeychainPath: def, open: open)
            try v.put("ssh-key/a", Data("h".utf8))
            #expect(try v.get("ssh-key/a") == Data("h".utf8))
            #expect(itemCount(store.keychain, service: v.service, account: "ssh-key/a") == 1)
            #expect(itemCount(other.keychain, service: v.service, account: "ssh-key/a") == 0)
        }
        #expect(opened.value == Array(repeating: loginPath, count: defaults.count))
        // Nothing was created in the home: no Library, no Keychains, no file.
        eh.expectUntouched()
    }

    @Test func realPathResolvesTheLongestExistingPrefix() throws {
        let eh = try EmptyHome()
        defer { eh.destroy() }
        let realHome = try #require(realpath(eh.home.path, nil).map { String(cString: $0) })
        #expect(realHome.hasPrefix("/private/"), "\(realHome)")
        let missing = "/Library/Keychains/login.keychain-db"
        #expect(KeychainVault.realPath(eh.home.path + missing) == realHome + missing)
        #expect(KeychainVault.realPath(eh.link.path + missing) == realHome + missing)
        #expect(KeychainVault.realPath(eh.home.path + "/Library/./Keychains/../Keychains/x") == realHome + "/Library/Keychains/x")
        #expect(KeychainVault.realPath(realHome + missing) == realHome + missing)
        #expect(KeychainVault.realPath("/var") == "/private/var")
        #expect(KeychainVault.realPath("/var/nope/a") == "/private/var/nope/a")
        #expect(KeychainVault.realPath("/") == "/")
        #expect(KeychainVault.realPath("") == "")
        #expect(KeychainVault.realPath("/nope/x") == "/nope/x")
        eh.expectUntouched()
    }

    // Concurrent puts of one name (two requests creating the same key record)
    // never fail with a duplicate and leave exactly one item.
    @Test func concurrentPutsLeaveOneItem() throws {
        let (v, tk) = try vault()
        defer { tk.destroy() }
        let errors = VaultTestErrors([])
        let values = (0..<16).map { Data("v\($0)".utf8) }
        DispatchQueue.concurrentPerform(iterations: values.count) { i in
            do { try v.put("config/prompts", values[i]) } catch { errors.mutate { $0.append("\(error)") } }
            do { try v.put("ssh-key/k\(i % 4)", values[i]) } catch { errors.mutate { $0.append("\(error)") } }
        }
        #expect(errors.value == [])
        #expect(itemCount(tk.keychain, service: v.service, account: "config/prompts") == 1)
        #expect(values.contains(try v.get("config/prompts")))
        #expect(try v.list(prefix: "") == ["config/prompts", "ssh-key/k0", "ssh-key/k1", "ssh-key/k2", "ssh-key/k3"])
        expectOnlyTrusted(try ownAccessList(v, "config/prompts"), [try myIdentity()])
    }
}

// MARK: - In-memory store: everything a real keychain could only show by reaching securityd

@Suite(.serialized, .timeLimit(.minutes(1))) struct KeychainVaultRulesTests {
    // The fake behaves like the vault's contract so the hostile cases below
    // mean something: round trip, one item per name, the calls in order.
    @Test func fakeStoreRoundTrip() throws {
        let (v, s) = try fakeVault()
        #expect(throws: PlatformError.notFound) { try v.get("ssh-key/a") }
        #expect(s.calls == ["find"])
        s.clearLog()
        try v.put("ssh-key/a", Data("1".utf8))
        #expect(s.calls == ["find", "add"])
        s.clearLog()
        #expect(try v.get("ssh-key/a") == Data("1".utf8))
        #expect(s.calls == ["find", "accessList", "content"], "a value is read only after its access list")
        s.clearLog()
        try v.put("ssh-key/a", Data("2".utf8))
        #expect(s.calls == ["find", "accessList", "replace"], "a value is rewritten only after its access list")
        #expect(try v.get("ssh-key/a") == Data("2".utf8))
        #expect(s.allItems.count == 1)
        expectOnlyTrusted(try #require(s.item(v.service, "ssh-key/a")).entries, [nazarID])
        try v.put("config/approved", Data("c".utf8))
        #expect(try v.list(prefix: "") == ["config/approved", "ssh-key/a"])
        #expect(try v.list(prefix: "ssh-key/") == ["ssh-key/a"])
        try v.delete("ssh-key/a")
        #expect(throws: PlatformError.notFound) { try v.delete("ssh-key/a") }
        #expect(try v.list(prefix: "") == ["config/approved"])
        #expect(throws: PlatformError.invalid("vault name")) { try v.get("") }
        #expect(throws: PlatformError.invalid("vault name")) { try v.put("a b", Data()) }
        #expect(throws: PlatformError.invalid("vault name")) { try v.delete("/x") }
    }

    // Attack: malware creates the item before Nazar does (first run, or a name
    // Nazar has not written yet), with an access list that lets it read,
    // rewrite or re-open the item later. A foreign-shaped item is refused
    // BEFORE its value is touched: get never calls content, put never calls
    // replace or add, the item is left exactly as it was for the user to
    // inspect, and the error is a `.failed` naming the item (never `.notFound`,
    // which would hide it). The same holds on a login-shaped keychain, where
    // securityd's managed entries sit next to the planted ones (they are
    // skipped, never a mask). forgedChangeACL / forgedDecryptEncrypt are the
    // regression for the path-only comparison; mixedManaged for the
    // managed-entry skip; bundled* for ChangeACL bundled with a grant (answered
    // by a password prompt, the one subject the dialogs-off flag is not known
    // to silence).
    @Test(arguments: HostileShape.all)
    func foreignShapedPlantIsRefusedBeforeAnyRead(shape: HostileShape) throws {
        for loginShaped in [false, true] {
            let (v, s) = try fakeVault()
            s.loginShaped = loginShaped
            let name = "config/approved"
            let forged = Data("forged".utf8)
            let entries = shape.entries + (loginShaped ? FakeKeychainStore.managedEntries : [])
            let planted = s.plant(service: v.service, account: name, value: forged, entries: entries)
            // The shape is really hostile to the pure rule (else this test proves nothing).
            #expect(KeychainVault.refusal(of: entries, trusted: [nazarID]) != nil, "\(shape) is Nazar's shape")

            s.clearLog()
            do {
                let d = try v.get(name)
                Issue.record("\(shape): get returned \(d == forged ? "the forged value" : "a value") from a planted item")
            } catch let e as PlatformError {
                guard case .failed(let msg) = e else { Issue.record("\(shape): \(e)"); continue }
                #expect(msg.hasPrefix("vault \(name): ") && msg.contains(shape.reason), "\(shape): \(msg)")
            }
            #expect(s.calls == ["find", "accessList"], "\(shape): get touched more than the access list: \(s.calls)")

            s.clearLog()
            let secret = Data("secret-handle".utf8)
            #expect(throws: PlatformError.self, "\(shape): put accepted a planted item") { try v.put(name, secret) }
            #expect(s.calls == ["find", "accessList"], "\(shape): put touched more than the access list: \(s.calls)")
            #expect(planted.value == forged, "\(shape): the secret was written into the planted item")
            #expect(planted.entries == entries, "\(shape): the planted access list was changed")
            #expect(s.allItems.count == 1, "\(shape): an item was added next to the planted one")

            // The item is visible (listing reads attributes, not values) and
            // deletable, so the user can clear it; the vault never deletes it
            // by itself.
            #expect(try v.list(prefix: "") == [name])
            #expect(try v.list(prefix: "config/") == [name])
            try v.delete(name)
            #expect(s.allItems.isEmpty)
            // And now Nazar's own item takes the name, with Nazar's shape.
            try v.put(name, secret)
            #expect(try v.get(name) == secret)
            expectOnlyTrusted(try #require(s.item(v.service, name)).entries, [nazarID])
        }
        try requireKeychainDialogsOff()
    }

    // checkAccess is the gate get and put share; its verdict on each shape
    // through the real store path (accessList -> refusal) carries the reason.
    @Test func checkAccessCarriesTheReason() throws {
        let (v, s) = try fakeVault()
        for shape in HostileShape.all {
            let item = s.plant(service: v.service, account: "x/\(shape.name)", value: Data(), entries: shape.entries)
            let reason = try #require(KeychainVault.refusal(of: shape.entries, trusted: [nazarID]), "\(shape)")
            do {
                try v.checkAccess(of: item, "x/\(shape.name)")
                Issue.record("\(shape): accepted")
            } catch let e as PlatformError {
                #expect(e == .failed("vault x/\(shape.name): \(reason)"), "\(shape): \(e)")
                #expect(reason.contains(shape.reason), "\(shape): \(reason)")
            }
        }
        let own = s.plant(service: v.service, account: "own", value: Data(), entries: FakeKeychainStore.ownShape(trusted: [nazarID]))
        try v.checkAccess(of: own, "own")
        #expect(!s.calls.contains("content") && !s.calls.contains("replace"))
    }

    // Two trusted applications (a vault made with `trusted: [a, b]`): every
    // grant must name exactly both; one of them alone is another shape.
    @Test func twoTrustedApplicationsMustBothBeNamed() throws {
        let two: Set<AppIdentity> = [nazarID, evilID]
        let (v, s) = try fakeVault(trusted: two)
        try v.put("ssh-key/two", Data("2".utf8))
        expectOnlyTrusted(try #require(s.item(v.service, "ssh-key/two")).entries, two)
        #expect(try v.get("ssh-key/two") == Data("2".utf8))
        let group = FakeKeychainStore.decryptGroup
        for (name, entries) in [
            ("oneOfTwo", [Entry(auths: group, apps: [nazarID]), Entry(auths: [encryptAuth], apps: [nazarID]), Entry(auths: [changeACLAuth], apps: [])]),
            ("twoPlusOne", [Entry(auths: group, apps: [nazarID, evilID, forgedID]), Entry(auths: [encryptAuth], apps: [nazarID, evilID]),
                            Entry(auths: [changeACLAuth], apps: [])]),
        ] {
            s.plant(service: v.service, account: name, value: Data("forged".utf8), entries: entries)
            s.clearLog()
            #expect(throws: PlatformError.self, "\(name)") { try v.get(name) }
            #expect(!s.calls.contains("content"), "\(name)")
        }
        // The bare ChangeACL entry may trust one of the two (a subset): it is
        // the owner prompt, not a grant.
        s.plant(service: v.service, account: "changeOne", value: Data("ok".utf8),
                entries: [Entry(auths: group, apps: [evilID, nazarID]), Entry(auths: [encryptAuth], apps: [nazarID, evilID]),
                          Entry(auths: [changeACLAuth], apps: [evilID])])
        #expect(try v.get("changeOne") == Data("ok".utf8))
    }

    // Known limit (spec 4.8): a legacy keychain records no creator the vault
    // could compare, so an item another process adds with Nazar's EXACT access
    // list passes checkAccess. The vault's own check guarantees that other
    // processes cannot read Nazar's items or rewrite them in place (checked by
    // hand), not that an item it finds is Nazar's. On a keychain OUTSIDE
    // Library/Keychains (no partition entry) the vault reads such a plant; on
    // the login keychain securityd's partition check refuses the read from any
    // identity but the creator's with errSecAuthFailed (-25293), silently with
    // dialogs off (verified with two separately ad-hoc-signed helpers;
    // the partition securityd derives for Nazar.app is left to a check by
    // hand), and the vault reports it as a `.failed` that `nazar status` shows,
    // never as a dialog the user could mis-click.
    @Test func nazarShapedPlantIsAcceptedUnlessSecuritydRefusesIt() throws {
        let name = "state/trust"
        let forged = Data("forged".utf8)
        let own = FakeKeychainStore.ownShape(trusted: [nazarID])
        // Outside Library/Keychains: byte-for-byte Nazar's shape, no creator to compare: read.
        let (v1, s1) = try fakeVault()
        s1.plant(service: v1.service, account: name, value: forged, entries: own, creator: "evil")
        #expect(KeychainVault.refusal(of: own, trusted: [nazarID]) == nil)
        #expect(try v1.get(name) == forged) // documented, not a bug here
        // The login keychain: securityd's partition check, dialogs off.
        let (v2, s2) = try fakeVault()
        s2.loginShaped = true
        s2.partitionCheck = true
        let planted = s2.plant(service: v2.service, account: name, value: forged,
                               entries: own + FakeKeychainStore.managedEntries, creator: "evil")
        s2.clearLog()
        do {
            _ = try v2.get(name)
            Issue.record("get read an item securityd refuses")
        } catch let e as PlatformError {
            #expect(e == .failed("vault \(name): item was not created by this program (securityd partition check) "
                                 + "or the keychain is locked (get: SecKeychainItemCopyContent \(errSecAuthFailed))"), "\(e)")
        }
        #expect(s2.calls == ["find", "accessList", "content"])
        do {
            try v2.put(name, Data("mine".utf8))
            Issue.record("put rewrote an item securityd refuses")
        } catch let e as PlatformError {
            #expect(e == .failed("vault \(name): item was not created by this program (securityd partition check) "
                                 + "or the keychain is locked (update: SecKeychainItemModifyAttributesAndData \(errSecAuthFailed))"), "\(e)")
        }
        #expect(planted.value == forged && s2.allItems.count == 1)
        // Nazar's own items on the same keychain are fine.
        try v2.put("config/approved", Data("cfg".utf8))
        #expect(try v2.get("config/approved") == Data("cfg".utf8))
        #expect(try v2.list(prefix: "") == ["config/approved", name])
    }

    // Items in a keychain placed like the login keychain carry securityd's
    // Integrity and PartitionID entries, which read as "any application".
    // The vault must accept its own items there (the first version refused
    // every one of them with "open to any application") without accepting a
    // grant dressed as a managed entry. That securityd adds exactly these
    // two entries to a real login-keychain item is checked by hand.
    @Test func loginShapedItemsAreAccepted() throws {
        let (v, s) = try fakeVault()
        s.loginShaped = true
        s.partitionCheck = true
        try v.put("ssh-key/a", Data("h".utf8))
        let entries = try #require(s.item(v.service, "ssh-key/a")).entries
        #expect(entries.filter { KeychainVault.isManaged($0.auths) }.map(\.auths) == [[integrityAuth], [partitionAuth]])
        #expect(entries.filter { KeychainVault.isManaged($0.auths) }.allSatisfy { $0.apps == nil })
        expectOnlyTrusted(entries, [nazarID])
        #expect(try v.get("ssh-key/a") == Data("h".utf8))
        try v.put("ssh-key/a", Data("h2".utf8))
        #expect(try v.get("ssh-key/a") == Data("h2".utf8))
        #expect(try v.list(prefix: "") == ["ssh-key/a"])
        try v.delete("ssh-key/a")
        #expect(throws: PlatformError.notFound) { try v.get("ssh-key/a") }
    }

    // A locked keychain is never locked by automation (an unlock prompt is a
    // password dialog) and the locked login keychain is checked by hand;
    // here the store answers like one with dialogs off (seen on macOS 27:
    // SecKeychainItemCopyAccess is the first call to fail, -25293; a call that
    // would need the unlock dialog gets -25308). The vault fails with the
    // message `nazar status` shows, reads no value, adds nothing.
    @Test func lockedKeychainFailsWithoutADialog() throws {
        let (v, s) = try fakeVault()
        try v.put("ssh-key/a", Data("h".utf8))
        s.locked = true
        s.clearLog()
        do {
            _ = try v.get("ssh-key/a")
            Issue.record("get read a locked keychain")
        } catch let e as PlatformError {
            #expect(e == .failed("vault ssh-key/a: item was not created by this program (securityd partition check) "
                                 + "or the keychain is locked (access list: SecKeychainItemCopyAccess \(errSecAuthFailed))"), "\(e)")
        }
        #expect(s.calls == ["find", "accessList"])
        s.clearLog()
        #expect(throws: PlatformError.self) { try v.put("ssh-key/a", Data("x".utf8)) }
        #expect(s.calls == ["find", "accessList"])
        #expect(try #require(s.item(v.service, "ssh-key/a")).value == Data("h".utf8))
        do {
            try v.put("ssh-key/new", Data("x".utf8))
            Issue.record("put added to a locked keychain")
        } catch let e as PlatformError {
            #expect(e == .failed("vault ssh-key/new: item was not created by this program (securityd partition check) "
                                 + "or the keychain is locked (add: SecItemAdd \(errSecInteractionNotAllowed))"), "\(e)")
        }
        #expect(s.allItems.count == 1)
        #expect(try v.list(prefix: "") == ["ssh-key/a"]) // attributes are readable on a locked keychain
        try requireKeychainDialogsOff()
    }

    // Every other status a Keychain call can return is reported with the
    // call and the status, never swallowed; an item that vanished between
    // the access-list check and the read is `.notFound`; an ACL entry whose
    // application cannot be identified fails closed before any read.
    @Test func statusesArePropagated() throws {
        let (v, s) = try fakeVault()
        try v.put("ssh-key/a", Data("h".utf8))
        let io = errSecInternalComponent
        s.failures["find"] = io
        #expect(throws: PlatformError.failed("vault find ssh-key/a: SecItemCopyMatching \(io)")) { try v.get("ssh-key/a") }
        #expect(throws: PlatformError.failed("vault find ssh-key/a: SecItemCopyMatching \(io)")) { try v.put("ssh-key/a", Data()) }
        s.failures = ["accounts": io]
        #expect(throws: PlatformError.failed("vault list: SecItemCopyMatching \(io)")) { try v.list(prefix: "") }
        s.failures = ["delete": io]
        #expect(throws: PlatformError.failed("vault delete ssh-key/a: SecItemDelete \(io)")) { try v.delete("ssh-key/a") }
        s.failures = ["add": errSecDuplicateItem]
        #expect(throws: PlatformError.failed("vault add ssh-key/b: SecItemAdd \(errSecDuplicateItem)")) { try v.put("ssh-key/b", Data()) }
        s.failures = ["accessList": io]
        #expect(throws: PlatformError.failed("vault access list ssh-key/a: SecKeychainItemCopyAccess \(io)")) { try v.get("ssh-key/a") }
        s.failures = ["content": errSecItemNotFound]
        #expect(throws: PlatformError.notFound) { try v.get("ssh-key/a") }
        s.failures = ["content": io]
        #expect(throws: PlatformError.failed("vault get ssh-key/a: SecKeychainItemCopyContent \(io)")) { try v.get("ssh-key/a") }
        s.failures = ["replace": io]
        #expect(throws: PlatformError.failed("vault update ssh-key/a: SecKeychainItemModifyAttributesAndData \(io)")) {
            try v.put("ssh-key/a", Data("x".utf8))
        }
        s.failures = [:]
        s.accessListFailure = KeychainCallFailed(call: "SecTrustedApplicationCopyRequirement ([\"\(decryptAuth)\"])",
                                                 status: errSecUnimplemented)
        s.clearLog()
        #expect(throws: PlatformError.failed("vault access list ssh-key/a: SecTrustedApplicationCopyRequirement ([\"\(decryptAuth)\"]) \(errSecUnimplemented)")) {
            try v.get("ssh-key/a")
        }
        #expect(s.calls == ["find", "accessList"])
        s.accessListFailure = nil
        #expect(try v.get("ssh-key/a") == Data("h".utf8))

        // The two codes securityd returns with dialogs off are spelled out.
        for code in [errSecAuthFailed, errSecInteractionNotAllowed] {
            let f = KeychainCallFailed(call: "SecKeychainItemCopyContent", status: code)
            guard case .failed(let msg) = KeychainVault.accessError("get", "state/trust", f) else {
                Issue.record("accessError(\(code)) is not .failed"); continue
            }
            #expect(msg.contains("vault state/trust") && msg.contains("not created by this program")
                        && msg.contains("keychain is locked") && msg.contains("(get: SecKeychainItemCopyContent \(code))"), "\(msg)")
        }
        #expect(KeychainVault.accessError("add", "x", KeychainCallFailed(call: "SecItemAdd", status: errSecDuplicateItem))
                    == .failed("vault add x: SecItemAdd \(errSecDuplicateItem)"))
    }

    // The per-entry and whole-item rules on made-up entries: securityd's
    // managed entries are skipped, a grant dressed as one is a grant to any
    // application, the ChangeACL subset rule is confined to the bare
    // ChangeACL entry, every other entry must trust exactly `trusted`, and
    // the item needs a Decrypt and an Encrypt entry of that kind.
    @Test func managedEntriesAreSkippedAndGrantsAreJudged() throws {
        typealias V = KeychainVault
        let (integrity, partition) = (integrityAuth, partitionAuth)
        let (decrypt, encrypt, change) = (decryptAuth, encryptAuth, changeACLAuth)
        let (me, other) = (nazarID, evilID)
        let trusted: Set<AppIdentity> = [me]
        // securityd's own entries, in the shape they read back (any application).
        #expect(V.classify(auths: [integrity], apps: nil, trusted: trusted) == .managed)
        #expect(V.classify(auths: [partition], apps: nil, trusted: trusted) == .managed)
        #expect(V.classify(auths: [integrity, partition], apps: nil, trusted: trusted) == .managed)
        #expect(V.isManaged([integrity]) && V.isManaged([partition]))
        // A grant dressed as a managed entry is a grant to any application (mixedManaged).
        #expect(V.classify(auths: [partition, decrypt], apps: nil, trusted: trusted)
                    == .refused("item is open to any application ([\"\(partition)\", \"\(decrypt)\"])"))
        #expect(V.classify(auths: [integrity, encrypt], apps: nil, trusted: trusted)
                    == .refused("item is open to any application ([\"\(integrity)\", \"\(encrypt)\"])"))
        #expect(!V.isManaged([partition, decrypt]))
        // An entry with no authorizations at all is not managed either.
        #expect(!V.isManaged([]))
        #expect(V.classify(auths: [], apps: nil, trusted: trusted) == .refused("item is open to any application ([])"))
        #expect(V.classify(auths: [], apps: [other], trusted: trusted) == .refused("item trusts another application ([])"))
        // Nazar's own shape.
        #expect(V.classify(auths: [decrypt], apps: [me], trusted: trusted) == .trusted)
        #expect(V.classify(auths: [encrypt], apps: [me], trusted: trusted) == .trusted)
        #expect(V.classify(auths: [change], apps: [], trusted: trusted) == .trusted) // ChangeACL: ask (never answered)
        #expect(V.classify(auths: [change], apps: [me], trusted: trusted) == .trusted)
        // Everything else.
        #expect(V.classify(auths: [decrypt], apps: nil, trusted: trusted) == .refused("item is open to any application ([\"\(decrypt)\"])"))
        #expect(V.classify(auths: [encrypt], apps: nil, trusted: trusted) == .refused("item is open to any application ([\"\(encrypt)\"])"))
        #expect(V.classify(auths: [decrypt], apps: [other], trusted: trusted) == .refused("item trusts another application ([\"\(decrypt)\"])"))
        #expect(V.classify(auths: [decrypt], apps: [me, other], trusted: trusted) == .refused("item trusts another application ([\"\(decrypt)\"])"))
        #expect(V.classify(auths: [decrypt], apps: [me, me], trusted: trusted) == .refused("item trusts another application ([\"\(decrypt)\"])"))
        #expect(V.classify(auths: [decrypt], apps: [], trusted: trusted) == .refused("item trusts another application ([\"\(decrypt)\"])"))
        #expect(V.classify(auths: [change], apps: nil, trusted: trusted) == .refused("item is open to any application ([\"\(change)\"])"))
        #expect(V.classify(auths: [change], apps: [other], trusted: trusted) == .refused("item trusts another application ([\"\(change)\"])"))
        #expect(V.classify(auths: [change], apps: [me, other], trusted: trusted) == .refused("item trusts another application ([\"\(change)\"])"))
        // Same path, another requirement, is another application (forgedChangeACL / forgedDecryptEncrypt).
        #expect(forgedID != me && forgedID.path == me.path)
        #expect(V.classify(auths: [decrypt], apps: [forgedID], trusted: trusted) == .refused("item trusts another application ([\"\(decrypt)\"])"))
        #expect(V.classify(auths: [change], apps: [forgedID], trusted: trusted) == .refused("item trusts another application ([\"\(change)\"])"))
        // Two trusted applications: exactly both, in any order.
        let two: Set<AppIdentity> = [me, other]
        #expect(V.classify(auths: [decrypt], apps: [other, me], trusted: two) == .trusted)
        #expect(V.classify(auths: [decrypt], apps: [me], trusted: two) == .refused("item trusts another application ([\"\(decrypt)\"])"))
        #expect(V.classify(auths: [change], apps: [other], trusted: two) == .trusted)

        // The subset rule belongs to the BARE ChangeACL entry only. An entry
        // bundling ChangeACL with a grant is a grant: with no applications it
        // is answered by a password prompt, not by this process, and must trust
        // exactly `trusted` like any grant.
        #expect(V.isChangeACLOnly([change]) && V.isChangeACLOnly([change, change]))
        #expect(!V.isChangeACLOnly([change, decrypt]) && !V.isChangeACLOnly([]) && !V.isChangeACLOnly([decrypt]))
        #expect(V.classify(auths: [change, decrypt], apps: [], trusted: trusted)
                    == .refused("item trusts another application ([\"\(change)\", \"\(decrypt)\"])"))
        #expect(V.classify(auths: [change, decrypt, encrypt], apps: [], trusted: trusted)
                    == .refused("item trusts another application ([\"\(change)\", \"\(decrypt)\", \"\(encrypt)\"])"))
        #expect(V.classify(auths: [change, encrypt], apps: [], trusted: trusted)
                    == .refused("item trusts another application ([\"\(change)\", \"\(encrypt)\"])"))
        #expect(V.classify(auths: [change, decrypt], apps: [other], trusted: trusted)
                    == .refused("item trusts another application ([\"\(change)\", \"\(decrypt)\"])"))
        #expect(V.classify(auths: [change, decrypt], apps: [me, other], trusted: trusted)
                    == .refused("item trusts another application ([\"\(change)\", \"\(decrypt)\"])"))
        #expect(V.classify(auths: [change, decrypt], apps: [me], trusted: two)
                    == .refused("item trusts another application ([\"\(change)\", \"\(decrypt)\"])"))
        // A bundled entry trusting exactly `trusted` grants nobody else anything...
        #expect(V.classify(auths: [change, encrypt], apps: [me], trusted: trusted) == .trusted)
        // ...but alone it is not Nazar's shape: the item needs a Decrypt AND an
        // Encrypt entry trusting exactly `trusted` (refusal, the whole-item rule).
        let own = [Entry(auths: [decrypt, "ACLAuthorizationSign"], apps: [me]), Entry(auths: [encrypt], apps: [me]),
                   Entry(auths: [change], apps: [])]
        #expect(V.refusal(of: own, trusted: trusted) == nil)
        #expect(V.refusal(of: own + FakeKeychainStore.managedEntries, trusted: trusted) == nil)
        #expect(V.refusal(of: [Entry(auths: [decrypt], apps: [me]), Entry(auths: [encrypt], apps: [me])], trusted: trusted) == nil)
        #expect(V.refusal(of: [Entry(auths: [decrypt, encrypt], apps: [me])], trusted: trusted) == nil)
        #expect(V.refusal(of: [Entry(auths: [change, encrypt], apps: [me])], trusted: trusted)
                    == "item has no Decrypt entry trusting this program")
        #expect(V.refusal(of: [Entry(auths: [change], apps: [])], trusted: trusted) == "item has no Decrypt entry trusting this program")
        #expect(V.refusal(of: [], trusted: trusted) == "item has no Decrypt entry trusting this program")
        #expect(V.refusal(of: [Entry(auths: [integrity], apps: nil)], trusted: trusted) == "item has no Decrypt entry trusting this program")
        #expect(V.refusal(of: [Entry(auths: [encrypt], apps: [me]), Entry(auths: [change], apps: [])], trusted: trusted)
                    == "item has no Decrypt entry trusting this program")
        #expect(V.refusal(of: [Entry(auths: [decrypt], apps: [me]), Entry(auths: [change], apps: [])], trusted: trusted)
                    == "item has no Encrypt entry trusting this program")
        // A planted entry: one prompt-only entry bundling everything.
        #expect(V.refusal(of: [Entry(auths: [change, decrypt, encrypt], apps: [])], trusted: trusted)
                    == "item trusts another application ([\"\(change)\", \"\(decrypt)\", \"\(encrypt)\"])")
        // Next to Nazar's own grants it is still refused (the first bad entry wins).
        #expect(V.refusal(of: own + [Entry(auths: [change, decrypt, encrypt], apps: [])], trusted: trusted)
                    == "item trusts another application ([\"\(change)\", \"\(decrypt)\", \"\(encrypt)\"])")
        // A grant to another application anywhere refuses the item.
        #expect(V.refusal(of: own + [Entry(auths: [decrypt], apps: [other])], trusted: trusted)
                    == "item trusts another application ([\"\(decrypt)\"])")
        #expect(V.refusal(of: own + [Entry(auths: [encrypt], apps: nil)], trusted: trusted)
                    == "item is open to any application ([\"\(encrypt)\"])")
        // Every hostile shape of the table is refused for the reason it says.
        for shape in HostileShape.all {
            #expect(V.refusal(of: shape.entries, trusted: trusted)?.contains(shape.reason) == true, "\(shape)")
        }
    }
}

// MARK: - TemporaryKeychain

@Suite(.serialized, .timeLimit(.minutes(1))) struct TemporaryKeychainTests {
    @Test func createsAPrivateFolderAndDestroyRemovesIt() throws {
        try requireKeychainDialogsOff()
        let before = userSearchList()
        let defaultBefore = userDefaultKeychain()
        let tk = try TemporaryKeychain()
        let dir = tk.dir
        var isDir: ObjCBool = false
        #expect(FileManager.default.fileExists(atPath: dir.path, isDirectory: &isDir) && isDir.boolValue)
        let mode = try FileManager.default.attributesOfItem(atPath: dir.path)[.posixPermissions] as? Int
        #expect(mode == 0o700)
        let path = keychainPath(tk.keychain)
        #expect(isInside(path, dir), "keychain \(path) outside \(dir.path)")
        #expect(!TemporaryKeychain.isUnderLibraryKeychains(dir))
        #expect(FileManager.default.fileExists(atPath: path))
        #expect(!userSearchList().contains(path))
        #expect(userSearchList() == before)
        #expect(userDefaultKeychain() == defaultBefore)
        #expect(userDefaultKeychain() != path)
        tk.destroy()
        #expect(!FileManager.default.fileExists(atPath: path))
        #expect(!FileManager.default.fileExists(atPath: dir.path))
        tk.destroy() // idempotent
        #expect(userSearchList() == before)
        #expect(userDefaultKeychain() == defaultBefore)
        try requireKeychainDialogsOff()
    }

    // Creating a temporary keychain turns Keychain dialogs off first, so a
    // process whose first Keychain call is this one can never show a dialog.
    @Test func turnsKeychainDialogsOffBeforeCreating() throws {
        let tk = try TemporaryKeychain()
        defer { tk.destroy() }
        var allowed: DarwinBoolean = true
        #expect(SecKeychainGetUserInteractionAllowed(&allowed) == errSecSuccess)
        #expect(allowed == false)
    }

    @Test func honoursTheGivenDirectory() throws {
        try requireKeychainDialogsOff()
        let base = FileManager.default.temporaryDirectory.appendingPathComponent("nzkc-given-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: base) }
        let tk = try TemporaryKeychain(directory: base)
        #expect(KeychainVault.realPath(tk.dir.path) == KeychainVault.realPath(base.path))
        #expect(isInside(keychainPath(tk.keychain), tk.dir))
        tk.destroy()
        #expect(!FileManager.default.fileExists(atPath: base.path))
    }

    // Hard rule (AGENTS.md): automation never creates a keychain under any
    // Library/Keychains folder. securityd treats one there like the login
    // keychain, and that machinery is what reaches the user's screen as a
    // SecurityAgent dialog. The guard sees the path as given and resolved along
    // its longest existing prefix (so through a symlink even when the folder
    // does not exist); nothing is created when it refuses, and this test itself
    // never creates a `Keychains` folder.
    @Test func refusesAnyLibraryKeychainsFolder() throws {
        try requireKeychainDialogsOff()
        let home = FileManager.default.temporaryDirectory.appendingPathComponent("nzhome-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: home) }
        let loginDir = home.appendingPathComponent("Library/Keychains")
        for dir in [loginDir, loginDir.appendingPathComponent("sub/deeper"), URL(fileURLWithPath: "/tmp/x/Library/Keychains"),
                    home.appendingPathComponent("Library/./Keychains"), home.appendingPathComponent("Library/x/../Keychains")] {
            #expect(TemporaryKeychain.isUnderLibraryKeychains(dir), "\(dir.path)")
            #expect(throws: PlatformError.self, "\(dir.path)") { try TemporaryKeychain(directory: dir) }
            #expect(!FileManager.default.fileExists(atPath: dir.path), "refusing must create nothing: \(dir.path)")
        }
        #expect(!FileManager.default.fileExists(atPath: home.path))
        // Through a symlink that hides the pair: `alias` -> <home>/Library (an
        // empty folder), and the asked-for folder is alias/Keychains, which
        // does not exist and is never created.
        let library = home.appendingPathComponent("Library")
        try FileManager.default.createDirectory(at: library, withIntermediateDirectories: true)
        let alias = FileManager.default.temporaryDirectory.appendingPathComponent("nzalias-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: alias) }
        try FileManager.default.createSymbolicLink(at: alias, withDestinationURL: library)
        let hidden = alias.appendingPathComponent("Keychains")
        #expect(!hidden.standardizedFileURL.pathComponents.contains("Library"), "the symlink must hide the pair")
        #expect(TemporaryKeychain.isUnderLibraryKeychains(hidden))
        #expect(throws: PlatformError.self) { try TemporaryKeychain(directory: hidden) }
        #expect(try FileManager.default.contentsOfDirectory(atPath: library.path) == [], "refusing must create nothing")
        // Look-alikes are fine: the folder pair must be exactly Library/Keychains.
        for ok in [home.appendingPathComponent("Library/NotKeychains"), home.appendingPathComponent("Keychains/Library"),
                   home.appendingPathComponent("LibraryKeychains"), library, home.appendingPathComponent("plain"),
                   alias] {
            #expect(!TemporaryKeychain.isUnderLibraryKeychains(ok), "\(ok.path)")
        }
        let tk = try TemporaryKeychain(directory: home.appendingPathComponent("plain"))
        #expect(isInside(keychainPath(tk.keychain), home.appendingPathComponent("plain")))
        tk.destroy()
    }

    @Test func twoKeychainsAreDistinct() throws {
        try requireKeychainDialogsOff()
        let a = try TemporaryKeychain()
        defer { a.destroy() }
        let b = try TemporaryKeychain()
        defer { b.destroy() }
        #expect(a.dir != b.dir)
        #expect(keychainPath(a.keychain) != keychainPath(b.keychain))
    }

    @Test func deinitCleansUp() throws {
        try requireKeychainDialogsOff()
        func make() throws -> (URL, String) {
            let tk = try TemporaryKeychain()
            return (tk.dir, keychainPath(tk.keychain))
        }
        let (dir, path) = try make()
        #expect(!FileManager.default.fileExists(atPath: path))
        #expect(!FileManager.default.fileExists(atPath: dir.path))
    }
}
