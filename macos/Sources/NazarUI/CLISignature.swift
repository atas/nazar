import Foundation
import Security

// Nazar UI.app runs the nazar CLI and nothing else (spec 6.1, Milestone 6),
// and only a CLI signed as nazar's own: identifier dev.nazar.cli, by the
// same team as Nazar UI.app itself. The UI is a client like any other (the
// agent trusts it with nothing), so the check protects the person reading
// the window from a program that is not nazar answering in nazar's place.

/// The code requirement a CLI must satisfy before the UI runs it.
public struct CLIRequirement: Equatable, Sendable, CustomStringConvertible {
    /// Requirement-language text, e.g. `identifier "dev.nazar.cli" and
    /// anchor apple generic and certificate leaf[subject.OU] = "TEAM"`.
    public let text: String
    public var description: String { text }

    public static let cliIdentifier = "dev.nazar.cli"
    /// The Info.plist key `make ui` writes into an ad-hoc build: the cdhash
    /// of the one CLI build that UI build runs (sealed by the UI's own
    /// signature, so it can't be edited without breaking it).
    public static let devPinKey = "NazarDevCLICDHash"

    public enum Problem: Error, Equatable, CustomStringConvertible {
        /// The UI is ad hoc and pins no CLI build: it trusts no CLI.
        case noRule
        case badTeam(String)
        case badPin(String)
        /// The UI's own signature can't be read or is not valid.
        case ownSignature(OSStatus)

        public var description: String {
            switch self {
            case .noRule: return "this Nazar UI is not signed by a team and pins no CLI build (\(CLIRequirement.devPinKey)), so it trusts no nazar CLI"
            case .badTeam(let t): return "invalid team identifier \(t.debugDescription)"
            case .badPin(let p): return "invalid \(CLIRequirement.devPinKey) \(p.debugDescription)"
            case .ownSignature(let st): return "can't read this app's own signature (\(st))"
            }
        }
    }

    /// The rule, from the UI's own signing team and its build's pin:
    ///
    /// - signed by a team (a release, or a developer's Apple Development
    ///   build): identifier dev.nazar.cli signed with an Apple-issued
    ///   certificate of that same team. The pin is ignored: a team build
    ///   never trusts by cdhash, so it is never weaker than the team rule.
    /// - ad hoc (`make ui`): exactly the CLI build whose cdhash `make ui`
    ///   pinned (identifier dev.nazar.cli and that cdhash).
    /// - ad hoc without a pin: no CLI at all.
    ///
    /// Both values are checked byte for byte before they reach requirement
    /// text, so neither can add a clause.
    public static func make(ownTeam: String?, devPin: String?) -> Result<CLIRequirement, Problem> {
        if let team = ownTeam {
            guard team.utf8.count == 10, team.utf8.allSatisfy({ isUpper($0) || isDigit($0) }) else { return .failure(.badTeam(team)) }
            return .success(CLIRequirement(text: "identifier \"\(cliIdentifier)\" and anchor apple generic and certificate leaf[subject.OU] = \"\(team)\""))
        }
        guard let pin = devPin else { return .failure(.noRule) }
        guard pin.utf8.count == 40, pin.utf8.allSatisfy({ isDigit($0) || (UInt8(ascii: "a")...UInt8(ascii: "f")).contains($0) }) else {
            return .failure(.badPin(pin))
        }
        return .success(CLIRequirement(text: "identifier \"\(cliIdentifier)\" and cdhash H\"\(pin)\""))
    }

    /// The rule for the running app: its own team (CodeSignature.ownTeam)
    /// and the pin in its Info.plist.
    public static func forThisApp(bundle: Bundle = .main) -> Result<CLIRequirement, Problem> {
        switch CodeSignature.ownTeam() {
        case .failure(let e): return .failure(.ownSignature(e.status))
        case .success(let team): return make(ownTeam: team, devPin: bundle.object(forInfoDictionaryKey: devPinKey) as? String)
        }
    }

    private static func isUpper(_ b: UInt8) -> Bool { (UInt8(ascii: "A")...UInt8(ascii: "Z")).contains(b) }
    private static func isDigit(_ b: UInt8) -> Bool { (UInt8(ascii: "0")...UInt8(ascii: "9")).contains(b) }

    /// The compiled requirement, or nil when the text does not parse.
    func compiled() -> SecRequirement? {
        var r: SecRequirement?
        guard SecRequirementCreateWithString(text as CFString, [], &r) == errSecSuccess else { return nil }
        return r
    }
}

/// A Security call's failure status.
public struct SignatureStatus: Error, Equatable, Sendable {
    public let status: OSStatus
}

/// The Security calls the UI makes, all on code signatures (no keychain).
public enum CodeSignature {
    /// This process's signing team, after checking that the running code is
    /// valid; nil when it is signed ad hoc.
    public static func ownTeam() -> Result<String?, SignatureStatus> {
        var me: SecCode?
        var st = SecCodeCopySelf([], &me)
        guard st == errSecSuccess, let me else { return .failure(SignatureStatus(status: st)) }
        st = SecCodeCheckValidity(me, [], nil)
        guard st == errSecSuccess else { return .failure(SignatureStatus(status: st)) }
        var sc: SecStaticCode?
        st = SecCodeCopyStaticCode(me, [], &sc)
        guard st == errSecSuccess, let sc else { return .failure(SignatureStatus(status: st)) }
        return info(sc).map { $0[kSecCodeInfoTeamIdentifier as String] as? String }
    }

    /// The signing information of sc.
    static func info(_ sc: SecStaticCode) -> Result<[String: Any], SignatureStatus> {
        var d: CFDictionary?
        let st = SecCodeCopySigningInformation(sc, SecCSFlags(rawValue: kSecCSSigningInformation), &d)
        guard st == errSecSuccess, let d = d as? [String: Any] else { return .failure(SignatureStatus(status: st)) }
        return .success(d)
    }

    /// The cdhash (lowercase hex) of the code at url, or nil when it has no
    /// valid signature. What `make ui` pins, computed the same way.
    public static func cdhash(of url: URL) -> String? {
        var sc: SecStaticCode?
        guard SecStaticCodeCreateWithPath(url as CFURL, [], &sc) == errSecSuccess, let sc,
              SecStaticCodeCheckValidity(sc, [], nil) == errSecSuccess,
              case .success(let i) = info(sc), let h = i[kSecCodeInfoUnique as String] as? Data else { return nil }
        return h.map { String(format: "%02x", $0) }.joined()
    }

    /// Why the file at url does not satisfy requirement (nil: it does).
    /// The check the locator makes before it offers a CLI; the runner checks
    /// the running process again (checkRunning).
    public static func checkFile(_ url: URL, _ requirement: CLIRequirement) -> String? {
        guard let req = requirement.compiled() else { return "the requirement does not parse" }
        var sc: SecStaticCode?
        var st = SecStaticCodeCreateWithPath(url as CFURL, [], &sc)
        guard st == errSecSuccess, let sc else { return "no code signature (\(st))" }
        st = SecStaticCodeCheckValidity(sc, SecCSFlags(rawValue: kSecCSCheckAllArchitectures), req)
        return st == errSecSuccess ? nil : explain(st)
    }

    /// Why the process pid (a child the caller started suspended and has not
    /// reaped, so the pid is its own) does not satisfy requirement (nil: it
    /// does). The kernel's view of the running code is checked, together
    /// with the file it was started from.
    public static func checkRunning(pid: pid_t, _ requirement: CLIRequirement) -> String? {
        guard let req = requirement.compiled() else { return "the requirement does not parse" }
        var code: SecCode?
        var st = SecCodeCopyGuestWithAttributes(nil, [kSecGuestAttributePid: pid] as CFDictionary, [], &code)
        guard st == errSecSuccess, let code else { return "can't identify the started process (\(st))" }
        st = SecCodeCheckValidity(code, [], req)
        return st == errSecSuccess ? nil : explain(st)
    }

    static func explain(_ st: OSStatus) -> String {
        switch st {
        case errSecCSReqFailed: return "not signed as \(CLIRequirement.cliIdentifier) by this app's developer"
        case errSecCSUnsigned: return "not signed"
        default:
            let msg = SecCopyErrorMessageString(st, nil) as String? ?? ""
            return msg.isEmpty ? "signature check failed (\(st))" : "\(msg) (\(st))"
        }
    }
}
