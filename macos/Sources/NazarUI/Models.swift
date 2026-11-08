import Foundation

// The objects `nazar --json` prints (core/control/api.go, spec 6): every
// line is one object with apiVersion nazar/v1 and a kind. The fields are
// the ones the window uses; unknown fields are ignored, so an older window
// keeps working when the CLI adds one, and a renamed or retyped field fails
// FixtureTests (the fixtures come from the real CLI's encoders,
// cmd/nazar/uicontract_test.go).

public let apiVersion = "nazar/v1"

public enum Kind {
    public static let sshKey = "SSHKey"
    public static let sshKeyList = "SSHKeyList"
    public static let sshKeyRules = "SSHKeyRules"
    public static let approval = "Approval"
    public static let status = "Status"
    public static let configCheck = "ConfigCheck"
    public static let configDiff = "ConfigDiff"
    public static let configEdit = "ConfigEdit"
    public static let appList = "AppList"
    public static let revokeResult = "RevokeResult"
    public static let auditEvent = "AuditEvent"
    public static let secret = "Secret"
    public static let secretList = "SecretList"
    public static let k8sContext = "K8sContext"
    public static let k8sContextList = "K8sContextList"
    public static let problem = "Problem"
}

/// Every object's header.
public struct TypeMeta: Decodable, Equatable, Sendable {
    public var apiVersion: String
    public var kind: String
}

public struct Problem: Decodable, Equatable, Sendable {
    public var code: String
    public var message: String
    public var details: [String]?
    public init(code: String, message: String, details: [String]? = nil) {
        self.code = code
        self.message = message
        self.details = details
    }
}

public struct MatcherInfo: Decodable, Equatable, Sendable {
    public var name: String?
    public var kind: String
    public var team: String?
    public var id: String?
    public var path: String?
    public var command: [String]?
    public var ref: String
}

public struct PolicyInfo: Decodable, Equatable, Sendable {
    public var scope: String
    public var gate: String
    public var expire: String?
    public init(scope: String, gate: String, expire: String? = nil) {
        self.scope = scope
        self.gate = gate
        self.expire = expire
    }
}

public struct RuleInfo: Decodable, Equatable, Sendable {
    public var index: Int
    public var apps: [MatcherInfo]
    public var to: [MatcherInfo]
    public var policy: PolicyInfo
}

public struct SSHKeyRules: Decodable, Equatable, Sendable {
    public var name: String
    public var configured: Bool
    public var staged: Bool
    public var configHash: String
    public var rules: [RuleInfo]
    public var own: PolicyInfo?
    public var fallback: PolicyInfo
    public var fallbackSource: String
}

public struct KeyUse: Decodable, Equatable, Sendable {
    public var time: Date
    public var decision: String
    public var app: String?
    public var chain: String?
}

public struct SSHKey: Decodable, Equatable, Sendable, Identifiable {
    public var name: String
    public var type: String?
    public var fingerprint: String?
    public var publicKey: String?
    public var broken: Bool
    /// Whether the chip asks for the user's authentication on every use
    /// (`ssh-key create --always-ask`), from the key's creation-time vault
    /// record.
    public var userPresence: Bool
    /// Whether the chip lets the key sign while the Mac is locked too
    /// (false for `--only-when-unlocked`, `--always-ask` and keys made
    /// before nazar knew the difference), from its vault record.
    public var whileLocked: Bool
    public var configured: Bool
    public var created: Date
    public var usable: Bool
    public var unusableReason: String?
    public var remedy: String?
    public var warnings: [String]
    public var lastUsed: KeyUse?
    public var policy: SSHKeyRules?
    public var id: String { name }
}

public struct SSHKeyList: Decodable, Equatable, Sendable {
    public var items: [SSHKey]
    public var since: Date
}

public struct Approval: Decodable, Equatable, Sendable {
    public var event: String?
    public var reason: String?
    public var target: String
    public var rule: String
    public var scope: String
    public var scopeId: String
    public var receiver: String?
    /// What the approval covers (Milestone 7): `op` as the core keys it,
    /// `covers` as shown ("github.com", "git commits and tags").
    public var op: String
    public var covers: String
    public var chain: String
    public var app: String?
    public var created: Date
    public var expires: Date?

    /// What identifies one remembered approval (approval.Key in the core).
    public var identity: String { [target, rule, scopeId, receiver ?? "", op].joined(separator: "\u{1F}") }
}

public struct ConfigDiff: Decodable, Equatable, Sendable {
    public var hash: String
    public var loosens: Bool
    public var applied: Bool
    public var changes: [String]
    public var loosening: [String]?
}

public struct ConfigProblem: Decodable, Equatable, Sendable {
    public var severity: String
    public var path: String?
    public var line: Int?
    public var message: String
}

public struct VaultProblem: Decodable, Equatable, Sendable {
    public var item: String
    public var reason: String
    public var effect: String
    public var remedy: String
}

public struct Status: Decodable, Equatable, Sendable {
    public var activeHash: String
    public var staged: ConfigDiff?
    public var problems: [ConfigProblem]?
    public var vault: [VaultProblem]?
    public var approvals: [Approval]
    public var agentSocket: String
    /// What the CLI found wrong on the client side: a host of
    /// ~/.ssh/config not wired to nazar, git's signing program or key, keys
    /// another agent holds; each message ends with its fix. Absent when all
    /// is well.
    public var setup: [ConfigProblem]?
}

public struct ConfigCheck: Decodable, Equatable, Sendable {
    public var path: String
    public var valid: Bool
    public var problems: [ConfigProblem]
    public var staged: ConfigDiff?
}

public struct ConfigEdit: Decodable, Equatable, Sendable {
    public var op: String
    public var key: String
    /// The secret a `secret rule` edit changed; `key` is then empty.
    public var secret: String?
    /// The context a `k8s rule` edit changed; `key` is then empty.
    public var context: String?
    public var path: String
    public var hash: String
    public var changed: Bool
    public var applied: Bool
    public var staged: ConfigDiff?
    public var problems: [ConfigProblem]
}

public struct AppEntry: Decodable, Equatable, Sendable, Identifiable {
    public var name: String
    public var matcher: MatcherInfo
    public var pinnedTeam: String?
    public var problem: String?
    public var fix: String?
    public var usedBy: [String]
    public var id: String { name.isEmpty ? "inline:" + matcher.ref : "name:" + name }
}

public struct AppList: Decodable, Equatable, Sendable {
    public var staged: Bool
    public var configHash: String
    public var items: [AppEntry]
}

public struct RevokeResult: Decodable, Equatable, Sendable {
    public var revoked: Int
}

/// A secret as `nazar --json secret list` shows it: never a value (the
/// CLI has none to give the window).
public struct Secret: Decodable, Equatable, Sendable, Identifiable {
    public var name: String
    public var created: Date?
    public var deliver: [String]
    public var configured: Bool
    public var stored: Bool
    /// Whether the secret's key works while the Mac is locked too (as
    /// SSHKey.whileLocked); false when no value is stored.
    public var whileLocked: Bool
    public var broken: Bool
    public var unusableReason: String?
    public var remedy: String?
    public var warnings: [String]
    public var policy: SSHKeyRules?
    public var id: String { name }
}

public struct SecretList: Decodable, Equatable, Sendable {
    public var items: [Secret]
}

/// The cluster a context is pinned to: its server, and the TLS server name
/// and proxy when set (the cluster CA's hash is not decoded: the page doesn't
/// show it).
public struct K8sCluster: Decodable, Equatable, Sendable {
    public var server: String
    public var tlsServerName: String?
    public var proxyURL: String?
}

/// A context's CA, its public facts only (no certificate, no file path).
public struct K8sCA: Decodable, Equatable, Sendable {
    public var fingerprint: String
    public var created: Date
    public var notAfter: Date
    /// Whether the CA signs while the Mac is locked too (as SSHKey.whileLocked).
    public var whileLocked: Bool
}

/// Who the certificates nazar mints name: the user (CN) and groups (O).
public struct K8sIdentity: Decodable, Equatable, Sendable {
    public var user: String
    public var groups: [String]
}

/// A Kubernetes context as `nazar --json k8s list` shows it: public facts
/// only (the CA's fingerprint and dates, the cluster pin, the identity, the
/// rules); the CLI has no key, certificate or kubeconfig content to give
/// the window.
public struct K8sContext: Decodable, Equatable, Sendable, Identifiable {
    public var name: String
    public var configured: Bool
    public var identity: K8sIdentity?
    public var ttlCert: String?
    public var cluster: K8sCluster?
    public var ca: K8sCA?
    public var caBroken: Bool
    public var unusableReason: String?
    public var remedy: String?
    /// ok | no-entry | no-ca | ca-unusable | absent.
    public var state: String
    /// nil without a config.yaml entry (a CA alone): no rule editor.
    public var policy: SSHKeyRules?
    public var warnings: [String]
    public var id: String { name }
}

public struct K8sContextList: Decodable, Equatable, Sendable {
    public var items: [K8sContext]
}

/// One audit line (`nazar log --json`): its time and its parsed fields
/// (decision, reason, target, rule, scope, gate, app, chain, …). Every
/// field is caller-controlled text from the audit log: show it with
/// PlainText only.
public struct AuditEvent: Decodable, Equatable, Sendable {
    public var time: Date
    public var fields: [String: String]
}

/// One line of the Activity list: an event, and how many blocked events just
/// like it came in a row. Only the window folds; `nazar log` shows every line.
public struct ActivityLine: Equatable, Sendable {
    public var event: AuditEvent // the newest of the run
    public var count = 1
    public var oldest: Date

    /// Folds neighbours, newest first, into one line. Only `blocked` lines
    /// fold: one kubectl or ssh makes several, and a caller that retries makes
    /// many. Two fold when every field is the same but the session and the
    /// process ids in the chain, which each new run changes, so any other
    /// difference (the target, the reason, the program, the folder) stays on
    /// a line of its own.
    public static func fold(_ events: [AuditEvent]) -> [ActivityLine] {
        var lines: [ActivityLine] = []
        for e in events {
            if let last = lines.last, last.event.fields["decision"] == "blocked", foldKey(last.event) == foldKey(e) {
                lines[lines.count - 1].count += 1
                lines[lines.count - 1].oldest = e.time
            } else {
                lines.append(ActivityLine(event: e, oldest: e.time))
            }
        }
        return lines
    }

    private static func foldKey(_ e: AuditEvent) -> [String: String] {
        var f = e.fields
        f["session"] = nil
        f["chain"] = f["chain"]?.replacingOccurrences(of: #"\(\d+"#, with: "(", options: .regularExpression)
        return f
    }
}

/// The decoder for CLI output: Go's time.Time is RFC 3339 with up to nine
/// fractional digits.
public enum CLIJSON {
    public static func decoder() -> JSONDecoder {
        let d = JSONDecoder()
        d.dateDecodingStrategy = .custom { dec in
            let c = try dec.singleValueContainer()
            let s = try c.decode(String.self)
            if let t = try? Date(s, strategy: Date.ISO8601FormatStyle(includingFractionalSeconds: true)) { return t }
            if let t = try? Date(s, strategy: Date.ISO8601FormatStyle()) { return t }
            throw DecodingError.dataCorruptedError(in: c, debugDescription: "not an RFC 3339 time: \(s)")
        }
        return d
    }
}
