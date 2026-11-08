import Foundation

/// One stdout object of the CLI: its kind and its bytes, decoded on demand.
public struct CLIObject: Equatable, Sendable {
    public var kind: String
    public var data: Data

    public func decode<T: Decodable>(_ t: T.Type) -> T? { try? CLIJSON.decoder().decode(t, from: data) }

    /// Parses one stdout line: a JSON object with apiVersion nazar/v1 and a
    /// kind, or nil.
    public static func parse(_ line: Data) -> CLIObject? {
        guard let meta = try? JSONDecoder().decode(TypeMeta.self, from: line), meta.apiVersion == apiVersion,
              !meta.kind.isEmpty else { return nil }
        return CLIObject(kind: meta.kind, data: line)
    }
}

/// How a command ended, by the CLI's stable exit codes (spec 6): 0 ok,
/// 1 error, 2 usage, 3 refused (the gate wasn't passed), 4 staged (waiting
/// for approval), 5 Nazar.app isn't running.
public enum CLIOutcome: Equatable, Sendable {
    case ok([CLIObject])
    case staged([CLIObject])
    case refused(Problem)
    case unavailable(Problem)
    case failed(Problem)

    public var objects: [CLIObject] {
        switch self {
        case .ok(let o), .staged(let o): return o
        default: return []
        }
    }

    /// The first object of kind, decoded.
    public func first<T: Decodable>(_ kind: String, as t: T.Type) -> T? {
        objects.first { $0.kind == kind }?.decode(t)
    }

    /// The problem to show, if the command did not succeed.
    public var problem: Problem? {
        switch self {
        case .refused(let p), .unavailable(let p), .failed(let p): return p
        default: return nil
        }
    }
}

/// Runs UIActions through a CLIRunner and classifies the result.
public final class CLIClient: Sendable {
    public let runner: CLIRunner
    public init(runner: CLIRunner) { self.runner = runner }

    /// Runs action; input goes to its stdin, and only to an action that
    /// reads stdin (readsInput). When the two disagree nothing runs and the
    /// input is wiped.
    public func call(_ action: UIAction, input: CLIInput? = nil) async -> CLIOutcome {
        guard action.readsInput == (input != nil) else {
            input?.wipe()
            return .failed(Problem(code: "usage", message: action.readsInput
                ? "nazar \(action.template.dropFirst().prefix(2).joined(separator: " ")) needs its value"
                : "this command reads nothing on stdin"))
        }
        return Self.outcome(await runner.run(action.argv, input: input))
    }

    /// Starts a --follow action; onObject runs on a background queue.
    public func follow(_ action: UIAction, onObject: @escaping @Sendable (CLIObject) -> Void,
                       onExit: @escaping @Sendable (Int32) -> Void) -> CLIStream {
        runner.stream(action.argv, onLine: { line in
            if let o = CLIObject.parse(line) { onObject(o) }
        }, onExit: onExit)
    }

    /// Classifies a finished run. A Problem object (the CLI prints one on
    /// stdout with --json) gives the message; without one, stderr does.
    public static func outcome(_ r: CLIResult) -> CLIOutcome {
        var objects: [CLIObject] = []
        var bad = false
        for line in r.stdout.split(separator: 0x0A, omittingEmptySubsequences: true) {
            if let o = CLIObject.parse(Data(line)) { objects.append(o) } else { bad = true }
        }
        let problem = objects.last { $0.kind == Kind.problem }?.decode(Problem.self)
            ?? Problem(code: "error", message: r.stderr.isEmpty ? "nazar exited with status \(r.exitCode)" : r.stderr)
        switch r.exitCode {
        case 0 where !bad: return .ok(objects)
        case 0: return .failed(Problem(code: "error", message: "nazar printed something that is not a nazar/v1 object"))
        case 3: return .refused(problem)
        case 4: return .staged(objects)
        case 5: return .unavailable(problem)
        default: return .failed(problem)
        }
    }
}
