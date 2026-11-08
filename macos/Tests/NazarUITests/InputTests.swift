import Foundation
import Testing
@testable import NazarUI

// CLIInput, the one way a value reaches the CLI (on its stdin).
@Suite struct InputTests {
    /// Printing, interpolating, reflecting or dumping an input shows none of its bytes.
    @Test func inputIsHidden() {
        let input = CLIInput("s3cret-m11")
        var dumped = ""
        dump(input, to: &dumped)
        for s in [String(describing: input), "\(input)", String(reflecting: input), dumped] {
            #expect(!s.contains("s3cret"), "\(s.count) characters")
        }
        #expect(Mirror(reflecting: input).children.isEmpty)
    }

    /// drain reads the bytes once and wipes them; wipe leaves nothing to read.
    @Test func drainReadsOnceThenWipes() {
        let input = CLIInput("abc é")
        #expect(!input.isWiped)
        #expect(input.drain { Data($0) } == Data("abc é".utf8))
        #expect(input.isWiped && input.drain { $0.count } == 0)
        // A String bridged from AppKit (NSString) is copied byte for byte too.
        let bridged = CLIInput(NSString(string: "brïdged") as String)
        #expect(bridged.drain { Data($0) } == Data("brïdged".utf8) && bridged.isWiped)
        let other = CLIInput("xyz")
        other.wipe()
        #expect(other.isWiped && other.drain { $0.count } == 0)
    }

    /// Input goes only to an action that reads stdin (secret add, the only
    /// one): for any other, nothing runs and the input is wiped.
    @Test func inputOnlyGoesToACommandThatReadsIt() async {
        let fake = FakeCLIRunner()
        fake.on(["status"], CLIResult(exitCode: 0))
        let client = CLIClient(runner: fake)
        for a in UIAction.samples where !a.readsInput {
            let input = CLIInput("s3cret")
            let out = await client.call(a, input: input)
            #expect(out.problem?.code == "usage" && input.isWiped, "\(a)")
        }
        #expect(fake.calls.isEmpty)
        _ = await client.call(.status)
        #expect(fake.calls == [["--json", "status"]] && fake.inputs == [nil])
    }
}
