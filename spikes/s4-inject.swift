import CoreGraphics
import Foundation

// usage: swift s4-inject.swift <LETTER> <mode> [targetPID]
//   mode = hid      -> CGEventSource(.hidSystemState), post to .cghidEventTap
//          private  -> CGEventSource(.privateState),   post to .cghidEventTap
//          forge    -> like hid, but also force eventSourceUnixProcessID=0 and
//                      eventSourceStateID=1 on the event, to try to look like hardware
//          session  -> hidSystemState, post to .cgSessionEventTap
//          pid      -> hidSystemState, post straight to the S4 process (postToPid targetPID)
//
// This is a forging attempt: it is the only way to show whether a
// synthetic press can be made to carry sourcePID==0 (the field S4Confirm trusts). Running it
// is a USER step: posting to .cghidEventTap needs Accessibility (TCC) granted to the posting
// app, and will otherwise be dropped or prompt. Never run unattended.
let codes: [Character: CGKeyCode] = ["A": 0, "S": 1, "D": 2, "F": 3, "H": 4, "G": 5, "Z": 6, "X": 7, "C": 8,
    "V": 9, "B": 11, "Q": 12, "W": 13, "E": 14, "R": 15, "Y": 16, "T": 17, "U": 32, "P": 35, "L": 37,
    "J": 38, "K": 40, "N": 45, "M": 46]

let letter = Character(CommandLine.arguments[1].uppercased())
let mode = CommandLine.arguments.count > 2 ? CommandLine.arguments[2] : "hid"
let targetPID = CommandLine.arguments.count > 3 ? Int32(CommandLine.arguments[3]) ?? -1 : -1
let code = codes[letter]!

let stateID: CGEventSourceStateID = (mode == "private") ? .privateState : .hidSystemState
let tap: CGEventTapLocation = (mode == "session") ? .cgSessionEventTap : .cghidEventTap

// Note: "pid" mode with a missing or non-positive targetPID previously fell through to
// the else branch and posted to .cghidEventTap, i.e. into whatever app was frontmost. Refuse
// instead of injecting into an unintended target during the attended run.
if mode == "pid" && targetPID <= 0 {
    print("mode=pid requires a positive targetPID; refusing to post to the frontmost app"); exit(2)
}

sleep(3)  // time to bring the S4 panel to the front

let src = CGEventSource(stateID: stateID)
guard let down = CGEvent(keyboardEventSource: src, virtualKey: code, keyDown: true),
      let up = CGEvent(keyboardEventSource: src, virtualKey: code, keyDown: false) else {
    print("could not create events"); exit(1)
}

if mode == "forge" {
    // Try to make a synthetic event claim to be hardware.
    for e in [down, up] {
        e.setIntegerValueField(.eventSourceUnixProcessID, value: 0)
        e.setIntegerValueField(.eventSourceStateID, value: 1)   // kCGEventSourceStateHIDSystemState
    }
}

if mode == "pid", targetPID > 0 {
    down.postToPid(pid_t(targetPID))
    up.postToPid(pid_t(targetPID))
} else {
    down.post(tap: tap)
    up.post(tap: tap)
}
let tapLabel = mode == "pid" ? "pid=\(targetPID)" : (mode == "session" ? "session" : "hid")
print("posted \(letter) mode=\(mode) stateID=\(stateID == .hidSystemState ? "hid" : "private") tap=\(tapLabel)")
