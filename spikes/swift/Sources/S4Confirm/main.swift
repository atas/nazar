import AppKit
import Carbon

// Note: the spike runs `S4Confirm | tee ~/.nazar/spike/s4.log`; stdout is block-buffered
// to a pipe/file, so the log stays empty while the panel is up. Line-buffer it.
setvbuf(stdout, nil, _IOLBF, 0)

let letters = Array("ABCDEFGHJKLMNPQRSTUVWXYZ")
let target = letters.randomElement()!
let app = NSApplication.shared
app.setActivationPolicy(.accessory)

let panel = NSPanel(contentRect: NSRect(x: 0, y: 0, width: 460, height: 140),
                    styleMask: [.titled], backing: .buffered, defer: false)
panel.title = "S4 confirm spike"
let label = NSTextField(labelWithString: "Press \(target) to allow   (Esc quits)")
label.font = .systemFont(ofSize: 22)
label.frame = NSRect(x: 20, y: 50, width: 420, height: 40)
panel.contentView?.addSubview(label)
panel.center()

NSEvent.addLocalMonitorForEvents(matching: [.keyDown]) { event in
    let cg = event.cgEvent
    let sourcePID = cg?.getIntegerValueField(.eventSourceUnixProcessID) ?? -1
    let sourceState = cg?.getIntegerValueField(.eventSourceStateID) ?? -1
    let key = event.charactersIgnoringModifiers?.uppercased() ?? ""
    print("key=\(key) keyCode=\(event.keyCode) sourcePID=\(sourcePID) sourceStateID=\(sourceState) " +
          "secureInput=\(IsSecureEventInputEnabled()) target=\(target) " +
          "→ \(sourcePID == 0 ? "HARDWARE?" : "SYNTHETIC?")")
    if event.keyCode == 53 { exit(0) }
    return nil
}

EnableSecureEventInput()
panel.makeKeyAndOrderFront(nil)
NSApp.activate()
print("S4 showing panel; target letter \(target)")
app.run()
