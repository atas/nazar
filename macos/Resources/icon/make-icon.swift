// Draws Nazar's app icon (a nazar boncuk: dark blue, white, light blue,
// black rings on a rounded square) as a 1024 px PNG. Run by
// macos/Resources/icon/make-icon.sh; nothing is put on screen.
import AppKit

let size = 1024.0
let out = CommandLine.arguments[1]
guard let rep = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: Int(size), pixelsHigh: Int(size),
                                 bitsPerSample: 8, samplesPerPixel: 4, hasAlpha: true, isPlanar: false,
                                 colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0),
      let ctx = NSGraphicsContext(bitmapImageRep: rep) else { fatalError("no bitmap") }
NSGraphicsContext.current = ctx
func rgb(_ r: Double, _ g: Double, _ b: Double) -> NSColor { NSColor(deviceRed: r / 255, green: g / 255, blue: b / 255, alpha: 1) }

// The macOS icon grid: an 824 px rounded square centred in 1024.
let tile = NSRect(x: 100, y: 100, width: 824, height: 824)
let shape = NSBezierPath(roundedRect: tile, xRadius: 185, yRadius: 185)
NSGradient(starting: rgb(250, 250, 252), ending: rgb(222, 228, 238))!.draw(in: shape, angle: -90)

let c = NSPoint(x: size / 2, y: size / 2)
func disc(_ r: Double, _ color: NSColor) {
    color.setFill()
    NSBezierPath(ovalIn: NSRect(x: c.x - r, y: c.y - r, width: 2 * r, height: 2 * r)).fill()
}
disc(330, rgb(16, 52, 166))   // dark blue
disc(222, rgb(255, 255, 255)) // white
disc(150, rgb(84, 172, 236))  // light blue
disc(78, rgb(12, 14, 22))     // black pupil
// A soft highlight on the glass.
NSColor(white: 1, alpha: 0.35).setFill()
NSBezierPath(ovalIn: NSRect(x: c.x - 245, y: c.y + 160, width: 100, height: 64)).fill()

NSGraphicsContext.current = nil
try! rep.representation(using: .png, properties: [:])!.write(to: URL(fileURLWithPath: out))
