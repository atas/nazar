#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")"
APP=~/.nazar/spike/S2.app
# Build products live under a per-group scratch path during the spike run; default to the
# plan's path, override with S1ENCLAVE_BIN=/path/to/S1Enclave.
BIN="${S1ENCLAVE_BIN:-../swift/.build/debug/S1Enclave}"
rm -rf "$APP"; mkdir -p "$APP/Contents/MacOS"
cp "$BIN" "$APP/Contents/MacOS/S1Enclave"
cat > "$APP/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>CFBundleIdentifier</key><string>dev.nazar.spike.s2</string>
  <key>CFBundleName</key><string>NazarSpikeS2</string>
  <key>CFBundleExecutable</key><string>S1Enclave</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>LSUIElement</key><true/>
</dict></plist>
PLIST
codesign --force --sign - "$APP"
echo "built $APP"
