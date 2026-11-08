#!/bin/bash
# Regenerates macos/Resources/AppIcon.icns from make-icon.swift.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
swift "$here/make-icon.swift" "$tmp/1024.png"
set=$tmp/AppIcon.iconset; mkdir "$set"
for s in 16 32 128 256 512; do
  sips -z $s $s "$tmp/1024.png" --out "$set/icon_${s}x${s}.png" >/dev/null
  sips -z $((s*2)) $((s*2)) "$tmp/1024.png" --out "$set/icon_${s}x${s}@2x.png" >/dev/null
done
iconutil -c icns "$set" -o "$here/../AppIcon.icns"
echo "wrote $(cd "$here/.." && pwd)/AppIcon.icns"
