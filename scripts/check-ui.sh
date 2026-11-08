#!/bin/bash
# check-ui.sh <Nazar UI.app> [<nazar-agent.app>] — checks a built Nazar
# UI.app without starting it (spec 6.1, Milestone 6). Nazar UI.app is an
# ordinary app (a Dock icon while open, no menu bar item, nothing in the
# background) that runs the nazar CLI and nothing else: it ships no CLI of
# its own, holds no Go core and calls no Keychain API. An ad-hoc build
# pins the cdhash of the one CLI build it runs; given the agent bundle, the
# pin must be that bundle's CLI.
set -euo pipefail
app=${1:?usage: check-ui.sh <Nazar UI.app> [<nazar-agent.app>]}
agent=${2:-}
fail() { echo "check-ui: $*" >&2; exit 1; }
plist="$app/Contents/Info.plist"
exe="$app/Contents/MacOS/NazarUI"
[ -f "$plist" ] || fail "no Info.plist"
key() { /usr/bin/plutil -extract "$1" raw -expect "$2" -o - "$plist" 2>/dev/null || true; }
has() { /usr/bin/plutil -extract "$1" raw -o - "$plist" >/dev/null 2>&1; }
[ "$(key CFBundleIdentifier string)" = dev.nazar.ui ] || fail "CFBundleIdentifier is not dev.nazar.ui"
[ "$(key CFBundleExecutable string)" = NazarUI ] || fail "CFBundleExecutable is not NazarUI"
[ "$(key LSMinimumSystemVersion string)" = 26.0 ] || fail "LSMinimumSystemVersion is not 26.0"
# A regular app: never an agent or background-only app (no Dock icon while
# open, or no UI at all), never launched at login by its own plist.
for k in LSUIElement LSBackgroundOnly; do
    if has "$k"; then fail "Info.plist has $k (Nazar UI is a regular app)"; fi
done
[ -f "$exe" ] && [ ! -L "$exe" ] && [ -x "$exe" ] || fail "no Contents/MacOS/NazarUI"
extra=$(cd "$app/Contents/MacOS" && ls -A | grep -vxE 'NazarUI' || true)
[ -z "$extra" ] || fail "unexpected file in Contents/MacOS: $(echo $extra) (Nazar UI ships no CLI and no helper)"
for d in Library/LoginItems Library/LaunchAgents Library/LaunchDaemons XPCServices Helpers; do
    [ ! -e "$app/Contents/$d" ] || fail "Contents/$d: Nazar UI runs nothing in the background"
done
# Nothing else may live in the bundle: no framework, plug-in or helper
# (nested code codesign --deep would happily verify) and nothing runnable
# among the resources.
extra=$(cd "$app/Contents" && ls -A | grep -vxE 'Info\.plist|PkgInfo|MacOS|Resources|_CodeSignature' || true)
[ -z "$extra" ] || fail "unexpected entry in Contents: $(echo $extra) (Nazar UI ships no framework, plug-in or helper)"
# (-quit: find stops at the first hit. Piped into grep -q, a long listing
# dies of SIGPIPE and under pipefail an `if` on it passes silently.)
if [ -d "$app/Contents/Resources" ] &&
    [ -n "$(find "$app/Contents/Resources" -type f \( -perm -u+x -o -perm -g+x -o -perm -o+x \) -print -quit)" ]; then
    fail "executable file in Contents/Resources (Nazar UI ships no CLI and no helper)"
fi
/usr/bin/codesign --verify --strict --deep "$app" || fail "codesign --verify failed"
sig=$(/usr/bin/codesign -dvv "$app" 2>&1) || fail "Nazar UI is not signed"
grep -qxF "Identifier=dev.nazar.ui" <<<"$sig" || fail "signing identifier is not dev.nazar.ui"
grep -qxF 'Signature=adhoc' <<<"$sig" || fail "Nazar UI is not ad-hoc signed (automation never uses a real identity)"
grep -q 'flags=0x10002(adhoc,runtime)' <<<"$sig" || fail "Nazar UI lacks the hardened runtime"
ent=$(/usr/bin/codesign -d --entitlements - --xml "$app" 2>/dev/null) || fail "cannot read entitlements"
if grep -q '<key>' <<<"$ent"; then fail "Nazar UI has entitlements"; fi
/usr/bin/dwarfdump --uuid "$exe" | grep -q 'arm64' || fail "NazarUI has no arm64 LC_UUID"
libs=$(/usr/bin/otool -L "$exe" | tail -n +2) || fail "otool -L NazarUI failed"
if grep -vE '^[[:space:]]+(/usr/lib/|/System/Library/)' <<<"$libs" || grep -q '/\.\./' <<<"$libs"; then
    fail "NazarUI links a non-system library"
fi
syms=$(/usr/bin/nm -u "$exe" 2>/dev/null) || fail "nm -u NazarUI failed"
if grep -qE '_OBJC_CLASS_\$_(NSStatusBar|NSStatusItem)$|MenuBarExtra' <<<"$syms"; then fail "Nazar UI has a menu bar item (NSStatusBar or MenuBarExtra)"; fi
if grep -qE '^[[:space:]]*_(SecItem|SecKeychain|SecTrustedApplication|SecAccess)' <<<"$syms"; then fail "Nazar UI calls a Keychain API"; fi
if grep -qE '_OBJC_CLASS_\$_SMAppService$|_SMLoginItemSetEnabled$|_LSSharedFileList' <<<"$syms"; then fail "Nazar UI registers a login item"; fi
defined=$(/usr/bin/nm -U "$exe" 2>/dev/null) || fail "nm -U NazarUI failed"
if grep -qE '[[:space:]]_Nazar(CoreStart|CoreStop|ProcessExited|ScreenLocked)$' <<<"$defined"; then fail "Nazar UI contains the Go core"; fi
# The dev pin: an ad-hoc build trusts exactly one CLI build.
pin=$(key NazarDevCLICDHash string)
[[ "$pin" =~ ^[0-9a-f]{40}$ ]] || fail "an ad-hoc Nazar UI pins no CLI build (NazarDevCLICDHash)"
if [ -n "$agent" ]; then
    want=$(/usr/bin/codesign -dvvv "$agent/Contents/MacOS/nazar" 2>&1 | sed -n 's/^CDHash=//p')
    [ -n "$want" ] || fail "no CLI in $agent"
    [ "$pin" = "$want" ] || fail "Nazar UI pins another CLI build ($pin, not $agent's $want)"
fi
# The app's sources never use the test stand-ins, nor a menu bar item.
src="$(dirname "$0")/../macos/Sources/NazarUIApp"
compgen -G "$src/*.swift" >/dev/null || fail "no NazarUIApp sources in $src"
rc=0
grep -nE 'FakeCLIRunner|dev\.nazar\.test|NSStatusBar|NSStatusItem|MenuBarExtra|SMAppService|LSUIElement|setActivationPolicy' "$src"/*.swift || rc=$?
case $rc in
    0) fail "NazarUIApp sources use a test stand-in or a background or menu bar item" ;;
    1) ;;
    *) fail "cannot read the NazarUIApp sources" ;;
esac
echo "check-ui: $app OK"
