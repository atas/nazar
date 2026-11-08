#!/bin/bash
# check-agent.sh <nazar-agent.app> — checks a built agent bundle without
# starting it (Milestone 6). Never starts nazar-agent (it would use the
# login keychain and show real prompts); it only runs the bundled CLI's
# `version`. The agent is the background service: no menu bar item, no
# window of its own and no UI code (spec 4, 6.1); it carries nazar run's
# loaders.
set -euo pipefail
app=${1:?usage: check-agent.sh <nazar-agent.app>}
fail() { echo "check-agent: $*" >&2; exit 1; }
plist="$app/Contents/Info.plist"
exe="$app/Contents/MacOS/nazar-agent"
cli="$app/Contents/MacOS/nazar"
[ -f "$plist" ] || fail "no Info.plist"
key() { /usr/bin/plutil -extract "$1" raw -expect "$2" -o - "$plist" 2>/dev/null || true; }
[ "$(key CFBundleIdentifier string)" = dev.nazar.agent ] || fail "CFBundleIdentifier is not dev.nazar.agent"
[ "$(key CFBundleExecutable string)" = nazar-agent ] || fail "CFBundleExecutable is not nazar-agent"
[ "$(key LSUIElement bool)" = true ] || fail "LSUIElement is not true"
[ "$(key LSMinimumSystemVersion string)" = 26.0 ] || fail "LSMinimumSystemVersion is not 26.0"
# Regular files, never links: a link would let one file stand for both.
[ -f "$exe" ] && [ ! -L "$exe" ] && [ -x "$exe" ] || fail "no Contents/MacOS/nazar-agent"
[ -f "$cli" ] && [ ! -L "$cli" ] && [ -x "$cli" ] || fail "no bundled CLI at Contents/MacOS/nazar"
# Nothing else is shipped as code next to them.
extra=$(cd "$app/Contents/MacOS" && ls -A | grep -vxE 'nazar-agent|nazar' || true)
[ -z "$extra" ] || fail "unexpected file in Contents/MacOS: $(echo $extra)"
# Two different files (no hard link, no case-insensitive merge).
[ "$(stat -f %i "$exe")" != "$(stat -f %i "$cli")" ] || fail "agent and CLI are one file"
# nazar run's loaders (secrets design 6.3.1): exactly the
# repository's two files, plain files in plain folders; the seal below
# covers them. Nothing else may sit beside them: Python imports a module,
# an extension or cached bytecode beside its loader first.
ld="$app/Contents/Resources/loaders"
for d in "$ld" "$ld/node" "$ld/python"; do
    [ -d "$d" ] && [ ! -L "$d" ] || fail "no loaders folder at Contents/Resources/loaders"
done
held=$(cd "$ld" && find . -mindepth 1 | LC_ALL=C sort | tr '\n' ' ')
[ "$held" = "./node ./node/env.cjs ./python ./python/sitecustomize.py " ] ||
    fail "Contents/Resources/loaders must hold only node/env.cjs and python/sitecustomize.py"
for f in node/env.cjs python/sitecustomize.py; do
    [ -f "$ld/$f" ] && [ ! -L "$ld/$f" ] || fail "loader $f is not a regular file"
    cmp -s "$ld/$f" "$(dirname "$0")/../loaders/$f" || fail "loader $f is not the repository's (run make agent again)"
done
/usr/bin/codesign --verify --strict --deep "$app" || fail "codesign --verify failed"
# sigcheck <path> <identifier> <what>: ad hoc (automation never uses a real
# identity), the hardened runtime, and no entitlements at all (get-task-allow
# would let any process of the user read the agent's memory).
sigcheck() {
    local sig ent
    sig=$(/usr/bin/codesign -dvv "$1" 2>&1) || fail "$3 is not signed"
    grep -qxF "Identifier=$2" <<<"$sig" || fail "$3 signing identifier is not $2"
    grep -qxF 'Signature=adhoc' <<<"$sig" || fail "$3 is not ad-hoc signed (automation never uses a real identity)"
    grep -q 'flags=0x10002(adhoc,runtime)' <<<"$sig" || fail "$3 lacks the hardened runtime"
    ent=$(/usr/bin/codesign -d --entitlements - --xml "$1" 2>/dev/null) || fail "$3: cannot read entitlements"
    if grep -q '<key>' <<<"$ent"; then fail "$3 has entitlements"; fi
}
sigcheck "$app" dev.nazar.agent agent
sigcheck "$cli" dev.nazar.cli CLI
"$cli" version | grep -q '^nazar ' || fail "bundled CLI does not run"
/usr/bin/dwarfdump --uuid "$exe" | grep -q 'arm64' || fail "nazar-agent has no arm64 LC_UUID"
# Only system libraries: the Go core and the Swift platform are linked in.
libs=$(/usr/bin/otool -L "$exe") || fail "otool -L nazar-agent failed"
if tail -n +2 <<<"$libs" | grep -vE '^[[:space:]]+(/usr/lib/|/System/Library/)'; then
    fail "nazar-agent links a non-system library"
fi
# No UI of its own (Milestone 6): SwiftUI is Nazar UI.app's, and a menu
# bar item needs NSStatusBar / NSStatusItem, whose class references stay
# in the symbol table of even a stripped binary (dyld binds them).
if grep -qE '/SwiftUI\.framework/' <<<"$libs"; then fail "nazar-agent links SwiftUI (the UI is Nazar UI.app)"; fi
syms=$(/usr/bin/nm -u "$exe" 2>/dev/null) || fail "nm -u nazar-agent failed"
if grep -qE '_OBJC_CLASS_\$_(NSStatusBar|NSStatusItem)$' <<<"$syms"; then fail "nazar-agent has a menu bar item (NSStatusBar)"; fi
# The agent's sources never use the test stand-ins, nor any UI.
src="$(dirname "$0")/../macos/Sources/NazarAgent"
compgen -G "$src/*.swift" >/dev/null || fail "no NazarAgent sources in $src"
rc=0
grep -nE 'Scripted|SoftwareEnclave|NoUserPresence|MemoryVault|MemoryAudit|RecordedWarnings|TemporaryKeychain|testPlatform|dev\.nazar\.test|FakeCLIRunner' "$src"/*.swift || rc=$?
case $rc in
    0) fail "nazar-agent uses a test stand-in" ;;
    1) ;;
    *) fail "cannot read the NazarAgent sources" ;;
esac
rc=0
grep -nE 'import (NazarUI|SwiftUI)|NSStatusBar|NSStatusItem|NSHostingController|makeKeyAndOrderFront' "$src"/*.swift || rc=$?
case $rc in
    0) fail "nazar-agent sources have UI of their own" ;;
    1) ;;
    *) fail "cannot read the NazarAgent sources" ;;
esac
# The CLI the agent trusts with secret values is exactly this one:
# its cdhash is compiled into the agent (main.devCLIPin), never a file.
cli_cdhash=$(/usr/bin/codesign -dvvv "$cli" 2>&1 | sed -n 's/^CDHash=//p')
[ -n "$cli_cdhash" ] || fail "the bundled CLI has no cdhash"
LC_ALL=C grep -aqF "$cli_cdhash" "$exe" || fail "nazar-agent does not pin the bundled CLI (devCLIPin is not $cli_cdhash: was the core archive rebuilt after the CLI?)"
echo "check-agent: $app OK"
