#!/bin/bash
# check-ui_test.sh — tests for Nazar UI.app's bundle check and the app's
# sources (Milestone 6).
#
# Part 1 runs scripts/check-ui.sh against forged bundles built from tiny C
# and Objective-C programs in a temporary folder (compiled, never run): a
# good bundle must pass, and every way the UI could be more than an
# ordinary app running the CLI (an agent or background-only plist, a
# bundled CLI or helper, a login item, a menu bar item, a Keychain call,
# the Go core, a missing or wrong CLI pin, a bad signature, non-system
# libraries, test stand-ins in the sources) must fail with its own message.
# Part 2 checks the tree: the UI's Info.plist, its app sources,
# Package.swift and the `make ui` recipe (dry run only).
#
# Nothing here starts an app, touches a keychain, or signs with anything
# but ad hoc (`codesign --sign -`). Every file lives under one mktemp folder
# that is removed on exit.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
repo=$(dirname "$here")
tmpdir=${TMPDIR:-/tmp}
tmp=$(mktemp -d "${tmpdir%/}/nz-checkui.XXXXXX")
trap 'rm -rf "$tmp"' EXIT

failures=0
passes=0
pass() { passes=$((passes + 1)); echo "ok   $*"; }
bad() { failures=$((failures + 1)); echo "FAIL $*"; }

# ---------------------------------------------------------------- fixtures

bin="$tmp/bin"
mkdir -p "$bin"
cat >"$bin/app.c" <<'C'
int main(void) { return 0; }
C
cat >"$bin/cli.c" <<'C'
int main(void) { return 0; }
C
cat >"$bin/othercli.c" <<'C'
int main(void) { return 1; }
C
cat >"$bin/statusbar.m" <<'M'
#import <AppKit/AppKit.h>
int main(void) { return [NSStatusBar systemStatusBar] == nil; }
M
cat >"$bin/keychain.c" <<'C'
#include <Security/Security.h>
int main(void) { return (int)SecItemCopyMatching(NULL, NULL); }
C
cat >"$bin/gocore.c" <<'C'
int NazarCoreStart(void) { return 0; }
int main(void) { return NazarCoreStart(); }
C
cat >"$bin/loginitem.c" <<'C'
#include <CoreFoundation/CoreFoundation.h>
extern Boolean SMLoginItemSetEnabled(CFStringRef, Boolean);
int main(void) { return SMLoginItemSetEnabled(CFSTR("x"), false); }
C
cat >"$bin/menubarextra.c" <<'C'
// SwiftUI's MenuBarExtra, as a stripped Swift binary still names it.
extern int menuBarExtra __asm__("_$s7SwiftUI12MenuBarExtraVMn");
int main(void) { return menuBarExtra; }
C
cat >"$bin/evil.c" <<'C'
int evil(void) { return 1; }
C
cat >"$bin/linksevil.c" <<'C'
int evil(void);
int main(void) { return evil(); }
C
cc -arch arm64 -o "$bin/app" "$bin/app.c"
cc -arch x86_64 -o "$bin/app-x86_64" "$bin/app.c"
cc -arch arm64 -o "$bin/cli" "$bin/cli.c"
cc -arch arm64 -o "$bin/othercli" "$bin/othercli.c"
cc -arch arm64 -framework AppKit -o "$bin/app-statusbar" "$bin/statusbar.m"
cc -arch arm64 -framework Security -o "$bin/app-keychain" "$bin/keychain.c"
cc -arch arm64 -o "$bin/app-gocore" "$bin/gocore.c"
cc -arch arm64 -framework CoreFoundation -framework ServiceManagement -o "$bin/app-loginitem" "$bin/loginitem.c"
cc -arch arm64 -dynamiclib -install_name @rpath/libevil.dylib -o "$bin/libevil.dylib" "$bin/evil.c"
cc -arch arm64 -o "$bin/app-rpath" "$bin/linksevil.c" -L"$bin" -levil -Wl,-rpath,@executable_path
cc -arch arm64 -Wl,-undefined,dynamic_lookup -o "$bin/app-menubarextra" "$bin/menubarextra.c"
# A library whose path starts like a system one but leaves /usr/lib.
cc -arch arm64 -dynamiclib -install_name "/usr/lib/../..$bin/libdotdot.dylib" -o "$bin/libdotdot.dylib" "$bin/evil.c"
cc -arch arm64 -o "$bin/app-dotdot" "$bin/linksevil.c" "$bin/libdotdot.dylib"

cat >"$bin/get-task-allow.plist" <<'P'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>com.apple.security.get-task-allow</key>
	<true/>
</dict>
</plist>
P

# An agent bundle whose CLI the UI pins (only its CLI matters here).
A="$tmp/agent/nazar-agent.app"
mkdir -p "$A/Contents/MacOS"
cp "$bin/cli" "$A/Contents/MacOS/nazar"
codesign --force --sign - --options runtime --identifier dev.nazar.cli "$A/Contents/MacOS/nazar" 2>/dev/null
pin=$(codesign -dvvv "$A/Contents/MacOS/nazar" 2>&1 | sed -n 's/^CDHash=//p')
O="$tmp/other/nazar-agent.app"
mkdir -p "$O/Contents/MacOS"
cp "$bin/othercli" "$O/Contents/MacOS/nazar"
codesign --force --sign - --options runtime --identifier dev.nazar.cli "$O/Contents/MacOS/nazar" 2>/dev/null

# A fake repository: check-ui.sh reads the app sources relative to itself.
fake_repo() { # fake_repo <dir> [NazarUIApp.swift contents]
    mkdir -p "$1/scripts" "$1/macos/Sources/NazarUIApp"
    cp "$here/check-ui.sh" "$1/scripts/check-ui.sh"
    printf '%s\n' "${2:-// clean
@main struct NazarUIApp: App { var body: some Scene { Window(\"Nazar\", id: \"nazar\") { Text(\"x\") } } }}" >"$1/macos/Sources/NazarUIApp/NazarUIApp.swift"
}

good_plist() { # good_plist <path>
    cat >"$1" <<'P'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CFBundleIdentifier</key>
	<string>dev.nazar.ui</string>
	<key>CFBundleName</key>
	<string>Nazar UI</string>
	<key>CFBundleExecutable</key>
	<string>NazarUI</string>
	<key>CFBundlePackageType</key>
	<string>APPL</string>
	<key>CFBundleVersion</key>
	<string>1</string>
	<key>CFBundleInfoDictionaryVersion</key>
	<string>6.0</string>
	<key>LSMinimumSystemVersion</key>
	<string>26.0</string>
</dict>
</plist>
P
}

# unsigned_bundle <app> [executable]: the layout `make ui` produces, with
# the pin, before signing.
unsigned_bundle() {
    rm -rf "$1"
    mkdir -p "$1/Contents/MacOS" "$1/Contents/Resources"
    good_plist "$1/Contents/Info.plist"
    plutil -insert NazarDevCLICDHash -string "$pin" "$1/Contents/Info.plist"
    cp "${2:-$bin/app}" "$1/Contents/MacOS/NazarUI"
}
# sign_app <app> [codesign args...]: default is what `make ui` must do.
sign_app() {
    local app=$1
    shift
    if [ $# -eq 0 ]; then set -- --options runtime; fi
    codesign --force --sign - "$@" "$app" 2>/dev/null
}
good_bundle() { unsigned_bundle "$1" "${2:-}"; sign_app "$1"; }

# run_check <repo> <app> [agent]: sets $out and $rc.
run_check() {
    rc=0
    out=$("$1/scripts/check-ui.sh" "$2" ${3:+"$3"} 2>&1) || rc=$?
}
expect_ok() { # expect_ok <name> <repo> <app> [agent]
    run_check "$2" "$3" "${4:-}"
    if [ "$rc" -eq 0 ] && grep -qxF "check-ui: $3 OK" <<<"$out"; then pass "$1"; else bad "$1: want OK, got rc=$rc: $out"; fi
}
expect_fail() { # expect_fail <name> <repo> <app> <message> [agent]
    run_check "$2" "$3" "${5:-}"
    if [ "$rc" -ne 0 ] && grep -qF "check-ui: $4" <<<"$out" && ! grep -q ' OK$' <<<"$out"; then
        pass "$1"
    else
        bad "$1: want failure \"$4\", got rc=$rc: $out"
    fi
}

# ------------------------------------------------- part 1: the bundle check

R="$tmp/repo"
fake_repo "$R"
B="$tmp/with space/Nazar UI.app" # the real name has a space

good_bundle "$B"
expect_ok "a correctly built bundle passes" "$R" "$B"
expect_ok "a bundle pinning the agent's CLI passes" "$R" "$B" "$A"
expect_fail "a bundle pinning another CLI build is refused" "$R" "$B" "Nazar UI pins another CLI build" "$O"

rc=0
out=$("$R/scripts/check-ui.sh" 2>&1) || rc=$?
if [ "$rc" -ne 0 ] && grep -q 'usage: check-ui.sh' <<<"$out"; then pass "no argument prints the usage"; else bad "no argument: rc=$rc $out"; fi
expect_fail "a folder that is not a bundle" "$R" "$tmp/nothing-here" "no Info.plist"

# Info.plist
for c in \
    "CFBundleIdentifier|string|dev.nazar|CFBundleIdentifier is not dev.nazar.ui" \
    "CFBundleIdentifier|string|dev.nazar.agent|CFBundleIdentifier is not dev.nazar.ui" \
    "CFBundleIdentifier|string|dev.nazar.ui.evil|CFBundleIdentifier is not dev.nazar.ui" \
    "CFBundleExecutable|string|nazar|CFBundleExecutable is not NazarUI" \
    "LSMinimumSystemVersion|string|15.0|LSMinimumSystemVersion is not 26.0"; do
    IFS='|' read -r k t v msg <<<"$c"
    unsigned_bundle "$B"
    plutil -replace "$k" -"$t" "$v" "$B/Contents/Info.plist"
    sign_app "$B" 2>/dev/null || true
    expect_fail "Info.plist $k=$v is refused" "$R" "$B" "$msg"
done
for c in "LSUIElement|bool|true" "LSUIElement|bool|false" "LSBackgroundOnly|bool|true"; do
    IFS='|' read -r k t v <<<"$c"
    unsigned_bundle "$B"
    plutil -insert "$k" -"$t" "$v" "$B/Contents/Info.plist"
    sign_app "$B"
    expect_fail "Info.plist with $k=$v is refused" "$R" "$B" "Info.plist has $k (Nazar UI is a regular app)"
done
for p in "" "ABC" "$(tr 'a-f' 'A-F' <<<"$pin")" "${pin}0"; do
    unsigned_bundle "$B"
    plutil -replace NazarDevCLICDHash -string "$p" "$B/Contents/Info.plist"
    sign_app "$B"
    expect_fail "NazarDevCLICDHash \"$p\" is refused" "$R" "$B" "an ad-hoc Nazar UI pins no CLI build"
done
unsigned_bundle "$B"
plutil -remove NazarDevCLICDHash "$B/Contents/Info.plist"
sign_app "$B"
expect_fail "an ad-hoc bundle without a pin is refused" "$R" "$B" "an ad-hoc Nazar UI pins no CLI build"

# The executable and what may sit next to it.
unsigned_bundle "$B"
rm "$B/Contents/MacOS/NazarUI"
expect_fail "a bundle without NazarUI is refused" "$R" "$B" "no Contents/MacOS/NazarUI"

unsigned_bundle "$B"
rm "$B/Contents/MacOS/NazarUI"
ln -s /usr/bin/true "$B/Contents/MacOS/NazarUI"
sign_app "$B" 2>/dev/null || true
expect_fail "NazarUI as a symlink is refused" "$R" "$B" "no Contents/MacOS/NazarUI"

unsigned_bundle "$B"
cp "$A/Contents/MacOS/nazar" "$B/Contents/MacOS/nazar"
sign_app "$B"
expect_fail "a CLI bundled in the UI is refused" "$R" "$B" "unexpected file in Contents/MacOS: nazar"

for d in Library/LoginItems Library/LaunchAgents Library/LaunchDaemons XPCServices Helpers; do
    unsigned_bundle "$B"
    mkdir -p "$B/Contents/$d"
    sign_app "$B" 2>/dev/null || true
    expect_fail "a bundle with Contents/$d is refused" "$R" "$B" "Contents/$d: Nazar UI runs nothing in the background"
done
# Nested code that codesign --verify --deep accepts when it is signed, and a
# CLI hidden among the resources.
for d in Frameworks PlugIns/x.bundle/Contents/MacOS; do
    unsigned_bundle "$B"
    mkdir -p "$B/Contents/$d"
    cp "$bin/app" "$B/Contents/$d/x"
    codesign --force --sign - --options runtime "$B/Contents/$d/x" 2>/dev/null
    sign_app "$B"
    expect_fail "a bundle with Contents/${d%%/*} is refused" "$R" "$B" "unexpected entry in Contents: ${d%%/*}"
done
unsigned_bundle "$B"
cp "$bin/libevil.dylib" "$B/Contents/Frameworks.dylib"
sign_app "$B"
expect_fail "a stray file in Contents is refused" "$R" "$B" "unexpected entry in Contents: Frameworks.dylib"
unsigned_bundle "$B"
cp "$A/Contents/MacOS/nazar" "$B/Contents/Resources/nazar"
sign_app "$B"
expect_fail "a CLI under Resources is refused" "$R" "$B" "executable file in Contents/Resources"
unsigned_bundle "$B"
mkdir -p "$B/Contents/Resources/deep/er"
cp "$bin/libevil.dylib" "$B/Contents/Resources/deep/er/helper"
chmod 0650 "$B/Contents/Resources/deep/er/helper"
sign_app "$B"
expect_fail "a group-executable file deep under Resources is refused" "$R" "$B" "executable file in Contents/Resources"
# A helper tree: hundreds of executables, more than one pipe buffer of find
# output. A `find | grep -q` would die of SIGPIPE and, under pipefail,
# pass silently.
unsigned_bundle "$B"
mkdir -p "$B/Contents/Resources/deep"
for i in $(seq 1 400); do
    : >"$B/Contents/Resources/deep/helper-with-a-long-name-$i"
    chmod 0755 "$B/Contents/Resources/deep/helper-with-a-long-name-$i"
done
sign_app "$B"
expect_fail "many executables under Resources are refused (find must not die of SIGPIPE)" "$R" "$B" "executable file in Contents/Resources"
unsigned_bundle "$B"
printf 'icon' >"$B/Contents/Resources/AppIcon.icns"
chmod 0644 "$B/Contents/Resources/AppIcon.icns"
sign_app "$B"
expect_ok "a plain resource file (the icon) passes" "$R" "$B"

# The signature
unsigned_bundle "$B"
expect_fail "an unsigned bundle is refused" "$R" "$B" "codesign --verify failed"

good_bundle "$B"
plutil -replace NazarDevCLICDHash -string "$(printf '%040d' 0)" "$B/Contents/Info.plist"
expect_fail "a pin edited after signing is refused" "$R" "$B" "codesign --verify failed"

unsigned_bundle "$B"
sign_app "$B" --options runtime --identifier dev.nazar.agent
expect_fail "signing identifier dev.nazar.agent is refused" "$R" "$B" "signing identifier is not dev.nazar.ui"

unsigned_bundle "$B"
sign_app "$B" --identifier dev.nazar.ui
expect_fail "no hardened runtime is refused" "$R" "$B" "Nazar UI lacks the hardened runtime"

unsigned_bundle "$B"
sign_app "$B" --options runtime --entitlements "$bin/get-task-allow.plist"
expect_fail "get-task-allow is refused" "$R" "$B" "Nazar UI has entitlements"

# The binary
good_bundle "$B" "$bin/app-x86_64"
expect_fail "an x86_64-only NazarUI is refused" "$R" "$B" "NazarUI has no arm64 LC_UUID"
good_bundle "$B" "$bin/app-rpath"
expect_fail "NazarUI linking @rpath/libevil.dylib is refused" "$R" "$B" "NazarUI links a non-system library"
good_bundle "$B" "$bin/app-dotdot"
expect_fail "NazarUI linking /usr/lib/../../… is refused" "$R" "$B" "NazarUI links a non-system library"
good_bundle "$B" "$bin/app-statusbar"
expect_fail "NazarUI using NSStatusBar is refused" "$R" "$B" "Nazar UI has a menu bar item"
good_bundle "$B" "$bin/app-menubarextra"
expect_fail "NazarUI using SwiftUI's MenuBarExtra is refused" "$R" "$B" "Nazar UI has a menu bar item"
good_bundle "$B" "$bin/app-keychain"
expect_fail "NazarUI calling SecItemCopyMatching is refused" "$R" "$B" "Nazar UI calls a Keychain API"
good_bundle "$B" "$bin/app-gocore"
expect_fail "NazarUI defining NazarCoreStart is refused" "$R" "$B" "Nazar UI contains the Go core"
good_bundle "$B" "$bin/app-loginitem"
expect_fail "NazarUI calling SMLoginItemSetEnabled is refused" "$R" "$B" "Nazar UI registers a login item"

# The sources
good_bundle "$B"
R2="$tmp/repo-nosrc"
fake_repo "$R2"
rm -rf "$R2/macos/Sources/NazarUIApp"
expect_fail "missing NazarUIApp sources are refused (not silently passed)" "$R2" "$B" "no NazarUIApp sources"
i=0
for standin in 'FakeCLIRunner()' 'NSStatusBar.system.statusItem(withLength: 10)' 'MenuBarExtra("n") { }' \
    'try SMAppService.mainApp.register()' 'NSApp.setActivationPolicy(.accessory)' 'let id = "dev.nazar.test.x"'; do
    i=$((i + 1))
    Ri="$tmp/repo-standin-$i"
    fake_repo "$Ri" "let x = $standin"
    expect_fail "NazarUIApp source with \"$standin\" is refused" "$Ri" "$B" "NazarUIApp sources use a test stand-in or a background or menu bar item"
done

# ------------------------------------------------------ part 2: the tree

T="$tmp/repo-tree"
fake_repo "$T"
plist="$repo/macos/Resources/UI/Info.plist"
appsrc="$repo/macos/Sources/NazarUIApp"
if [ -f "$plist" ] && compgen -G "$appsrc/*.swift" >/dev/null; then
    cp "$appsrc"/*.swift "$T/macos/Sources/NazarUIApp/"
    unsigned_bundle "$B"
    cp "$plist" "$B/Contents/Info.plist"
    plutil -insert NazarDevCLICDHash -string "$pin" "$B/Contents/Info.plist"
    sign_app "$B"
    expect_ok "the tree's Info.plist and NazarUIApp sources pass check-ui.sh" "$T" "$B" "$A"
else
    bad "the tree has macos/Resources/UI/Info.plist and macos/Sources/NazarUIApp/*.swift"
fi
if plutil -lint -s "$plist" && [ "$(plutil -extract CFBundleName raw -o - "$plist" 2>/dev/null)" = "Nazar UI" ] &&
    ! plutil -extract NazarDevCLICDHash raw -o - "$plist" >/dev/null 2>&1; then
    pass "Info.plist: valid, named Nazar UI, no pin in the source plist (make ui adds it)"
else
    bad "macos/Resources/UI/Info.plist: valid, CFBundleName Nazar UI, no NazarDevCLICDHash"
fi

# The app: quits when its window closes, stops every stream on quit, one
# window, built on RootView and the session; nothing else runs.
main=$(cat "$appsrc"/*.swift 2>/dev/null || true)
for want in '@main' 'Window(' 'RootView(session:' 'UISession.forThisApp()' \
    'applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { true }' \
    'applicationWillTerminate' 'session.stopAll()'; do
    if grep -qF -- "$want" <<<"$main"; then pass "NazarUIApp uses $want"; else bad "NazarUIApp does not use $want"; fi
done
for never in 'Process(' 'ProcessCLIRunner(' 'posix_spawn' 'NSWorkspace' 'getenv(' 'processInfo.environment' 'WindowGroup' 'Settings {'; do
    if grep -qF -- "$never" <<<"$main"; then bad "NazarUIApp must not contain $never"; else pass "NazarUIApp has no $never"; fi
done
ui_target=$(tr '\n' ' ' <"$repo/macos/Package.swift" | grep -oE '\.executableTarget\([[:space:]]*name: "NazarUIApp"[^)]*\)' || true)
if [ -n "$ui_target" ] && grep -qF 'dependencies: ["NazarUI"]' <<<"$ui_target"; then
    pass "Package.swift: the NazarUIApp target depends on NazarUI only"
else
    bad "Package.swift has .executableTarget(name: \"NazarUIApp\", dependencies: [\"NazarUI\"])"
fi

# `make ui`, dry run only.
rc=0
recipe=$(env -u MAKEFLAGS -u MFLAGS -u MAKELEVEL make -n -C "$repo" ui 2>&1) || rc=$?
if [ "$rc" -ne 0 ]; then
    bad "make ui exists: $recipe"
else
    uisigns=$(grep -E '(^|[[:space:]])codesign[[:space:]]+--force' <<<"$recipe" | grep -F 'Nazar UI.app' || true)
    if [ "$(wc -l <<<"$uisigns" | tr -d ' ')" = 1 ] && grep -qE -- '--sign -( |$)' <<<"$uisigns" && grep -q -- '--options runtime' <<<"$uisigns" &&
        ! grep -q -- '--entitlements' <<<"$uisigns"; then
        pass "make ui signs the bundle once, ad hoc, hardened runtime, no entitlements"
    else
        bad "make ui signs \"Nazar UI.app\" once with --sign - --options runtime: $uisigns"
    fi
    if grep -q 'Apple Development' <<<"$recipe"; then bad "make ui never names a real identity"; else pass "make ui never names a real identity"; fi
    if grep -qF 'NazarDevCLICDHash' <<<"$recipe" && grep -qF 'nazar-agent.app/Contents/MacOS/nazar' <<<"$recipe"; then
        pass "make ui pins the agent's CLI"
    else
        bad "make ui writes NazarDevCLICDHash from build/nazar-agent.app/Contents/MacOS/nazar"
    fi
    pin_line=$(grep -nF 'NazarDevCLICDHash' <<<"$recipe" | head -1 | cut -d: -f1)
    sign_line=$(grep -nE 'codesign[[:space:]]+--force.*Nazar UI\.app' <<<"$recipe" | head -1 | cut -d: -f1)
    if [ -n "$pin_line" ] && [ -n "$sign_line" ] && [ "$pin_line" -lt "$sign_line" ]; then
        pass "make ui pins before it signs (the seal covers the pin)"
    else
        bad "make ui pins before it signs"
    fi
    if tail -1 <<<"$recipe" | grep -qE 'scripts/check-ui\.sh[[:space:]]+"build/Nazar UI\.app"[[:space:]]+build/nazar-agent\.app'; then
        pass "make ui ends with scripts/check-ui.sh \"build/Nazar UI.app\" build/nazar-agent.app"
    else
        bad "make ui ends with scripts/check-ui.sh \"build/Nazar UI.app\" build/nazar-agent.app"
    fi
    if awk '{print $1}' <<<"$recipe" | grep -qE '^(open|.*NazarUI"?|.*\.app"?/?)$'; then
        bad "make ui never starts the app"
    else
        pass "make ui never starts the app"
    fi
fi

# `make test` runs this suite and `make check` builds and checks the UI
# (dry runs only).
rc=0
t=$(env -u MAKEFLAGS -u MFLAGS -u MAKELEVEL make -n -C "$repo" test 2>&1) || rc=$?
if [ "$rc" -eq 0 ] && grep -qF 'scripts/check-ui_test.sh' <<<"$t"; then pass "make test runs check-ui_test.sh"; else bad "make test runs check-ui_test.sh: rc=$rc"; fi
rc=0
c=$(env -u MAKEFLAGS -u MFLAGS -u MAKELEVEL make -n -C "$repo" check 2>&1) || rc=$?
if [ "$rc" -eq 0 ] && grep -qE 'scripts/check-ui\.sh[[:space:]]+"build/Nazar UI\.app"' <<<"$c"; then pass "make check builds and checks Nazar UI.app"; else bad "make check runs make ui: rc=$rc"; fi

echo "check-ui_test: $passes passed, $failures failed"
[ "$failures" -eq 0 ]
