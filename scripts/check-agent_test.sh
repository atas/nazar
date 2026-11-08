#!/bin/bash
# check-agent_test.sh — tests for nazar-agent.app's bundle check and the
# agent's sources (Milestone 6).
#
# Part 1 runs scripts/check-agent.sh against forged bundles built from tiny
# C and Objective-C programs in a temporary folder (compiled, never run): a
# good bundle must pass, and every way a bundle can be wrong (one file under
# two names, links, a broken seal, a real-identity or entitlement-carrying
# signature, non-system libraries, a menu bar item or SwiftUI in the agent,
# test stand-ins or UI in the sources) must fail with its own message.
# Part 2 checks the tree: the agent's Info.plist, main.swift, Package.swift,
# the `make agent` recipe (dry run only) and the spec text.
#
# Nothing here starts nazar-agent, touches a keychain, or signs with
# anything but ad hoc (`codesign --sign -`). Every file lives under one
# mktemp folder that is removed on exit.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
repo=$(dirname "$here")
tmpdir=${TMPDIR:-/tmp}
tmp=$(mktemp -d "${tmpdir%/}/nz-checkagent.XXXXXX")
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
#include <stdio.h>
#include <string.h>
int main(int argc, char **argv) {
    if (argc > 1 && strcmp(argv[1], "version") == 0) { puts("nazar 0.0.0-checkapp-test"); return 0; }
    return 2;
}
C
cat >"$bin/statusbar.m" <<'M'
#import <AppKit/AppKit.h>
int main(void) { return [NSStatusBar systemStatusBar] == nil; }
M
cat >"$bin/statusitem.m" <<'M'
#import <AppKit/AppKit.h>
int main(void) { return [NSStatusItem class] == nil; }
M
cat >"$bin/swiftui.swift" <<'S'
import SwiftUI
print(Text("x"))
S
cat >"$bin/othercli.c" <<'C'
#include <stdio.h>
int main(void) { puts("something else 1.0"); return 0; }
C
cat >"$bin/failcli.c" <<'C'
#include <stdio.h>
int main(void) { puts("nazar 0.0.0"); return 1; }
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
cc -arch arm64 -o "$bin/failcli" "$bin/failcli.c"
cc -arch arm64 -dynamiclib -install_name @rpath/libevil.dylib -o "$bin/libevil.dylib" "$bin/evil.c"
cc -arch arm64 -o "$bin/app-rpath" "$bin/linksevil.c" -L"$bin" -levil -Wl,-rpath,@executable_path
cc -arch arm64 -dynamiclib -install_name "$bin/libabs.dylib" -o "$bin/libabs.dylib" "$bin/evil.c"
cc -arch arm64 -o "$bin/app-abs" "$bin/linksevil.c" -L"$bin" -labs
cc -arch arm64 -framework AppKit -o "$bin/app-statusbar" "$bin/statusbar.m"
cc -arch arm64 -framework AppKit -o "$bin/app-statusitem" "$bin/statusitem.m"
printf '#!/bin/sh\nexit 0\n' >"$bin/app-script"
chmod +x "$bin/app-script"
swiftc -target arm64-apple-macos26.0 -o "$bin/app-swiftui" "$bin/swiftui.swift" 2>/dev/null

# The good agent pins the good CLI: `make agent` compiles the
# CLI's cdhash into the agent. An ad-hoc signature of the same bytes with
# the same options has the same cdhash wherever the file is, so the pin is
# taken from a signed copy and compiled into the good agent; app-plain is
# an agent that pins nothing, othercli-version a CLI that answers like
# nazar but is another build.
cp "$bin/app" "$bin/app-plain"
cp "$bin/cli" "$bin/cli-pin"
codesign --force --sign - --options runtime --identifier dev.nazar.cli "$bin/cli-pin" 2>/dev/null
cli_pin=$(codesign -dvvv "$bin/cli-pin" 2>&1 | sed -n 's/^CDHash=//p')
[ -n "$cli_pin" ] || { echo "FAIL no cdhash for the fixture CLI"; exit 1; }
printf '__attribute__((used)) static const char pin[] = "%s";\nint main(void) { return 0; }\n' "$cli_pin" >"$bin/app-pinned.c"
cc -arch arm64 -o "$bin/app" "$bin/app-pinned.c"
sed 's/checkapp-test/checkapp-other/' "$bin/cli.c" >"$bin/othercli-version.c"
cc -arch arm64 -o "$bin/othercli-version" "$bin/othercli-version.c"

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

# A fake repository: check-agent.sh reads the agent sources relative to
# itself, so each case gets a copy of the script next to sources of its
# choosing.
fake_repo() { # fake_repo <dir> [main.swift contents]
    mkdir -p "$1/scripts" "$1/macos/Sources/NazarAgent" "$1/loaders/node" "$1/loaders/python"
    cp "$here/check-agent.sh" "$1/scripts/check-agent.sh"
    cp "$repo/loaders/node/env.cjs" "$1/loaders/node/env.cjs"
    cp "$repo/loaders/python/sitecustomize.py" "$1/loaders/python/sitecustomize.py"
    printf '%s\n' "${2:-// clean
let vault = try KeychainVault.login()
let backend = SecureEnclaveBackend()}" >"$1/macos/Sources/NazarAgent/main.swift"
}

good_plist() { # good_plist <path>
    cat >"$1" <<'P'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CFBundleIdentifier</key>
	<string>dev.nazar.agent</string>
	<key>CFBundleName</key>
	<string>nazar-agent</string>
	<key>CFBundleExecutable</key>
	<string>nazar-agent</string>
	<key>CFBundlePackageType</key>
	<string>APPL</string>
	<key>CFBundleVersion</key>
	<string>1</string>
	<key>CFBundleInfoDictionaryVersion</key>
	<string>6.0</string>
	<key>LSMinimumSystemVersion</key>
	<string>26.0</string>
	<key>LSUIElement</key>
	<true/>
</dict>
</plist>
P
}

# unsigned_bundle <app>: the layout `make agent` produces, before signing.
unsigned_bundle() {
    rm -rf "$1"
    mkdir -p "$1/Contents/MacOS" "$1/Contents/Resources/loaders/node" "$1/Contents/Resources/loaders/python"
    good_plist "$1/Contents/Info.plist"
    cp "$bin/app" "$1/Contents/MacOS/nazar-agent"
    cp "$bin/cli" "$1/Contents/MacOS/nazar"
    cp "$repo/loaders/node/env.cjs" "$1/Contents/Resources/loaders/node/env.cjs"
    cp "$repo/loaders/python/sitecustomize.py" "$1/Contents/Resources/loaders/python/sitecustomize.py"
}

# sign_cli <app> [codesign args...]: default is what `make agent` must do.
sign_cli() {
    local app=$1
    shift
    if [ $# -eq 0 ]; then set -- --options runtime --identifier dev.nazar.cli; fi
    codesign --force --sign - "$@" "$app/Contents/MacOS/nazar" 2>/dev/null
}
# sign_app <app> [codesign args...]
sign_app() {
    local app=$1
    shift
    if [ $# -eq 0 ]; then set -- --options runtime; fi
    codesign --force --sign - "$@" "$app" 2>/dev/null
}
good_bundle() { unsigned_bundle "$1"; sign_cli "$1"; sign_app "$1"; }

# run_check <repo> <app>: sets $out and $rc.
run_check() {
    rc=0
    out=$("$1/scripts/check-agent.sh" "$2" 2>&1) || rc=$?
}
expect_ok() { # expect_ok <name> <repo> <app>
    run_check "$2" "$3"
    if [ "$rc" -eq 0 ] && grep -qxF "check-agent: $3 OK" <<<"$out"; then pass "$1"; else bad "$1: want OK, got rc=$rc: $out"; fi
}
expect_fail() { # expect_fail <name> <repo> <app> <message>
    run_check "$2" "$3"
    if [ "$rc" -ne 0 ] && grep -qF "check-agent: $4" <<<"$out" && ! grep -q ' OK$' <<<"$out"; then
        pass "$1"
    else
        bad "$1: want failure \"$4\", got rc=$rc: $out"
    fi
}

# ------------------------------------------------- part 1: the bundle check

R="$tmp/repo"
fake_repo "$R"
B="$tmp/with space/nazar-agent.app" # a path with a space must work
mkdir -p "$(dirname "$B")"

good_bundle "$B"
expect_ok "a correctly built bundle passes (path with a space)" "$R" "$B"

# An agent that does not pin its bundled CLI (a stale core archive)
# is refused, and so is a CLI other than the one pinned.
unsigned_bundle "$B"
cp "$bin/app-plain" "$B/Contents/MacOS/nazar-agent"
sign_cli "$B"
sign_app "$B"
expect_fail "an agent that does not pin the bundled CLI is refused" "$R" "$B" "nazar-agent does not pin the bundled CLI"
unsigned_bundle "$B"
cp "$bin/othercli-version" "$B/Contents/MacOS/nazar"
sign_cli "$B"
sign_app "$B"
expect_fail "a CLI other than the pinned one is refused" "$R" "$B" "nazar-agent does not pin the bundled CLI"

rc=0
out=$("$R/scripts/check-agent.sh" 2>&1) || rc=$?
if [ "$rc" -ne 0 ] && grep -q 'usage: check-agent.sh' <<<"$out"; then pass "no argument prints the usage"; else bad "no argument: rc=$rc $out"; fi

expect_fail "a folder that is not a bundle" "$R" "$tmp/nothing-here" "no Info.plist"

# Info.plist
for c in \
    "CFBundleIdentifier|string|dev.nazar|CFBundleIdentifier is not dev.nazar.agent" \
    "CFBundleIdentifier|string|dev.nazar.ui|CFBundleIdentifier is not dev.nazar.agent" \
    "CFBundleIdentifier|string|DEV.NAZAR.AGENT|CFBundleIdentifier is not dev.nazar.agent" \
    "LSUIElement|bool|false|LSUIElement is not true" \
    "LSUIElement|string|true|LSUIElement is not true" \
    "LSUIElement|integer|1|LSUIElement is not true" \
    "LSMinimumSystemVersion|string|15.0|LSMinimumSystemVersion is not 26.0" \
    "CFBundleExecutable|string|nazar|CFBundleExecutable is not nazar-agent" \
    "CFBundleExecutable|string|NazarApp|CFBundleExecutable is not nazar-agent"; do
    IFS='|' read -r k t v msg <<<"$c"
    unsigned_bundle "$B"
    plutil -replace "$k" -"$t" "$v" "$B/Contents/Info.plist"
    sign_cli "$B"
    sign_app "$B" 2>/dev/null || true
    expect_fail "Info.plist $k=$v ($t) is refused" "$R" "$B" "$msg"
done
for k in CFBundleIdentifier CFBundleExecutable LSUIElement LSMinimumSystemVersion; do
    unsigned_bundle "$B"
    plutil -remove "$k" "$B/Contents/Info.plist"
    sign_cli "$B"
    sign_app "$B" 2>/dev/null || true
    case $k in
        CFBundleIdentifier) msg="CFBundleIdentifier is not dev.nazar.agent" ;;
        CFBundleExecutable) msg="CFBundleExecutable is not nazar-agent" ;;
        LSUIElement) msg="LSUIElement is not true" ;;
        LSMinimumSystemVersion) msg="LSMinimumSystemVersion is not 26.0" ;;
    esac
    expect_fail "Info.plist without $k is refused" "$R" "$B" "$msg"
done

# The old Nazar.app layout (executable NazarApp) is not an agent bundle.
unsigned_bundle "$B"
mv "$B/Contents/MacOS/nazar-agent" "$B/Contents/MacOS/NazarApp"
plutil -replace CFBundleExecutable -string NazarApp "$B/Contents/Info.plist"
sign_cli "$B"
sign_app "$B" 2>/dev/null || true
expect_fail "the old Contents/MacOS/NazarApp layout is refused" "$R" "$B" "CFBundleExecutable is not nazar-agent"

# The executables
unsigned_bundle "$B"
rm "$B/Contents/MacOS/nazar-agent"
expect_fail "a bundle without nazar-agent is refused" "$R" "$B" "no Contents/MacOS/nazar-agent"

unsigned_bundle "$B"
rm "$B/Contents/MacOS/nazar"
sign_app "$B"
expect_fail "a bundle without the CLI is refused" "$R" "$B" "no bundled CLI at Contents/MacOS/nazar"

unsigned_bundle "$B"
chmod -x "$B/Contents/MacOS/nazar"
sign_cli "$B"
sign_app "$B"
expect_fail "a CLI that is not executable is refused" "$R" "$B" "no bundled CLI at Contents/MacOS/nazar"

unsigned_bundle "$B"
rm "$B/Contents/MacOS/nazar-agent"
ln -s nazar "$B/Contents/MacOS/nazar-agent"
sign_cli "$B"
sign_app "$B" 2>/dev/null || true
expect_fail "nazar-agent as a symlink to the CLI is refused" "$R" "$B" "no Contents/MacOS/nazar-agent"

unsigned_bundle "$B"
rm "$B/Contents/MacOS/nazar"
ln -s nazar-agent "$B/Contents/MacOS/nazar"
sign_app "$B" 2>/dev/null || true
expect_fail "the CLI as a symlink to nazar-agent is refused" "$R" "$B" "no bundled CLI at Contents/MacOS/nazar"

# One file under two names (what a case-insensitive volume does to two
# names that differ only by case). A hard link reproduces it on any volume
# (made after signing, since codesign rewrites a file and so would split
# the link).
good_bundle "$B"
rm "$B/Contents/MacOS/nazar"
ln "$B/Contents/MacOS/nazar-agent" "$B/Contents/MacOS/nazar"
expect_fail "agent and CLI as one file (hard link) is refused" "$R" "$B" "agent and CLI are one file"

unsigned_bundle "$B"
cp "$bin/othercli" "$B/Contents/MacOS/helper"
codesign --force --sign - --options runtime "$B/Contents/MacOS/helper" 2>/dev/null
sign_cli "$B"
sign_app "$B"
expect_fail "an extra executable in Contents/MacOS is refused" "$R" "$B" "unexpected file in Contents/MacOS"

# A hidden file is still a file next to the executables.
unsigned_bundle "$B"
cp "$bin/othercli" "$B/Contents/MacOS/.helper"
codesign --force --sign - --options runtime "$B/Contents/MacOS/.helper" 2>/dev/null || true
sign_cli "$B"
sign_app "$B" 2>/dev/null || true
expect_fail "a hidden extra file in Contents/MacOS is refused" "$R" "$B" "unexpected file in Contents/MacOS"

# The seal
unsigned_bundle "$B"
expect_fail "an unsigned bundle is refused" "$R" "$B" "codesign --verify failed"

good_bundle "$B"
plutil -replace CFBundleVersion -string 2 "$B/Contents/Info.plist"
expect_fail "an Info.plist edited after signing is refused" "$R" "$B" "codesign --verify failed"

good_bundle "$B"
cp "$bin/othercli" "$tmp/swapped"
codesign --force --sign - --options runtime --identifier dev.nazar.cli "$tmp/swapped" 2>/dev/null
cp "$tmp/swapped" "$B/Contents/MacOS/nazar"
expect_fail "a CLI swapped after signing is refused" "$R" "$B" "codesign --verify failed"

good_bundle "$B"
printf 'x' >>"$B/Contents/MacOS/nazar-agent"
expect_fail "nazar-agent modified after signing is refused" "$R" "$B" "codesign --verify failed"

unsigned_bundle "$B"
sign_app "$B" # the CLI never signed on its own
expect_fail "a CLI without its own signature is refused" "$R" "$B" "CLI signing identifier is not dev.nazar.cli"

# nazar run's loaders: exactly the repository's two files, plain
# files in plain folders, sealed with the bundle.
L="$B/Contents/Resources/loaders"
unsigned_bundle "$B"
rm -rf "$L"
sign_cli "$B"
sign_app "$B"
expect_fail "a bundle without loaders is refused" "$R" "$B" "no loaders folder at Contents/Resources/loaders"

unsigned_bundle "$B"
mv "$L" "$B/Contents/Resources/real-loaders"
ln -s real-loaders "$L"
sign_cli "$B"
sign_app "$B" 2>/dev/null || true
expect_fail "a loaders folder that is a link is refused" "$R" "$B" "no loaders folder at Contents/Resources/loaders"

unsigned_bundle "$B"
mv "$L/python" "$B/Contents/Resources/python"
ln -s ../python "$L/python"
sign_cli "$B"
sign_app "$B" 2>/dev/null || true
expect_fail "a loader's folder that is a link is refused" "$R" "$B" "no loaders folder at Contents/Resources/loaders"

for f in node/env.cjs python/sitecustomize.py; do
    unsigned_bundle "$B"
    rm "$L/$f"
    sign_cli "$B"
    sign_app "$B"
    expect_fail "a bundle without loaders/$f is refused" "$R" "$B" "Contents/Resources/loaders must hold only"
done

for extra in python/socket.py python/sitecustomize.cpython-314-darwin.so python/__pycache__/sitecustomize.cpython-314.pyc node/extra.js notes.txt; do
    unsigned_bundle "$B"
    mkdir -p "$(dirname "$L/$extra")"
    printf 'x' >"$L/$extra"
    sign_cli "$B"
    sign_app "$B"
    expect_fail "loaders/$extra beside the loaders is refused" "$R" "$B" "Contents/Resources/loaders must hold only"
done

unsigned_bundle "$B"
mv "$L/node/env.cjs" "$B/Contents/Resources/env.cjs"
ln -s ../../env.cjs "$L/node/env.cjs"
sign_cli "$B"
sign_app "$B" 2>/dev/null || true
expect_fail "a loader that is a link is refused" "$R" "$B" "loader node/env.cjs is not a regular file"

for f in node/env.cjs python/sitecustomize.py; do
    unsigned_bundle "$B"
    printf '\n// changed\n' >>"$L/$f"
    sign_cli "$B"
    sign_app "$B"
    expect_fail "loaders/$f other than the repository's is refused, sealed or not" "$R" "$B" "loader $f is not the repository's"
done

# The repository's loader changed after the build: the bundle is stale.
Rs="$tmp/repo-newer-loader"
fake_repo "$Rs"
printf '\n// newer\n' >>"$Rs/loaders/node/env.cjs"
good_bundle "$B"
expect_fail "a bundle built before the repository's loader changed is refused" "$Rs" "$B" "loader node/env.cjs is not the repository's"

# Sealed: a loader changed after signing together with the repository's
# copy, so that only the seal can tell.
for f in node/env.cjs python/sitecustomize.py; do
    Rx="$tmp/repo-seal-${f%%/*}"
    fake_repo "$Rx"
    good_bundle "$B"
    printf '\n// after signing\n' | tee -a "$L/$f" >>"$Rx/loaders/$f"
    expect_fail "loaders/$f changed after signing is refused (the seal covers it)" "$Rx" "$B" "codesign --verify failed"
done

# One Python run with nazar-agent's loader variables leaves the bundle as
# built; without PYTHONDONTWRITEBYTECODE, Python writes __pycache__ into it.
py=$(command -v python3 || true)
if [ -n "$py" ]; then
    good_bundle "$B"
    (cd / && env -i PATH=/usr/bin:/bin HOME="$tmp" PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="$L/python" "$py" -c pass) || bad "python3 -c pass with the bundle's loader failed"
    expect_ok "a Python run with nazar-agent's variables leaves the bundle as built" "$R" "$B"
    (cd / && env -i PATH=/usr/bin:/bin HOME="$tmp" PYTHONPATH="$L/python" "$py" -c pass) || bad "python3 -c pass with the bundle's loader failed"
    expect_fail "a Python run without PYTHONDONTWRITEBYTECODE writes into the bundle, and is caught" "$R" "$B" "Contents/Resources/loaders must hold only"
else
    bad "python3 on PATH (the loader run)"
fi

# The agent's signature
unsigned_bundle "$B"
sign_cli "$B"
sign_app "$B" --options runtime --identifier dev.nazar
expect_fail "agent signing identifier dev.nazar (the old Nazar.app) is refused" "$R" "$B" "agent signing identifier is not dev.nazar.agent"

unsigned_bundle "$B"
sign_cli "$B"
sign_app "$B" --options runtime --identifier devXnazarXagent
expect_fail "agent signing identifier devXnazarXagent is refused (no regex match)" "$R" "$B" "agent signing identifier is not dev.nazar.agent"

unsigned_bundle "$B"
sign_cli "$B"
sign_app "$B" --identifier dev.nazar.agent
expect_fail "agent without the hardened runtime is refused" "$R" "$B" "agent lacks the hardened runtime"

unsigned_bundle "$B"
sign_cli "$B"
sign_app "$B" --options runtime --entitlements "$bin/get-task-allow.plist"
expect_fail "agent with get-task-allow is refused" "$R" "$B" "agent has entitlements"

# The CLI's signature
unsigned_bundle "$B"
sign_cli "$B" --options runtime # identifier defaults to the file name
sign_app "$B"
expect_fail "CLI signed as 'nazar' is refused" "$R" "$B" "CLI signing identifier is not dev.nazar.cli"

unsigned_bundle "$B"
sign_cli "$B" --options runtime --identifier dev.nazar.agent
sign_app "$B"
expect_fail "CLI signed as dev.nazar.agent (the agent's identity) is refused" "$R" "$B" "CLI signing identifier is not dev.nazar.cli"

unsigned_bundle "$B"
sign_cli "$B" --identifier dev.nazar.cli
sign_app "$B"
expect_fail "CLI without the hardened runtime is refused" "$R" "$B" "CLI lacks the hardened runtime"

unsigned_bundle "$B"
sign_cli "$B" --options runtime --identifier dev.nazar.cli --entitlements "$bin/get-task-allow.plist"
sign_app "$B"
expect_fail "CLI with get-task-allow is refused" "$R" "$B" "CLI has entitlements"

# The CLI must run
unsigned_bundle "$B"
cp "$bin/othercli" "$B/Contents/MacOS/nazar"
sign_cli "$B"
sign_app "$B"
expect_fail "a CLI whose version is not 'nazar …' is refused" "$R" "$B" "bundled CLI does not run"

unsigned_bundle "$B"
cp "$bin/failcli" "$B/Contents/MacOS/nazar"
sign_cli "$B"
sign_app "$B"
expect_fail "a CLI whose version exits non-zero is refused" "$R" "$B" "bundled CLI does not run"

# nazar-agent's binary
unsigned_bundle "$B"
cp "$bin/app-x86_64" "$B/Contents/MacOS/nazar-agent"
sign_cli "$B"
sign_app "$B"
expect_fail "an x86_64-only nazar-agent is refused" "$R" "$B" "nazar-agent has no arm64 LC_UUID"

unsigned_bundle "$B"
cp "$bin/app-rpath" "$B/Contents/MacOS/nazar-agent"
sign_cli "$B"
sign_app "$B"
expect_fail "nazar-agent linking @rpath/libevil.dylib is refused" "$R" "$B" "nazar-agent links a non-system library"

unsigned_bundle "$B"
cp "$bin/app-abs" "$B/Contents/MacOS/nazar-agent"
sign_cli "$B"
sign_app "$B"
expect_fail "nazar-agent linking a dylib in a temp folder is refused" "$R" "$B" "nazar-agent links a non-system library"

# No menu bar item and no SwiftUI in the agent (Milestone 6).
unsigned_bundle "$B"
cp "$bin/app-statusbar" "$B/Contents/MacOS/nazar-agent"
sign_cli "$B"
sign_app "$B"
expect_fail "nazar-agent using NSStatusBar (a menu bar item) is refused" "$R" "$B" "nazar-agent has a menu bar item (NSStatusBar)"
/usr/bin/strip -x "$B/Contents/MacOS/nazar-agent" 2>/dev/null
sign_app "$B"
expect_fail "a stripped nazar-agent using NSStatusBar is refused too" "$R" "$B" "nazar-agent has a menu bar item (NSStatusBar)"

# NSStatusItem alone (no NSStatusBar reference) is a menu bar item too.
unsigned_bundle "$B"
cp "$bin/app-statusitem" "$B/Contents/MacOS/nazar-agent"
/usr/bin/strip -x "$B/Contents/MacOS/nazar-agent" 2>/dev/null
sign_cli "$B"
sign_app "$B"
expect_fail "a stripped nazar-agent referencing only NSStatusItem is refused" "$R" "$B" "nazar-agent has a menu bar item (NSStatusBar)"

# A script is no agent binary (no arm64 Mach-O, so none of the binary checks could hold).
unsigned_bundle "$B"
cp "$bin/app-script" "$B/Contents/MacOS/nazar-agent"
sign_cli "$B"
sign_app "$B" 2>/dev/null || true
expect_fail "a shell script as nazar-agent is refused" "$R" "$B" "nazar-agent has no arm64 LC_UUID"

if [ -x "$bin/app-swiftui" ]; then
    unsigned_bundle "$B"
    cp "$bin/app-swiftui" "$B/Contents/MacOS/nazar-agent"
    sign_cli "$B"
    sign_app "$B"
    expect_fail "nazar-agent linking SwiftUI is refused" "$R" "$B" "nazar-agent links SwiftUI"
else
    bad "swiftc could not build the SwiftUI stand-in"
fi

# The sources: nazar-agent never uses a test stand-in, nor UI of its own.
good_bundle "$B"
R2="$tmp/repo-nosrc"
fake_repo "$R2"
rm -rf "$R2/macos/Sources/NazarAgent"
expect_fail "missing NazarAgent sources are refused (not silently passed)" "$R2" "$B" "no NazarAgent sources"

i=0
for standin in \
    'ScriptedLoginEvaluator()' 'ScriptedConfirmer()' 'ScriptedAuthContext()' \
    'SoftwareEnclaveBackend()' 'NoUserPresenceBackend(SecureEnclaveBackend())' \
    'MemoryVault()' 'MemoryAudit()' 'RecordedWarnings()' 'TemporaryKeychain()' \
    'SwiftPlatform.testPlatform()' \
    'ScreenLockWatcher(name: "dev.nazar.test.screenIsLocked")' 'FakeCLIRunner()'; do
    i=$((i + 1))
    Ri="$tmp/repo-standin-$i"
    fake_repo "$Ri" "let vault = try KeychainVault.login()
let x = $standin"
    expect_fail "nazar-agent source using $standin is refused" "$Ri" "$B" "nazar-agent uses a test stand-in"
done

i=0
for ui in 'import NazarUI' 'import SwiftUI' 'NSStatusBar.system.statusItem(withLength: 10)' \
    'let s: NSStatusItem? = nil' 'NSHostingController(rootView: v)' 'w.makeKeyAndOrderFront(nil)'; do
    i=$((i + 1))
    Ri="$tmp/repo-ui-$i"
    fake_repo "$Ri" "let vault = try KeychainVault.login()
$ui"
    expect_fail "nazar-agent source with \"$ui\" is refused" "$Ri" "$B" "nazar-agent sources have UI of their own"
done

# Every Swift file of the agent counts, not only main.swift.
Ri="$tmp/repo-ui-otherfile"
fake_repo "$Ri"
printf '%s\n' 'import SwiftUI' 'struct W: View { var body: some View { Text("x") } }' >"$Ri/macos/Sources/NazarAgent/Window.swift"
expect_fail "UI in a second NazarAgent source file is refused" "$Ri" "$B" "nazar-agent sources have UI of their own"
Ri="$tmp/repo-standin-otherfile"
fake_repo "$Ri"
printf '%s\n' 'let audit = MemoryAudit()' >"$Ri/macos/Sources/NazarAgent/Parts.swift"
expect_fail "a test stand-in in a second NazarAgent source file is refused" "$Ri" "$B" "nazar-agent uses a test stand-in"

# ------------------------------------------------------ part 2: the tree

# The tree's Info.plist and agent sources, in a bundle of stand-in
# binaries, must pass the same check `make agent` runs.
T="$tmp/repo-tree"
fake_repo "$T"
plist="$repo/macos/Resources/Agent/Info.plist"
if [ -f "$plist" ] && compgen -G "$repo/macos/Sources/NazarAgent/*.swift" >/dev/null; then
    cp "$repo"/macos/Sources/NazarAgent/*.swift "$T/macos/Sources/NazarAgent/"
    unsigned_bundle "$B"
    cp "$plist" "$B/Contents/Info.plist"
    sign_cli "$B"
    sign_app "$B" 2>/dev/null || true
    expect_ok "the tree's Info.plist and NazarAgent sources pass check-agent.sh" "$T" "$B"
else
    bad "the tree has macos/Resources/Agent/Info.plist and macos/Sources/NazarAgent/*.swift"
fi

if [ -f "$plist" ] && plutil -lint -s "$plist" &&
    [ "$(plutil -extract CFBundlePackageType raw -o - "$plist" 2>/dev/null)" = APPL ] &&
    [ "$(plutil -extract CFBundleName raw -o - "$plist" 2>/dev/null)" = nazar-agent ]; then
    pass "Info.plist: valid, an APPL bundle named nazar-agent"
else
    bad "Info.plist: valid, CFBundlePackageType APPL, CFBundleName nazar-agent"
fi
if [ ! -e "$repo/macos/Resources/Info.plist" ] && [ ! -e "$repo/macos/Sources/NazarApp" ]; then
    pass "the old Nazar.app plist and NazarApp sources are gone"
else
    bad "macos/Resources/Info.plist and macos/Sources/NazarApp are removed"
fi

# main.swift wires the real parts (spec 4, 4.7) and stops the core on SIGTERM.
main="$repo/macos/Sources/NazarAgent/main.swift"
if [ -f "$main" ]; then
    for want in \
        'import CNazarCore' 'import NazarPlatform' \
        'SecureEnclaveBackend()' 'KeychainVault.login()' 'LAEvaluator(mode:' \
        'DialogGate(' 'ConfirmPanel(' 'LocalKeyMonitor()' 'CarbonSecureInput()' \
        'WarningCenter(' 'OSLogAuditSink()' 'ProcessResolver()' 'InstalledApps()' \
        'ExitWatcher()' 'ScreenLockWatcher()' 'AppKitPresenter()' \
        'NazarCoreStart(' 'NazarCoreStop()' 'SIGTERM' \
        'NazarProcessExited(' 'NazarScreenLocked(' \
        'setActivationPolicy(.accessory)'; do
        if grep -qF -- "$want" "$main"; then pass "main.swift uses $want"; else bad "main.swift does not use $want"; fi
    done
    # No environment switches: a test override in the shipped agent would be
    # a way around its checks (the CLI's NAZAR_TEST_PEER is CLI-only).
    for never in 'SecKeychainSetUserInteractionAllowed(true)' 'Apple Development' 'NoUserPresenceBackend' \
        'getenv(' 'processInfo.environment' 'NazarUIHost' 'NazarSetShowWindow'; do
        if grep -qF -- "$never" "$main"; then bad "main.swift must not contain $never"; else pass "main.swift has no $never"; fi
    done
else
    bad "macos/Sources/NazarAgent/main.swift exists"
fi
# The agent runs no CLI of its own (the UI is Nazar UI.app, Milestone 6).
for never in 'Process()' 'ProcessCLIRunner' 'BundledCLI' 'NSStatusBar'; do
    if grep -qF -- "$never" "$repo"/macos/Sources/NazarAgent/*.swift; then bad "NazarAgent sources must not contain $never"; else pass "NazarAgent sources have no $never"; fi
done

# The package builds the agent from the Go core's archive, without NazarUI.
mm="$repo/macos/Sources/CNazarCore/module.modulemap"
if [ -f "$mm" ] && grep -qF 'link "nazar-core"' "$mm" && grep -qF 'build/libnazar-core.h' "$mm"; then
    pass "CNazarCore links build/libnazar-core.a"
else
    bad "macos/Sources/CNazarCore/module.modulemap links nazar-core with build/libnazar-core.h"
fi
agent_target=$(tr '\n' ' ' <"$repo/macos/Package.swift" | grep -oE '\.executableTarget\([[:space:]]*name: "NazarAgent"[^)]*\)' || true)
if [ -n "$agent_target" ] && grep -qF '"CNazarCore"' <<<"$agent_target"; then
    pass "Package.swift has the NazarAgent executable target on CNazarCore"
else
    bad "Package.swift has .executableTarget(name: \"NazarAgent\" …) depending on CNazarCore"
fi
if [ -n "$agent_target" ] && ! grep -qF '"NazarUI"' <<<"$agent_target"; then
    pass "the NazarAgent target does not depend on NazarUI"
else
    bad "the NazarAgent target must not depend on NazarUI"
fi
if grep -qF 'name: "NazarApp"' "$repo/macos/Package.swift"; then bad "Package.swift has no NazarApp target"; else pass "Package.swift has no NazarApp target"; fi

# `make agent`, dry run only (make -n executes nothing here).
rc=0
recipe=$(env -u MAKEFLAGS -u MFLAGS -u MAKELEVEL make -n -C "$repo" agent 2>&1) || rc=$?
if [ "$rc" -ne 0 ]; then
    bad "make agent exists: $recipe"
else
    signs=$(grep -E '(^|[[:space:]])codesign[[:space:]]' <<<"$recipe" || true)
    if [ -z "$signs" ]; then
        bad "make agent signs the bundle"
    else
        pass "make agent signs the bundle"
        if grep -vE -- '--sign -( |$)' <<<"$signs" >/dev/null; then bad "make agent signs only ad hoc: $signs"; else pass "make agent signs only ad hoc"; fi
        if grep -v -- '--options runtime' <<<"$signs" >/dev/null; then bad "make agent signs with the hardened runtime: $signs"; else pass "make agent signs with the hardened runtime"; fi
        if grep -q -- '--entitlements' <<<"$signs"; then bad "make agent adds no entitlements"; else pass "make agent adds no entitlements"; fi
        if grep -- '--identifier dev.nazar.cli' <<<"$signs" | grep -q 'Contents/MacOS/nazar'; then
            pass "make agent signs the CLI as dev.nazar.cli"
        else
            bad "make agent signs Contents/MacOS/nazar with --identifier dev.nazar.cli"
        fi
        # The CLI is signed before the bundle, so the bundle's seal covers it.
        cli_line=$(grep -n -- 'Contents/MacOS/nazar' <<<"$signs" | head -1 | cut -d: -f1)
        last_line=$(wc -l <<<"$signs" | tr -d ' ')
        if [ -n "$cli_line" ] && [ "$cli_line" -lt "$last_line" ] && tail -1 <<<"$signs" | grep -qE 'nazar-agent\.app/?$'; then
            pass "make agent signs the CLI first and the bundle last"
        else
            bad "make agent signs the CLI first and the bundle last: $signs"
        fi
    fi
    if grep -q 'Apple Development' <<<"$recipe"; then bad "make agent never names a real identity"; else pass "make agent never names a real identity"; fi
    if grep -qE 'Contents/MacOS/nazar-agent' <<<"$recipe" && grep -qF 'macos/Resources/Agent/Info.plist' <<<"$recipe"; then
        pass "make agent installs nazar-agent and the Info.plist"
    else
        bad "make agent copies macos/Resources/Agent/Info.plist and Contents/MacOS/nazar-agent"
    fi
    # The loaders go into the bundle before its last codesign, so its seal covers them.
    seal_line=$( (grep -nE '(^|[[:space:]])codesign[[:space:]].*nazar-agent\.app/?$' <<<"$recipe" || true) | tail -1 | cut -d: -f1)
    for f in node/env.cjs python/sitecustomize.py; do
        cp_line=$( (grep -nE "^cp[[:space:]]+loaders/$f[[:space:]]+build/nazar-agent\.app/Contents/Resources/loaders/$f\$" <<<"$recipe" || true) | head -1 | cut -d: -f1)
        if [ -n "$cp_line" ] && [ -n "$seal_line" ] && [ "$cp_line" -lt "$seal_line" ]; then
            pass "make agent copies loaders/$f into the bundle before signing it"
        else
            bad "make agent copies loaders/$f to Contents/Resources/loaders/$f before the bundle's codesign"
        fi
    done
    if tail -1 <<<"$recipe" | grep -qE 'scripts/check-agent\.sh[[:space:]]+build/nazar-agent\.app'; then
        pass "make agent ends with scripts/check-agent.sh build/nazar-agent.app"
    else
        bad "make agent ends with scripts/check-agent.sh build/nazar-agent.app"
    fi
    # No recipe line runs the agent: neither `open` nor nazar-agent nor the
    # bundle as a command (its first word).
    if awk '{print $1}' <<<"$recipe" | grep -qE '^(open|.*nazar-agent|.*\.app/?)$'; then
        bad "make agent never starts nazar-agent"
    else
        pass "make agent never starts nazar-agent"
    fi
fi
rc=0
out=$(env -u MAKEFLAGS -u MFLAGS -u MAKELEVEL make -n -C "$repo" app 2>&1) || rc=$?
if [ "$rc" -ne 0 ]; then pass "make app is gone (it is make agent)"; else bad "make app is gone: $out"; fi

# The spec (4.7, 12) says how the agent is really built.
spec="$repo/docs/design/nazar-design.md"
if grep -q xcodebuild "$spec"; then bad "spec 4.7/12 no longer say xcodebuild"; else pass "spec 4.7/12 no longer say xcodebuild"; fi
if grep -qF 'Contents/MacOS/nazar-agent' "$spec" && grep -qF 'make agent' "$spec"; then
    pass "spec names Contents/MacOS/nazar-agent and make agent"
else
    bad "spec names Contents/MacOS/nazar-agent and make agent"
fi

echo "check-agent_test: $passes passed, $failures failed"
[ "$failures" -eq 0 ]
