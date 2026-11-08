#!/bin/bash
# release_test.sh — tests for scripts/release.sh and the cask templates
# (Milestone 6). Bundles are forged from tiny C programs in a temporary
# folder and signed ad hoc only; nothing is notarized, uploaded or
# installed, no app is started, and no keychain is touched. Every file
# lives under one mktemp folder that is removed on exit.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
repo=$(dirname "$here")
tmpdir=${TMPDIR:-/tmp}
tmp=$(mktemp -d "${tmpdir%/}/nz-release.XXXXXX")
trap 'rm -rf "$tmp"' EXIT
rel="$here/release.sh"

failures=0
passes=0
pass() { passes=$((passes + 1)); echo "ok   $*"; }
bad() { failures=$((failures + 1)); echo "FAIL $*"; }
run() { rc=0; out=$("$@" 2>&1) || rc=$?; }
expect_ok() { # expect_ok <name> <cmd...>
    local name=$1
    shift
    run "$@"
    if [ "$rc" -eq 0 ]; then pass "$name"; else bad "$name: rc=$rc $out"; fi
}
expect_fail() { # expect_fail <name> <message> <cmd...>
    local name=$1 msg=$2
    shift 2
    run "$@"
    if [ "$rc" -ne 0 ] && grep '^release: ' <<<"$out" | grep -qF -- "$msg"; then pass "$name"; else bad "$name: want \"$msg\", got rc=$rc $out"; fi
}

bin="$tmp/bin"
mkdir -p "$bin"
cat >"$bin/cli.c" <<'C'
#include <stdio.h>
#include <string.h>
int main(int argc, char **argv) {
    if (argc > 1 && strcmp(argv[1], "version") == 0) { puts("nazar " VERSION); return 0; }
    return 2;
}
C
cat >"$bin/app.c" <<'C'
int main(void) { return 0; }
C
cc -arch arm64 -o "$bin/app" "$bin/app.c"
cc -arch arm64 -DVERSION='"1.2.3"' -o "$bin/cli" "$bin/cli.c"
cc -arch arm64 -DVERSION='"1.2.3-dev"' -o "$bin/cli-dev" "$bin/cli.c"

plist() { # plist <path> <id> <exe> <version>
    cat >"$1" <<P
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>$2</string>
<key>CFBundleExecutable</key><string>$3</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleShortVersionString</key><string>$4</string>
</dict></plist>
P
}
agent_bundle() { # agent_bundle <dir> <version> [cli]
    local a="$1/nazar-agent.app"
    rm -rf "$a"
    mkdir -p "$a/Contents/MacOS"
    plist "$a/Contents/Info.plist" dev.nazar.agent nazar-agent "$2"
    cp "$bin/app" "$a/Contents/MacOS/nazar-agent"
    cp "${3:-$bin/cli}" "$a/Contents/MacOS/nazar"
    codesign --force --sign - --options runtime --identifier dev.nazar.cli "$a/Contents/MacOS/nazar" 2>/dev/null
    codesign --force --sign - --options runtime "$a" 2>/dev/null
}
ui_bundle() { # ui_bundle <dir> <version>
    local u="$1/Nazar UI.app"
    rm -rf "$u"
    mkdir -p "$u/Contents/MacOS"
    plist "$u/Contents/Info.plist" dev.nazar.ui NazarUI "$2"
    plutil -insert NazarDevCLICDHash -string "$(printf '%040d' 7)" "$u/Contents/Info.plist"
    cp "$bin/app" "$u/Contents/MacOS/NazarUI"
    codesign --force --sign - --options runtime "$u" 2>/dev/null
}

B="$tmp/built"
mkdir -p "$B"
agent_bundle "$B" 1.2.3
ui_bundle "$B" 1.2.3
R="$tmp/with space/release"

# prepare
expect_ok "prepare copies both bundles" "$rel" prepare 1.2.3 "$B/nazar-agent.app" "$B/Nazar UI.app" "$R"
if [ -x "$R/nazar-agent.app/Contents/MacOS/nazar" ] && [ -x "$R/Nazar UI.app/Contents/MacOS/NazarUI" ]; then
    pass "prepare: both bundles are in the release folder"
else
    bad "prepare: both bundles are in the release folder"
fi
# The copy's Info.plist must still be there (and still name the UI): a
# missing plist would also have no pin.
if [ "$(plutil -extract CFBundleIdentifier raw -o - "$R/Nazar UI.app/Contents/Info.plist" 2>/dev/null)" != dev.nazar.ui ] ||
    plutil -extract NazarDevCLICDHash raw -o - "$R/Nazar UI.app/Contents/Info.plist" >/dev/null 2>&1; then
    bad "prepare removes the UI's development pin"
else
    pass "prepare removes the UI's development pin"
fi
if plutil -extract NazarDevCLICDHash raw -o - "$B/Nazar UI.app/Contents/Info.plist" >/dev/null 2>&1; then
    pass "prepare leaves the built UI as it was"
else
    bad "prepare changed the built UI"
fi
expect_fail "prepare refuses a version that is not MAJOR.MINOR.PATCH" "version 1.2 is not MAJOR.MINOR.PATCH" "$rel" prepare 1.2 "$B/nazar-agent.app" "$B/Nazar UI.app" "$R"
expect_fail "prepare refuses an agent of another version" "says version 1.2.3, not 1.2.4" "$rel" prepare 1.2.4 "$B/nazar-agent.app" "$B/Nazar UI.app" "$R"
ui_bundle "$tmp/oldui" 1.2.2
expect_fail "prepare refuses a UI of another version" "Nazar UI.app says version 1.2.2, not 1.2.3" "$rel" prepare 1.2.3 "$B/nazar-agent.app" "$tmp/oldui/Nazar UI.app" "$R"
agent_bundle "$tmp/devcli" 1.2.3 "$bin/cli-dev"
expect_fail "prepare refuses a CLI that says another version" 'says "nazar 1.2.3-dev", not "nazar 1.2.3"' "$rel" prepare 1.2.3 "$tmp/devcli/nazar-agent.app" "$B/Nazar UI.app" "$R"

# check-signed and zips refuse what is not signed for release.
expect_fail "check-signed refuses an ad-hoc agent" "is not signed with a Developer ID Application certificate" "$rel" check-signed "$B/nazar-agent.app" dev.nazar.agent
expect_fail "check-signed refuses the wrong identifier" "is not signed as dev.nazar.ui" "$rel" check-signed "$B/nazar-agent.app" dev.nazar.ui
# The CLI inside the agent is a bare executable: checked the same way.
expect_fail "check-signed refuses an ad-hoc CLI (a bare executable)" "is not signed with a Developer ID Application certificate" "$rel" check-signed "$B/nazar-agent.app/Contents/MacOS/nazar" dev.nazar.cli
expect_fail "check-signed refuses a bare executable with the wrong identifier" "is not signed as dev.nazar.agent" "$rel" check-signed "$B/nazar-agent.app/Contents/MacOS/nazar" dev.nazar.agent
expect_fail "check-signed refuses an unsigned folder" "is not signed" "$rel" check-signed "$tmp" dev.nazar.agent
agent_bundle "$R" 1.2.3
ui_bundle "$R" 1.2.3
expect_fail "zips refuses ad-hoc bundles" "is not signed with a Developer ID Application certificate" "$rel" zips 1.2.3 "$R"
if compgen -G "$R/*.zip" >/dev/null || [ -e "$R/Casks" ]; then bad "a refused zips wrote nothing"; else pass "a refused zips wrote nothing"; fi

# check-signed past the signature checks, which no test build passes (it
# needs a notarized Developer ID build): the function run with stubs for
# codesign, the stapler and spctl. The spctl stub answers as Gatekeeper
# does: a bare executable is never an app (rc 3, even when notarized).
cs="$tmp/check_signed.sh"
{
    sed -n '/^fail() /p' "$rel"
    sed -n '/^check_signed() {/,/^}/p' "$rel" |
        sed -e 's#/usr/bin/codesign#fake_codesign#g' -e 's#/usr/bin/xcrun#fake_xcrun#g' -e 's#/usr/sbin/spctl#fake_spctl#g'
} >"$cs"
if grep -q 'check_signed() {' "$cs" && grep -q '^fail() ' "$cs" && ! grep -q '/usr/' "$cs"; then
    pass "check_signed runs only codesign, the stapler and spctl"
else
    bad "check_signed runs only codesign, the stapler and spctl: $(cat "$cs")"
fi
cat >"$tmp/fakes.sh" <<'SH'
fake_codesign() {
    case $1 in
        -dvv) printf '%s\n' "Identifier=$FAKE_ID" 'Authority=Developer ID Application: Example (ABCDE12345)' \
            'Timestamp=1 Jan 2030 at 00:00:00' 'CodeDirectory v=20500 size=1 flags=0x10000(runtime) hashes=1' >&2 ;;
        -d) printf '<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict></dict></plist>' ;;
        --verify) ;;
        *) return 1 ;;
    esac
}
fake_xcrun() { [ "$1" = stapler ] && [ "$2" = validate ] && [ -d "$3" ]; }
fake_spctl() {
    echo "spctl $*" >>"$FAKE_LOG"
    local p=${!#}
    [ -d "$p" ] && [ -z "${FAKE_REJECT:-}" ] && return 0
    echo "$p: rejected (the code is valid but does not seem to be an app)" >&2
    return 3
}
SH
fake_check() { # fake_check <path> <identifier> [VAR=value...]
    local p=$1 id=$2
    shift 2
    : >"$tmp/spctl.log"
    # shellcheck disable=SC2016 # expanded by the inner bash
    env FAKE_ID="$id" FAKE_LOG="$tmp/spctl.log" "$@" bash -c 'set -euo pipefail; . "$1"; . "$2"; check_signed "$3" "$4"' _ "$tmp/fakes.sh" "$cs" "$p" "$id"
}
expect_ok "check-signed accepts a notarized bare executable (Gatekeeper never assesses one)" fake_check "$B/nazar-agent.app/Contents/MacOS/nazar" dev.nazar.cli
if [ -s "$tmp/spctl.log" ]; then bad "check-signed never asks Gatekeeper about a bare executable: $(cat "$tmp/spctl.log")"; else pass "check-signed never asks Gatekeeper about a bare executable"; fi
expect_ok "check-signed accepts a notarized bundle" fake_check "$B/nazar-agent.app" dev.nazar.agent
if grep -qxF "spctl --assess --type execute $B/nazar-agent.app" "$tmp/spctl.log"; then pass "check-signed asks Gatekeeper about a bundle"; else bad "check-signed asks Gatekeeper about a bundle: $(cat "$tmp/spctl.log")"; fi
expect_fail "check-signed refuses a bundle Gatekeeper rejects" "is not accepted by Gatekeeper" fake_check "$B/nazar-agent.app" dev.nazar.agent FAKE_REJECT=1

# zip: a ditto archive whose bundle keeps its signature.
Z="$tmp/zips"
mkdir -p "$Z"
expect_ok "zip archives the agent" "$rel" zip "$B/nazar-agent.app" "$Z/nazar-1.2.3.zip"
expect_ok "zip archives the UI (a name with a space)" "$rel" zip "$B/Nazar UI.app" "$Z/nazar-ui-1.2.3.zip"
mkdir -p "$tmp/x"
if (cd "$tmp/x" && /usr/bin/ditto -x -k "$Z/nazar-1.2.3.zip" . && /usr/bin/codesign --verify --strict --deep nazar-agent.app); then
    pass "the zipped agent unpacks to a bundle that still verifies"
else
    bad "the zipped agent unpacks to a bundle that still verifies"
fi
cp -R "$B/nazar-agent.app" "$tmp/broken.app"
printf x >>"$tmp/broken.app/Contents/MacOS/nazar-agent"
expect_fail "zip refuses a bundle whose seal is broken" "codesign --verify failed" "$rel" zip "$tmp/broken.app" "$Z/broken.zip"

# casks
C="$tmp/tap"
expect_ok "casks renders both casks" "$rel" casks 1.2.3 "$Z/nazar-1.2.3.zip" "$Z/nazar-ui-1.2.3.zip" "$C"
# (|| true: a missing zip is reported by the cases below, not by set -e.)
asha=$(shasum -a 256 "$Z/nazar-1.2.3.zip" 2>/dev/null | cut -d' ' -f1 || true)
usha=$(shasum -a 256 "$Z/nazar-ui-1.2.3.zip" 2>/dev/null | cut -d' ' -f1 || true)
n="$C/Casks/nazar.rb"
u="$C/Casks/nazar-ui.rb"
check_has() { # check_has <file> <text>
    if grep -qF -- "$2" "$1"; then pass "$(basename "$1") has $2"; else bad "$(basename "$1") lacks $2"; fi
}
# lacks <name> <grep args...> <file>: passes only when the file exists and
# nothing matches (grep rc 1); a missing file (rc 2) never passes.
lacks() {
    local name=$1 rc=0
    shift
    grep -q "$@" 2>/dev/null || rc=$?
    if [ "$rc" -eq 1 ]; then pass "$name"; else bad "$name (grep rc=$rc)"; fi
}
for want in 'cask "nazar" do' 'version "1.2.3"' "sha256 \"$asha\"" \
    'url "https://github.com/atas/nazar/releases/download/v#{version}/nazar-#{version}.zip"' \
    'binary "nazar-agent.app/Contents/MacOS/nazar"' 'binary "nazar-agent.app/Contents/MacOS/nazar", target: "nazar-sign-git"' \
    'binary "nazar-agent.app/Contents/MacOS/nazar", target: "git-credential-nazar"' \
    'args:         ["install", "--no-links"]' 'args:         ["uninstall"]' 'uninstall_preflight do' 'postflight do' \
    'depends_on arch: :arm64' 'depends_on macos: :tahoe'; do
    check_has "$n" "$want"
done
for want in 'cask "nazar-ui" do' 'version "1.2.3"' "sha256 \"$usha\"" \
    'url "https://github.com/atas/nazar/releases/download/v#{version}/nazar-ui-#{version}.zip"' \
    'app "Nazar UI.app"' 'depends_on arch: :arm64' 'depends_on macos: :tahoe'; do
    check_has "$u" "$want"
done
# nazar.rb keeps its two legacy flight blocks (brew style's Cask/InstallSteps
# wants *_steps, whose sandbox has a temporary HOME and no launchctl; the
# exact-stanza check below pins that there are two and no more), so brew
# style reports those two offenses and nothing else; it also forbids
# rubocop directives, hence 'rubocop:' in the never list.
lacks "nazar.rb has no *_steps stanza" -E '^ *(uninstall_)?(pre|post)flight_steps' "$n"
for f in "$n" "$u"; do
    lacks "$(basename "$f") has no placeholder left" '@[A-Z0-9_]*@' "$f"
    for never in 'app "nazar-agent.app"' 'sudo' 'launchctl' 'security ' 'rm -rf' 'Keychain"' 'zap trash: ["~/.config' 'rubocop:'; do
        lacks "$(basename "$f") has no $never" -F -- "$never" "$f"
    done
done
lacks "nazar.rb installs no app into /Applications" -F 'app "' "$n"
ruby=$(command -v ruby || true)
[ -n "$ruby" ] || ruby=$(ls /opt/homebrew/Library/Homebrew/vendor/portable-ruby/current/bin/ruby 2>/dev/null || true)
# The casks evaluated against a stand-in of Homebrew's cask DSL (Homebrew
# itself loads casks only from a tap, and no tap is added here): the
# stanzas each cask declares, in order, with their arguments. Blocks
# (postflight, uninstall_preflight) are recorded, not run.
cat >"$tmp/dsl.rb" <<'RUBY'
class StandIn
  attr_reader :log
  def initialize; @log = []; @version = nil; end
  def version(v = nil)
    return @version if v.nil?
    @version = v
    @log << "version #{v}"
  end
  def method_missing(name, *args, **kw, &blk)
    @log << ([name.to_s] + args.map(&:inspect) + kw.map { |k, v| "#{k}: #{v.inspect}" } + (blk ? ["{block}"] : [])).join(" ")
    nil
  end
  def respond_to_missing?(*) = true
end
def cask(token, &blk)
  s = StandIn.new
  s.instance_eval(&blk)
  puts "cask #{token}"
  puts s.log
end
load ARGV[0]
RUBY
if [ -n "$ruby" ]; then
    for f in "$n" "$u"; do
        if "$ruby" -c "$f" >/dev/null 2>&1; then pass "$(basename "$f") is valid Ruby"; else bad "$(basename "$f") is not valid Ruby"; fi
    done
    got=$("$ruby" "$tmp/dsl.rb" "$n" 2>&1 | grep -v '^caveats' || true)
    want="cask nazar
version 1.2.3
sha256 \"$asha\"
url \"https://github.com/atas/nazar/releases/download/v1.2.3/nazar-1.2.3.zip\"
name \"nazar\"
desc \"SSH agent with Secure Enclave keys and per-key caller rules\"
homepage \"https://github.com/atas/nazar\"
depends_on arch: :arm64
depends_on macos: :tahoe
binary \"nazar-agent.app/Contents/MacOS/nazar\"
binary \"nazar-agent.app/Contents/MacOS/nazar\" target: \"nazar-sign-git\"
binary \"nazar-agent.app/Contents/MacOS/nazar\" target: \"git-credential-nazar\"
postflight {block}
uninstall_preflight {block}"
    if [ "$got" = "$want" ]; then pass "nazar.rb declares exactly its stanzas"; else bad "nazar.rb stanzas: $got"; fi
    got=$("$ruby" "$tmp/dsl.rb" "$u" 2>&1 | grep -v '^caveats' || true)
    want="cask nazar-ui
version 1.2.3
sha256 \"$usha\"
url \"https://github.com/atas/nazar/releases/download/v1.2.3/nazar-ui-1.2.3.zip\"
name \"Nazar UI\"
desc \"Optional window for the nazar SSH agent\"
homepage \"https://github.com/atas/nazar\"
depends_on arch: :arm64
depends_on macos: :tahoe
app \"Nazar UI.app\"
zap trash: [\"~/Library/Preferences/dev.nazar.ui.plist\", \"~/Library/Saved Application State/dev.nazar.ui.savedState\"]"
    if [ "$got" = "$want" ]; then pass "nazar-ui.rb declares exactly its stanzas"; else bad "nazar-ui.rb stanzas: $got"; fi
else
    bad "no ruby to check the casks with (ruby on PATH, or Homebrew's portable Ruby)"
fi
# Before the first release: `-` for both zips, sha256 :no_check.
P="$tmp/prerelease"
expect_ok "casks renders unreleased casks" "$rel" casks 0.1.0 - - "$P"
for f in "$P/Casks/nazar.rb" "$P/Casks/nazar-ui.rb"; do
    if grep -qxF '  sha256 :no_check' "$f" && grep -qxF '  version "0.1.0"' "$f" && ! grep -q '@[A-Z0-9_]*@' "$f"; then
        pass "$(basename "$f"): unreleased cask says sha256 :no_check"
    else
        bad "$(basename "$f"): unreleased cask: $(grep -n 'sha256\|version' "$f")"
    fi
done
expect_fail "casks refuses a bad version" "version v1.2.3 is not MAJOR.MINOR.PATCH" "$rel" casks v1.2.3 "$Z/nazar-1.2.3.zip" "$Z/nazar-ui-1.2.3.zip" "$C"
expect_fail "casks refuses a missing zip" "no $Z/missing.zip" "$rel" casks 1.2.3 "$Z/missing.zip" "$Z/nazar-ui-1.2.3.zip" "$C"
expect_fail "an unknown subcommand prints the usage" "usage: release.sh" "$rel" sign 1.2.3

# The postflight and uninstall commands are real CLI commands (the CLI's
# own flag parser: --no-links exists for install, uninstall takes none).
if grep -qF '"no-links"' "$repo/cmd/nazar/install.go"; then pass "nazar install has --no-links"; else bad "nazar install has --no-links"; fi

# The tooling never signs, notarizes or uploads; make's release targets
# exist, sign nothing with a real identity and never start an app.
for never in 'codesign --sign' 'codesign --force' '--sign ' 'notarytool' 'gh release' 'curl ' 'git push'; do
    lacks "release.sh never runs $never" -F -- "$never" "$rel"
done
for t in release-prepare release-zips; do
    rc=0
    recipe=$(env -u MAKEFLAGS -u MFLAGS -u MAKELEVEL make -n -C "$repo" "$t" 2>&1) || rc=$?
    if [ "$rc" -ne 0 ]; then bad "make $t exists: $recipe"; continue; fi
    if grep -q 'Apple Development\|Developer ID\|notarytool' <<<"$recipe"; then bad "make $t never signs or notarizes with a real identity"; else pass "make $t never signs or notarizes with a real identity"; fi
    if grep -qF 'scripts/release.sh' <<<"$recipe"; then pass "make $t runs scripts/release.sh"; else bad "make $t runs scripts/release.sh"; fi
done

# release-sign.sh (make release): every refusal comes before anything is
# signed, and the dry run (ad hoc, no notary service) runs end to end. The
# identities below are never used: each case is refused first, and only
# NAZAR_SIGN_ID=- ever reaches codesign.
sgn="$here/release-sign.sh"
cdh() { /usr/bin/codesign -dvvv "$1" 2>&1 | sed -n 's/^CDHash=//p'; }
clean_env() { env -u NAZAR_SIGN_ID -u NAZAR_NOTARY_PROFILE -u DRY_RUN "$@"; }
devid='NAZAR_SIGN_ID=Developer ID Application: Example (ABCDE12345)'
S="$tmp/sign"
"$rel" prepare 1.2.3 "$B/nazar-agent.app" "$B/Nazar UI.app" "$S" >/dev/null
cli_before=$(cdh "$S/nazar-agent.app/Contents/MacOS/nazar")
agent_before=$(cdh "$S/nazar-agent.app")
expect_fail "release-sign refuses a missing identity" "NAZAR_SIGN_ID is not set" clean_env "$sgn" 1.2.3 "$S"
expect_fail "release-sign refuses an empty identity" "NAZAR_SIGN_ID is not set" clean_env NAZAR_SIGN_ID= DRY_RUN=1 "$sgn" 1.2.3 "$S"
expect_fail "release-sign refuses a missing identity before the build (no folder)" "NAZAR_SIGN_ID is not set" clean_env "$sgn" 1.2.3
expect_fail "release-sign refuses ad hoc for a release" "is never released: add DRY_RUN=1" clean_env NAZAR_SIGN_ID=- NAZAR_NOTARY_PROFILE=nazar "$sgn" 1.2.3 "$S"
expect_fail "release-sign refuses an Apple Development identity" "must be a Developer ID Application identity" \
    clean_env 'NAZAR_SIGN_ID=Apple Development: Example (ABCDE12345)' NAZAR_NOTARY_PROFILE=nazar "$sgn" 1.2.3 "$S"
expect_fail "release-sign refuses to notarize without a profile" "NAZAR_NOTARY_PROFILE is not set" clean_env "$devid" "$sgn" 1.2.3 "$S"
expect_fail "release-sign refuses an empty profile" "NAZAR_NOTARY_PROFILE is not set" clean_env "$devid" NAZAR_NOTARY_PROFILE= DRY_RUN=0 "$sgn" 1.2.3 "$S"
expect_fail "release-sign refuses no profile before the build (no folder)" "NAZAR_NOTARY_PROFILE is not set" clean_env "$devid" "$sgn" 1.2.3
expect_fail "release-sign refuses a DRY_RUN that is not 0 or 1" "DRY_RUN must be 0 or 1" clean_env NAZAR_SIGN_ID=- DRY_RUN=yes "$sgn" 1.2.3 "$S"
expect_fail "release-sign refuses a bad version" "version 1.2 is not MAJOR.MINOR.PATCH" clean_env NAZAR_SIGN_ID=- DRY_RUN=1 "$sgn" 1.2 "$S"
expect_fail "release-sign refuses bundles of another version" "says version 1.2.3, not 1.2.4" clean_env NAZAR_SIGN_ID=- DRY_RUN=1 "$sgn" 1.2.4 "$S"
expect_fail "release-sign refuses a UI that still pins a development CLI" "still pins a development CLI build" clean_env NAZAR_SIGN_ID=- DRY_RUN=1 "$sgn" 1.2.3 "$B"
# A release builds from the tag on a clean tree: the script run from a
# copy in a repository of its own (no commit, no tag; git's global and
# system config ignored, so nothing of the developer's is read).
G="$tmp/repo"
mkdir -p "$G/scripts"
cp "$sgn" "$rel" "$G/scripts/"
GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1 git -C "$G" init -q
expect_fail "release-sign refuses a tree with uncommitted changes" "the tree has uncommitted changes" \
    clean_env GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1 "$devid" NAZAR_NOTARY_PROFILE=nazar "$G/scripts/release-sign.sh" 1.2.3 "$S"
echo '*' >"$G/.git/info/exclude"
expect_fail "release-sign refuses a HEAD not tagged vVERSION" "HEAD is not tagged v1.2.3" \
    clean_env GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1 "$devid" NAZAR_NOTARY_PROFILE=nazar "$G/scripts/release-sign.sh" 1.2.3 "$S"
if [ "$(cdh "$S/nazar-agent.app/Contents/MacOS/nazar")" = "$cli_before" ] && [ "$(cdh "$S/nazar-agent.app")" = "$agent_before" ] &&
    ! compgen -G "$S/*.zip" >/dev/null && [ ! -e "$S/Casks" ]; then
    pass "a refused release-sign signed and wrote nothing"
else
    bad "a refused release-sign signed or wrote something"
fi
# Code anywhere but the three executables is refused.
X="$tmp/extra"
"$rel" prepare 1.2.3 "$B/nazar-agent.app" "$B/Nazar UI.app" "$X" >/dev/null
mkdir -p "$X/nazar-agent.app/Contents/Resources"
cp "$bin/app" "$X/nazar-agent.app/Contents/Resources/helper"
expect_fail "release-sign refuses an unexpected Mach-O" "has unexpected code: Contents/Resources/helper" clean_env NAZAR_SIGN_ID=- DRY_RUN=1 "$sgn" 1.2.3 "$X"

# The dry run, end to end.
expect_ok "release-sign DRY_RUN=1 signs ad hoc, zips and renders the casks" clean_env NAZAR_SIGN_ID=- DRY_RUN=1 "$sgn" 1.2.3 "$S"
dry_out=$out
for want in 'DRY_RUN=1: not notarizing or stapling' 'DRY RUN: signed as - and not notarized' 'nazar     sha256 ' 'nazar-ui  sha256 '; do
    if grep -qF -- "$want" <<<"$dry_out"; then pass "dry run says $want"; else bad "dry run lacks $want"; fi
done
if grep -q 'notarytool\|stapler staple' <<<"$dry_out"; then bad "dry run never notarizes"; else pass "dry run never notarizes"; fi
asha=$(shasum -a 256 "$S/nazar-1.2.3.zip" 2>/dev/null | cut -d' ' -f1 || true)
usha=$(shasum -a 256 "$S/nazar-ui-1.2.3.zip" 2>/dev/null | cut -d' ' -f1 || true)
if [ -n "$asha" ] && grep -qF "nazar     sha256 $asha" <<<"$dry_out" && [ -n "$usha" ] && grep -qF "nazar-ui  sha256 $usha" <<<"$dry_out"; then
    pass "dry run prints the zips' sha256"
else
    bad "dry run prints the zips' sha256"
fi
check_has "$S/Casks/nazar.rb" "sha256 \"$asha\""
check_has "$S/Casks/nazar.rb" 'version "1.2.3"'
check_has "$S/Casks/nazar-ui.rb" "sha256 \"$usha\""
check_has "$S/Casks/nazar-ui.rb" 'version "1.2.3"'
mkdir -p "$tmp/dry"
if (cd "$tmp/dry" && /usr/bin/ditto -x -k "$S/nazar-1.2.3.zip" . && /usr/bin/ditto -x -k "$S/nazar-ui-1.2.3.zip" . &&
    /usr/bin/codesign --verify --strict --deep nazar-agent.app && /usr/bin/codesign --verify --strict --deep "Nazar UI.app"); then
    pass "the dry run's zips unpack to bundles that verify"
else
    bad "the dry run's zips unpack to bundles that verify"
fi
sig_has() { # sig_has <path> <identifier>
    local sig
    sig=$(/usr/bin/codesign -dvv "$1" 2>&1 || true)
    if grep -qxF "Identifier=$2" <<<"$sig" && grep -qE 'flags=0x[0-9a-f]+\([a-z,-]*runtime' <<<"$sig"; then
        pass "dry run signs $2 with the hardened runtime"
    else
        bad "dry run signs $2 with the hardened runtime: $sig"
    fi
}
sig_has "$tmp/dry/nazar-agent.app/Contents/MacOS/nazar" dev.nazar.cli
sig_has "$tmp/dry/nazar-agent.app" dev.nazar.agent
sig_has "$tmp/dry/Nazar UI.app" dev.nazar.ui
# The dry run's bundles are ad hoc: what renders the tap refuses them.
expect_fail "check-signed refuses the dry run's agent" "is not signed with a Developer ID Application certificate" "$rel" check-signed "$S/nazar-agent.app" dev.nazar.agent

# release-sign.sh signs only as NAZAR_SIGN_ID and never uploads or pushes.
lacks "release-sign.sh never uploads, pushes or runs security" -E 'gh release|git push|curl |security |--keychain ' "$sgn"
# shellcheck disable=SC2016 # the literal text "$id"
if grep -- '--sign' "$sgn" | grep -v '^ *#' | grep -qvF -- '--sign "$id"'; then bad "release-sign.sh signs only as \$NAZAR_SIGN_ID"; else pass "release-sign.sh signs only as \$NAZAR_SIGN_ID"; fi
# make release checks the variables before it builds anything, and the
# rendering into a tap checks the signatures first.
rc=0
recipe=$(env -u MAKEFLAGS -u MFLAGS -u MAKELEVEL -u NAZAR_SIGN_ID make -n -C "$repo" release 2>&1) || rc=$?
first=$(grep -m1 -F 'scripts/' <<<"$recipe" || true)
if [ "$rc" -eq 0 ] && grep -qF 'scripts/release-sign.sh 0.' <<<"$first" && grep -qF 'scripts/release.sh prepare' <<<"$recipe" &&
    grep -qF 'scripts/release-sign.sh' <<<"$(tail -1 <<<"$recipe")"; then
    pass "make release checks, prepares, then signs"
else
    bad "make release checks, prepares, then signs: rc=$rc $recipe"
fi
if grep -q 'Apple Development:\|Developer ID Application:\|notarytool' <<<"$recipe"; then bad "make release names no identity"; else pass "make release names no identity"; fi
rc=0
mout=$(env -u MAKEFLAGS -u MFLAGS -u MAKELEVEL -u NAZAR_SIGN_ID -u NAZAR_NOTARY_PROFILE -u DRY_RUN make -C "$repo" release 2>&1) || rc=$?
if [ "$rc" -ne 0 ] && grep -qF 'NAZAR_SIGN_ID is not set' <<<"$mout" && ! grep -q 'go build\|swift build' <<<"$mout"; then
    pass "make release refuses a missing identity before building"
else
    bad "make release refuses a missing identity before building: rc=$rc $mout"
fi
rc=0
recipe=$(env -u MAKEFLAGS -u MFLAGS -u MAKELEVEL make -n -C "$repo" release-tap TAP=/nonexistent 2>&1) || rc=$?
if [ "$rc" -eq 0 ] && [ "$(grep -c 'release.sh check-signed' <<<"$recipe")" -eq 3 ] &&
    [ "$(grep -n 'release.sh' <<<"$recipe" | tail -1 | grep -c 'release.sh casks')" -eq 1 ]; then
    pass "make release-tap checks all three signatures, then renders"
else
    bad "make release-tap checks all three signatures, then renders: $recipe"
fi
rc=0
mout=$(env -u MAKEFLAGS -u MFLAGS -u MAKELEVEL make -C "$repo" release-tap TAP="$tmp/notatap" 2>&1) || rc=$?
if [ "$rc" -ne 0 ] && grep -qF 'TAP=path to a tap checkout' <<<"$mout"; then pass "make release-tap refuses a folder that is not a tap"; else bad "make release-tap refuses a folder that is not a tap: $mout"; fi
# Only the release workflow signs, notarizes or releases; it runs on main
# only (a schedule or a manual run, never a pull request or a push), and
# only its job in the `release` environment gets the signing secrets.
lacks "no other workflow signs, notarizes or releases" -rE --exclude=release.yml 'release-sign|make release|notarytool|NAZAR_SIGN_ID|NAZAR_NOTARY_PROFILE|codesign|stapler|DEVELOPER_ID|NOTARY_API_KEY|TAP_DEPLOY_KEY' "$repo/.github"
wf="$repo/.github/workflows/release.yml"
trig=$(awk '/^on:/{on=1; next} on && /^[^ ]/{exit} on' "$wf" | grep -E '^ {4}[a-z_]+:' || true)
if [ "$(printf '%s\n' "$trig" | sed 's/ //g' | sort | tr '\n' ' ')" = "schedule: workflow_dispatch: " ] &&
    grep -qE '^ +environment: release$' "$wf" && [ "$(grep -cE '^ +environment:' "$wf")" -eq 1 ]; then
    pass "the release workflow runs only on a schedule or by hand, in the release environment"
else
    bad "the release workflow runs only on a schedule or by hand, in the release environment: $trig"
fi

echo "release_test: $passes passed, $failures failed"
[ "$failures" -eq 0 ]
