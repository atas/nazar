#!/bin/bash
# release.sh — the release tooling for the two packages (spec 12,
# Milestone 6): nazar (nazar-agent.app with the CLI inside) and nazar-ui
# (Nazar UI.app). It never signs and never notarizes: signing with the
# Developer ID certificate, notarizing and stapling are release-sign.sh's
# (`make release`, run by a person; docs/RELEASING.md), between `prepare`
# and `zips`.
#
#   release.sh prepare VERSION AGENT UI OUTDIR
#       copies the two ad-hoc bundles `make agent ui` built into OUTDIR for
#       signing, after checking that both say VERSION, and removes the UI's
#       development pin (NazarDevCLICDHash: a release trusts the CLI by
#       team, never by a cdhash). The copies' seals are then broken on
#       purpose: they must be signed before anything else.
#   release.sh check-signed BUNDLE IDENTIFIER
#       refuses BUNDLE unless it is signed with a Developer ID Application
#       certificate as IDENTIFIER, with the hardened runtime and a secure
#       timestamp, carries no entitlements, is notarized with the ticket
#       stapled, and Gatekeeper accepts it. Reads only. A bare executable
#       (the CLI inside the agent) gets every check but the stapled ticket
#       and Gatekeeper: a ticket staples to a bundle, never to a Mach-O,
#       Gatekeeper rejects any bare Mach-O as "not an app", and the agent's
#       ticket and assessment cover the CLI it contains.
#   release.sh zip BUNDLE OUT.zip
#       zips BUNDLE (ditto, as Homebrew and Apple's notary service expect) and prints
#       its sha256.
#   release.sh casks VERSION AGENT.zip|- UI.zip|- OUTDIR
#       renders OUTDIR/Casks/nazar.rb and nazar-ui.rb from
#       packaging/homebrew/*.rb.in with VERSION and the zips' sha256; `-`
#       for a zip not released yet writes `sha256 :no_check` (the tap's
#       first casks, before the first release; that release
#       renders them again with the real zips).
#   release.sh zips VERSION OUTDIR
#       check-signed both bundles in OUTDIR (and the CLI inside the agent),
#       zips them as nazar-VERSION.zip and nazar-ui-VERSION.zip and renders
#       the casks next to them.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
repo=$(dirname "$here")
fail() { echo "release: $*" >&2; exit 1; }
agent_name=nazar-agent.app
ui_name="Nazar UI.app"

check_version() { # check_version <VERSION>
    [[ "$1" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail "version $1 is not MAJOR.MINOR.PATCH"
}
plist_version() { /usr/bin/plutil -extract CFBundleShortVersionString raw -o - "$1/Contents/Info.plist" 2>/dev/null || true; }

prepare() {
    local version=$1 agent=$2 ui=$3 out=$4
    check_version "$version"
    [ -d "$agent" ] && [ -d "$ui" ] || fail "usage: release.sh prepare VERSION AGENT UI OUTDIR"
    [ "$(plist_version "$agent")" = "$version" ] || fail "$agent says version $(plist_version "$agent"), not $version"
    [ "$(plist_version "$ui")" = "$version" ] || fail "$ui says version $(plist_version "$ui"), not $version"
    local v
    v=$("$agent/Contents/MacOS/nazar" version 2>/dev/null || true)
    [ "$v" = "nazar $version" ] || fail "$agent/Contents/MacOS/nazar says \"$v\", not \"nazar $version\""
    rm -rf "$out"
    mkdir -p "$out"
    /usr/bin/ditto "$agent" "$out/$agent_name"
    /usr/bin/ditto "$ui" "$out/$ui_name"
    /usr/bin/plutil -remove NazarDevCLICDHash "$out/$ui_name/Contents/Info.plist" 2>/dev/null || true
    echo "release: $out/$agent_name and $out/$ui_name are ready to sign (docs/RELEASING.md)"
}

check_signed() {
    local b=$1 id=$2 sig ent
    sig=$(/usr/bin/codesign -dvv "$b" 2>&1) || fail "$b is not signed"
    grep -qxF "Identifier=$id" <<<"$sig" || fail "$b is not signed as $id"
    grep -q '^Authority=Developer ID Application: ' <<<"$sig" || fail "$b is not signed with a Developer ID Application certificate"
    grep -q '^Timestamp=' <<<"$sig" || fail "$b has no secure timestamp (codesign --timestamp)"
    grep -qE 'flags=0x10000\(runtime\)' <<<"$sig" || fail "$b lacks the hardened runtime (and only it)"
    ent=$(/usr/bin/codesign -d --entitlements - --xml "$b" 2>/dev/null) || fail "$b: cannot read entitlements"
    if grep -q '<key>' <<<"$ent"; then fail "$b has entitlements"; fi
    /usr/bin/codesign --verify --strict --deep "$b" || fail "$b: codesign --verify failed"
    # A bare executable's bundle carries the ticket, and Gatekeeper assesses
    # only bundles (spctl rejects any bare Mach-O as "not an app").
    if [ -d "$b" ]; then
        /usr/bin/xcrun stapler validate "$b" >/dev/null 2>&1 || fail "$b has no stapled notarization ticket"
        /usr/sbin/spctl --assess --type execute "$b" 2>/dev/null || fail "$b is not accepted by Gatekeeper"
    fi
}

zip_bundle() {
    local b=$1 out=$2
    [ -d "$b" ] || fail "no bundle $b"
    /usr/bin/codesign --verify --strict --deep "$b" || fail "$b: codesign --verify failed"
    rm -f "$out"
    /usr/bin/ditto -c -k --sequesterRsrc --keepParent "$b" "$out"
    /usr/bin/shasum -a 256 "$out"
}

sha() { /usr/bin/shasum -a 256 "$1" | cut -d' ' -f1; }

# shalit <zip|->: the sha256 stanza's value for a zip, or :no_check.
shalit() {
    if [ "$1" = - ]; then echo ':no_check'; else echo "\"$(sha "$1")\""; fi
}

render() { # render <template> <out> <VERSION> <agent sha256 value> <ui sha256 value>
    sed -e "s/@VERSION@/$3/g" -e "s/\"@AGENT_SHA256@\"/$4/g" -e "s/\"@UI_SHA256@\"/$5/g" "$1" >"$2"
    if grep -q '@[A-Z0-9_]*@' "$2"; then fail "$2 still has a placeholder"; fi
}

casks() {
    local version=$1 agentzip=$2 uizip=$3 out=$4
    check_version "$version"
    [ "$agentzip" = - ] || [ -f "$agentzip" ] || fail "no $agentzip"
    [ "$uizip" = - ] || [ -f "$uizip" ] || fail "no $uizip"
    mkdir -p "$out/Casks"
    local a u
    a=$(shalit "$agentzip")
    u=$(shalit "$uizip")
    render "$repo/packaging/homebrew/nazar.rb.in" "$out/Casks/nazar.rb" "$version" "$a" "$u"
    render "$repo/packaging/homebrew/nazar-ui.rb.in" "$out/Casks/nazar-ui.rb" "$version" "$a" "$u"
    echo "release: $out/Casks/nazar.rb (sha256 $a) and $out/Casks/nazar-ui.rb (sha256 $u)"
}

zips() {
    local version=$1 dir=$2
    check_version "$version"
    check_signed "$dir/$agent_name" dev.nazar.agent
    check_signed "$dir/$agent_name/Contents/MacOS/nazar" dev.nazar.cli
    check_signed "$dir/$ui_name" dev.nazar.ui
    if /usr/bin/plutil -extract NazarDevCLICDHash raw -o - "$dir/$ui_name/Contents/Info.plist" >/dev/null 2>&1; then
        fail "$dir/$ui_name still pins a development CLI build (run release.sh prepare)"
    fi
    zip_bundle "$dir/$agent_name" "$dir/nazar-$version.zip"
    zip_bundle "$dir/$ui_name" "$dir/nazar-ui-$version.zip"
    casks "$version" "$dir/nazar-$version.zip" "$dir/nazar-ui-$version.zip" "$dir"
}

cmd=${1:-}
shift || true
case $cmd in
    prepare) [ $# -eq 4 ] || fail "usage: release.sh prepare VERSION AGENT UI OUTDIR"; prepare "$@" ;;
    check-signed) [ $# -eq 2 ] || fail "usage: release.sh check-signed BUNDLE IDENTIFIER"; check_signed "$@"; echo "release: $1 is signed for release" ;;
    zip) [ $# -eq 2 ] || fail "usage: release.sh zip BUNDLE OUT.zip"; zip_bundle "$@" ;;
    casks) [ $# -eq 4 ] || fail "usage: release.sh casks VERSION AGENT.zip UI.zip OUTDIR"; casks "$@" ;;
    zips) [ $# -eq 2 ] || fail "usage: release.sh zips VERSION OUTDIR"; zips "$@" ;;
    *) fail "usage: release.sh prepare|check-signed|zip|casks|zips …" ;;
esac
