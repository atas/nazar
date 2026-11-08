#!/bin/bash
# release-sign.sh VERSION [DIR] — signs, notarizes and staples the two bundles
# `release.sh prepare` copied to DIR, verifies them, zips them and renders
# the casks (spec 12; docs/RELEASING.md). `make release` runs it. A person
# runs it, on their Mac, with the Developer ID certificate in their login
# keychain; CI and the tests never give it a real identity.
#
#   NAZAR_SIGN_ID         the identity: "Developer ID Application: NAME (TEAMID)",
#                         or - (ad hoc) with DRY_RUN=1
#   NAZAR_NOTARY_PROFILE  the notarytool keychain profile
#                         (xcrun notarytool store-credentials); not read with DRY_RUN=1
#   DRY_RUN=1             signs and zips, but does not notarize or staple, and
#                         reports Gatekeeper and the ticket without requiring
#                         them: the path end to end, never a release
#
# Signing is inside out: the CLI inside the agent first (as dev.nazar.cli,
# so the agent's seal covers it), then the agent, then the UI. Every
# signature has the hardened runtime and a secure timestamp and no
# entitlements: the apps need none (check-agent.sh, check-ui.sh and
# `release.sh check-signed` refuse any). A release also needs HEAD tagged
# vVERSION and a clean tree, so the zips are that tag's source. Without
# DIR it only makes those checks (make release runs them before building).
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
repo=$(dirname "$here")
rel="$here/release.sh"
fail() { echo "release: $*" >&2; exit 1; }
say() { echo "release: $*"; }
[ $# -eq 1 ] || [ $# -eq 2 ] || fail "usage: release-sign.sh VERSION [DIR]"
version=$1 dir=${2:-}
id=${NAZAR_SIGN_ID:-}
profile=${NAZAR_NOTARY_PROFILE:-}
dry=${DRY_RUN:-0}
agent="$dir/nazar-agent.app"
ui="$dir/Nazar UI.app"
cli="$agent/Contents/MacOS/nazar"

# Everything that can refuse does so before anything is signed.
case $dry in 0 | 1) ;; *) fail "DRY_RUN must be 0 or 1, not $dry" ;; esac
[ -n "$id" ] || fail "NAZAR_SIGN_ID is not set (\"Developer ID Application: NAME (TEAMID)\", or - with DRY_RUN=1)"
if [ "$id" = - ]; then
    [ "$dry" = 1 ] || fail "an ad-hoc signature (NAZAR_SIGN_ID=-) is never released: add DRY_RUN=1 to test the path"
elif ! [[ "$id" =~ ^Developer\ ID\ Application:\ .+\ \([A-Z0-9]{10}\)$ ]]; then
    fail "NAZAR_SIGN_ID must be a Developer ID Application identity (\"Developer ID Application: NAME (TEAMID)\"), not \"$id\""
fi
if [ "$dry" = 0 ] && [ -z "$profile" ]; then
    fail "NAZAR_NOTARY_PROFILE is not set: a release is notarized (xcrun notarytool store-credentials; docs/RELEASING.md)"
fi
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail "version $version is not MAJOR.MINOR.PATCH"
if [ "$dry" = 0 ]; then
    [ -z "$(git -C "$repo" status --porcelain 2>/dev/null)" ] || fail "the tree has uncommitted changes: release from the tag v$version"
    tags=$(git -C "$repo" tag --points-at HEAD 2>/dev/null || true)
    grep -qxF "v$version" <<<"$tags" || fail "HEAD is not tagged v$version"
fi
if [ -z "$dir" ]; then
    say "ready to sign $version as $id$([ "$dry" = 1 ] && echo ' (DRY_RUN=1)' || true)"
    exit 0
fi
[ -d "$agent" ] && [ -d "$ui" ] || fail "no $agent or $ui (run release.sh prepare first)"
pv() { /usr/bin/plutil -extract CFBundleShortVersionString raw -o - "$1/Contents/Info.plist" 2>/dev/null || true; }
[ "$(pv "$agent")" = "$version" ] || fail "$agent says version $(pv "$agent"), not $version"
[ "$(pv "$ui")" = "$version" ] || fail "$ui says version $(pv "$ui"), not $version"
if /usr/bin/plutil -extract NazarDevCLICDHash raw -o - "$ui/Contents/Info.plist" >/dev/null 2>&1; then
    fail "$ui still pins a development CLI build (run release.sh prepare)"
fi
# The only code in the bundles is the three executables signed below: a
# Mach-O anywhere else would ship unsigned or sealed as a plain file.
macho() { # macho <bundle> <expected relative path...>
    local b=$1 f p want ok
    shift
    while IFS= read -r -d '' f; do
        case $(/usr/bin/file -b "$f") in *Mach-O*) ;; *) continue ;; esac
        p=${f#"$b/"} ok=0
        for want in "$@"; do
            if [ "$p" = "$want" ]; then ok=1; fi
        done
        [ "$ok" = 1 ] || fail "$b has unexpected code: $p"
    done < <(find "$b" -type f -print0)
}
macho "$agent" Contents/MacOS/nazar-agent Contents/MacOS/nazar
macho "$ui" Contents/MacOS/NazarUI

sign=(/usr/bin/codesign --force --sign "$id" --options runtime)
if [ "$id" = - ]; then sign+=(--timestamp=none); else sign+=(--timestamp); fi
say "signing as $id"
"${sign[@]}" --identifier dev.nazar.cli "$cli"
"${sign[@]}" "$agent"
"${sign[@]}" "$ui"

check_sig() { # check_sig <path> <identifier>
    local sig
    sig=$(/usr/bin/codesign -dvv "$1" 2>&1) || fail "$1 is not signed"
    grep -qxF "Identifier=$2" <<<"$sig" || fail "$1 is not signed as $2"
    grep -qE 'flags=0x[0-9a-f]+\([a-z,-]*runtime' <<<"$sig" || fail "$1 lacks the hardened runtime"
    /usr/bin/codesign --verify --strict --deep "$1" || fail "$1: codesign --verify --strict --deep failed"
}
check_sig "$cli" dev.nazar.cli
check_sig "$agent" dev.nazar.agent
check_sig "$ui" dev.nazar.ui

# One submission per bundle: notarytool takes a zip, and the ticket is
# stapled to the bundle, which is zipped again for the release.
notarize() { # notarize <bundle> <name>
    local b=$1 z="$dir/notarize-$2.zip" out sid
    rm -f "$z"
    /usr/bin/ditto -c -k --sequesterRsrc --keepParent "$b" "$z"
    say "notarizing $2 (this waits for Apple)"
    out=$(/usr/bin/xcrun notarytool submit "$z" --keychain-profile "$profile" --wait 2>&1) || true
    echo "$out"
    rm -f "$z"
    sid=$(sed -n 's/^ *id: //p' <<<"$out" | head -1)
    grep -qE '^ *status: Accepted' <<<"$out" ||
        fail "$2 was not accepted by the notary service (xcrun notarytool log ${sid:-ID} --keychain-profile \"$profile\")"
    /usr/bin/xcrun stapler staple "$b" || fail "$b: stapler staple failed"
}
if [ "$dry" = 0 ]; then
    notarize "$agent" nazar
    notarize "$ui" nazar-ui
else
    say "DRY_RUN=1: not notarizing or stapling"
fi

# What Gatekeeper and the stapler say; required for a release.
gate() { # gate <bundle>
    local out rc=0
    out=$(/usr/sbin/spctl -a -vv -t exec "$1" 2>&1) || rc=$?
    echo "$out"
    if [ "$dry" = 0 ] && { [ "$rc" -ne 0 ] || ! grep -qxF 'source=Notarized Developer ID' <<<"$out"; }; then
        fail "$1 is not accepted by Gatekeeper as Notarized Developer ID"
    fi
    rc=0
    out=$(/usr/bin/xcrun stapler validate "$1" 2>&1) || rc=$?
    echo "$out"
    if [ "$dry" = 0 ] && [ "$rc" -ne 0 ]; then fail "$1 has no valid stapled ticket"; fi
}
[ "$dry" = 0 ] || say "DRY_RUN=1: Gatekeeper and the stapler are expected to refuse an unnotarized build"
gate "$agent"
gate "$ui"

az="$dir/nazar-$version.zip"
uz="$dir/nazar-ui-$version.zip"
if [ "$dry" = 0 ]; then
    "$rel" zips "$version" "$dir" # check-signed all three, then the zips and casks
else
    "$rel" zip "$agent" "$az"
    "$rel" zip "$ui" "$uz"
    "$rel" casks "$version" "$az" "$uz" "$dir"
fi
echo
say "for the casks (version $version):"
echo "  nazar     sha256 $(/usr/bin/shasum -a 256 "$az" | cut -d' ' -f1)  $az"
echo "  nazar-ui  sha256 $(/usr/bin/shasum -a 256 "$uz" | cut -d' ' -f1)  $uz"
if [ "$dry" = 1 ]; then
    say "DRY RUN: signed as $id and not notarized; never upload these zips or render them into the tap"
else
    say "next: docs/RELEASING.md, \"Publish\""
fi
