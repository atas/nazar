#!/bin/bash
# release-linux.sh: the Linux half of a release (docs/RELEASING.md). It needs
# no secret, signs nothing (checksums only in v1) and never uploads or pushes;
# release.yml does those.
#
#   release-linux.sh tarballs VERSION OUTDIR
#       on Linux, empties OUTDIR and builds nazar and nazar-agent for amd64
#       and arm64 (static, no cgo). It refuses a build that go version -m
#       shows was made with -tags or cgo, or for another machine: a test build
#       must never ship. It packs nazar-VERSION-linux-ARCH/{nazar,nazar-agent,
#       LICENSE,README.md} into OUTDIR/nazar-VERSION-linux-ARCH.tar.gz, copies
#       scripts/install.sh to OUTDIR/install.sh and writes OUTDIR/SHA256SUMS.
#       The same source and toolchain give the same bytes.
#   release-linux.sh formula VERSION SHA256SUMS TAPDIR
#       renders packaging/homebrew/nazar-linux.rb.in into
#       TAPDIR/nazar-linux.rb with VERSION and the two tarballs' sums. At the
#       tap's root, never under Formula/: the tap keeps its other formulae
#       at the root, and Homebrew reads a tap's formulae from Formula/ alone
#       once that folder exists (tap.rb, formula_dir), so making it would
#       hide them from every Mac.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
repo=$(dirname "$here")
fail() { echo "release-linux: $*" >&2; exit 1; }
usage="usage: release-linux.sh tarballs VERSION OUTDIR | formula VERSION SHA256SUMS TAPDIR"

check_version() { # check_version <VERSION>
    [[ "$1" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail "version $1 is not MAJOR.MINOR.PATCH"
}

# check_build <binary> <arch>: what go version -m says the binary was built
# with. Reads the file only; the binary may be for another machine.
check_build() {
    local bin=$1 arch=$2 info
    info=$(go version -m "$bin") || fail "$bin: go version -m failed"
    if grep -qE '^[[:space:]]+build[[:space:]]+-tags=' <<<"$info"; then
        fail "$bin was built with -tags; a release build takes none"
    fi
    if grep -qE '^[[:space:]]+build[[:space:]]+CGO_ENABLED=1$' <<<"$info"; then
        fail "$bin was built with CGO_ENABLED=1; a release build is static"
    fi
    grep -qE '^[[:space:]]+build[[:space:]]+CGO_ENABLED=0$' <<<"$info" || fail "$bin does not say CGO_ENABLED=0"
    grep -qE "^[[:space:]]+build[[:space:]]+GOOS=linux\$" <<<"$info" || fail "$bin does not say GOOS=linux"
    grep -qE "^[[:space:]]+build[[:space:]]+GOARCH=$arch\$" <<<"$info" || fail "$bin does not say GOARCH=$arch"
}

tarballs() {
    local version=$1 out=$2 arch cmd bin work folder
    check_version "$version"
    # GNU tar's flags and sha256sum; a Mac has neither. make linux-run has both.
    [ "$(uname)" = Linux ] || fail "tarballs runs on Linux"
    rm -rf "$out"
    mkdir -p "$out"
    out=$(cd "$out" && pwd)
    work=$(mktemp -d "${TMPDIR:-/tmp}/nz-tarballs.XXXXXX")
    # shellcheck disable=SC2064 # the folder is known now
    trap "rm -rf '$work'" EXIT
    for arch in amd64 arm64; do
        folder="nazar-$version-linux-$arch"
        mkdir -p "$work/$folder"
        for cmd in nazar nazar-agent; do
            bin="$work/$folder/$cmd"
            (cd "$repo" && CGO_ENABLED=0 GOOS=linux GOARCH=$arch \
                go build -trimpath -ldflags "-s -w -X main.version=$version" -o "$bin" "./cmd/$cmd")
            check_build "$bin" "$arch"
        done
        cp "$repo/LICENSE" "$repo/README.md" "$work/$folder/"
        chmod 0755 "$work/$folder/nazar" "$work/$folder/nazar-agent"
        chmod 0644 "$work/$folder/LICENSE" "$work/$folder/README.md"
        # Named one by one, so the tarball holds exactly these four paths.
        tar -C "$work" --format=ustar --owner=0 --group=0 --numeric-owner --mtime=@0 -cf - \
            "$folder/LICENSE" "$folder/README.md" "$folder/nazar" "$folder/nazar-agent" |
            gzip -n -9 >"$work/$folder.tar.gz"
    done
    cp "$here/install.sh" "$out/install.sh"
    chmod 0755 "$out/install.sh"
    for arch in amd64 arm64; do
        mv "$work/nazar-$version-linux-$arch.tar.gz" "$out/"
    done
    (cd "$out" && sha256sum install.sh "nazar-$version-linux-amd64.tar.gz" "nazar-$version-linux-arm64.tar.gz" >SHA256SUMS)
    echo "release-linux: $out"
    cat "$out/SHA256SUMS"
}

# sum_of <SHA256SUMS> <file>: the file's sum, or nothing unless it is a sha256.
sum_of() {
    awk -v f="$2" '$2 == f && $1 ~ /^[0-9a-f]+$/ && length($1) == 64 { print $1 }' "$1"
}

formula() {
    local version=$1 sums=$2 tap=$3 amd arm tmpl rb
    check_version "$version"
    [ -f "$sums" ] || fail "no $sums"
    amd=$(sum_of "$sums" "nazar-$version-linux-amd64.tar.gz")
    arm=$(sum_of "$sums" "nazar-$version-linux-arm64.tar.gz")
    [ -n "$amd" ] || fail "$sums has no valid sum for nazar-$version-linux-amd64.tar.gz"
    [ -n "$arm" ] || fail "$sums has no valid sum for nazar-$version-linux-arm64.tar.gz"
    tmpl="$repo/packaging/homebrew/nazar-linux.rb.in"
    mkdir -p "$tap"
    rb="$tap/nazar-linux.rb"
    sed -e "s/@VERSION@/$version/g" -e "s/@AMD64_SHA256@/$amd/g" -e "s/@ARM64_SHA256@/$arm/g" "$tmpl" >"$rb.tmp"
    if grep -q '@' "$rb.tmp"; then
        rm -f "$rb.tmp"
        fail "$tmpl still has a placeholder"
    fi
    mv "$rb.tmp" "$rb"
    echo "release-linux: $rb"
}

cmd=${1:-}
shift || true
case $cmd in
    tarballs) [ $# -eq 2 ] || fail "$usage"; tarballs "$@" ;;
    formula) [ $# -eq 3 ] || fail "$usage"; formula "$@" ;;
    *) fail "$usage" ;;
esac
