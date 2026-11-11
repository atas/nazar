#!/bin/sh
# install.sh [VERSION]: installs nazar for Linux (a preview) into your home.
# It downloads a release's tarball and SHA256SUMS, refuses a checksum
# mismatch, extracts to ~/.local/lib/nazar/VERSION and links ~/.local/bin/nazar.
# It never runs sudo: it prints the commands to run next. With no VERSION it
# takes the latest release.
#
# NAZAR_RELEASE_URL replaces https://github.com/atas/nazar/releases/download.
set -eu

fail() {
    echo "install: $*" >&2
    exit 1
}

pick_arch() {
    machine=$(uname -m)
    case $machine in
        x86_64) echo amd64 ;;
        aarch64 | arm64) echo arm64 ;;
        *) fail "no nazar for $machine; there are builds for x86_64 and aarch64" ;;
    esac
}

check_version() {
    # The version goes into a path and a URL.
    case $1 in
        '' | *[!0-9.]*) fail "version $1 is not MAJOR.MINOR.PATCH" ;;
    esac
    printf '%s\n' "$1" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$' || fail "version $1 is not MAJOR.MINOR.PATCH"
}

fetch() { # fetch <url> <file>
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "$1" -o "$2"
    elif command -v wget >/dev/null 2>&1; then
        wget -q -O "$2" "$1"
    else
        fail "install needs curl or wget"
    fi
}

sha256() { # sha256 <file>
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | cut -d' ' -f1
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | cut -d' ' -f1
    else
        fail "install needs sha256sum or shasum to check the download"
    fi
}

# main is one call at the end of the file, so a download cut short runs nothing.
main() {
    [ $# -le 1 ] || fail "usage: install.sh [VERSION]"
    [ -n "${HOME:-}" ] || fail "HOME is not set"
    system=$(uname -s)
    [ "$system" = Linux ] || fail "this is the Linux install, and this is $system"
    arch=$(pick_arch)

    base=${NAZAR_RELEASE_URL:-https://github.com/atas/nazar/releases/download}
    base=${base%/}
    bindir=$HOME/.local/bin
    libdir=$HOME/.local/lib/nazar
    link=$bindir/nazar

    tmp=$(mktemp -d)
    new=
    trap 'rm -rf "$tmp" "$new"' EXIT
    trap 'exit 1' HUP INT TERM

    if [ $# -eq 1 ]; then
        version=$1
    else
        fetch "${base%/download}/latest/download/SHA256SUMS" "$tmp/latest" ||
            fail "can't find a Linux build in the latest release; name a version: install.sh X.Y.Z"
        version=$(sed -n 's/^[0-9a-f]\{64\}  nazar-\([0-9.]*\)-linux-amd64\.tar\.gz$/\1/p' "$tmp/latest")
        [ -n "$version" ] || fail "the latest release's SHA256SUMS names no version; name a version: install.sh X.Y.Z"
    fi
    check_version "$version"

    # A file of the user's at the link's place is never replaced, as
    # `nazar install` does not replace one either.
    if [ -e "$link" ] || [ -L "$link" ]; then
        target=$(readlink "$link" 2>/dev/null) || target=
        case $target in
            /*/nazar) ;;
            *) fail "$link exists and is not a nazar link; move it away" ;;
        esac
    fi

    folder=nazar-$version-linux-$arch
    tarball=$folder.tar.gz
    release=$base/v$version
    fetch "$release/SHA256SUMS" "$tmp/SHA256SUMS" || fail "can't download $release/SHA256SUMS"
    fetch "$release/$tarball" "$tmp/$tarball" || fail "can't download $release/$tarball"

    want=$(awk -v f="$tarball" '$2 == f { print $1 }' "$tmp/SHA256SUMS")
    [ -n "$want" ] || fail "SHA256SUMS does not list $tarball"
    got=$(sha256 "$tmp/$tarball")
    [ "$got" = "$want" ] || fail "$tarball: checksum mismatch (SHA256SUMS says $want, the download is $got); nothing installed"

    # Exactly the four paths, before anything is unpacked.
    tar -tzf "$tmp/$tarball" | LC_ALL=C sort >"$tmp/listed"
    printf '%s\n' "$folder/LICENSE" "$folder/README.md" "$folder/nazar" "$folder/nazar-agent" |
        LC_ALL=C sort >"$tmp/expected"
    cmp -s "$tmp/listed" "$tmp/expected" || fail "$tarball has unexpected contents; nothing installed"

    mkdir -p "$libdir" "$bindir"
    # In the same folder, so the last step is one rename.
    new=$(mktemp -d "$libdir/.new.XXXXXX")
    tar -xzf "$tmp/$tarball" --strip-components=1 -C "$new"
    chmod 0755 "$new"
    dest=$libdir/$version
    rm -rf "$dest"
    mv "$new" "$dest"
    new=
    ln -sfn "$dest/nazar" "$link"

    echo "nazar $version (Linux preview, not yet verified on real hardware) is installed."
    echo
    echo "Run this once, then log out and back in:"
    echo "  sudo ~/.local/lib/nazar/$version/nazar install --system"
    echo "It runs that file as root. This script checked it against the release's SHA256SUMS, so run it"
    echo "now; if a program prints that line later, check the file against SHA256SUMS first."
    echo "Then:"
    echo "  nazar install"
}

main "$@"
