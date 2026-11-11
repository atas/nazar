#!/bin/bash
# install_test.sh: tests for scripts/install.sh. Linux only (make test runs it
# there, and `make linux-run` in the container). The release is local: the
# real tarballs, built into one mktemp folder that is removed on exit, served
# through file://. Every run has its own temporary HOME, and a sudo on PATH
# that only leaves a mark, to show that install.sh never runs it.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
if [ "$(uname)" != Linux ]; then
    echo "install_test: needs Linux; use make linux-run CMD=scripts/install_test.sh" >&2
    exit 1
fi
tmpdir=${TMPDIR:-/tmp}
tmp=$(mktemp -d "${tmpdir%/}/nz-install.XXXXXX")
trap 'rm -rf "$tmp"' EXIT
inst="$here/install.sh"
V=1.2.3

failures=0
passes=0
pass() { passes=$((passes + 1)); echo "ok   $*"; }
bad() { failures=$((failures + 1)); echo "FAIL $*"; }
check() { # check <name> <cmd...>
    local name=$1
    shift
    if "$@"; then pass "$name"; else bad "$name"; fi
}
same() { # same <name> <want> <got>
    if [ "$2" = "$3" ]; then pass "$1"; else bad "$1: want [$2], got [$3]"; fi
}

case $(uname -m) in
    x86_64) host=amd64 ;;
    aarch64 | arm64) host=arm64 ;;
    *) echo "install_test: no tarball for $(uname -m)" >&2; exit 1 ;;
esac

# The release, as GitHub lays it out: download/vV/<asset> and, for the latest
# release, latest/download/<asset>.
"$here/release-linux.sh" tarballs "$V" "$tmp/built" >/dev/null
rel="$tmp/rel"
mkdir -p "$rel/download/v$V" "$rel/latest/download"
cp "$tmp/built"/* "$rel/download/v$V/"
cp "$tmp/built"/* "$rel/latest/download/"
url="file://$rel/download"

# The shims: a sudo that leaves a mark, and a uname that can lie.
shims="$tmp/shims"
mkdir -p "$shims"
cat >"$shims/sudo" <<SH
#!/bin/sh
echo "\$*" >>"$tmp/sudo-ran"
exit 1
SH
realuname=$(command -v uname)
cat >"$shims/uname" <<SH
#!/bin/sh
if [ "\$1" = -m ] && [ -n "\${FAKE_MACHINE:-}" ]; then echo "\$FAKE_MACHINE"; exit 0; fi
if [ "\$1" = -s ] && [ -n "\${FAKE_SYSTEM:-}" ]; then echo "\$FAKE_SYSTEM"; exit 0; fi
exec "$realuname" "\$@"
SH
chmod +x "$shims"/*

homes=0
new_home() { homes=$((homes + 1)); H="$tmp/home$homes"; mkdir -p "$H"; }
# go <args>: install.sh in the current home, under plain sh, with the shims.
go_inst() {
    rc=0
    out=$(HOME="$H" PATH="$shims:$PATH" NAZAR_RELEASE_URL="$url" sh "$inst" "$@" 2>&1) || rc=$?
}
refused() { # refused <name> <message>: refused, with the message, nothing installed
    if [ "$rc" -ne 0 ] && grep '^install: ' <<<"$out" | grep -qF -- "$2"; then
        pass "$1"
    else
        bad "$1: want \"$2\", got rc=$rc $out"
    fi
    same "$1: nothing installed" "" "$(cd "$H" && find . -mindepth 1 ! -path './.local' ! -path './.local/lib' ! -path './.local/lib/nazar' ! -path './.local/bin' | LC_ALL=C sort | tr '\n' ' ')"
    if [ -e "$H/.local/lib/nazar/$V" ] || [ -L "$H/.local/bin/nazar" ]; then bad "$1: no version folder and no link"; else pass "$1: no version folder and no link"; fi
}

# --- the plain install ------------------------------------------------------
new_home
go_inst "$V"
same "installs: exit 0" 0 "$rc"
dest="$H/.local/lib/nazar/$V"
same "installs the four files" "LICENSE README.md nazar nazar-agent" "$(cd "$dest" && LC_ALL=C ls -A | LC_ALL=C sort | tr '\n' ' ' | sed 's/ $//')"
check "the link is a link" test -L "$H/.local/bin/nazar"
# An absolute link: nazar install takes over the slot only from a link that
# names a nazar CLI by absolute path.
same "the link names the version's nazar" "$dest/nazar" "$(readlink "$H/.local/bin/nazar")"
same "nazar runs through the link" "nazar $V (Linux preview)" "$(HOME="$H" "$H/.local/bin/nazar" version)"
check "nazar-agent is executable" test -x "$dest/nazar-agent"
# shellcheck disable=SC2016 # literal text
check "the folder is readable by the user's other tools" test "$(stat -c %a "$dest")" = 755

# The printed lines are exact.
cmd1="  sudo ~/.local/lib/nazar/$V/nazar install --system"
cmd2="  nazar install"
if grep -qxF -- "$cmd1" <<<"$out"; then pass "prints the install --system line"; else bad "prints the install --system line: $out"; fi
if grep -qxF -- "$cmd2" <<<"$out"; then pass "prints the nazar install line"; else bad "prints the nazar install line: $out"; fi
same "the system line comes first" "$cmd1
$cmd2" "$(grep -E '^  (sudo|nazar) ' <<<"$out")"
if grep -qF 'log out and back in' <<<"$out"; then pass "says to log out and back in"; else bad "says to log out and back in: $out"; fi
# The sudo line runs a user-owned file as root (THREAT-MODEL 7.2): the user is told to check it
# against SHA256SUMS before following that line from anywhere but this install.
if grep -qF 'check the file against SHA256SUMS first' <<<"$out"; then pass "says to check the file before a later sudo line"; else bad "says to check the file before a later sudo line: $out"; fi
if grep -qF 'Linux preview' <<<"$out"; then pass "says it is a preview"; else bad "says it is a preview: $out"; fi
check "it left nothing but the install" test ! -e "$H/.nazar"
same "no temporary folder is left" "$V" "$(LC_ALL=C ls -A "$H/.local/lib/nazar" | tr '\n' ' ' | sed 's/ $//')"

# Installing the same version again replaces the folder and keeps the link.
echo stale >"$dest/stale"
go_inst "$V"
same "installs again: exit 0" 0 "$rc"
check "installing again replaces the folder" test ! -e "$dest/stale"
same "nazar still runs" "nazar $V (Linux preview)" "$(HOME="$H" "$H/.local/bin/nazar" version)"

# The latest release, with no version named.
new_home
go_inst
same "the latest release: exit 0" 0 "$rc"
check "the latest release is installed by its version" test -x "$H/.local/lib/nazar/$V/nazar"

# A newer version takes the link and leaves the older folder.
same "the link moves to a newer version" "$H/.local/lib/nazar/1.2.4/nazar" "$(
    v2=1.2.4
    "$here/release-linux.sh" tarballs "$v2" "$tmp/built2" >/dev/null
    mkdir -p "$rel/download/v$v2"
    cp "$tmp/built2"/* "$rel/download/v$v2/"
    HOME="$H" PATH="$shims:$PATH" NAZAR_RELEASE_URL="$url" sh "$inst" "$v2" >/dev/null 2>&1
    readlink "$H/.local/bin/nazar"
)"
check "the older version stays" test -x "$H/.local/lib/nazar/$V/nazar"

# --- the architecture -------------------------------------------------------
# Which tarball a machine name picks: the installed nazar is that tarball's.
for pair in x86_64:amd64 aarch64:arm64 arm64:arm64; do
    m=${pair%:*}
    a=${pair#*:}
    new_home
    FAKE_MACHINE=$m go_inst "$V"
    same "uname -m $m: exit 0" 0 "$rc"
    mkdir -p "$tmp/x-$m"
    tar -xzf "$rel/download/v$V/nazar-$V-linux-$a.tar.gz" -C "$tmp/x-$m"
    check "uname -m $m installs $a" cmp -s "$tmp/x-$m/nazar-$V-linux-$a/nazar" "$H/.local/lib/nazar/$V/nazar"
done
new_home
FAKE_MACHINE=riscv64 go_inst "$V"
refused "an unknown uname -m is refused" "riscv64"
new_home
FAKE_SYSTEM=Darwin go_inst "$V"
refused "another system is refused" "Darwin"

# --- what it refuses --------------------------------------------------------
# A tarball that does not match SHA256SUMS.
bad_rel() { # bad_rel <name>: a copy of the release, url pointing at it
    rel2="$tmp/$1"
    mkdir -p "$rel2/download/v$V" "$rel2/latest/download"
    cp "$tmp/built"/* "$rel2/download/v$V/"
    cp "$tmp/built"/* "$rel2/latest/download/"
    url="file://$rel2/download"
}
tb="nazar-$V-linux-$host.tar.gz"
bad_rel corrupt
printf 'x' >>"$rel2/download/v$V/$tb"
new_home
go_inst "$V"
refused "a corrupted tarball is refused" "checksum mismatch"

bad_rel unlisted
grep -v "$tb" "$tmp/built/SHA256SUMS" >"$rel2/download/v$V/SHA256SUMS"
new_home
go_inst "$V"
refused "a tarball SHA256SUMS does not list is refused" "SHA256SUMS does not list"

bad_rel nosums
rm "$rel2/download/v$V/SHA256SUMS"
new_home
go_inst "$V"
refused "a release with no SHA256SUMS is refused" "SHA256SUMS"

bad_rel notarball
rm "$rel2/download/v$V/$tb"
new_home
go_inst "$V"
refused "a release with no tarball for this machine is refused" "$tb"

# A tarball whose sum matches but whose contents are not the four paths: the
# sum is only as good as the site it came from.
bad_rel forged
d="nazar-$V-linux-$host"
mkdir -p "$tmp/forged/$d"
tar -xzf "$tmp/built/$tb" -C "$tmp/forged"
echo evil >"$tmp/forged/$d/extra"
tar -C "$tmp/forged" -czf "$rel2/download/v$V/$tb" "$d"
(cd "$rel2/download/v$V" && sha256sum "$tb") >"$tmp/forged.sum"
grep -v "$tb" "$tmp/built/SHA256SUMS" >>"$tmp/forged.sum"
cp "$tmp/forged.sum" "$rel2/download/v$V/SHA256SUMS"
new_home
go_inst "$V"
refused "a tarball with anything else in it is refused" "unexpected"

url="file://$rel/download"

# The version goes into a path and a URL.
new_home
go_inst ../../evil
refused "a version with a path in it is refused" "is not MAJOR.MINOR.PATCH"
new_home
go_inst v1.2.3
refused "a version with a v is refused" "is not MAJOR.MINOR.PATCH"
new_home
go_inst "1.2.3
evil"
refused "a version of two lines is refused" "version 1.2.3"
new_home
go_inst 1.2.3 1.2.4
refused "two arguments are refused" "usage"

# A latest release with no Linux build (the Linux job failed that week).
bad_rel nolatest
rm "$rel2/latest/download/SHA256SUMS"
new_home
go_inst
refused "a latest release with no Linux build says to name a version" "name a version"
bad_rel badlatest
echo "$(printf '%064d' 0)  nazar-../../evil-linux-amd64.tar.gz" >"$rel2/latest/download/SHA256SUMS"
new_home
go_inst
refused "a latest SHA256SUMS naming no version is refused" "name a version"
url="file://$rel/download"

# A file of the user's at the link's place is never replaced.
new_home
mkdir -p "$H/.local/bin"
echo mine >"$H/.local/bin/nazar"
go_inst "$V"
if [ "$rc" -ne 0 ] && grep -qF "is not a nazar link" <<<"$out"; then pass "a file at the link's place is refused"; else bad "a file at the link's place is refused: rc=$rc $out"; fi
same "the user's file is untouched" mine "$(cat "$H/.local/bin/nazar")"
check "the refusal installs nothing" test ! -e "$H/.local/lib/nazar/$V"

# --- the tools it falls back to ---------------------------------------------
# A PATH of just these tools, so a missing one is really missing.
tools="$tmp/tools"
mkdir -p "$tools"
for t in sh uname mktemp rm mkdir awk sed tar gzip cmp sort chmod mv ln grep readlink cat cut; do
    ln -s "$(command -v "$t")" "$tools/$t"
done
realsha=$(command -v sha256sum)
realcp=$(command -v cp)
realcurl=$(command -v curl)
minimal() { # minimal <dir of extras>: run install.sh with only the tools and the extras
    rc=0
    out=$(HOME="$H" PATH="$1:$tools" NAZAR_RELEASE_URL="$url" "$tools/sh" "$inst" "$V" 2>&1) || rc=$?
}

# shasum when there is no sha256sum.
ex="$tmp/ex-shasum"
mkdir -p "$ex"
ln -s "$realcurl" "$ex/curl"
cat >"$ex/shasum" <<SH
#!/bin/sh
[ "\$1" = -a ] && [ "\$2" = 256 ] || exit 9
echo used >>"$tmp/shasum-ran"
shift 2
exec "$realsha" "\$@"
SH
chmod +x "$ex/shasum"
new_home
minimal "$ex"
same "shasum instead of sha256sum: exit 0" 0 "$rc"
check "shasum was used" test -s "$tmp/shasum-ran"
check "shasum instead of sha256sum installs" test -x "$H/.local/lib/nazar/$V/nazar"

# shasum still catches a corrupted tarball.
bad_rel corrupt2
printf 'x' >>"$rel2/download/v$V/$tb"
new_home
minimal "$ex"
refused "shasum catches a corrupted tarball" "checksum mismatch"
url="file://$rel/download"

# Neither is a refusal, not an unchecked install.
ex="$tmp/ex-nosum"
mkdir -p "$ex"
ln -s "$realcurl" "$ex/curl"
new_home
minimal "$ex"
refused "no sha256sum and no shasum is refused" "sha256sum"

# wget when there is no curl (a desktop may have only that).
ex="$tmp/ex-wget"
mkdir -p "$ex"
ln -s "$realsha" "$ex/sha256sum"
cat >"$ex/wget" <<SH
#!/bin/sh
[ "\$1" = -q ] && [ "\$2" = -O ] || exit 9
echo used >>"$tmp/wget-ran"
exec "$realcp" "\${4#file://}" "\$3"
SH
chmod +x "$ex/wget"
new_home
minimal "$ex"
same "wget instead of curl: exit 0" 0 "$rc"
check "wget was used" test -s "$tmp/wget-ran"
check "wget instead of curl installs" test -x "$H/.local/lib/nazar/$V/nazar"

# Neither is a refusal.
ex="$tmp/ex-nofetch"
mkdir -p "$ex"
ln -s "$realsha" "$ex/sha256sum"
new_home
minimal "$ex"
refused "no curl and no wget is refused" "curl or wget"

# --- never sudo -------------------------------------------------------------
check "install.sh never ran sudo" test ! -e "$tmp/sudo-ran"
if grep -vE '^[[:space:]]*#' "$inst" | grep -E '(^|[;&|([:space:]])sudo[[:space:]]' | grep -vE 'echo|printf' | grep -q .; then
    bad "install.sh has no sudo command, only a line it prints"
else
    pass "install.sh has no sudo command, only a line it prints"
fi

echo "install_test: $passes passed, $failures failed"
[ "$failures" -eq 0 ]
