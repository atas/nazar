#!/bin/bash
# release-linux_test.sh: tests for scripts/release-linux.sh, the nazar-linux
# formula template and the Linux half of release.yml. Linux only (make test
# runs it there, and `make linux-run` in the container). It builds the real
# binaries into one mktemp folder that is removed on exit; nothing is
# uploaded or installed. Only the binary built for this machine runs, and
# only `nazar version`, under a temporary HOME.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
repo=$(dirname "$here")
if [ "$(uname)" != Linux ]; then
    echo "release-linux_test: needs Linux; use make linux-run CMD=scripts/release-linux_test.sh" >&2
    exit 1
fi
tmpdir=${TMPDIR:-/tmp}
tmp=$(mktemp -d "${tmpdir%/}/nz-release-linux.XXXXXX")
trap 'rm -rf "$tmp"' EXIT
rel="$here/release-linux.sh"
V=1.2.3

failures=0
passes=0
pass() { passes=$((passes + 1)); echo "ok   $*"; }
bad() { failures=$((failures + 1)); echo "FAIL $*"; }
run() { rc=0; out=$("$@" 2>&1) || rc=$?; }
expect_fail() { # expect_fail <name> <message> <cmd...>
    local name=$1 msg=$2
    shift 2
    run "$@"
    if [ "$rc" -ne 0 ] && grep '^release-linux: ' <<<"$out" | grep -qF -- "$msg"; then
        pass "$name"
    else
        bad "$name: want \"$msg\", got rc=$rc $out"
    fi
}
check() { # check <name> <cmd...>
    local name=$1
    shift
    if "$@"; then pass "$name"; else bad "$name"; fi
}
same() { # same <name> <want> <got>
    if [ "$2" = "$3" ]; then pass "$1"; else bad "$1: want [$2], got [$3]"; fi
}

# ELF header fields, read by offset, so no test depends on `file`.
elf() { od -An -tu"$3" -j"$2" -N"$3" "$1" | tr -d ' '; } # elf <file> <offset> <size>
# elf_static: no PT_DYNAMIC and no PT_INTERP among the program headers.
elf_static() {
    local f=$1 off ent num i t
    off=$(elf "$f" 32 8)
    ent=$(elf "$f" 54 2)
    num=$(elf "$f" 56 2)
    [ "$num" -gt 0 ] || return 1
    for ((i = 0; i < num; i++)); do
        t=$(elf "$f" $((off + i * ent)) 4)
        if [ "$t" = 2 ] || [ "$t" = 3 ]; then return 1; fi
    done
}
is_elf64_le() { [ "$(od -An -tx1 -N6 "$1" | tr -d ' ')" = 7f454c460201 ]; }

case $(uname -m) in
    x86_64) host=amd64 ;;
    aarch64 | arm64) host=arm64 ;;
    *) echo "release-linux_test: no tarball for $(uname -m)" >&2; exit 1 ;;
esac

# --- tarballs ---------------------------------------------------------------
out="$tmp/out"
rc=0
"$rel" tarballs "$V" "$out" || rc=$?
same "tarballs exits 0" 0 "$rc"
same "tarballs makes exactly the four files" \
    "SHA256SUMS install.sh nazar-$V-linux-amd64.tar.gz nazar-$V-linux-arm64.tar.gz" \
    "$(cd "$out" && LC_ALL=C ls -A | LC_ALL=C sort | tr '\n' ' ' | sed 's/ $//')"
check "install.sh is scripts/install.sh" cmp -s "$here/install.sh" "$out/install.sh"
check "install.sh is executable" test -x "$out/install.sh"

machine_amd64=62
machine_arm64=183
for arch in amd64 arm64; do
    tb="$out/nazar-$V-linux-$arch.tar.gz"
    d="nazar-$V-linux-$arch"
    same "$arch tarball lists exactly the four paths" \
        "$d/LICENSE $d/README.md $d/nazar $d/nazar-agent" \
        "$(tar -tzf "$tb" | LC_ALL=C sort | tr '\n' ' ' | sed 's/ $//')"
    x="$tmp/x-$arch"
    mkdir -p "$x"
    tar -xzf "$tb" -C "$x"
    check "$arch LICENSE is the repo's" cmp -s "$repo/LICENSE" "$x/$d/LICENSE"
    check "$arch README.md is the repo's" cmp -s "$repo/README.md" "$x/$d/README.md"
    want_machine=machine_$arch
    for b in nazar nazar-agent; do
        f="$x/$d/$b"
        check "$arch $b is a 64-bit little-endian ELF" is_elf64_le "$f"
        same "$arch $b is for the right machine" "${!want_machine}" "$(elf "$f" 18 2)"
        check "$arch $b is static" elf_static "$f"
        check "$arch $b is executable" test -x "$f"
        info=$(go version -m "$f")
        if grep -qE '^[[:space:]]+build[[:space:]]+-tags=' <<<"$info"; then bad "$arch $b has no build tags"; else pass "$arch $b has no build tags"; fi
        check "$arch $b was built with CGO_ENABLED=0" grep -qE '^[[:space:]]+build[[:space:]]+CGO_ENABLED=0$' <<<"$info"
        check "$arch $b was built with -trimpath" grep -qE '^[[:space:]]+build[[:space:]]+-trimpath=true$' <<<"$info"
    done
    # nazar version in each. The other architecture's binary runs only where
    # the machine can (qemu or Rosetta); where it can't, what it would print
    # is checked in the flags it was built with. CI runs on amd64 and the
    # Mac's container on arm64, so each binary really runs on one of them.
    nz="$x/$d/nazar"
    rc=0
    got=$(HOME="$tmp/home" "$nz" version 2>&1) || rc=$?
    if [ "$arch" = "$host" ] || [ "$rc" -eq 0 ]; then
        same "$arch nazar version prints the version" "nazar $V (Linux preview)" "$got"
    else
        check "$arch nazar (can't run here) is built with the version" grep -qF -- "-X main.version=$V" <<<"$(go version -m "$nz")"
    fi
done

# SHA256SUMS: the two tarballs and install.sh, sorted by name, sha256sum format.
sums="$out/SHA256SUMS"
same "SHA256SUMS names the three files, sorted" \
    "install.sh nazar-$V-linux-amd64.tar.gz nazar-$V-linux-arm64.tar.gz" \
    "$(awk '{print $2}' "$sums" | tr '\n' ' ' | sed 's/ $//')"
if (cd "$out" && sha256sum --status --strict -c SHA256SUMS); then pass "SHA256SUMS verifies"; else bad "SHA256SUMS verifies"; fi
if grep -qvE '^[0-9a-f]{64}  [^ ]+$' "$sums"; then bad "SHA256SUMS is in sha256sum format"; else pass "SHA256SUMS is in sha256sum format"; fi

# Building twice gives the same bytes, so a rerun can't publish a different file.
"$rel" tarballs "$V" "$tmp/again" >/dev/null
check "tarballs are reproducible" cmp -s "$sums" "$tmp/again/SHA256SUMS"

# A second run into the same folder leaves only that run's files.
touch "$tmp/again/stale"
"$rel" tarballs 1.2.4 "$tmp/again" >/dev/null
same "tarballs clears the folder first" \
    "SHA256SUMS install.sh nazar-1.2.4-linux-amd64.tar.gz nazar-1.2.4-linux-arm64.tar.gz" \
    "$(cd "$tmp/again" && LC_ALL=C ls -A | LC_ALL=C sort | tr '\n' ' ' | sed 's/ $//')"

# A test build must never ship: the tag comes in through GOFLAGS, as it could
# on a runner, and go version -m shows it.
GOFLAGS=-tags=nazartest expect_fail "a -tags nazartest build is refused" "built with -tags" "$rel" tarballs "$V" "$tmp/tagged"
same "a refused build leaves no tarball" "" "$(find "$tmp/tagged" -name '*.tar.gz' 2>/dev/null)"

# A cgo build must never ship either. The script asks for CGO_ENABLED=0, so a
# shim named go stands for whatever would undo that. It builds for this
# machine, because cgo can't cross-compile here, and the check must refuse it
# before anything looks at the architecture.
shim="$tmp/shim"
mkdir -p "$shim"
realgo=$(command -v go)
cat >"$shim/go" <<SH
#!/bin/sh
if [ "\$1" = build ]; then
    CGO_ENABLED=1 GOOS=linux GOARCH=$host exec "$realgo" "\$@"
fi
exec "$realgo" "\$@"
SH
chmod +x "$shim/go"
PATH="$shim:$PATH" expect_fail "a CGO_ENABLED=1 build is refused" "CGO_ENABLED=1" "$rel" tarballs "$V" "$tmp/cgo"
same "a refused cgo build leaves no tarball" "" "$(find "$tmp/cgo" -name '*.tar.gz' 2>/dev/null)"

# A build for the wrong machine is refused too.
cat >"$shim/go" <<SH
#!/bin/sh
if [ "\$1" = build ]; then
    GOARCH=$([ "$host" = amd64 ] && echo arm64 || echo amd64) exec "$realgo" "\$@"
fi
exec "$realgo" "\$@"
SH
PATH="$shim:$PATH" expect_fail "a build for another architecture is refused" "GOARCH" "$rel" tarballs "$V" "$tmp/wrongarch"

expect_fail "tarballs refuses a bad version" "is not MAJOR.MINOR.PATCH" "$rel" tarballs 1.2 "$tmp/bad"
expect_fail "tarballs refuses a version with a path in it" "is not MAJOR.MINOR.PATCH" "$rel" tarballs ../1.2.3 "$tmp/bad"
expect_fail "tarballs needs its arguments" "usage" "$rel" tarballs "$V"
expect_fail "an unknown command is refused" "usage" "$rel" nope

# --- formula ----------------------------------------------------------------
tap="$tmp/tap"
rc=0
"$rel" formula "$V" "$sums" "$tap" >/dev/null || rc=$?
same "formula exits 0" 0 "$rc"
rb="$tap/nazar-linux.rb"
check "formula is at the tap's root, nazar-linux.rb" test -f "$rb"
# Once a tap has a Formula/ folder Homebrew reads its formulae from there
# alone, and the formulae at the tap's root (autotunnel.rb) vanish.
check "formula makes no Formula/ folder" test ! -e "$tap/Formula"
if grep -q '@' "$rb"; then bad "formula has no @ placeholder left: $(grep '@' "$rb")"; else pass "formula has no @ placeholder left"; fi
sum_of() { awk -v f="$1" '$2 == f {print $1}' "$sums"; }
amd=$(sum_of "nazar-$V-linux-amd64.tar.gz")
arm=$(sum_of "nazar-$V-linux-arm64.tar.gz")
# Lines of the formula, in the order the block must hold them.
block() { # block <start line> <count>: that many lines from the first match
    grep -F -A"$2" -- "$1" "$rb" | sed 's/^ *//'
}
has() { # has <literal line, stripped of its indent>
    if sed 's/^ *//' "$rb" | grep -qxF -- "$1"; then pass "formula: $1"; else bad "formula lacks: $1"; fi
}
has 'class NazarLinux < Formula'
has 'desc "SSH agent with TPM keys and per-key caller rules (Linux preview)"'
has 'license "Apache-2.0"'
has "version \"$V\""
has 'depends_on :linux'
has 'bin.install "nazar", "nazar-agent"'
has 'bin.install_symlink "nazar" => "nazar-sign-git"'
has 'bin.install_symlink "nazar" => "git-credential-nazar"'
has 'sudo #{opt_bin}/nazar install --system'
has 'nazar install --no-links'
has 'IdentityAgent ~/.nazar/run/agent.sock'
has 'assert_match version.to_s, shell_output("#{bin}/nazar version")'
url="https://github.com/atas/nazar/releases/download/v$V"
same "on_intel has the amd64 url and sum" \
    "on_intel do
url \"$url/nazar-$V-linux-amd64.tar.gz\"
sha256 \"$amd\"
end" "$(block 'on_intel do' 3)"
same "on_arm has the arm64 url and sum" \
    "on_arm do
url \"$url/nazar-$V-linux-arm64.tar.gz\"
sha256 \"$arm\"
end" "$(block 'on_arm do' 3)"
if grep -qiF 'preview' <<<"$(sed -n '/def caveats/,/^ *EOS$/p' "$rb")" && grep -qF 'not yet verified on real hardware' "$rb"; then pass "the caveats say preview, not verified"; else bad "the caveats say preview, not verified"; fi
if grep -qF 'log out and back in' "$rb"; then pass "the caveats say to log out and back in"; else bad "the caveats say to log out and back in"; fi
# The sudo line runs a user-owned file as root (THREAT-MODEL 7.2): the caveats say to check it
# against SHA256SUMS before following that line from anywhere but this install.
if grep -qF "SHA256SUMS first" "$rb"; then pass "the caveats say to check the file before a later sudo line"; else bad "the caveats say to check the file before a later sudo line"; fi
if grep -qF 'every upgrade' "$rb"; then pass "the caveats name every upgrade"; else bad "the caveats name every upgrade"; fi

grep -v "linux-arm64" "$sums" >"$tmp/nosum"
expect_fail "formula refuses a SHA256SUMS without the arm64 tarball" "no valid sum" "$rel" formula "$V" "$tmp/nosum" "$tmp/tap2"
sed 's/^[0-9a-f]\{64\}/nothex/' "$sums" >"$tmp/badsum"
expect_fail "formula refuses a sum that is not a sha256" "no valid sum" "$rel" formula "$V" "$tmp/badsum" "$tmp/tap2"
check "a refused formula writes nothing" test ! -e "$tmp/tap2/nazar-linux.rb"
expect_fail "formula refuses a missing SHA256SUMS" "no $tmp/nofile" "$rel" formula "$V" "$tmp/nofile" "$tmp/tap2"
expect_fail "formula refuses a bad version" "is not MAJOR.MINOR.PATCH" "$rel" formula 1.2 "$sums" "$tmp/tap2"

# --- release.yml ------------------------------------------------------------
wf="$repo/.github/workflows/release.yml"
job() { awk -v j="    $1:" '$0 == j {on=1; next} on && /^    [a-z_-]+:$/ {exit} on' "$wf"; } # job <name>
# step <job text> <name>: one named step, up to the next step or comment.
step() { awk -v n="            - name: $2" '$0 == n {on=1; print; next} on && /^            (- |# )/ {exit} on' <<<"$1"; }
# run_body: the shell of a step's `run: |` block, as the runner gets it.
run_body() { awk '/^ +run: \|$/ {on=1; next} on' | sed 's/^                  //'; }
linux=$(job linux)
macos=$(job release)
same "the jobs are plan, release and linux" "plan release linux" \
    "$(awk '/^jobs:/{on=1; next} on' "$wf" | grep -E '^    [a-z_-]+:$' | tr -d ' :' | tr '\n' ' ' | sed 's/ $//')"
if [ -n "$linux" ] && ! grep -qE 'secrets\.|environment:|ssh-key' <<<"$linux"; then pass "the linux job has no secret and no environment"; else bad "the linux job has no secret and no environment"; fi
check "the linux job needs only plan" grep -qxE ' +needs: plan' <<<"$linux"
check "the linux job only reads" grep -qxE ' +contents: read' <<<"$linux"
check "the linux job keeps no token in .git" grep -qxE ' +persist-credentials: false' <<<"$linux"
check "the linux job runs make test" grep -qE 'run: make test$' <<<"$linux"
check "the linux job makes the tarballs" grep -qF 'scripts/release-linux.sh tarballs "$V" build/release-linux' <<<"$linux"
# macOS runs after a timeout in linux too. A step that times out fails; what a
# job-level timeout does to a job that needs it is not documented, so linux
# has none and every one of its steps carries its own.
if grep -qE '^        timeout-minutes:' <<<"$linux"; then bad "the linux job has no job-level timeout"; else pass "the linux job has no job-level timeout"; fi
same "every step of the linux job has its own timeout" \
    "$(grep -cE '^            - ' <<<"$linux")" "$(grep -cE '^              timeout-minutes: [0-9]+$' <<<"$linux")"
check "macOS runs after plan and linux" grep -qxF '        needs: [plan, linux]' <<<"$macos"
check "macOS runs whatever linux did, unless the run is cancelled" grep -qxF "        if: \${{ !cancelled() && needs.plan.outputs.version != '' }}" <<<"$macos"
same "only the macOS job has an environment" 1 "$(grep -cE '^ +environment:' "$wf")"
check "the macOS job is in the release environment" grep -qxE ' +environment: release' <<<"$macos"
same "the macOS job's steps, in order" \
    "uses actions/checkout|uses actions/setup-go|Version and tag|Keychain|Build, sign, notarize|Publish|Download the Linux files|Publish Linux|uses actions/checkout|Update the tap|Say that Linux was not published|Remove the keychain" \
    "$(grep -E '^            - (name|uses): ' <<<"$macos" | sed -E 's/^ +- name: //; s/^ +- uses: ([^@]+)@.*/uses \1/' | paste -sd'|' -)"
check "the macOS job takes the deploy key" grep -qF 'ssh-key: ${{ secrets.TAP_DEPLOY_KEY }}' <<<"$macos"
check "the macOS job commits nazar \$V" grep -qF 'git commit -m "nazar $V"' <<<"$macos"
get=$(step "$macos" "Download the Linux files")
pub=$(step "$macos" "Publish Linux")
upd=$(step "$macos" "Update the tap")
say=$(step "$macos" "Say that Linux was not published")
check "the Linux files come down only when linux built" grep -qF "if: needs.linux.result == 'success'" <<<"$get"
check "Linux is published only when it built" grep -qF "if: needs.linux.result == 'success' && steps.get-linux.outcome == 'success'" <<<"$pub"
# A Linux part that fails or hangs must not stop the casks: it may fail without
# failing the job, it has its own timeout, and the job has time for it on top
# of the hour the macOS steps always had.
check "a failed Linux download does not stop the casks" grep -qxE ' +continue-on-error: true' <<<"$get"
check "a failed Linux publish does not stop the casks" grep -qxE ' +continue-on-error: true' <<<"$pub"
same "the Linux steps have 15 minutes between them" 15 \
    "$(($(grep -E 'timeout-minutes:' <<<"$get" | awk '{print $2}') + $(grep -E 'timeout-minutes:' <<<"$pub" | awk '{print $2}')))"
check "the macOS job has 60 minutes and those 15" grep -qxF '        timeout-minutes: 75' <<<"$macos"
if grep -qE '^ +if:' <<<"$upd"; then bad "the tap is pushed whatever Linux did"; else pass "the tap is pushed whatever Linux did"; fi
check "the run fails when Linux built and was not published" grep -qF "if: needs.linux.result == 'success' && steps.publish-linux.outcome != 'success'" <<<"$say"
check "the notes name the Linux files" grep -qF 'Linux (preview, not yet verified on real hardware): nazar-$V-linux-amd64.tar.gz, nazar-$V-linux-arm64.tar.gz, SHA256SUMS, install.sh' <<<"$pub"
check "the Linux publish checks each download" grep -qF 'releases/download/v$V/' <<<"$pub"
check "the Linux publish renders the formula last" bash -c 'tail -1 <<<"$1" | grep -qF "scripts/release-linux.sh formula"' _ "$pub"
# The macOS image has shasum; sha256sum is not promised there.
if grep -qF 'sha256sum' <<<"$macos"; then bad "the macOS job uses shasum, as Publish does"; else pass "the macOS job uses shasum, as Publish does"; fi
unpinned=$(grep -E '^ *(- )?uses:' "$wf" | grep -vE 'uses: [^@ ]+@[0-9a-f]{40} # v[0-9]' || true)
same "every action is pinned to a full SHA with its version" "" "$unpinned"

# --- the appended steps, run with stubs --------------------------------------
# The shell of the workflow's own steps, in a folder of their own, with gh,
# curl, shasum and make replaced and a local bare repository as the tap.
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1
w="$tmp/steps"
mkdir -p "$w/bin" "$w/temp" "$w/served" "$w/build"
cp -R "$tmp/out" "$w/build/release-linux"
cp "$tmp/out"/* "$w/served/"
ln -s "$here" "$w/scripts"
ln -s "$repo/packaging" "$w/packaging"
run_body <<<"$pub" >"$w/publish.sh"
run_body <<<"$upd" >"$w/update.sh"
cat >"$w/bin/gh" <<'SH'
#!/bin/bash
echo "$*" >>"$W/gh.log"
case "$1 $2" in
    "release view") echo "the generated notes" ;;
    "release edit") while [ $# -gt 0 ]; do [ "$1" = --notes-file ] && cp "$2" "$W/notes"; shift; done ;;
esac
exit 0
SH
cat >"$w/bin/curl" <<'SH'
#!/bin/bash
for last; do :; done
cat "$W/served/$(basename "$last")"
SH
cat >"$w/bin/shasum" <<'SH'
#!/bin/bash
shift 2
exec sha256sum "$@"
SH
cat >"$w/bin/make" <<'SH'
#!/bin/bash
[ "$*" = "release-tap TAP=tap" ] || { echo "make: unexpected: $*" >&2; exit 1; }
echo "cask $V" >tap/Casks/nazar.rb
SH
chmod +x "$w/bin"/*
in_steps() { # in_steps <script>: as the runner would, in the step folder
    (cd "$w" && W="$w" V="$V" GITHUB_REPOSITORY=atas/nazar RUNNER_TEMP="$w/temp" PATH="$w/bin:$PATH" bash "$w/$1")
}
new_tap() { # a clone in $w/tap of a tap in $w/tap.git with one commit: a formula at the tap's root, as atas/homebrew-tap keeps autotunnel.rb
    rm -rf "$w/tap" "$w/tap.git" "$w/tap-seed"
    git init -q --bare -b main "$w/tap.git"
    git init -q -b main "$w/tap-seed"
    echo "class Autotunnel < Formula; end" >"$w/tap-seed/autotunnel.rb"
    git -C "$w/tap-seed" add autotunnel.rb
    git -C "$w/tap-seed" -c user.name=t -c user.email=t@example.com commit -q -m start
    git -C "$w/tap-seed" push -q "$w/tap.git" main
    git clone -q "$w/tap.git" "$w/tap"
}
tap_files() { git -C "$w/tap.git" ls-tree -r --name-only main | paste -sd' ' -; }
tap_subject() { git -C "$w/tap.git" log -1 --format=%s main; }

# A download that does not match stops before the notes and the formula.
tb="nazar-$V-linux-arm64.tar.gz"
echo corrupted >"$w/served/$tb"
rc=0
errs=$(in_steps publish.sh 2>&1) || rc=$?
if [ "$rc" -ne 0 ]; then pass "publish: a bad download fails the step"; else bad "publish: a bad download fails the step"; fi
check "publish: a bad download is named" grep -qF "$tb: downloaded" <<<"$errs"
if grep -q 'release edit' "$w/gh.log"; then bad "publish: a bad download adds no notes line"; else pass "publish: a bad download adds no notes line"; fi
check "publish: a bad download renders no formula" test ! -e "$w/build/tap-out/nazar-linux.rb"

# Casks alone: no formula was rendered, and the push still happens.
new_tap
rc=0
in_steps update.sh >/dev/null 2>&1 || rc=$?
same "update: the casks are pushed alone when Linux was not published" 0 "$rc"
same "update: only the cask is in the tap" "Casks/nazar.rb autotunnel.rb" "$(tap_files)"
same "update: the commit is nazar \$V" "nazar $V" "$(tap_subject)"

# The whole of it.
rm -f "$w/gh.log"
cp "$tmp/out/$tb" "$w/served/$tb"
rc=0
in_steps publish.sh >/dev/null 2>&1 || rc=$?
same "publish: a good release passes" 0 "$rc"
check "publish: all four files are uploaded" grep -qF "release upload v$V --repo atas/nazar build/release-linux/nazar-$V-linux-amd64.tar.gz build/release-linux/$tb build/release-linux/SHA256SUMS build/release-linux/install.sh" "$w/gh.log"
same "publish: the notes keep what they said and gain the line" \
    "the generated notes

Linux (preview, not yet verified on real hardware): nazar-$V-linux-amd64.tar.gz, $tb, SHA256SUMS, install.sh" \
    "$(cat "$w/notes" 2>/dev/null)"
check "publish: the formula is rendered" test -f "$w/build/tap-out/nazar-linux.rb"
new_tap
rc=0
in_steps update.sh >/dev/null 2>&1 || rc=$?
same "update: the casks and the formula are pushed together" 0 "$rc"
# The tap's own formula at its root stays, and no Formula/ folder appears:
# Homebrew would then read formulae from it alone and autotunnel.rb would
# be gone from every Mac.
same "update: both are in the tap, at the root, next to the tap's own formula" "Casks/nazar.rb autotunnel.rb nazar-linux.rb" "$(tap_files)"
check "update: no Formula/ folder was made" test ! -e "$w/tap/Formula"
same "update: the one commit is nazar \$V" "nazar $V" "$(tap_subject)"

echo "release-linux_test: $passes passed, $failures failed"
[ "$failures" -eq 0 ]
