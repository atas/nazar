#!/bin/bash
# The Linux test image's entrypoint (test/linux/Dockerfile), run as root by
# `make linux` and `make linux-run CMD='...'`. It copies the read-only source
# in /src to /work, installs nazar's polkit action, starts the container's
# own system bus and polkitd, marks the container ready
# (internal/linuxtest/container checks the mark), then runs the command as
# the unprivileged test user nazartest in /work. The command is the
# arguments, run by bash; with none it is `all`, the whole Linux suite.
set -euo pipefail

if [ "$(id -u)" != 0 ]; then
    echo "run.sh: must start as root (the container's entrypoint)" >&2
    exit 1
fi
if [ ! -d /src ]; then
    echo "run.sh: no source at /src (docker run -v \"\$PWD\":/src:ro ...)" >&2
    exit 1
fi

cmd="$*"
if [ -z "$cmd" ] || [ "$cmd" = all ]; then
    # The unit tests, the Linux platform tests, the integration suite and
    # the end-to-end tests of nazar-agent for Linux (test/linux/e2e).
    cmd='make test &&
go test -race -count=1 -tags linuxplatform ./core/... ./cmd/... ./internal/... &&
make integration &&
go test -count=1 -tags linuxe2e ./test/linux/...'
fi

# A copy the test user owns: the tests build, write test data and run
# gofmt in it, and the host's tree stays untouched. Not copied: git's
# folder (a worktree's .git is a file naming a host path, which would break
# go's VCS stamping), build outputs and local tool folders.
mkdir -p /work
tar -C /src --exclude=./.git --exclude=./build --exclude=./.claude -cf - . | tar -C /work -xf -
chown -R nazartest:nazartest /work

# nazar's polkit action, owned by the test user: polkitd takes the prompt
# text (a CheckAuthorization detail) only from root or an action owner.
# The packaging file carries a placeholder for the owner, which `nazar
# install --system` fills in for the installing user; here it is the test
# user. A file without the placeholder would install with no owner and
# every login gate would fail, so refuse it here, as the installer does.
policy=/work/packaging/linux/dev.nazar.authenticate.policy
if ! grep -q '@NAZAR_OWNERS@' "$policy"; then
    echo "run.sh: $policy has no @NAZAR_OWNERS@ placeholder" >&2
    exit 1
fi
sed 's/@NAZAR_OWNERS@/unix-user:nazartest/g' "$policy" > /usr/share/polkit-1/actions/dev.nazar.authenticate.policy
chmod 0644 /usr/share/polkit-1/actions/dev.nazar.authenticate.policy

# The container's own system bus, at its default address, and polkitd on it.
dbus-uuidgen --ensure
mkdir -p /run/dbus
rm -f /run/dbus/pid
dbus-daemon --system --fork
/usr/lib/polkit-1/polkitd --no-debug >/tmp/polkitd.log 2>&1 &

for _ in $(seq 1 300); do
    if dbus-send --system --print-reply --dest=org.freedesktop.DBus /org/freedesktop/DBus \
        org.freedesktop.DBus.GetNameOwner string:org.freedesktop.PolicyKit1 >/dev/null 2>&1; then
        break
    fi
    sleep 0.1
done
if ! dbus-send --system --print-reply --dest=org.freedesktop.DBus /org/freedesktop/DBus \
    org.freedesktop.DBus.GetNameOwner string:org.freedesktop.PolicyKit1 >/dev/null 2>&1; then
    echo "run.sh: polkitd did not take org.freedesktop.PolicyKit1 within 30 s" >&2
    cat /tmp/polkitd.log >&2 || true
    exit 1
fi

mkdir -p /run/nazar-test
touch /run/nazar-test/ready

home=/tmp/nazartest-home
mkdir -p "$home"
chown nazartest:nazartest "$home"

cd /work
exec runuser -u nazartest -- env -i \
    HOME="$home" USER=nazartest LOGNAME=nazartest SHELL=/bin/bash \
    LANG=C.UTF-8 TERM="${TERM:-dumb}" \
    PATH=/usr/local/go/bin:/tmp/go/bin:/usr/local/bin:/usr/bin:/bin \
    GOPATH=/tmp/go GOCACHE=/tmp/gocache GOMODCACHE=/tmp/gomodcache \
    GOTOOLCHAIN=local NAZAR_LINUX_TEST_CONTAINER=1 \
    bash -lc "cd /work && $cmd"
