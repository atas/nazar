#!/bin/bash
# Runs a user-level sshd on 127.0.0.1:2222 trusting ~/.nazar/s678.pub. Ctrl-C to stop.
set -euo pipefail
D="$(cd "$(dirname "$0")" && pwd)/test-sshd"
mkdir -p "$D"
[ -f "$D/host_ed25519" ] || ssh-keygen -q -t ed25519 -N "" -f "$D/host_ed25519"
cp ~/.nazar/s678.pub "$D/authorized_keys"
cat > "$D/sshd_config" <<EOF
Port 2222
ListenAddress 127.0.0.1
HostKey $D/host_ed25519
AuthorizedKeysFile $D/authorized_keys
PidFile $D/sshd.pid
StrictModes no
UsePAM no
PasswordAuthentication no
KbdInteractiveAuthentication no
EOF
exec /usr/sbin/sshd -D -e -f "$D/sshd_config"
