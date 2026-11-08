//go:build linux

package unixsock

import "golang.org/x/sys/unix"

// peerUID reads the credentials the kernel recorded for the peer at
// connect time (SO_PEERCRED); nothing the peer sends can change them.
func peerUID(fd int) (int, error) {
	cred, err := unix.GetsockoptUcred(fd, unix.SOL_SOCKET, unix.SO_PEERCRED)
	if err != nil {
		return -1, err
	}
	return int(cred.Uid), nil
}
