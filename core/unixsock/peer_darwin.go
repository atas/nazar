//go:build darwin

package unixsock

import "golang.org/x/sys/unix"

// peerUID reads the credentials the kernel recorded for the peer at
// connect time (LOCAL_PEERCRED); nothing the peer sends can change them.
func peerUID(fd int) (int, error) {
	cred, err := unix.GetsockoptXucred(fd, unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	if err != nil {
		return -1, err
	}
	return int(cred.Uid), nil
}
