// peerlistener is the stand-in Nazar.app executable of the codesign tests.
//
//	peerlistener SOCK      listen on SOCK, hold every connection open
//	peerlistener -own-fd3  listen() on the inherited fd 3 (a listening socket
//	                       some other process made), print "owned", then
//	                       block without ever accepting, until killed
//
// -own-fd3 makes this process the one LOCAL_PEERTOKEN names for new
// connections to that socket while another process services them (the
// kernel facts pinned in the package doc).
package main

import (
	"fmt"
	"net"
	"os"
	"syscall"
	"time"
)

func main() {
	if len(os.Args) != 2 {
		os.Exit(2)
	}
	if os.Args[1] == "-own-fd3" {
		if err := syscall.Listen(3, 16); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Println("owned")
		for {
			time.Sleep(time.Hour)
		}
	}
	l, err := net.Listen("unix", os.Args[1])
	if err != nil {
		os.Exit(1)
	}
	for {
		c, err := l.Accept()
		if err != nil {
			return
		}
		defer c.Close()
	}
}
