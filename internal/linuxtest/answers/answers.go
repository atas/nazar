// Package answers is the scripted user of the Linux platform tests: a test
// pushes what the person would answer (allow or deny), in order, and the
// prompts consume the answers. In-process consumers (the test polkit agent)
// call Queue.Pop; helper processes (fakedialog) get the socket in
// NAZAR_TEST_ANSWERS and call PopFrom. Test-only code; nothing in it ships.
package answers

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// maxWait caps the wait a helper process may ask for.
const maxWait = 5 * time.Minute

// grace is how much longer PopFrom waits for the reply than it asked the
// server to wait, so an answer the server popped is not lost in flight.
const grace = 5 * time.Second

// Queue holds the answers in order and serves them on a unix socket.
type Queue struct {
	mu     sync.Mutex
	items  []bool
	wake   chan struct{} // closed and replaced on every Push
	done   chan struct{} // closed at cleanup: every Pop returns
	socket string
	ln     net.Listener
	wg     sync.WaitGroup
}

// NewQueue starts an empty queue whose socket lives in a short temporary
// folder (unix socket paths are limited to about 104 bytes), removed with
// the listener at cleanup.
func NewQueue(t testing.TB) *Queue {
	t.Helper()
	dir, err := os.MkdirTemp("", "nzans")
	if err != nil {
		t.Fatalf("answers: %v", err)
	}
	socket := filepath.Join(dir, "answers.sock")
	ln, err := net.Listen("unix", socket)
	if err != nil {
		os.RemoveAll(dir)
		t.Fatalf("answers: listen %s: %v", socket, err)
	}
	q := &Queue{wake: make(chan struct{}), done: make(chan struct{}), socket: socket, ln: ln}
	q.wg.Add(1)
	go q.serve()
	t.Cleanup(func() {
		close(q.done)
		ln.Close()
		q.wg.Wait()
		os.RemoveAll(dir)
	})
	return q
}

// Socket is the path helper processes get as NAZAR_TEST_ANSWERS.
func (q *Queue) Socket() string { return q.socket }

// Push adds an answer at the end of the queue.
func (q *Queue) Push(allow bool) {
	q.mu.Lock()
	q.items = append(q.items, allow)
	close(q.wake)
	q.wake = make(chan struct{})
	q.mu.Unlock()
}

// Pop takes the first answer, waiting up to timeout for one. ok is false
// when none came in time (or the queue was cleaned up).
func (q *Queue) Pop(timeout time.Duration) (allow bool, ok bool) {
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	for {
		q.mu.Lock()
		if len(q.items) > 0 {
			allow = q.items[0]
			q.items = q.items[1:]
			q.mu.Unlock()
			return allow, true
		}
		wake := q.wake
		q.mu.Unlock()
		select {
		case <-wake:
		case <-timer.C:
			return false, false
		case <-q.done:
			return false, false
		}
	}
}

// unpop puts an answer back at the front: its reply never reached the
// helper, so the next prompt must get it.
func (q *Queue) unpop(allow bool) {
	q.mu.Lock()
	q.items = append([]bool{allow}, q.items...)
	close(q.wake)
	q.wake = make(chan struct{})
	q.mu.Unlock()
}

func (q *Queue) serve() {
	defer q.wg.Done()
	for {
		c, err := q.ln.Accept()
		if err != nil {
			return
		}
		q.wg.Add(1)
		go func() {
			defer q.wg.Done()
			q.handle(c)
		}()
	}
}

// The protocol is one line each way: "pop <milliseconds>\n", then
// "allow\n", "deny\n" or "none\n".
func (q *Queue) handle(c net.Conn) {
	defer c.Close()
	c.SetReadDeadline(time.Now().Add(grace))
	line, err := bufio.NewReader(c).ReadString('\n')
	if err != nil {
		return
	}
	ms, ok := strings.CutPrefix(strings.TrimSuffix(line, "\n"), "pop ")
	if !ok {
		return
	}
	n, err := strconv.ParseInt(ms, 10, 64)
	if err != nil || n < 0 {
		return
	}
	wait := min(time.Duration(n)*time.Millisecond, maxWait)
	allow, ok := q.Pop(wait)
	reply := "none\n"
	if ok {
		reply = "deny\n"
		if allow {
			reply = "allow\n"
		}
	}
	c.SetWriteDeadline(time.Now().Add(grace))
	if _, err := c.Write([]byte(reply)); err != nil && ok {
		q.unpop(allow)
	}
}

// PopFrom asks the queue at socket for the next answer, waiting up to
// timeout. Any failure (no queue, a bad reply) is ok == false: the helper
// treats it as no answer.
func PopFrom(socket string, timeout time.Duration) (allow bool, ok bool) {
	if timeout < 0 {
		timeout = 0
	}
	c, err := net.DialTimeout("unix", socket, grace)
	if err != nil {
		return false, false
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(timeout + grace))
	if _, err := fmt.Fprintf(c, "pop %d\n", timeout.Milliseconds()); err != nil {
		return false, false
	}
	line, err := bufio.NewReader(c).ReadString('\n')
	if err != nil {
		return false, false
	}
	switch line {
	case "allow\n":
		return true, true
	case "deny\n":
		return false, true
	}
	return false, false
}
