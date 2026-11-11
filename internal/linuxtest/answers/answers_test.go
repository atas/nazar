package answers

import (
	"path/filepath"
	"testing"
	"time"
)

func TestOrderAcrossPopAndPopFrom(t *testing.T) {
	q := NewQueue(t)
	q.Push(false)
	q.Push(true)
	q.Push(false)
	if allow, ok := q.Pop(time.Second); !ok || allow {
		t.Fatalf("Pop = %v, %v; want false, true", allow, ok)
	}
	if allow, ok := PopFrom(q.Socket(), time.Second); !ok || !allow {
		t.Fatalf("PopFrom = %v, %v; want true, true", allow, ok)
	}
	if allow, ok := q.Pop(time.Second); !ok || allow {
		t.Fatalf("Pop = %v, %v; want false, true", allow, ok)
	}
	if _, ok := q.Pop(50 * time.Millisecond); ok {
		t.Fatal("Pop on an empty queue: ok")
	}
}

func TestPopFromWaitsForAPush(t *testing.T) {
	q := NewQueue(t)
	go func() {
		time.Sleep(100 * time.Millisecond)
		q.Push(true)
	}()
	if allow, ok := PopFrom(q.Socket(), 5*time.Second); !ok || !allow {
		t.Fatalf("PopFrom = %v, %v; want true, true", allow, ok)
	}
}

func TestPopTimesOut(t *testing.T) {
	q := NewQueue(t)
	start := time.Now()
	if _, ok := q.Pop(100 * time.Millisecond); ok {
		t.Fatal("Pop on an empty queue: ok")
	}
	if d := time.Since(start); d < 100*time.Millisecond || d > 2*time.Second {
		t.Fatalf("Pop returned after %v, want about 100ms", d)
	}
}

func TestPopFromWithoutAQueue(t *testing.T) {
	if _, ok := PopFrom(filepath.Join(t.TempDir(), "none.sock"), time.Second); ok {
		t.Fatal("PopFrom with no queue: ok")
	}
}

// An answer whose reply could not be written goes back to the front.
func TestUnpopKeepsTheOrder(t *testing.T) {
	q := NewQueue(t)
	q.Push(false)
	q.unpop(true)
	if allow, ok := q.Pop(time.Second); !ok || !allow {
		t.Fatalf("Pop = %v, %v; want true, true", allow, ok)
	}
	if allow, ok := q.Pop(time.Second); !ok || allow {
		t.Fatalf("Pop = %v, %v; want false, true", allow, ok)
	}
}
