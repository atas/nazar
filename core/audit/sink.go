package audit

import (
	"fmt"
	"io"
	"sync"
	"time"
)

// Sink receives formatted audit lines. The macOS implementation (Milestone 3)
// writes os_log at .default level, subsystem Subsystem, category Category,
// with every field marked public. Lines are at most MaxLine bytes, below
// what the unified log stores before truncating a message. Implementations
// must be safe for concurrent use.
type Sink interface {
	WriteAudit(t time.Time, line string) error
}

// Logger formats events and writes them to a sink. A failing sink is
// reported through onError and never blocks the decision.
type Logger struct {
	sink    Sink
	onError func(error)
	mu      sync.Mutex
	format  Formatter
	observe func(Event)
}

// SetObserver registers fn to see every event after it was written (nil
// removes it). The daemon uses it to remember when each key was last used
// (Milestone 5). fn runs on the logging goroutine and must not block or
// call Log.
func (l *Logger) SetObserver(fn func(Event)) {
	l.mu.Lock()
	l.observe = fn
	l.mu.Unlock()
}

// NewLogger returns a Logger; onError may be nil.
func NewLogger(sink Sink, f Formatter, onError func(error)) *Logger {
	return &Logger{sink: sink, format: f, onError: onError}
}

// SetFormatter changes the formatting (audit.args changes on config reload).
func (l *Logger) SetFormatter(f Formatter) {
	l.mu.Lock()
	l.format = f
	l.mu.Unlock()
}

// Log writes one event. The event's Time is passed to the sink separately
// and never appears in the message text.
func (l *Logger) Log(e Event) {
	l.mu.Lock()
	f, observe := l.format, l.observe
	l.mu.Unlock()
	if err := l.sink.WriteAudit(e.Time, f.Format(e)); err != nil && l.onError != nil {
		l.onError(err)
	}
	if observe != nil {
		observe(e)
	}
}

// MemorySink keeps lines in memory (tests).
type MemorySink struct {
	mu    sync.Mutex
	lines []string
}

// WriteAudit implements Sink.
func (m *MemorySink) WriteAudit(_ time.Time, line string) error {
	m.mu.Lock()
	m.lines = append(m.lines, line)
	m.mu.Unlock()
	return nil
}

// Lines returns a copy of everything written so far.
func (m *MemorySink) Lines() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]string(nil), m.lines...)
}

// WriterSink writes "<RFC3339 UTC> <line>\n" to W (the test daemon's audit
// file). Writes are serialised so concurrent events never interleave.
type WriterSink struct {
	mu sync.Mutex
	W  io.Writer
}

// WriteAudit implements Sink.
func (w *WriterSink) WriteAudit(t time.Time, line string) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	_, err := fmt.Fprintf(w.W, "%s %s\n", t.UTC().Format(time.RFC3339), line)
	return err
}
