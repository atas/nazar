//go:build linux && linuxplatform

package session

// MaxPending is how many warnings wait to be sent before the oldest goes.
const MaxPending = maxPending

// CallTimeout bounds every bus call.
const CallTimeout = callTimeout

// SetResolveHook makes the watch goroutine call fn, with the display
// session's id ("" when there is none to watch), after each time it looks
// the session up. Tests use it to know when a lock may be sent; set it
// before the first OnScreenLock.
func (s *Session) SetResolveHook(fn func(sessionID string)) { s.onResolve = fn }
