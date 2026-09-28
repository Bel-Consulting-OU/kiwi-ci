// Package progress carries an optional progress-pulse callback in a context.
//
// The streaming inactivity guard in internal/app cancels a request when no
// byte moves for one idle window. Socket reads and writes are obvious
// progress, but they are not the only real progress: a backend transfer (a
// CAS/S3 put or open, a staging spool drain) moves bytes without touching the
// client socket, sometimes for minutes on an 8 GiB object. The middleware
// installs a pulse callback with WithPulse; lower layers that move bytes call
// Pulse on every successful unit of transfer, so the guard measures "no
// socket OR backend byte progress for the idle window" instead of "no socket
// activity". A layer that has no pulse installed pays nothing: Pulse is a
// single context lookup and a nil check.
package progress

import "context"

// pulseKey is the private context key for the progress callback. The zero
// value is used as the key so no other package can collide with it.
type pulseKey struct{}

// WithPulse returns a context that carries pulse. Every call to Pulse on the
// returned context (or a context derived from it) invokes pulse; a nil pulse
// returns ctx unchanged. The callback must be safe for concurrent use: byte
// movement happens on the handler goroutine and, for streaming bodies, on the
// net/http server goroutine.
func WithPulse(ctx context.Context, pulse func()) context.Context {
	if pulse == nil {
		return ctx
	}
	return context.WithValue(ctx, pulseKey{}, pulse)
}

// Pulse reports one unit of real byte progress to the callback installed by
// WithPulse, when the context carries one. It is safe to call on any context,
// including one that never went through WithPulse.
func Pulse(ctx context.Context) {
	if ctx == nil {
		return
	}
	if fn, ok := ctx.Value(pulseKey{}).(func()); ok && fn != nil {
		fn()
	}
}
