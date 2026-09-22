// Package staging provides the control plane's bounded scratch space for
// large runner uploads (job cache entries, workspace snapshots, artifacts):
// a weighted byte budget over one configured directory plus an abandoned-file
// pruner. It exists because staging a multi-GB request body in an unbounded
// system temp directory lets concurrent valid runners exhaust the
// control-plane root filesystem; every large body must instead be charged
// against a configured budget before a single byte is written.
//
// Accounting model: callers reserve the number of bytes the upload may stage
// (the known Content-Length, or the endpoint's maximum when the length is
// unknown) BEFORE streaming. Acquire blocks while the reservation would
// exceed the bound and returns when room is available or the context ends, so
// the sum of in-flight staged bytes can never exceed maxBytes. Every
// reservation must be released on every exit path (a deferred Release is the
// expected pattern).
//
// The directory is also the prune root: Prune removes abandoned spool files
// (process crashes leave them behind) that are older than a minimum age, and
// never touches files outside the package's own name prefix. Startup wiring
// calls Prune before the listeners accept traffic.
package staging

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// FilePrefix names every spool file this package creates. Prune only ever
// deletes entries carrying this prefix, so pointing the staging directory at
// a shared path can never destroy unrelated files.
const FilePrefix = "kiwi-stage-"

// DefaultMaxBytes is the built-in dev-mode budget (32 GiB): enough for four
// concurrent maximum-size (8 GiB) uploads. Production deployments must
// configure an explicit bound through staging.dir/staging.max_bytes.
const DefaultMaxBytes int64 = 32 << 30

// DefaultPruneMinAge is how old an abandoned spool file must be before Prune
// removes it. It protects files that a live handler has just created (or is
// about to publish) when Prune runs concurrently with traffic.
const DefaultPruneMinAge = time.Hour

// ErrNoBound reports that no usable staging bound is configured: a missing
// directory or a non-positive byte budget. Callers treat it as a
// configuration error, and production startup refuses to serve with it.
var ErrNoBound = errors.New("staging: no usable staging bound configured")

// ErrBudgetExceeded reports that a single reservation request is larger than
// the whole budget. Acquire returns it immediately (it can never succeed);
// concurrent requests that fit the budget wait instead.
var ErrBudgetExceeded = errors.New("staging: reservation exceeds the staging budget")

// ErrTooLarge reports that a stream produced more bytes than the caller's
// per-file limit. SpoolFile removes the partial file before returning it.
var ErrTooLarge = errors.New("staging: stream exceeds the staging limit")

// Budget is the weighted byte budget over one staging directory. The zero
// value is not usable; construct with NewBudget. A Budget is safe for
// concurrent use.
type Budget struct {
	dir      string
	maxBytes int64

	// PruneMinAge overrides DefaultPruneMinAge for Prune. It is read once
	// per prune pass; callers that mutate it must not do so concurrently
	// with Prune (production leaves it zero).
	PruneMinAge time.Duration

	mu     sync.Mutex
	used   int64
	notify chan struct{}
}

// NewBudget creates the staging directory (when missing) and returns a
// budget bounded by maxBytes. It fails with ErrNoBound for an empty
// directory or a non-positive maxBytes, and with the underlying error when
// the directory cannot be created or written to — an unusable bound must
// surface at startup, never at the first multi-GB upload.
func NewBudget(dir string, maxBytes int64) (*Budget, error) {
	dir = strings.TrimSpace(dir)
	if dir == "" {
		return nil, fmt.Errorf("%w: staging directory is not configured", ErrNoBound)
	}
	if maxBytes <= 0 {
		return nil, fmt.Errorf("%w: staging max bytes must be positive, got %d", ErrNoBound, maxBytes)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("staging: create directory %s: %w", dir, err)
	}
	// Writability probe: MkdirAll succeeding is not enough (an existing
	// read-only directory, a full filesystem). Fail at startup with the real
	// error instead of failing every upload later.
	probe, err := os.CreateTemp(dir, FilePrefix+"probe-*")
	if err != nil {
		return nil, fmt.Errorf("staging: directory %s is not usable: %w", dir, err)
	}
	probePath := probe.Name()
	closeErr := probe.Close()
	removeErr := os.Remove(probePath)
	if closeErr != nil {
		return nil, fmt.Errorf("staging: directory %s is not usable: %w", dir, closeErr)
	}
	if removeErr != nil {
		return nil, fmt.Errorf("staging: directory %s is not usable: %w", dir, removeErr)
	}
	return &Budget{dir: dir, maxBytes: maxBytes, notify: make(chan struct{})}, nil
}

// Dir returns the configured staging directory.
func (b *Budget) Dir() string { return b.dir }

// MaxBytes returns the configured byte budget.
func (b *Budget) MaxBytes() int64 { return b.maxBytes }

// Used returns the number of bytes currently reserved. It is a snapshot:
// concurrent Acquire/Release may change the value immediately after it
// returns.
func (b *Budget) Used() int64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.used
}

// Acquire reserves n bytes, blocking until the reservation fits inside the
// budget or ctx ends. A non-positive n reserves nothing and succeeds
// immediately. A request larger than the whole budget fails immediately with
// an error wrapping ErrBudgetExceeded (waiting could never make it fit); a
// cancelled context fails with ctx.Err(). The returned reservation must be
// released exactly once (Release is idempotent).
func (b *Budget) Acquire(ctx context.Context, n int64) (*Reservation, error) {
	if n < 0 {
		return nil, fmt.Errorf("staging: negative reservation %d", n)
	}
	if n > b.maxBytes {
		return nil, fmt.Errorf("%w: %d bytes requested, budget is %d", ErrBudgetExceeded, n, b.maxBytes)
	}
	for {
		b.mu.Lock()
		if b.used+n <= b.maxBytes {
			b.used += n
			b.mu.Unlock()
			return &Reservation{budget: b, n: n}, nil
		}
		wait := b.notify
		b.mu.Unlock()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-wait:
		}
	}
}

// broadcastLocked wakes every waiter so each re-checks the budget. The
// caller holds b.mu.
func (b *Budget) broadcastLocked() {
	close(b.notify)
	b.notify = make(chan struct{})
}

// Reservation is one successful Acquire. Release returns its bytes to the
// budget; it is idempotent and safe to call on a nil receiver.
type Reservation struct {
	budget *Budget
	n      int64
}

// Release returns the reserved bytes. It must be called on every exit path
// of the staged transfer, including error and disconnect paths.
func (r *Reservation) Release() {
	if r == nil || r.budget == nil {
		return
	}
	b := r.budget
	n := r.n
	r.budget = nil
	r.n = 0
	b.mu.Lock()
	b.used -= n
	if b.used < 0 {
		b.used = 0
	}
	b.broadcastLocked()
	b.mu.Unlock()
}

// Prune removes abandoned spool files older than the prune minimum age and
// returns how many were removed. Only files carrying FilePrefix are
// considered; directories and foreign files are never touched. A missing
// directory is not an error. ctx cancellation is reported with the count of
// files removed so far.
func (b *Budget) Prune(ctx context.Context) (int, error) {
	if b == nil {
		return 0, nil
	}
	entries, err := os.ReadDir(b.dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 0, nil
		}
		return 0, err
	}
	minAge := b.PruneMinAge
	if minAge <= 0 {
		minAge = DefaultPruneMinAge
	}
	cutoff := time.Now().Add(-minAge)
	removed := 0
	for _, e := range entries {
		if err := ctx.Err(); err != nil {
			return removed, err
		}
		if e.IsDir() || !strings.HasPrefix(e.Name(), FilePrefix) {
			continue
		}
		info, err := e.Info()
		if err != nil {
			// The entry vanished between ReadDir and Info: nothing to prune.
			continue
		}
		if info.ModTime().After(cutoff) {
			continue
		}
		if err := os.Remove(filepath.Join(b.dir, e.Name())); err != nil && !errors.Is(err, os.ErrNotExist) {
			return removed, err
		}
		removed++
	}
	return removed, nil
}

// SpoolFile stages r into a fresh file in dir under FilePrefix and returns
// its path and the number of bytes written. When limit is positive the copy
// stops after limit bytes and the partial file is removed with an error
// wrapping ErrTooLarge; a reader error (for example http.MaxBytesError from
// the caller's body cap) is returned unchanged after the partial file is
// removed. The caller owns the returned path and must remove it.
func SpoolFile(dir string, r io.Reader, limit int64) (string, int64, error) {
	dir = strings.TrimSpace(dir)
	if dir == "" {
		return "", 0, fmt.Errorf("%w: staging directory is not configured", ErrNoBound)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", 0, err
	}
	f, err := os.CreateTemp(dir, FilePrefix+"*")
	if err != nil {
		return "", 0, err
	}
	path := f.Name()
	src := r
	if limit > 0 {
		src = &limitedReader{r: r, remaining: limit + 1}
	}
	n, copyErr := io.Copy(f, src)
	syncErr := f.Sync()
	closeErr := f.Close()
	if err := firstErr(copyErr, syncErr, closeErr); err != nil {
		_ = os.Remove(path)
		return "", 0, err
	}
	if limit > 0 && n > limit {
		_ = os.Remove(path)
		return "", n, fmt.Errorf("%w: staged %d bytes with limit %d", ErrTooLarge, n, limit)
	}
	return path, n, nil
}

// limitedReader yields at most remaining bytes and then reports EOF; it
// bounds a reader that would otherwise stream forever, leaving the
// over-limit decision to SpoolFile's size check.
type limitedReader struct {
	r         io.Reader
	remaining int64
}

func (l *limitedReader) Read(p []byte) (int, error) {
	if l.remaining <= 0 {
		return 0, io.EOF
	}
	if int64(len(p)) > l.remaining {
		p = p[:l.remaining]
	}
	n, err := l.r.Read(p)
	l.remaining -= int64(n)
	return n, err
}

func firstErr(errs ...error) error {
	for _, err := range errs {
		if err != nil {
			return err
		}
	}
	return nil
}
