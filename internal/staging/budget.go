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
// expected pattern). SpoolFile never writes more than the caller's limit to
// disk, so staged bytes always fit the reservation that authorized them.
//
// Ownership model (single writer per directory): constructing a Budget takes
// an exclusive lock on <dir>/kiwi-stage.lock and holds it for the process
// lifetime. Because no other live process can hold the lock while we do,
// every kiwi-stage-* entry that already exists when the lock is taken is
// provably abandoned by a dead owner: the constructor deletes all of them
// (no age floor) and initializes the ledger to zero, which is what makes the
// byte bound real across crashes. A second live process that tries to own the
// same directory fails startup with ErrStagingDirOwned instead of admitting
// another full maxBytes over the same bytes; within one process the same
// directory maps to exactly one shared ledger (a process is one accounting
// authority). Budget.Close releases ownership explicitly, which is how a
// restart is simulated in tests and how a caller hands the directory to a
// successor. Prune stays for the runtime age-based sweep of files abandoned
// by the *current* process (a panicked or cancelled handler) and never
// touches files outside the package's own name prefix.
//
// Per-replica contract: the configured directory is a ROOT, and every process
// stages inside <root>/<instance-id> (see NewReplicaBudget and ReplicaDir).
// Replicas sharing a root MUST use distinct instance ids; without an explicit
// id the first process generates and persists one in the root, so a second
// replica without its own id is refused by the ownership lock rather than
// silently doubling the total footprint. The contract is enforced at startup
// and spelled out in the configuration validation text.
//
// Legacy-layout policy: a pre-contract process (< commit 72d887d) staged its
// ACTIVE spool files directly in the shared root, with no ownership lock, so a
// top-level kiwi-stage-* entry in the root is NOT provably abandoned — during
// a rolling HA upgrade it can be a still-running old replica's in-flight
// upload. Constructing a replica budget therefore NEVER reclaims top-level
// entries in the root; they stay untouched until an operator runs the explicit
// MigrateLegacyStagingLayout (kiwi storage migrate-staging-layout) once every
// old-layout replica has drained. Only the files inside a replica's own
// <root>/<instance-id> directory are reclaimed at construction, under that
// directory's ownership lock.
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
	"sync/atomic"
	"time"
)

// FilePrefix names every spool file this package creates. Startup reclaim
// and Prune only ever delete entries carrying this prefix, so pointing the
// staging directory at a shared path can never destroy unrelated files.
const FilePrefix = "kiwi-stage-"

// LockFileName is the ownership lock file inside a staging directory. It
// deliberately does not match FilePrefix (dot instead of dash), so neither
// the startup reclaim nor Prune can delete the lock that proves ownership.
const LockFileName = "kiwi-stage.lock"

// DefaultMaxBytes is the built-in dev-mode budget (32 GiB): enough for four
// concurrent maximum-size (8 GiB) uploads. Production deployments must
// configure an explicit bound through staging.dir/staging.max_bytes.
const DefaultMaxBytes int64 = 32 << 30

// DefaultPruneMinAge is how old a spool file abandoned by the RUNNING process
// must be before Prune removes it. It protects files that a live handler has
// just created (or is about to publish) when Prune runs concurrently with
// traffic. Files abandoned by a previous, dead process are not subject to
// this age floor: they are reclaimed at construction, under the ownership
// lock, the moment this process becomes the directory's only live writer.
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
// per-file limit. SpoolFile removes the partial file before returning it and
// never writes more than the limit to disk.
var ErrTooLarge = errors.New("staging: stream exceeds the staging limit")

// ErrStagingDirOwned reports that another LIVE process (or another owner in
// this process) holds the staging directory's ownership lock. Startup must
// fail rather than let two live ledgers share one directory: each would admit
// a full maxBytes while the disk holds the union of their staged bytes.
var ErrStagingDirOwned = errors.New("staging: staging directory is owned by another live process")

// ErrClosed reports a reservation attempt on a Budget whose ownership has
// been released with Close. The directory may already belong to a successor,
// so no new bytes may be admitted.
var ErrClosed = errors.New("staging: budget is closed")

// Budget is the weighted byte budget over one staging directory. The zero
// value is not usable; construct with NewBudget (exact directory) or
// NewReplicaBudget (configured root + replica instance id). A Budget is safe
// for concurrent use.
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

	// lock is the held ownership token of dir; release happens in Close (or
	// at process exit, when the OS drops the lock).
	lock *dirLock

	// registryKey is the canonical directory used by the process-wide
	// ownership registry, and staleRemoved counts the abandoned spool files
	// reclaimed when ownership was taken. Both are immutable after
	// construction, so accessors need no synchronization.
	registryKey  string
	staleRemoved int

	// closed is the CLOSING flag: Close sets it (under mu) before waiting, so
	// every Acquire that checks it under mu observes a budget that is at least
	// closing and fails closed. Reading it only under mu is what closes the
	// Close/Acquire race (a bare pre-lock check could see false and then
	// increment used after Close had already retired the budget).
	closed atomic.Bool

	// finalized and done implement the exactly-once ownership release. Close
	// sets finalized under mu when used has reached zero and then releases the
	// lock outside mu, closing done so every concurrent/retrying Close call
	// converges. Both are mu-guarded.
	finalized bool
	done      chan struct{}
}

// ownedDirs is the process-wide ownership registry: at most one live Budget
// per staging directory per process. Two constructors for the same directory
// in one process are not two owners competing for one disk bound, they are
// one process asking for the same ledger twice; returning the existing
// Budget keeps the bound exact. Cross-process exclusion is the lock file.
var (
	ownedDirsMu sync.Mutex
	ownedDirs   = map[string]*Budget{}
)

// registeredBudget returns the process's live Budget for the canonical
// directory, or nil when none is registered. A directory registered with a
// different byte bound is an error: one directory carries exactly one ledger,
// and silently reusing a different bound would misstate the byte limit.
func registeredBudget(key string, maxBytes int64) (*Budget, error) {
	ownedDirsMu.Lock()
	defer ownedDirsMu.Unlock()
	b := ownedDirs[key]
	if b == nil || b.closed.Load() {
		return nil, nil
	}
	if b.maxBytes != maxBytes {
		return nil, fmt.Errorf("staging: directory %s is already owned by this process with a %d-byte budget (requested %d); one staging directory carries exactly one ledger", b.dir, b.maxBytes, maxBytes)
	}
	return b, nil
}

func registerBudget(b *Budget) {
	ownedDirsMu.Lock()
	ownedDirs[b.registryKey] = b
	ownedDirsMu.Unlock()
}

func unregisterBudget(b *Budget) {
	ownedDirsMu.Lock()
	if ownedDirs[b.registryKey] == b {
		delete(ownedDirs, b.registryKey)
	}
	ownedDirsMu.Unlock()
}

// canonicalDir normalizes a staging path so equivalent spellings share one
// registry entry.
func canonicalDir(dir string) string {
	if abs, err := filepath.Abs(dir); err == nil {
		return filepath.Clean(abs)
	}
	return filepath.Clean(dir)
}

// validateBound is the shared input contract of both constructors.
func validateBound(dir string, maxBytes int64) error {
	if strings.TrimSpace(dir) == "" {
		return fmt.Errorf("%w: staging directory is not configured", ErrNoBound)
	}
	if maxBytes <= 0 {
		return fmt.Errorf("%w: staging max bytes must be positive, got %d", ErrNoBound, maxBytes)
	}
	return nil
}

// NewBudget creates the exact staging directory dir (when missing), takes
// exclusive ownership of it, reclaims every spool file a dead owner left
// behind, and returns a budget bounded by maxBytes with a zero ledger. It
// fails with ErrNoBound for an empty directory or a non-positive maxBytes,
// with ErrStagingDirOwned when another live owner holds the directory, and
// with the underlying error when the directory cannot be created, written to,
// or cleaned — an unusable bound must surface at startup, never at the first
// multi-GB upload.
//
// NewBudget treats dir as the replica-private directory itself. Callers that
// hold a configured ROOT (staging.dir) must use NewReplicaBudget instead, so
// replicas sharing the root stage into distinct subdirectories.
func NewBudget(dir string, maxBytes int64) (*Budget, error) {
	return newBudget(dir, maxBytes)
}

// newBudget is the constructor shared by NewBudget and NewReplicaBudget. It
// reclaims the spool files of the EXACT directory it owns (a dead owner's,
// proven by the ownership lock); it never touches a parent root.
func newBudget(dir string, maxBytes int64) (*Budget, error) {
	dir = strings.TrimSpace(dir)
	if err := validateBound(dir, maxBytes); err != nil {
		return nil, err
	}
	key := canonicalDir(dir)
	if existing, err := registeredBudget(key, maxBytes); err != nil {
		return nil, err
	} else if existing != nil {
		return existing, nil
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("staging: create directory %s: %w", dir, err)
	}
	// Ownership first: the lock is what turns "files I can see" into "files a
	// dead owner left". Until it is held, a concurrent live owner may still
	// be writing into dir.
	lock, err := acquireDirLock(dir)
	if err != nil {
		return nil, err
	}
	// Provably-dead-owner reclaim. We hold the exclusive lock, so no live
	// process can be writing into dir; every existing kiwi-stage-* entry
	// predates our ownership and belongs to an owner that crashed or was
	// killed (a clean exit releases the lock AND removes its spool files).
	// Deleting all of them — regardless of age — is what makes the ledger
	// start from a truthful zero: leaving any behind would let this process
	// admit another full maxBytes on top of bytes already occupying the
	// filesystem, exactly the crash-amnesia defect this constructor exists to
	// prevent. Directories and foreign files are never touched.
	removed, serr := sweepSpoolFiles(dir)
	if serr != nil {
		_ = lock.release()
		return nil, fmt.Errorf("staging: reclaim abandoned spool files in %s: %w", dir, serr)
	}
	// Writability probe: MkdirAll and the sweep succeeding is not enough (an
	// existing read-only directory, a full filesystem). The probe runs after
	// the reclaim so the file it creates cannot be mistaken for an abandoned
	// one, and it is removed before this function returns.
	if err := probeWritable(dir); err != nil {
		_ = lock.release()
		return nil, err
	}
	b := &Budget{
		dir:          dir,
		maxBytes:     maxBytes,
		notify:       make(chan struct{}),
		lock:         lock,
		registryKey:  key,
		staleRemoved: removed,
		done:         make(chan struct{}),
	}
	registerBudget(b)
	return b, nil
}

// probeWritable verifies that dir accepts and deletes a fresh file. It fails
// with the real error instead of deferring every upload to the same failure.
func probeWritable(dir string) error {
	probe, err := os.CreateTemp(dir, FilePrefix+"probe-*")
	if err != nil {
		return fmt.Errorf("staging: directory %s is not usable: %w", dir, err)
	}
	probePath := probe.Name()
	closeErr := probe.Close()
	removeErr := os.Remove(probePath)
	if closeErr != nil {
		return fmt.Errorf("staging: directory %s is not usable: %w", dir, closeErr)
	}
	if removeErr != nil {
		return fmt.Errorf("staging: directory %s is not usable: %w", dir, removeErr)
	}
	return nil
}

// sweepSpoolFiles removes every top-level FilePrefix entry in dir, without an
// age floor, and returns how many were removed. Directories are skipped, so a
// configured root's per-replica subdirectories are never entered or removed.
// A missing directory is not an error. A file that vanishes between ReadDir
// and Remove is treated as removed (nothing survives either way); any other
// removal failure is returned, because the ledger cannot claim a truthful
// zero while unaccounted bytes remain on disk.
func sweepSpoolFiles(dir string) (int, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 0, nil
		}
		return 0, err
	}
	removed := 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasPrefix(e.Name(), FilePrefix) {
			continue
		}
		if err := os.Remove(filepath.Join(dir, e.Name())); err != nil && !errors.Is(err, os.ErrNotExist) {
			return removed, err
		}
		removed++
	}
	return removed, nil
}

// Dir returns the replica-private staging directory: the exact directory the
// configured root was resolved to, or the exact directory passed to
// NewBudget. Spool files must be created here.
func (b *Budget) Dir() string { return b.dir }

// MaxBytes returns the configured byte budget.
func (b *Budget) MaxBytes() int64 { return b.maxBytes }

// StaleFilesRemoved returns how many abandoned spool files the constructor
// reclaimed when it took ownership: files left by a previous, dead process in
// the exact staging directory it owns. It never counts legacy bare files in a
// configured root, because replica construction deliberately leaves those
// untouched (see MigrateLegacyStagingLayout). It is immutable after
// construction.
func (b *Budget) StaleFilesRemoved() int { return b.staleRemoved }

// Used returns the number of bytes currently reserved. It is a snapshot:
// concurrent Acquire/Release may change the value immediately after it
// returns.
func (b *Budget) Used() int64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.used
}

// Close releases the directory ownership token and unregisters the budget
// from the process-wide registry. It is idempotent and nil-safe and is the
// unbounded fallback for CloseWithContext: it waits until every
// outstanding reservation has been released before returning.
//
// Close first transitions the budget to CLOSING, so Acquire fails closed with
// ErrClosed (the directory may already belong to a successor process) and
// acquires already blocked on the budget wake up and fail closed too. It then
// waits for Used() to reach zero before releasing the ownership lock: a
// successor budget must never start (and sweep spool files) while a
// reservation from this budget still covers staged bytes. Calls released
// after Close still return their bytes to the (now retired) ledger.
//
// Production servers hold ownership for the process lifetime and rely on
// process exit; Close exists for orderly hand-off and for tests that simulate
// a crash and restart. Because it waits for outstanding reservations, a
// caller that cannot guarantee a bounded drain should use CloseWithContext.
func (b *Budget) Close() error {
	return b.CloseWithContext(context.Background())
}

// CloseWithContext is Close bounded by ctx. It transitions the budget to
// CLOSING (rejecting new acquisitions with ErrClosed and waking blocked
// acquirers), then waits for Used() to reach zero before releasing the
// directory ownership lock and unregistering the budget.
//
// If ctx ends before the last reservation is released, CloseWithContext
// returns ctx.Err() WITHOUT releasing ownership: the directory stays ours and
// a later Close/CloseWithContext completes the hand-off once the ledger
// drains. That is the safe direction — a successor must never sweep bytes a
// live reservation still covers.
//
// Concurrent Close calls converge: exactly one performs the release and the
// others block until it completes (bounded by their own ctx). The release
// error is returned by the call that performed it; the others return nil.
func (b *Budget) CloseWithContext(ctx context.Context) error {
	if b == nil {
		return nil
	}
	b.mu.Lock()
	if b.done == nil {
		b.done = make(chan struct{})
	}
	if !b.closed.Load() {
		b.closed.Store(true)
		b.broadcastLocked()
	}
	for {
		if b.finalized {
			// Another call already completed (or is completing) the
			// hand-off; wait for it rather than releasing twice.
			done := b.done
			b.mu.Unlock()
			select {
			case <-done:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		if b.used == 0 {
			// Last reservation gone (or never existed): release ownership.
			b.finalized = true
			done := b.done
			lock := b.lock
			b.mu.Unlock()
			unregisterBudget(b)
			err := lock.release()
			close(done)
			return err
		}
		if err := ctx.Err(); err != nil {
			// Keep the CLOSING state and ownership: the last Release (or a
			// later Close) drains and releases.
			b.mu.Unlock()
			return err
		}
		wait := b.notify
		b.mu.Unlock()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-wait:
		}
		b.mu.Lock()
	}
}

// Acquire reserves n bytes, blocking until the reservation fits inside the
// budget or ctx ends. A non-positive n reserves nothing and succeeds
// immediately. A request larger than the whole budget fails immediately with
// an error wrapping ErrBudgetExceeded (waiting could never make it fit); a
// cancelled context fails with ctx.Err(); a closed budget fails with
// ErrClosed. The returned reservation must be released exactly once (Release
// is idempotent).
func (b *Budget) Acquire(ctx context.Context, n int64) (*Reservation, error) {
	if n < 0 {
		return nil, fmt.Errorf("staging: negative reservation %d", n)
	}
	if n > b.maxBytes {
		return nil, fmt.Errorf("%w: %d bytes requested, budget is %d", ErrBudgetExceeded, n, b.maxBytes)
	}
	for {
		// The closed check MUST happen under mu, immediately before the
		// increment: Close sets closed under the same mu, so once a caller
		// observes closed==false and then increments used, Close cannot have
		// retired the directory in between (it would have had to take mu
		// first and flip closed). A pre-lock check would let Close release the
		// ownership lock and a successor start while this call still handed
		// out a reservation against the retired ledger.
		b.mu.Lock()
		if b.closed.Load() {
			b.mu.Unlock()
			return nil, fmt.Errorf("%w: %s", ErrClosed, b.dir)
		}
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
// budget exactly once; it is idempotent and safe to call on a nil receiver.
type Reservation struct {
	budget *Budget
	n      int64

	// releaseOnce makes Release exactly-once even under concurrent calls.
	// The budget/n fields are immutable (never nil'd by Release), so the
	// only synchronization anyone needs for them is this Once: without it,
	// two concurrent releases both observe a live reservation and decrement
	// the ledger twice.
	releaseOnce sync.Once
}

// Release returns the reserved bytes. It must be called on every exit path of
// the staged transfer, including error and disconnect paths. Concurrent calls
// are safe: exactly one decrement happens, the rest are no-ops.
func (r *Reservation) Release() {
	if r == nil {
		return
	}
	r.releaseOnce.Do(func() {
		b := r.budget
		if b == nil {
			return
		}
		b.mu.Lock()
		b.used -= r.n
		if b.used < 0 {
			b.used = 0
		}
		b.broadcastLocked()
		b.mu.Unlock()
	})
}

// Prune removes abandoned spool files older than the prune minimum age and
// returns how many were removed. Only files carrying FilePrefix are
// considered; directories and foreign files are never touched. A missing
// directory is not an error. ctx cancellation is reported with the count of
// files removed so far.
//
// Prune is the RUNTIME sweep: files abandoned by the running process (a
// panicked handler, a cancelled upload). Files left by a previous, dead
// process are already reclaimed at construction, without an age floor,
// because ownership of the directory proves they cannot belong to anyone
// live.
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
// never writes more than limit bytes to disk: the stream is read up to limit
// and then probed for a single extra byte on the SOURCE, so an over-limit
// reader is detected and rejected (error wrapping ErrTooLarge, partial file
// removed) without that byte ever reaching the filesystem. A reader error
// (for example http.MaxBytesError from the caller's body cap) is returned
// unchanged after the partial file is removed. The caller owns the returned
// path and must remove it.
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
	n, copyErr := spoolCopy(f, r, limit)
	syncErr := f.Sync()
	closeErr := f.Close()
	if err := firstErr(copyErr, syncErr, closeErr); err != nil {
		_ = os.Remove(path)
		return "", n, err
	}
	return path, n, nil
}

// spoolCopy copies at most limit bytes of src into dst (unlimited when limit
// is not positive) and reports ErrTooLarge when the source still has data
// after those limit bytes. The over-limit byte is read from the SOURCE but
// never written, so a caller whose reservation equals limit can hold the
// exact "staged bytes never exceed the reservation" invariant even when the
// body lies about its length.
func spoolCopy(dst io.Writer, src io.Reader, limit int64) (int64, error) {
	if limit <= 0 {
		return io.Copy(dst, src)
	}
	n, err := io.Copy(dst, io.LimitReader(src, limit))
	if err != nil {
		return n, err
	}
	var probe [1]byte
	m, perr := src.Read(probe[:])
	switch {
	case m > 0:
		return n, fmt.Errorf("%w: staged %d bytes with limit %d", ErrTooLarge, n, limit)
	case perr == nil:
		// A reader returning (0, nil) forever cannot prove EOF; fail closed
		// rather than acknowledge an unbounded stream.
		return n, fmt.Errorf("%w: staged %d bytes with limit %d (reader made no progress)", ErrTooLarge, n, limit)
	case errors.Is(perr, io.EOF):
		return n, nil
	default:
		return n, perr
	}
}

func firstErr(errs ...error) error {
	for _, err := range errs {
		if err != nil {
			return err
		}
	}
	return nil
}
