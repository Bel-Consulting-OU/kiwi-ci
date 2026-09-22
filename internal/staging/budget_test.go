package staging

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestNewBudgetRequiresUsableBound(t *testing.T) {
	dir := t.TempDir()
	for name, tc := range map[string]struct {
		dir      string
		maxBytes int64
	}{
		"empty dir":    {"", 10},
		"blank dir":    {"   ", 10},
		"zero max":     {dir, 0},
		"negative max": {dir, -1},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := NewBudget(tc.dir, tc.maxBytes); !errors.Is(err, ErrNoBound) {
				t.Fatalf("NewBudget(%q, %d) = %v, want ErrNoBound", tc.dir, tc.maxBytes, err)
			}
		})
	}
}

func TestNewBudgetCreatesDirectoryAndRejectsUnusable(t *testing.T) {
	root := t.TempDir()
	nested := filepath.Join(root, "a", "b", "staging")
	b, err := NewBudget(nested, 1024)
	if err != nil {
		t.Fatalf("NewBudget nested: %v", err)
	}
	if b.Dir() != nested || b.MaxBytes() != 1024 {
		t.Fatalf("budget = dir %q max %d", b.Dir(), b.MaxBytes())
	}
	if fi, err := os.Stat(nested); err != nil || !fi.IsDir() {
		t.Fatalf("staging directory not created: %v", err)
	}
	// A path whose parent is a regular file can never be a usable staging
	// directory: construction must fail, not defer to the first upload.
	file := filepath.Join(root, "file")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewBudget(filepath.Join(file, "staging"), 1024); err == nil {
		t.Fatal("NewBudget under a regular file succeeded, want error")
	}
}

func TestBudgetReserveRelease(t *testing.T) {
	b, err := NewBudget(t.TempDir(), 100)
	if err != nil {
		t.Fatal(err)
	}
	if b.Used() != 0 {
		t.Fatalf("fresh used = %d", b.Used())
	}
	res, err := b.Acquire(context.Background(), 30)
	if err != nil {
		t.Fatal(err)
	}
	if b.Used() != 30 {
		t.Fatalf("used after acquire = %d, want 30", b.Used())
	}
	res.Release()
	if b.Used() != 0 {
		t.Fatalf("used after release = %d, want 0", b.Used())
	}
	// Release is idempotent (defer + explicit release must not underflow).
	res.Release()
	if b.Used() != 0 {
		t.Fatalf("used after double release = %d, want 0", b.Used())
	}
	var nilRes *Reservation
	nilRes.Release()
	// A zero-byte reservation is legal (empty bodies) and releases cleanly.
	z, err := b.Acquire(context.Background(), 0)
	if err != nil {
		t.Fatal(err)
	}
	if b.Used() != 0 {
		t.Fatalf("zero reservation used = %d", b.Used())
	}
	z.Release()
	if _, err := b.Acquire(context.Background(), -1); err == nil {
		t.Fatal("negative reservation accepted")
	}
}

func TestBudgetOverBudgetTypedError(t *testing.T) {
	b, err := NewBudget(t.TempDir(), 100)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Acquire(context.Background(), 101); !errors.Is(err, ErrBudgetExceeded) {
		t.Fatalf("over-budget acquire = %v, want ErrBudgetExceeded", err)
	}
	if b.Used() != 0 {
		t.Fatalf("refused reservation changed used to %d", b.Used())
	}
	// Exactly the budget fits.
	res, err := b.Acquire(context.Background(), 100)
	if err != nil {
		t.Fatalf("at-budget acquire: %v", err)
	}
	res.Release()
}

func TestBudgetAcquireBlocksUntilReleased(t *testing.T) {
	b, err := NewBudget(t.TempDir(), 100)
	if err != nil {
		t.Fatal(err)
	}
	first, err := b.Acquire(context.Background(), 60)
	if err != nil {
		t.Fatal(err)
	}
	got := make(chan *Reservation, 1)
	errs := make(chan error, 1)
	go func() {
		res, err := b.Acquire(context.Background(), 60)
		if err != nil {
			errs <- err
			return
		}
		got <- res
	}()
	select {
	case res := <-got:
		res.Release()
		t.Fatal("second acquire did not block while the budget was full")
	case err := <-errs:
		t.Fatalf("second acquire failed: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	first.Release()
	select {
	case res := <-got:
		if b.Used() != 60 {
			t.Fatalf("used after unblocked acquire = %d, want 60", b.Used())
		}
		res.Release()
	case err := <-errs:
		t.Fatalf("blocked acquire failed after release: %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("blocked acquire never resumed after a release")
	}
	if b.Used() != 0 {
		t.Fatalf("used at end = %d, want 0", b.Used())
	}
}

func TestBudgetAcquireContextCancellation(t *testing.T) {
	b, err := NewBudget(t.TempDir(), 10)
	if err != nil {
		t.Fatal(err)
	}
	held, err := b.Acquire(context.Background(), 10)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Release()
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() {
		_, err := b.Acquire(ctx, 5)
		errc <- err
	}()
	time.Sleep(20 * time.Millisecond)
	cancel()
	select {
	case err := <-errc:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancelled acquire = %v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("cancelled acquire never returned")
	}
	if b.Used() != 10 {
		t.Fatalf("cancelled acquire changed used to %d, want 10", b.Used())
	}
}

// TestBudgetConcurrentReservationsNeverExceed proves the weighted invariant:
// the sum of simultaneously held reservations never exceeds the bound, no
// matter how many goroutines contend.
func TestBudgetConcurrentReservationsNeverExceed(t *testing.T) {
	const (
		maxBytes  = 1000
		workers   = 64
		perWorker = 40
	)
	b, err := NewBudget(t.TempDir(), maxBytes)
	if err != nil {
		t.Fatal(err)
	}
	var held atomic.Int64
	var peak atomic.Int64
	weights := []int64{7, 13, 29, 101}
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < perWorker; i++ {
				n := weights[(w+i)%len(weights)]
				res, err := b.Acquire(context.Background(), n)
				if err != nil {
					t.Errorf("acquire(%d): %v", n, err)
					return
				}
				cur := held.Add(n)
				if cur > maxBytes {
					t.Errorf("held reservations = %d, bound = %d", cur, maxBytes)
				}
				for {
					old := peak.Load()
					if cur <= old || peak.CompareAndSwap(old, cur) {
						break
					}
				}
				held.Add(-n)
				res.Release()
			}
		}(w)
	}
	wg.Wait()
	if b.Used() != 0 {
		t.Fatalf("used after all releases = %d, want 0", b.Used())
	}
	if peak.Load() == 0 {
		t.Fatal("no reservations were taken")
	}
	if b.Used() > maxBytes {
		t.Fatalf("used %d exceeds bound %d", b.Used(), maxBytes)
	}
}

func TestBudgetPruneRemovesOnlyStaleSpoolFiles(t *testing.T) {
	dir := t.TempDir()
	b, err := NewBudget(dir, 1024)
	if err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-2 * time.Hour)
	write := func(name string, mtime time.Time) string {
		t.Helper()
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte("stale"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(p, mtime, mtime); err != nil {
			t.Fatal(err)
		}
		return p
	}
	stale := write(FilePrefix+"abandoned", old)
	fresh := write(FilePrefix+"inflight", time.Now())
	foreign := write("not-ours.txt", old)
	if err := os.Mkdir(filepath.Join(dir, FilePrefix+"dir"), 0o700); err != nil {
		t.Fatal(err)
	}
	removed, err := b.Prune(context.Background())
	if err != nil {
		t.Fatalf("Prune: %v", err)
	}
	if removed != 1 {
		t.Fatalf("Prune removed %d, want 1", removed)
	}
	if _, err := os.Stat(stale); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stale spool file survived: %v", err)
	}
	if _, err := os.Stat(fresh); err != nil {
		t.Fatalf("fresh spool file was pruned: %v", err)
	}
	if _, err := os.Stat(foreign); err != nil {
		t.Fatalf("foreign file was pruned: %v", err)
	}
	if fi, err := os.Stat(filepath.Join(dir, FilePrefix+"dir")); err != nil || !fi.IsDir() {
		t.Fatalf("directory was pruned: %v", err)
	}
	// A second pass removes nothing.
	if again, err := b.Prune(context.Background()); err != nil || again != 0 {
		t.Fatalf("second Prune = (%d, %v), want (0, nil)", again, err)
	}
}

func TestBudgetPruneHonoursMinAgeAndCancellation(t *testing.T) {
	dir := t.TempDir()
	b, err := NewBudget(dir, 1024)
	if err != nil {
		t.Fatal(err)
	}
	b.PruneMinAge = time.Hour
	p := filepath.Join(dir, FilePrefix+"recent")
	if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Fresh file (mtime now): kept even with the one-hour floor.
	if n, err := b.Prune(context.Background()); err != nil || n != 0 {
		t.Fatalf("Prune fresh = (%d, %v), want (0, nil)", n, err)
	}
	// Aged past the floor: removed.
	old := time.Now().Add(-2 * time.Hour)
	if err := os.Chtimes(p, old, old); err != nil {
		t.Fatal(err)
	}
	if n, err := b.Prune(context.Background()); err != nil || n != 1 {
		t.Fatalf("Prune aged = (%d, %v), want (1, nil)", n, err)
	}
	// A cancelled context stops the pass before removing anything.
	if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(p, old, old); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if n, err := b.Prune(ctx); !errors.Is(err, context.Canceled) || n != 0 {
		t.Fatalf("cancelled Prune = (%d, %v), want (0, context.Canceled)", n, err)
	}
	// Missing directory is not an error.
	gone := &Budget{dir: filepath.Join(dir, "gone"), notify: make(chan struct{})}
	if n, err := gone.Prune(context.Background()); err != nil || n != 0 {
		t.Fatalf("Prune missing dir = (%d, %v), want (0, nil)", n, err)
	}
}

func TestSpoolFileStagesContentAndBounds(t *testing.T) {
	dir := t.TempDir()
	payload := []byte("spool-me")
	path, n, err := SpoolFile(dir, bytes.NewReader(payload), 0)
	if err != nil {
		t.Fatalf("SpoolFile: %v", err)
	}
	if n != int64(len(payload)) {
		t.Fatalf("SpoolFile n = %d, want %d", n, len(payload))
	}
	if filepath.Dir(path) != dir || !strings.HasPrefix(filepath.Base(path), FilePrefix) {
		t.Fatalf("SpoolFile path %q not under %q with prefix %q", path, dir, FilePrefix)
	}
	got, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("spooled content = %q, %v", got, err)
	}
	// Exact limit passes and leaves exactly `limit` bytes on disk.
	exactPath, n, err := SpoolFile(dir, bytes.NewReader(payload), int64(len(payload)))
	if err != nil || n != int64(len(payload)) {
		t.Fatalf("SpoolFile at limit = (%d, %v)", n, err)
	}
	fi, statErr := os.Stat(exactPath)
	if statErr != nil {
		t.Fatalf("stat at-limit spool: %v", statErr)
	}
	if fi.Size() != int64(len(payload)) {
		t.Fatalf("at-limit spool file is %d bytes on disk, want exactly %d", fi.Size(), len(payload))
	}
	// One byte over fails with ErrTooLarge and removes the partial file, and
	// the reported staged count never exceeds the limit (nothing past it was
	// written).
	before, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, n, err := SpoolFile(dir, bytes.NewReader(payload), int64(len(payload)-1)); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("SpoolFile over limit = %v, want ErrTooLarge", err)
	} else if n > int64(len(payload)-1) {
		t.Fatalf("over-limit SpoolFile reported %d staged bytes with limit %d", n, len(payload)-1)
	}
	after, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != len(before) {
		t.Fatalf("over-limit spool left files behind: %d -> %d", len(before), len(after))
	}
	// Empty directory path is a bound error.
	if _, _, err := SpoolFile("", bytes.NewReader(payload), 1); !errors.Is(err, ErrNoBound) {
		t.Fatalf("SpoolFile empty dir = %v, want ErrNoBound", err)
	}
}

// TestReservationConcurrentReleaseDecrementsExactlyOnce is the O3-C
// regression: Release is documented idempotent, so 100 concurrent releases of
// one reservation must decrement the ledger exactly once. A second live
// reservation makes a double decrement observable (Used would fall to 100
// instead of 200; the underflow clamp would only hide it at zero).
func TestReservationConcurrentReleaseDecrementsExactlyOnce(t *testing.T) {
	b, err := NewBudget(t.TempDir(), 1000)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = b.Close() }()
	first, err := b.Acquire(context.Background(), 100)
	if err != nil {
		t.Fatal(err)
	}
	second, err := b.Acquire(context.Background(), 200)
	if err != nil {
		t.Fatal(err)
	}
	const racers = 100
	var wg sync.WaitGroup
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			first.Release()
		}()
	}
	wg.Wait()
	if got := b.Used(); got != 200 {
		t.Fatalf("Used() = %d after %d concurrent releases of a 100-byte reservation, want 200 (exactly one decrement)", got, racers)
	}
	// Releasing the other reservation concurrently converges to zero.
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			second.Release()
		}()
	}
	wg.Wait()
	if got := b.Used(); got != 0 {
		t.Fatalf("Used() = %d after releasing both reservations, want 0", got)
	}
}

// countingWriter records the bytes actually handed to a spool destination.
type countingWriter struct{ written int64 }

func (w *countingWriter) Write(p []byte) (int, error) {
	w.written += int64(len(p))
	return len(p), nil
}

// lyingEOFReader delivers its underlying bytes but never reports io.EOF,
// returning (0, nil) instead: a source that cannot prove it is complete.
type lyingEOFReader struct{ r io.Reader }

func (l *lyingEOFReader) Read(p []byte) (int, error) {
	n, err := l.r.Read(p)
	if errors.Is(err, io.EOF) {
		return n, nil
	}
	return n, err
}

// TestSpoolCopyNeverWritesBeyondLimit is the O3-D regression: the physical
// bound is exactly `limit` bytes written to the destination. The limit+1 byte
// that detects an over-long or lying source is read from the SOURCE for
// detection but never reaches disk, and bytes-written always equals the
// reported count.
func TestSpoolCopyNeverWritesBeyondLimit(t *testing.T) {
	const limit = 8
	payload := []byte("0123456789") // limit + 2 bytes available
	cases := map[string]struct {
		src     io.Reader
		wantN   int64
		wantErr bool
	}{
		"exactly limit":             {bytes.NewReader(payload[:limit]), limit, false},
		"limit+1":                   {bytes.NewReader(payload[:limit+1]), limit, true},
		"lying reader beyond limit": {&lyingEOFReader{r: bytes.NewReader(payload)}, limit, true},
		"lying reader at limit":     {&lyingEOFReader{r: bytes.NewReader(payload[:limit])}, limit, true},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			w := &countingWriter{}
			n, err := spoolCopy(w, tc.src, limit)
			if tc.wantErr {
				if !errors.Is(err, ErrTooLarge) {
					t.Fatalf("spoolCopy error = %v, want ErrTooLarge", err)
				}
			} else if err != nil {
				t.Fatalf("spoolCopy error = %v, want nil", err)
			}
			if n != tc.wantN {
				t.Fatalf("spoolCopy reported %d bytes, want %d", n, tc.wantN)
			}
			if w.written > limit {
				t.Fatalf("spoolCopy wrote %d bytes to disk with limit %d (exact bound violated)", w.written, limit)
			}
			if n != w.written {
				t.Fatalf("reported bytes %d != physically written %d", n, w.written)
			}
		})
	}
}

type failingReader struct{ err error }

func (f failingReader) Read([]byte) (int, error) { return 0, f.err }

func TestSpoolFilePropagatesReaderErrorAndKeepsNoFile(t *testing.T) {
	dir := t.TempDir()
	boom := fmt.Errorf("client disconnected")
	if _, _, err := SpoolFile(dir, failingReader{err: boom}, 1024); !errors.Is(err, boom) {
		t.Fatalf("SpoolFile reader error = %v, want %v", err, boom)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("failed spool left %d file(s)", len(entries))
	}
	// A reader that returns data then fails also leaves nothing behind.
	r := io.MultiReader(bytes.NewReader([]byte("partial")), failingReader{err: boom})
	if _, _, err := SpoolFile(dir, r, 1024); !errors.Is(err, boom) {
		t.Fatalf("SpoolFile partial reader error = %v, want %v", err, boom)
	}
	entries, err = os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("partial spool left %d file(s)", len(entries))
	}
}
