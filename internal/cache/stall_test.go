package cache

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// shrinkStoreStallTimeout shrinks the store transfer watchdog for one test.
func shrinkStoreStallTimeout(t *testing.T, d time.Duration) {
	t.Helper()
	prev := storeStallTimeout
	storeStallTimeout = d
	t.Cleanup(func() { storeStallTimeout = prev })
}

// noStalledTempLitter fails when the store root holds a partial temp file.
func noStalledTempLitter(t *testing.T, root string) {
	t.Helper()
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".") {
			t.Fatalf("stalled transfer left temp file %q behind", e.Name())
		}
	}
}

// TestStoreStallGuardBoundsStalledDownloadBodies proves a caller-supplied
// client no longer lets a stalled download hang: a 200 body and a 5xx error
// body both stop making progress, the shrunken watchdog cancels the request,
// and the failure is ErrTransferStalled rather than a bare context error.
func TestStoreStallGuardBoundsStalledDownloadBodies(t *testing.T) {
	for _, status := range []int{http.StatusOK, http.StatusInternalServerError} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			shrinkStoreStallTimeout(t, 150*time.Millisecond)

			release := make(chan struct{})
			defer close(release)
			started := make(chan struct{}, 1)
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				select {
				case started <- struct{}{}:
				default:
				}
				w.WriteHeader(status)
				_, _ = w.Write([]byte("partial"))
				if f, ok := w.(http.Flusher); ok {
					f.Flush()
				}
				select {
				case <-r.Context().Done():
				case <-release:
				}
			}))
			t.Cleanup(srv.Close)

			s := &Store{Root: t.TempDir(), RemoteURL: srv.URL, Client: &http.Client{}}
			begin := time.Now()
			err := s.fetchRemote("deadbeef")
			elapsed := time.Since(begin)

			if err == nil {
				t.Fatal("stalled download succeeded, want ErrTransferStalled")
			}
			if !errors.Is(err, ErrTransferStalled) {
				t.Fatalf("stalled download error = %v, want ErrTransferStalled", err)
			}
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("stalled download error %v is not distinguishable from context cancellation", err)
			}
			if elapsed > 5*time.Second {
				t.Fatalf("stalled download took %v; the watchdog did not fire", elapsed)
			}
			select {
			case <-started:
			default:
				t.Fatal("server handler never ran")
			}
			noStalledTempLitter(t, s.Root)
		})
	}
}

// TestStoreStallGuardBoundsStalledUploadWithCallerClient proves the upload
// body (request) phase is bounded the same way: the server never reads and
// never answers, so the watchdog cancels the PUT and Save surfaces
// ErrTransferStalled. The local archive remains published.
func TestStoreStallGuardBoundsStalledUploadWithCallerClient(t *testing.T) {
	shrinkStoreStallTimeout(t, 150*time.Millisecond)

	release := make(chan struct{})
	defer close(release)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}))
	t.Cleanup(srv.Close)

	ws := t.TempDir()
	if err := os.WriteFile(filepath.Join(ws, "f"), bytes.Repeat([]byte("u"), 512<<10), 0o644); err != nil {
		t.Fatal(err)
	}
	s := &Store{Root: t.TempDir(), RemoteURL: srv.URL, Client: &http.Client{}}
	begin := time.Now()
	err := s.Save("deadbeef", ws, []string{"f"})
	elapsed := time.Since(begin)

	if err == nil {
		t.Fatal("stalled upload succeeded, want ErrTransferStalled")
	}
	if !errors.Is(err, ErrTransferStalled) {
		t.Fatalf("stalled upload error = %v, want ErrTransferStalled", err)
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("stalled upload error %v is not distinguishable from context cancellation", err)
	}
	if elapsed > 5*time.Second {
		t.Fatalf("stalled upload took %v; the watchdog did not fire", elapsed)
	}
	if _, statErr := os.Stat(s.archivePath("deadbeef")); statErr != nil {
		t.Fatalf("local archive missing after failed upload: %v", statErr)
	}
}

// TestStoreStallGuardAllowsSlowContinuousDownload proves the watchdog is
// sliding, not a total transfer cap: 40 chunks arrive slower than the shrunken
// stall timeout in total but far faster than it per chunk (20ms vs 500ms), so
// the download completes intact.
func TestStoreStallGuardAllowsSlowContinuousDownload(t *testing.T) {
	shrinkStoreStallTimeout(t, 500*time.Millisecond)

	payload := bytes.Repeat([]byte("d"), 32<<10)
	sum := sha256.Sum256(payload)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(HeaderCacheSHA256, hex.EncodeToString(sum[:]))
		w.WriteHeader(http.StatusOK)
		flusher, _ := w.(http.Flusher)
		const chunk = 1 << 10
		for off := 0; off < len(payload); off += chunk {
			end := off + chunk
			if end > len(payload) {
				end = len(payload)
			}
			if _, err := w.Write(payload[off:end]); err != nil {
				return
			}
			if flusher != nil {
				flusher.Flush()
			}
			time.Sleep(20 * time.Millisecond)
		}
	}))
	t.Cleanup(srv.Close)

	s := &Store{Root: t.TempDir(), RemoteURL: srv.URL, Client: &http.Client{}}
	begin := time.Now()
	if err := s.fetchRemote("deadbeef"); err != nil {
		t.Fatalf("slow continuous download failed: %v", err)
	}
	if elapsed := time.Since(begin); elapsed < 500*time.Millisecond {
		t.Fatalf("download finished in %v, below the shrunken stall timeout; the test premise was not met", elapsed)
	}
	if got := readFile(t, s.archivePath("deadbeef")); !bytes.Equal(got, payload) {
		t.Fatalf("downloaded archive = %d bytes, want %d", len(got), len(payload))
	}
}

// TestStoreStallGuardCheckFiresOnStaleProgress pins the firing edge
// deterministically, without relying on a real timer: a check whose recorded
// progress is stale latches the stall and cancels the transfer. The real timer
// is effectively disarmed (one hour) so the test cannot race it.
func TestStoreStallGuardCheckFiresOnStaleProgress(t *testing.T) {
	ctx, guard := newStoreStallGuard(context.Background(), time.Hour)
	defer guard.release()

	guard.mu.Lock()
	guard.last = time.Now().Add(-2 * time.Hour)
	guard.mu.Unlock()
	guard.check()
	if err := ctx.Err(); err == nil {
		t.Fatal("stale progress did not trip the watchdog")
	}
	if !guard.stalled() {
		t.Fatal("fired watchdog did not latch a stall")
	}
}

// TestStoreStallGuardReaderAllowsSlowContinuousUpload proves the request-body
// wrapper re-arms the watchdog on every successful read: a body that drips
// bytes over a total longer than the stall window is never cut. Each gap is
// far inside the window (25ms vs 500ms) so load-induced scheduling delays
// cannot turn continuous progress into a stall. (At HTTP level the transport
// may buffer a whole upload into the socket and then wait on the response,
// which is conservatively a stall; per-read progress is the contract the
// wrapper enforces.)
func TestStoreStallGuardReaderAllowsSlowContinuousUpload(t *testing.T) {
	ctx, guard := newStoreStallGuard(context.Background(), 500*time.Millisecond)
	defer guard.release()

	body := &stallGuardReader{r: &dripReader{remaining: 96, chunk: 4, every: 25 * time.Millisecond}, guard: guard}
	begin := time.Now()
	n, err := io.Copy(io.Discard, body)
	if err != nil {
		t.Fatalf("continuous upload body failed: %v", err)
	}
	if elapsed := time.Since(begin); elapsed < 500*time.Millisecond {
		t.Fatalf("body finished in %v, below the stall window; the test premise was not met", elapsed)
	}
	if n != 96 {
		t.Fatalf("read %d body bytes, want 96", n)
	}
	if err := ctx.Err(); err != nil {
		t.Fatalf("continuous body progress was cut by the watchdog: %v", err)
	}
	if guard.stalled() {
		t.Fatal("continuous body progress latched a stall")
	}
}

// dripReader yields chunk bytes per Read, sleeping every between reads.
type dripReader struct {
	remaining int
	chunk     int
	every     time.Duration
}

func (d *dripReader) Read(p []byte) (int, error) {
	if d.remaining <= 0 {
		return 0, io.EOF
	}
	if d.every > 0 {
		time.Sleep(d.every)
	}
	n := d.chunk
	if n > len(p) {
		n = len(p)
	}
	if n > d.remaining {
		n = d.remaining
	}
	d.remaining -= n
	return n, nil
}

// TestStoreStallGuardBoundsStalledDefaultClient proves the no-client legacy
// path is watchdog-bounded WITHOUT any total deadline (W5-B): the default
// context is timeout-free, so a continuously-progressing transfer is never
// cut by a wall-clock cap, while a stalled body still fails fast with
// ErrTransferStalled through the sliding storeStallTimeout watchdog.
func TestStoreStallGuardBoundsStalledDefaultClient(t *testing.T) {
	shrinkStoreStallTimeout(t, 150*time.Millisecond)

	release := make(chan struct{})
	defer close(release)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("partial"))
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}))
	t.Cleanup(srv.Close)

	s := &Store{Root: t.TempDir(), RemoteURL: srv.URL}
	ctx, cancel := s.defaultContext()
	defer cancel()
	if _, ok := ctx.Deadline(); ok {
		t.Fatal("the nil-client default context must be timeout-free; the sliding watchdog bounds the body")
	}
	begin := time.Now()
	err := s.fetchRemote("deadbeef")
	if !errors.Is(err, ErrTransferStalled) {
		t.Fatalf("stalled default-client download = %v, want ErrTransferStalled", err)
	}
	if elapsed := time.Since(begin); elapsed > 5*time.Second {
		t.Fatalf("stalled default-client download took %v; the watchdog did not fire", elapsed)
	}
}

// TestStoreStallGuardDoesNotMaskCallerCancellation proves the typed stall
// error is reserved for the watchdog: a caller context that expires first
// still surfaces as context.DeadlineExceeded.
func TestStoreStallGuardDoesNotMaskCallerCancellation(t *testing.T) {
	shrinkStoreStallTimeout(t, time.Hour)

	release := make(chan struct{})
	defer close(release)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}))
	t.Cleanup(srv.Close)

	s := &Store{Root: t.TempDir(), RemoteURL: srv.URL, Client: &http.Client{}}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	err := s.fetchRemoteContext(ctx, "deadbeef")
	if errors.Is(err, ErrTransferStalled) {
		t.Fatalf("caller deadline was misreported as a transfer stall: %v", err)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("caller deadline = %v, want context.DeadlineExceeded", err)
	}
}

// TestStoreStallGuardStopDisarmsTimer proves a disarmed watchdog neither
// fires nor cancels its context, while an armed one still does.
func TestStoreStallGuardStopDisarmsTimer(t *testing.T) {
	ctx, guard := newStoreStallGuard(context.Background(), 40*time.Millisecond)
	guard.stop()
	time.Sleep(150 * time.Millisecond)
	if guard.stalled() {
		t.Fatal("a disarmed watchdog latched a stall")
	}
	if err := ctx.Err(); err != nil {
		t.Fatalf("a disarmed watchdog canceled its context: %v", err)
	}
	guard.release()

	ctx2, guard2 := newStoreStallGuard(context.Background(), 30*time.Millisecond)
	defer guard2.release()
	select {
	case <-ctx2.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("an armed watchdog never fired on inactivity")
	}
	if !guard2.stalled() {
		t.Fatal("the fired watchdog did not report a stall")
	}
}

// TestStoreStallGuardProgressRearms proves uninterrupted progress keeps a
// transfer alive beyond the stall window, deterministically: every recorded
// progress pushes the deadline out, so a check that fires inside the idle
// window (simulated directly here) re-arms instead of latching a stall. The
// real timer is effectively disarmed (one hour) so the test cannot race it.
func TestStoreStallGuardProgressRearms(t *testing.T) {
	ctx, guard := newStoreStallGuard(context.Background(), time.Hour)
	defer guard.release()
	for i := 0; i < 6; i++ {
		guard.progress()
		guard.mu.Lock()
		guard.last = time.Now().Add(-time.Minute)
		guard.mu.Unlock()
		guard.check()
	}
	if err := ctx.Err(); err != nil {
		t.Fatalf("continuous progress let the watchdog fire: %v", err)
	}
	if guard.stalled() {
		t.Fatal("continuous progress latched a stall")
	}
}

// TestStoreStallGuardArmsAndStopsOneTimerPerTransfer drives every remote path
// (download, 404, 5xx, transport error, upload, failed upload) and asserts
// every armed watchdog timer is stopped once the transfer ends.
func TestStoreStallGuardArmsAndStopsOneTimerPerTransfer(t *testing.T) {
	shrinkStoreStallTimeout(t, time.Hour)

	var mu sync.Mutex
	armed, stopped := 0, 0
	prev := storeStallGuardHook
	storeStallGuardHook = func(a bool) {
		mu.Lock()
		defer mu.Unlock()
		if a {
			armed++
		} else {
			stopped++
		}
	}
	t.Cleanup(func() { storeStallGuardHook = prev })

	payload := []byte("archive-bytes")
	sum := sha256.Sum256(payload)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "missing"):
			http.NotFound(w, r)
		case strings.HasSuffix(r.URL.Path, "boom"):
			http.Error(w, "refused", http.StatusInternalServerError)
		default:
			w.Header().Set(HeaderCacheSHA256, hex.EncodeToString(sum[:]))
			_, _ = w.Write(payload)
		}
	}))
	t.Cleanup(srv.Close)

	s := &Store{Root: t.TempDir(), RemoteURL: srv.URL, Client: &http.Client{}}
	if err := s.fetchRemote("deadbeef"); err != nil {
		t.Fatalf("fetchRemote: %v", err)
	}
	if err := s.fetchRemote("missing"); !errors.Is(err, errRemoteNotFound) {
		t.Fatalf("fetchRemote(404) = %v, want errRemoteNotFound", err)
	}
	if err := s.fetchRemote("boom"); err == nil || !strings.Contains(err.Error(), "refused") {
		t.Fatalf("fetchRemote(500) = %v, want the refused body", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	deadAddr := ln.Addr().String()
	_ = ln.Close()
	dead := &Store{Root: t.TempDir(), RemoteURL: "http://" + deadAddr, Client: &http.Client{}}
	if err := dead.fetchRemote("deadbeef"); err == nil {
		t.Fatal("fetchRemote to a closed port = nil, want a transport error")
	}

	ws := t.TempDir()
	if err := os.WriteFile(filepath.Join(ws, "f"), payload, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := s.Save("ok", ws, []string{"f"}); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := s.Save("boom", ws, []string{"f"}); err == nil {
		t.Fatal("Save(500) = nil, want an error")
	}

	mu.Lock()
	gotArmed, gotStopped := armed, stopped
	mu.Unlock()
	if gotArmed == 0 {
		t.Fatal("no watchdog was armed")
	}
	if gotArmed != gotStopped {
		t.Fatalf("watchdog timers armed = %d, stopped = %d; a completed transfer leaked its timer", gotArmed, gotStopped)
	}
}

// TestStoreStallGuardNoGoroutineLeak runs many bounded transfers and proves
// the goroutine count returns to its warm baseline.
func TestStoreStallGuardNoGoroutineLeak(t *testing.T) {
	shrinkStoreStallTimeout(t, 30*time.Second)

	payload := []byte("archive-bytes")
	sum := sha256.Sum256(payload)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(HeaderCacheSHA256, hex.EncodeToString(sum[:]))
		_, _ = w.Write(payload)
	}))
	t.Cleanup(srv.Close)

	tr := &http.Transport{DisableKeepAlives: true}
	t.Cleanup(tr.CloseIdleConnections)
	s := &Store{Root: t.TempDir(), RemoteURL: srv.URL, Client: &http.Client{Transport: tr}}

	if err := s.fetchRemote("deadbeef"); err != nil {
		t.Fatalf("warmup transfer: %v", err)
	}
	base := runtime.NumGoroutine()
	for i := 0; i < 40; i++ {
		if err := s.fetchRemote("deadbeef"); err != nil {
			t.Fatalf("transfer %d: %v", i, err)
		}
	}
	srv.Close()
	tr.CloseIdleConnections()

	deadline := time.Now().Add(5 * time.Second)
	for runtime.NumGoroutine() > base && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := runtime.NumGoroutine(); got > base {
		t.Fatalf("goroutines after 40 bounded transfers = %d, warm baseline %d", got, base)
	}
}

// orderedDrainBody simulates a peer that delivered a prefix and then stopped
// sending: every Read after the prefix blocks until the transfer context is
// canceled, and Close performs the drain a verification-on-close reader does
// when the caller stops reading early, recording whether the watchdog had
// already been released when the drain started.
type orderedDrainBody struct {
	prefix []byte
	ctx    context.Context
	guard  *storeStallGuard

	releasedBeforeDrain bool
}

func (b *orderedDrainBody) Read(p []byte) (int, error) {
	if len(b.prefix) > 0 {
		n := copy(p, b.prefix)
		b.prefix = b.prefix[n:]
		return n, nil
	}
	<-b.ctx.Done()
	return 0, b.ctx.Err()
}

func (b *orderedDrainBody) Close() error {
	b.guard.mu.Lock()
	b.releasedBeforeDrain = b.guard.stopped
	b.guard.mu.Unlock()
	_, err := io.Copy(io.Discard, b)
	return err
}

// TestStoreGuardedBodyCloseKeepsWatchdogThroughDrain pins the Store wrapper's
// close ordering: the inner Close (which drains the remaining stream for
// verification-on-close) must run BEFORE the watchdog is released, and the
// armed watchdog must terminate a stalled drain on the idle bound instead of
// hanging Close. Releasing first is the regression this guards.
func TestStoreGuardedBodyCloseKeepsWatchdogThroughDrain(t *testing.T) {
	ctx, guard := newStoreStallGuard(context.Background(), 200*time.Millisecond)
	inner := &orderedDrainBody{prefix: []byte("part"), ctx: ctx, guard: guard}
	body := &stallGuardedBody{ReadCloser: inner, guard: guard}

	buf := make([]byte, 4)
	if _, err := io.ReadFull(body, buf); err != nil {
		t.Fatalf("prefix read: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- body.Close() }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("stalled drain reported success")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Close hung: the watchdog was disarmed before the verification drain")
	}
	if inner.releasedBeforeDrain {
		t.Fatal("the watchdog was released before the inner Close returned; a drain that ignores the canceled context would be unbounded")
	}
	guard.release()
}
