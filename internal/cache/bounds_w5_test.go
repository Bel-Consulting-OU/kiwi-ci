package cache

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// W5-A boundary seams. MaxArchiveBytes is 8 GiB, so no test builds a real
// fixture at that size: the shrunken seam below stands in for the shared
// bound at 1/8192 scale, and every layer (client, store download/local gate,
// endpoint) is driven at seam-1, seam and seam+1 through its own real
// implementation. The retired 4 GiB client cap is seam/2 at the same scale,
// so a payload of seam/2+1 bytes is the logical "just over 4 GiB" case that
// used to pass the store/endpoint and fail the client.
const (
	archiveSeam          = int64(1 << 20) // shrunken stand-in for MaxArchiveBytes
	scaledOldClientCap   = archiveSeam / 2
	logicalAboveOldCap   = scaledOldClientCap + 1
	archiveSeamLogicalHi = archiveSeam + 1
)

// testPayload returns size deterministic bytes (incompressible enough that
// size expectations are exact on the wire).
func testPayload(t *testing.T, size int64) []byte {
	t.Helper()
	b := make([]byte, size)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

// TestMaxArchiveBytesSingleContract pins W5-A's constant wiring: the ONE
// cache-archive bound is 8 GiB, above the retired 4 GiB client cap, and every
// layer's default resolves to it rather than to a duplicated literal.
func TestMaxArchiveBytesSingleContract(t *testing.T) {
	if MaxArchiveBytes != 8<<30 {
		t.Fatalf("MaxArchiveBytes = %d, want 8 GiB", MaxArchiveBytes)
	}
	if MaxArchiveBytes <= 4<<30 {
		t.Fatalf("MaxArchiveBytes = %d, not above the retired 4 GiB client cap", MaxArchiveBytes)
	}
	if defaultMaxCompressedBytes != MaxArchiveBytes {
		t.Fatalf("client default = %d, want the shared %d", defaultMaxCompressedBytes, MaxArchiveBytes)
	}
	if defaultCacheArchiveBytes != MaxArchiveBytes {
		t.Fatalf("store default = %d, want the shared %d", defaultCacheArchiveBytes, MaxArchiveBytes)
	}
	if got := (&Client{}).maxCompressedBytes(); got != MaxArchiveBytes {
		t.Fatalf("Client default bound = %d, want %d", got, MaxArchiveBytes)
	}
	if got := (&Store{}).maxStoredBytes(); got != MaxArchiveBytes {
		t.Fatalf("Store default bound = %d, want %d", got, MaxArchiveBytes)
	}
}

// TestCacheBoundaryClientLayer drives the real Client.Restore stream through
// the shrunken seam: seam-1 and seam are accepted, seam+1 is rejected by the
// compressed-byte bound, and a payload whose scaled size exceeds the retired
// 4 GiB client cap is accepted.
func TestCacheBoundaryClientLayer(t *testing.T) {
	for _, tc := range []struct {
		name    string
		size    int64
		wantErr string
	}{
		{"seam-1 accepted", archiveSeam - 1, ""},
		{"seam accepted", archiveSeam, ""},
		{"seam+1 rejected", archiveSeamLogicalHi, "exceeds"},
		{"above retired 4 GiB cap (scaled) accepted", logicalAboveOldCap, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			payload := testPayload(t, tc.size)
			sum := sha256.Sum256(payload)
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set(HeaderCacheSHA256, hex.EncodeToString(sum[:]))
				_, _ = w.Write(payload)
			}))
			t.Cleanup(srv.Close)

			c := &Client{Server: srv.URL, MaxCompressedBytes: archiveSeam}
			rc, err := c.Restore(context.Background(), "job", nil, "k")
			if err != nil {
				t.Fatalf("Restore: %v", err)
			}
			defer rc.Close()
			got, err := io.ReadAll(rc)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("read: %v", err)
				}
				if !bytes.Equal(got, payload) {
					t.Fatalf("read %d bytes, want %d", len(got), len(payload))
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("read error = %v, want %q", err, tc.wantErr)
			}
			if int64(len(got)) != archiveSeam {
				t.Fatalf("rejected stream delivered %d bytes, want the bound %d", len(got), archiveSeam)
			}
		})
	}
}

// TestCacheBoundaryStoreLayer drives the Store's own bounds through the
// shrunken seam: the remote download bound (fetchRemote) is byte-exact at
// seam-1/seam/seam+1, the local restore size gate refuses seam+1 before any
// digest work while seam-1 and seam pass the gate, and Save's CappedWriter
// refuses an archive past the bound.
func TestCacheBoundaryStoreLayer(t *testing.T) {
	for _, tc := range []struct {
		name    string
		size    int64
		wantErr bool
	}{
		{"seam-1 accepted", archiveSeam - 1, false},
		{"seam accepted", archiveSeam, false},
		{"seam+1 rejected", archiveSeamLogicalHi, true},
		{"above retired 4 GiB cap (scaled) accepted", logicalAboveOldCap, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			payload := testPayload(t, tc.size)
			sum := sha256.Sum256(payload)
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set(HeaderCacheSHA256, hex.EncodeToString(sum[:]))
				_, _ = w.Write(payload)
			}))
			t.Cleanup(srv.Close)

			s := &Store{Root: t.TempDir(), RemoteURL: srv.URL, MaxCacheBytes: archiveSeam}
			err := s.fetchRemote("deadbeef")
			if tc.wantErr {
				if err == nil || !strings.Contains(err.Error(), "exceeds") {
					t.Fatalf("seam+1 fetch = %v, want the compressed-byte bound", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("fetch: %v", err)
			}
			if got := readFile(t, s.archivePath("deadbeef")); !bytes.Equal(got, payload) {
				t.Fatalf("stored archive = %d bytes, want %d", len(got), len(payload))
			}
		})
	}

	// Local restore size gate: seam+1 is refused before the digest sidecar is
	// even consulted, while seam-1 and seam reach the digest stage (missing
	// sidecar = errLocalUnverified, NOT a size rejection).
	root := t.TempDir()
	s := &Store{Root: root, MaxCacheBytes: archiveSeam}
	for _, tc := range []struct {
		name string
		size int64
	}{
		{"seam-1", archiveSeam - 1},
		{"seam", archiveSeam},
	} {
		key := strings.Repeat("b", 64)
		if err := os.WriteFile(s.archivePath(key), testPayload(t, tc.size), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := s.restoreLocal(context.Background(), key, t.TempDir(), []string{"."}); !errors.Is(err, errLocalUnverified) {
			t.Fatalf("%s local archive = %v, want it past the size gate (errLocalUnverified)", tc.name, err)
		}
	}
	if err := os.WriteFile(s.archivePath(strings.Repeat("c", 64)), testPayload(t, archiveSeamLogicalHi), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.restoreLocal(context.Background(), strings.Repeat("c", 64), t.TempDir(), []string{"."}); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("seam+1 local archive = %v, want the size-gate rejection", err)
	}

	// Save's CappedWriter is wired to the same bound: an incompressible file
	// past the cap is refused, never silently published.
	ws := t.TempDir()
	if err := os.WriteFile(filepath.Join(ws, "big"), testPayload(t, archiveSeamLogicalHi), 0o644); err != nil {
		t.Fatal(err)
	}
	sSave := &Store{Root: t.TempDir(), MaxCacheBytes: archiveSeam}
	if err := sSave.Save("deadbeef", ws, []string{"big"}); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("over-bound Save = %v, want the cap rejection", err)
	}
}

// zeroProgressReader returns (0, nil) for every non-empty read and counts the
// attempts, standing in for an abnormal source that neither transfers bytes
// nor reports an error.
type zeroProgressReader struct{ reads int }

func (z *zeroProgressReader) Read(p []byte) (int, error) {
	z.reads++
	return 0, nil
}

// TestBoundedReaderNoProgressAtBound pins W5-C for the client's bounded
// reader: an abnormal source answering the at-bound probe with (0, nil)
// latches io.ErrNoProgress after EXACTLY one probe attempt, and every later
// read returns the latched error without touching the source again.
func TestBoundedReaderNoProgressAtBound(t *testing.T) {
	// At-bound probe: the stream has already delivered max bytes, so the next
	// read probes the source for one byte. A (0, nil) answer must latch after
	// exactly one probe.
	src := &zeroProgressReader{}
	b := &boundedReadCloser{ReadCloser: io.NopCloser(src), max: 1, n: 1}
	if _, err := b.Read(make([]byte, 8)); !errors.Is(err, io.ErrNoProgress) {
		t.Fatalf("at-bound no-progress read = %v, want io.ErrNoProgress", err)
	}
	if src.reads != 1 {
		t.Fatalf("probe reads = %d, want exactly one", src.reads)
	}
	for i := 0; i < 3; i++ {
		if _, err := b.Read(make([]byte, 8)); !errors.Is(err, io.ErrNoProgress) {
			t.Fatalf("latched read %d = %v, want io.ErrNoProgress", i, err)
		}
	}
	if src.reads != 1 {
		t.Fatalf("latched no-progress re-probed the source (%d reads)", src.reads)
	}

	// Below the bound the same discipline applies: no-progress latches once
	// instead of permitting an io.ReadAll spin.
	src2 := &zeroProgressReader{}
	b2 := &boundedReadCloser{ReadCloser: io.NopCloser(src2), max: 8}
	if _, err := b2.Read(make([]byte, 4)); !errors.Is(err, io.ErrNoProgress) {
		t.Fatalf("below-bound no-progress read = %v, want io.ErrNoProgress", err)
	}
	if src2.reads != 1 {
		t.Fatalf("below-bound reads = %d, want exactly one", src2.reads)
	}
	if _, err := b2.Read(make([]byte, 4)); !errors.Is(err, io.ErrNoProgress) {
		t.Fatalf("below-bound latched read = %v, want io.ErrNoProgress", err)
	}
	if src2.reads != 1 {
		t.Fatalf("below-bound latch re-read the source (%d reads)", src2.reads)
	}
}

// TestStallGuardReadersNoProgress pins W5-C for both Store stall guards: a
// (0, nil) read of a non-empty buffer latches io.ErrNoProgress after exactly
// one source read, and the guard is never re-armed by a no-progress read.
func TestStallGuardReadersNoProgress(t *testing.T) {
	guard := &storeStallGuard{}
	src := &zeroProgressReader{}
	ur := &stallGuardReader{r: src, guard: guard}
	if _, err := ur.Read(make([]byte, 8)); !errors.Is(err, io.ErrNoProgress) {
		t.Fatalf("stallGuardReader no-progress read = %v, want io.ErrNoProgress", err)
	}
	if src.reads != 1 {
		t.Fatalf("stallGuardReader reads = %d, want exactly one", src.reads)
	}
	if _, err := ur.Read(make([]byte, 8)); !errors.Is(err, io.ErrNoProgress) || src.reads != 1 {
		t.Fatalf("stallGuardReader latched read = (%v, %d reads), want latched io.ErrNoProgress", err, src.reads)
	}

	bodySrc := &zeroProgressReader{}
	body := &stallGuardedBody{ReadCloser: io.NopCloser(bodySrc), guard: guard}
	if _, err := body.Read(make([]byte, 8)); !errors.Is(err, io.ErrNoProgress) {
		t.Fatalf("stallGuardedBody no-progress read = %v, want io.ErrNoProgress", err)
	}
	if bodySrc.reads != 1 {
		t.Fatalf("stallGuardedBody reads = %d, want exactly one", bodySrc.reads)
	}
	if _, err := body.Read(make([]byte, 8)); !errors.Is(err, io.ErrNoProgress) || bodySrc.reads != 1 {
		t.Fatalf("stallGuardedBody latched read = (%v, %d reads), want latched io.ErrNoProgress", err, bodySrc.reads)
	}
}

// TestLegacyWrappersTimeoutFreeContinuousTransfer pins W5-B end to end: the
// no-client legacy path must complete a continuously-progressing transfer
// whose total runtime exceeds the retired 30-second total bound. The whole
// time base is shrunk by the ratio of the old total bound (30s) to the store
// stall window (90s): the shrunken stall window is 150ms, so the retired
// total bound scales to 50ms, and the ~1.2s transfer is far past it. A
// stalled body is still cut by the watchdog (covered by
// TestStoreStallGuardBoundsStalledDefaultClient).
func TestLegacyWrappersTimeoutFreeContinuousTransfer(t *testing.T) {
	const (
		stallWindow     = 150 * time.Millisecond
		chunkDelay      = 20 * time.Millisecond
		chunks          = 60              // ~1.2s total, 24x the scaled 30s bound
		scaledLegacyCap = stallWindow / 3 // 30s/90s of the stall window = 50ms
	)
	shrinkStoreStallTimeout(t, stallWindow)

	payload := testPayload(t, 64<<10)
	sum := sha256.Sum256(payload)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(HeaderCacheSHA256, hex.EncodeToString(sum[:]))
		w.WriteHeader(http.StatusOK)
		flusher, _ := w.(http.Flusher)
		chunk := len(payload) / chunks
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
			time.Sleep(chunkDelay)
		}
	}))
	t.Cleanup(srv.Close)

	s := &Store{Root: t.TempDir(), RemoteURL: srv.URL}
	ctx, cancel := s.defaultContext()
	defer cancel()
	if _, ok := ctx.Deadline(); ok {
		t.Fatal("legacy default context must be timeout-free")
	}
	begin := time.Now()
	if err := s.fetchRemote("deadbeef"); err != nil {
		t.Fatalf("continuous transfer failed: %v", err)
	}
	elapsed := time.Since(begin)
	if elapsed <= scaledLegacyCap {
		t.Fatalf("transfer took %v, below the scaled retired 30s bound %v; the test premise was not met", elapsed, scaledLegacyCap)
	}
	if got := readFile(t, s.archivePath("deadbeef")); !bytes.Equal(got, payload) {
		t.Fatalf("downloaded archive = %d bytes, want %d", len(got), len(payload))
	}
}
