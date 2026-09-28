package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/blob"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/cas"
)

// pacedBlob is a blob.Store whose transfers advance one chunk every gap:
// Put consumes one chunk from the source per gap, Open produces one chunk per
// gap (the first after a full gap, which models the pre-first-byte backend
// latency of a real S3/CAS read). A stalled store produces one chunk and then
// blocks until its context is cancelled, modeling a backend that stops
// making progress without closing the stream.
type pacedBlob struct {
	payload []byte
	gap     time.Duration
	chunk   int
	stall   bool
}

func (b *pacedBlob) chunkSize() int {
	if b.chunk <= 0 {
		return 16
	}
	return b.chunk
}

func (b *pacedBlob) Put(ctx context.Context, key string, r io.Reader, size int64) (blob.Object, error) {
	var total int64
	buf := make([]byte, b.chunkSize())
	first := true
	for {
		n, err := r.Read(buf)
		if n > 0 {
			total += int64(n)
		}
		if err != nil && err != io.EOF {
			return blob.Object{}, err
		}
		if b.stall && !first {
			<-ctx.Done()
			return blob.Object{}, ctx.Err()
		}
		first = false
		select {
		case <-ctx.Done():
			return blob.Object{}, ctx.Err()
		case <-time.After(b.gap):
		}
		if err == io.EOF {
			break
		}
	}
	return blob.Object{Key: key, SHA256: key, Size: total}, nil
}

func (b *pacedBlob) Open(ctx context.Context, key string) (io.ReadCloser, blob.Object, error) {
	return &pacedReader{ctx: ctx, blob: b}, blob.Object{Key: key, SHA256: key, Size: int64(len(b.payload))}, nil
}

func (b *pacedBlob) Delete(context.Context, string) error { return nil }

// pacedReader produces the blob's payload one chunk per gap; a stalled blob
// blocks forever after its first chunk until the context is cancelled.
type pacedReader struct {
	ctx     context.Context
	blob    *pacedBlob
	off     int
	served  bool
	closed  bool
	readErr error
}

func (p *pacedReader) Read(b []byte) (int, error) {
	if p.readErr != nil {
		return 0, p.readErr
	}
	if p.blob.stall && p.served {
		<-p.ctx.Done()
		p.readErr = p.ctx.Err()
		return 0, p.readErr
	}
	select {
	case <-p.ctx.Done():
		p.readErr = p.ctx.Err()
		return 0, p.readErr
	case <-time.After(p.blob.gap):
	}
	if p.off >= len(p.blob.payload) {
		p.readErr = io.EOF
		return 0, io.EOF
	}
	end := p.off + p.blob.chunkSize()
	if end > len(p.blob.payload) {
		end = len(p.blob.payload)
	}
	n := copy(b, p.blob.payload[p.off:end])
	p.off += n
	p.served = true
	return n, nil
}

func (p *pacedReader) Close() error {
	if p.closed {
		return nil
	}
	p.closed = true
	return nil
}

// TestStreamingBackendProgressOutlivesIdleWindows is the P1/P2 regression for
// backend-aware inactivity: a CAS transfer that advances one 16-byte chunk
// every 100 ms — for a total several times the shrunken idle window — must
// survive on BOTH sides of the request. On the download side the backend
// transfer happens before the first response byte; on the upload side it
// happens after the request body reached EOF (the client socket is silent
// through the whole publication). Both would be cut by a socket-only idle
// guard; the CAS progress pulse keeps the application guard sliding.
func TestStreamingBackendProgressOutlivesIdleWindows(t *testing.T) {
	prevIdle := streamIdleTimeout.get()
	streamIdleTimeout.set(350 * time.Millisecond)
	t.Cleanup(func() { streamIdleTimeout.set(prevIdle) })

	payload := []byte(strings.Repeat("kiwi-backend-progress-", 8))
	sum := sha256.Sum256(payload)
	digest := hex.EncodeToString(sum[:])

	newServer := func(h http.HandlerFunc) *httptest.Server {
		return httptest.NewServer(withAPIDeadlines(h))
	}

	t.Run("download before first byte", func(t *testing.T) {
		store := &pacedBlob{payload: payload, gap: 100 * time.Millisecond}
		c := cas.New(store)
		srv := newServer(func(w http.ResponseWriter, r *http.Request) {
			rc, _, err := c.Open(r.Context(), digest)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			defer rc.Close()
			// Read the WHOLE backend transfer before the first client byte,
			// exactly like a verified download that preverifies a large
			// CAS/S3 object into staging before serving it: the socket is
			// completely silent while the backend advances.
			data, rerr := io.ReadAll(rc)
			if rerr != nil {
				http.Error(w, rerr.Error(), http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(data)
		})
		defer srv.Close()

		start := time.Now()
		resp, err := srv.Client().Get(srv.URL + "/api/v1/artifacts/" + digest)
		if err != nil {
			t.Fatalf("slow CAS download failed at the transport: %v", err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK || string(body) != string(payload) {
			t.Fatalf("slow CAS download = %d %q, want 200 with the full payload", resp.StatusCode, body)
		}
		if elapsed := time.Since(start); elapsed < 8*100*time.Millisecond {
			t.Fatalf("download finished in %v; the paced backend never transferred slowly", elapsed)
		}
	})

	t.Run("upload after request EOF", func(t *testing.T) {
		store := &pacedBlob{payload: payload, gap: 100 * time.Millisecond}
		c := cas.New(store)
		dir := t.TempDir()
		srv := newServer(func(w http.ResponseWriter, r *http.Request) {
			uploaded, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			path := filepath.Join(dir, "staged")
			if werr := os.WriteFile(path, uploaded, 0o600); werr != nil {
				http.Error(w, werr.Error(), http.StatusInternalServerError)
				return
			}
			bodySum := sha256.Sum256(uploaded)
			if _, perr := c.PutFile(r.Context(), path, hex.EncodeToString(bodySum[:]), int64(len(uploaded))); perr != nil {
				http.Error(w, perr.Error(), http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusCreated)
		})
		defer srv.Close()

		req, err := http.NewRequest(http.MethodPut, srv.URL+"/api/v1/jobs/job-1/cache/key", strings.NewReader(string(payload)))
		if err != nil {
			t.Fatal(err)
		}
		start := time.Now()
		resp, err := srv.Client().Do(req)
		if err != nil {
			t.Fatalf("slow CAS upload failed at the transport: %v", err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("slow CAS upload = %d, want 201", resp.StatusCode)
		}
		if elapsed := time.Since(start); elapsed < 8*100*time.Millisecond {
			t.Fatalf("upload finished in %v; the paced backend never transferred slowly", elapsed)
		}
	})
}

// TestStreamingStalledBackendStillCancelled is the counterpart: a backend
// that transfers one chunk and then stops producing bytes is NOT progress.
// The guard must still fire after one idle window and cancel the application
// work even though no socket operation can fail.
func TestStreamingStalledBackendStillCancelled(t *testing.T) {
	prevIdle := streamIdleTimeout.get()
	streamIdleTimeout.set(250 * time.Millisecond)
	t.Cleanup(func() { streamIdleTimeout.set(prevIdle) })

	payload := []byte(strings.Repeat("stalled", 32))
	sum := sha256.Sum256(payload)
	digest := hex.EncodeToString(sum[:])

	store := &pacedBlob{payload: payload, gap: 50 * time.Millisecond, stall: true}
	c := cas.New(store)
	cancelled := make(chan struct{})
	srv := httptest.NewServer(withAPIDeadlines(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rc, _, err := c.Open(r.Context(), digest)
		if err != nil {
			close(cancelled)
			return
		}
		defer rc.Close()
		w.WriteHeader(http.StatusOK)
		if _, cerr := io.Copy(w, rc); cerr != nil {
			// The stalled read only unblocks when the guard cancels the
			// request context.
			close(cancelled)
		}
	})))
	defer srv.Close()

	start := time.Now()
	resp, err := srv.Client().Get(srv.URL + "/api/v1/artifacts/" + digest)
	if err == nil {
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
	select {
	case <-cancelled:
	case <-time.After(5 * time.Second):
		t.Fatal("stalled CAS backend was never cancelled: the guard treated the stall as progress")
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("stalled CAS backend survived %v; the idle guard did not bound it", elapsed)
	}
}
