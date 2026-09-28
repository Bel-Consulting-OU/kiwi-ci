package cas

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"sync/atomic"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/blob"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/progress"
)

// drainingStore consumes the whole Put stream (like a real backend does) and
// serves a fixed payload from Open.
type drainingStore struct {
	payload []byte
}

func (s *drainingStore) Put(ctx context.Context, key string, r io.Reader, size int64) (blob.Object, error) {
	if _, err := io.Copy(io.Discard, r); err != nil {
		return blob.Object{}, err
	}
	return blob.Object{Key: key, SHA256: key, Size: size}, nil
}

func (s *drainingStore) Open(ctx context.Context, key string) (io.ReadCloser, blob.Object, error) {
	return io.NopCloser(bytes.NewReader(s.payload)), blob.Object{Key: key, SHA256: key, Size: int64(len(s.payload))}, nil
}

func (s *drainingStore) Delete(context.Context, string) error { return nil }

// TestPutPulsesBackendProgress pins that every successful CAS write counts as
// real byte progress: a publication that streams a large staged file into
// the backend pulses the request context while the client socket is silent.
func TestPutPulsesBackendProgress(t *testing.T) {
	var pulses atomic.Int64
	ctx := progress.WithPulse(context.Background(), func() { pulses.Add(1) })
	payload := bytes.Repeat([]byte("progress"), 64)
	sum := sha256.Sum256(payload)
	c := &CAS{Blobs: &drainingStore{}}
	if _, err := c.PutKnown(ctx, hex.EncodeToString(sum[:]), int64(len(payload)), bytes.NewReader(payload)); err != nil {
		t.Fatal(err)
	}
	if got := pulses.Load(); got == 0 {
		t.Fatal("CAS Put published without a single progress pulse")
	}
}

// TestOpenPulsesBackendProgress pins the read side: the reader returned by
// Open pulses on every byte it delivers, so a pre-first-client-byte CAS/S3
// transfer is not mistaken for an idle streaming request.
func TestOpenPulsesBackendProgress(t *testing.T) {
	var pulses atomic.Int64
	ctx := progress.WithPulse(context.Background(), func() { pulses.Add(1) })
	payload := bytes.Repeat([]byte("progress"), 64)
	sum := sha256.Sum256(payload)
	digest := hex.EncodeToString(sum[:])
	c := &CAS{Blobs: &drainingStore{payload: payload}}
	rc, _, err := c.Open(ctx, digest)
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	if _, err := io.Copy(io.Discard, rc); err != nil {
		t.Fatal(err)
	}
	if got := pulses.Load(); got == 0 {
		t.Fatal("CAS Open streamed without a single progress pulse")
	}
}

// TestPulseWithoutInstalledCallbackIsSilent proves direct CAS callers that
// never installed a pulse pay nothing and cannot panic.
func TestPulseWithoutInstalledCallbackIsSilent(t *testing.T) {
	c := &CAS{Blobs: &drainingStore{}}
	payload := []byte("no-pulse")
	sum := sha256.Sum256(payload)
	if _, err := c.PutKnown(context.Background(), hex.EncodeToString(sum[:]), int64(len(payload)), bytes.NewReader(payload)); err != nil {
		t.Fatal(err)
	}
}
