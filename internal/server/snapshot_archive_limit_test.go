package server

import (
	"bytes"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/snapshot"
)

// TestSnapshotUploadBodyLimitIsTheSharedArchiveBudget pins the receiver half
// of the unified snapshot size contract: the snapshot upload body cap IS the
// same exported symbol the runner clamps its capture cap to and snapshot.Parse
// defaults to. The boundary is exercised with a SMALL override (never GiBs):
// a body between the cap and twice the cap is refused with a 413 that names
// the limit, consistently in fs and DB mode.
func TestSnapshotUploadBodyLimitIsTheSharedArchiveBudget(t *testing.T) {
	if snapshotUploadMaxBytes != snapshot.MaxArchiveBytes {
		t.Fatalf("snapshot upload body cap = %d, want the shared snapshot.MaxArchiveBytes %d", snapshotUploadMaxBytes, snapshot.MaxArchiveBytes)
	}
	orig := snapshotUploadMaxBytes
	snapshotUploadMaxBytes = 4096
	t.Cleanup(func() { snapshotUploadMaxBytes = orig })

	// The body is between the cap and twice it; it never needs to be a valid
	// archive because the body cap rejects it before any parsing.
	over := bytes.Repeat([]byte{0x1f, 0x8b, 0x08, 0x00}, int(snapshotUploadMaxBytes)/4+1)
	if int64(len(over)) <= snapshotUploadMaxBytes || int64(len(over)) > 2*snapshotUploadMaxBytes {
		t.Fatalf("test premise broken: body %d, cap %d", len(over), snapshotUploadMaxBytes)
	}
	wantReason := fmt.Sprintf("%d-byte upload limit", snapshotUploadMaxBytes)

	t.Run("fs", func(t *testing.T) {
		s, err := NewPersistent("secret", "secret", t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		c := newTestClient(t, s.Handler(), "secret")
		_, jobID, runnerID, token, gen := leaseNativeJob(t, c, testPipeline)
		headers := map[string]string{
			"X-Kiwi-Runner-ID":        runnerID,
			"X-Kiwi-Lease-Token":      token,
			"X-Kiwi-Lease-Generation": fmt.Sprint(gen),
			"Content-Type":            "application/gzip",
		}
		w := c.do(http.MethodPost, "/api/v1/jobs/"+jobID+"/snapshots", over, headers)
		if w.Code != http.StatusRequestEntityTooLarge {
			t.Fatalf("fs over-limit upload = %d, want 413: %s", w.Code, w.Body.String())
		}
		if !strings.Contains(w.Body.String(), wantReason) {
			t.Fatalf("fs rejection = %q, want the cap in the reason", w.Body.String())
		}
	})

	t.Run("db", func(t *testing.T) {
		s, runnerID, jobID, task, c := snapshotCASServer(t, newDBFakeStore(), t.TempDir())
		_ = s
		w := uploadSnapshotCAS(t, c, jobID, runnerID, task, over)
		if w.Code != http.StatusRequestEntityTooLarge {
			t.Fatalf("db over-limit upload = %d, want 413: %s", w.Code, w.Body.String())
		}
		if !strings.Contains(w.Body.String(), wantReason) {
			t.Fatalf("db rejection = %q, want the cap in the reason", w.Body.String())
		}
	})

	// An archive within the cap still uploads (the boundary does not reject
	// valid archives).
	t.Run("within cap", func(t *testing.T) {
		s, err := NewPersistent("secret", "secret", t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		c := newTestClient(t, s.Handler(), "secret")
		_, jobID, runnerID, token, gen := leaseNativeJob(t, c, testPipeline)
		headers := map[string]string{
			"X-Kiwi-Runner-ID":        runnerID,
			"X-Kiwi-Lease-Token":      token,
			"X-Kiwi-Lease-Generation": fmt.Sprint(gen),
			"Content-Type":            "application/gzip",
		}
		body, _ := snapshotArchive(t)
		if int64(len(body)) >= snapshotUploadMaxBytes {
			t.Fatalf("test premise broken: archive %d, cap %d", len(body), snapshotUploadMaxBytes)
		}
		w := c.do(http.MethodPost, "/api/v1/jobs/"+jobID+"/snapshots", body, headers)
		if w.Code != http.StatusCreated {
			t.Fatalf("within-cap upload = %d: %s", w.Code, w.Body.String())
		}
	})
}
