package provenance

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/blob"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/cas"
)

// TestSignedEnvelopeDedupPublishIsVerified mirrors the CAS-mode provenance
// caller: the control plane publishes json.MarshalIndent(envelope) through
// CAS.PutKnown and records only the returned digest and size as the reference.
// A same-size corruption of the stored object must not be silently re-accepted
// by a later publication of the same envelope; after the verifier heals it,
// the bytes the recorded reference resolves to must still verify as the signed
// statement.
func TestSignedEnvelopeDedupPublishIsVerified(t *testing.T) {
	root := t.TempDir()
	c := cas.New(blob.NewFS(root))
	pub, priv, err := NewProvenanceKey()
	if err != nil {
		t.Fatal(err)
	}
	stmt := ArtifactStatement(ArtifactInput{
		Name:       "artifact.bin",
		SHA256:     strings.Repeat("ab", 32),
		RunID:      "run-1",
		JobID:      "job-1",
		Repository: "example/repo",
		Ref:        "refs/heads/main",
		Commit:     strings.Repeat("cd", 20),
		Runner:     "runner-1",
		Finished:   time.Now().UTC(),
	})
	env, err := Sign(stmt, "kid-1", priv)
	if err != nil {
		t.Fatal(err)
	}
	ab, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(ab)
	digest := hex.EncodeToString(sum[:])

	obj, err := c.PutKnown(context.Background(), digest, int64(len(ab)), bytes.NewReader(ab))
	if err != nil {
		t.Fatalf("initial provenance publication: %v", err)
	}
	if obj.Key != digest || obj.SHA256 != digest || obj.Size != int64(len(ab)) {
		t.Fatalf("publication metadata = %+v", obj)
	}

	// Same-size corruption of the stored envelope.
	path := filepath.Join(root, "sha256", digest[:2], digest)
	corrupt := bytes.Repeat([]byte("X"), len(ab))
	if err := os.WriteFile(path, corrupt, 0o600); err != nil {
		t.Fatal(err)
	}

	// Republishing the same envelope hits the dedup shortcut; the CAS must
	// verify the stored object and heal the corruption before acknowledging.
	obj, err = c.PutKnown(context.Background(), digest, int64(len(ab)), bytes.NewReader(ab))
	if err != nil {
		t.Fatalf("provenance republication over bitrot: %v", err)
	}
	if obj.Key != digest || obj.SHA256 != digest || obj.Size != int64(len(ab)) {
		t.Fatalf("healed provenance metadata = %+v", obj)
	}
	rc, _, err := c.Open(context.Background(), obj.Key)
	if err != nil {
		t.Fatal(err)
	}
	stored, err := io.ReadAll(rc)
	_ = rc.Close()
	if err != nil {
		t.Fatalf("read healed provenance: %v", err)
	}
	if _, err := VerifyWith(stored, nil, VerifyOptions{TrustedKey: pub}); err != nil {
		t.Fatalf("stored provenance envelope does not verify: %v", err)
	}
}
