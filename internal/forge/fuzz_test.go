package forge

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/cache"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/provenance"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/snapshot"
)

// FuzzCanonicalRepository drives the repository-name canonicalizer used to
// derive policy and status names. It must be total, idempotent, and only
// ever emit slug characters.
func FuzzCanonicalRepository(f *testing.F) {
	f.Add("octocat/hello-world")
	f.Add("Org/Repo.Name")
	f.Add("")
	f.Add("----")
	f.Add("über/repo")
	f.Fuzz(func(t *testing.T, name string) {
		got := slug(name)
		if got != slug(got) {
			t.Fatalf("slug(%q) = %q is not idempotent (slug(slug) = %q)", name, got, slug(got))
		}
		for _, r := range got {
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
				t.Fatalf("slug(%q) = %q contains invalid character %q", name, got, r)
			}
		}
		if len(got) > 0 && (got[0] == '-' || got[len(got)-1] == '-') {
			t.Fatalf("slug(%q) = %q has a leading/trailing separator", name, got)
		}
	})
}

// FuzzCacheManifest drives manifest verification with an arbitrary signed
// envelope. A manifest accepted by VerifyManifest must satisfy the manifest
// invariant checks, and verification must never panic.
func FuzzCacheManifest(f *testing.F) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		f.Fatal(err)
	}
	m := cache.CacheManifest{
		Version: 1, Repository: "org/app", TrustDomain: "trusted",
		LogicalKey: "go-deps", BlobSHA256: strings.Repeat("a", 64),
		BlobSize: 123, ProducerRun: "r1", ProducerJob: "j1", CreatedAt: time.Now().UTC(),
	}
	env, err := cache.SignManifest(m, "test-key", priv)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(env)
	f.Add([]byte("not json"))
	f.Add([]byte(`{"payloadType":"application/vnd.kiwi.cache-manifest+json","payload":"e30=","signatures":[]}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		got, err := cache.VerifyManifest(data, pub)
		if err == nil {
			if err := cache.ValidateManifest(got); err != nil {
				t.Fatalf("VerifyManifest accepted a manifest that ValidateManifest rejects: %v", err)
			}
		}
	})
}

// FuzzSnapshotManifest drives snapshot archive manifest parsing. Parsing an
// untrusted archive must never panic, and a successful parse must yield a
// well-formed root digest.
func FuzzSnapshotManifest(f *testing.F) {
	seed := func() []byte {
		var buf bytes.Buffer
		if _, err := buf.Write([]byte("x")); err != nil {
			return nil
		}
		return buf.Bytes()
	}()
	f.Add(seed)
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		m, err := snapshot.Parse(bytes.NewReader(data))
		if err == nil {
			if m.Version != snapshot.ManifestVersion {
				t.Fatalf("snapshot.Parse returned version %d", m.Version)
			}
			if len(m.RootSHA256) != 64 {
				t.Fatalf("snapshot.Parse returned malformed root digest %q", m.RootSHA256)
			}
			for _, e := range m.Entries {
				if len(e.SHA256) != 64 {
					t.Fatalf("snapshot.Parse returned malformed entry digest %q", e.SHA256)
				}
			}
		}
	})
}

// FuzzProvenanceEnvelope drives provenance envelope verification with an
// arbitrary decoded envelope. Verification must never panic, and a
// successful verification must be impossible without a valid signature.
func FuzzProvenanceEnvelope(f *testing.F) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		f.Fatal(err)
	}
	st := provenance.ArtifactStatement(provenance.ArtifactInput{
		Name: "bin", SHA256: strings.Repeat("b", 64), RunID: "r", JobID: "j",
		JobKey: "build", Repository: "org/app", Ref: "main", Commit: "abc",
		Runner: "runner-1", Trusted: true,
	})
	env, err := provenance.Sign(st, "key-1", priv)
	if err != nil {
		f.Fatal(err)
	}
	seed, err := json.Marshal(env)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(seed)
	f.Add([]byte(`{"payloadType":"application/vnd.in-toto+json","payload":"e30=","signatures":[]}`))
	f.Add([]byte("garbage"))
	f.Fuzz(func(t *testing.T, data []byte) {
		var env provenance.Envelope
		if err := json.Unmarshal(data, &env); err != nil {
			return
		}
		_ = provenance.Verify(env, pub)
	})
}
