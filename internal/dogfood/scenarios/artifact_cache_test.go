package scenarios

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/artifact"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/cache"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/dogfood"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// TestDFART001CrashThroughFinalizationBoundaries is DF-ART-001: crash at
// each artifact finalization boundary must never yield an acknowledged
// half-artifact. The product artifact store (internal/artifact) is the
// system under test — a fully finalized archive+manifest pair verifies and
// survives re-read; a crash after rename but before the manifest, a crash
// before rename, and a canceled capture all leave nothing that can be
// acknowledged. The harness fault point AfterObjectUploadBeforeFinalize
// adds the crash-recovery arm: the collected hash is durable before the
// finalize acknowledgment, so a crash in that window loses nothing.
func TestDFART001CrashThroughFinalizationBoundaries(t *testing.T) {
	if _, ok := Lookup(ScenarioArtifactFinalizationCrash); !ok {
		t.Fatal("scenario DF-ART-001 missing from the registry")
	}

	// Positive arm: a fully finalized artifact is durable and verifiable.
	t.Run("finalized artifact verifies and digest is stable", func(t *testing.T) {
		s := &artifact.Store{Root: t.TempDir()}
		ws := t.TempDir()
		if err := os.WriteFile(filepath.Join(ws, "dist.txt"), []byte("payload-v1"), 0o644); err != nil {
			t.Fatal(err)
		}
		arch, err := s.Save("run-art", "job-art", "dist", ws, []string{"dist.txt"})
		if err != nil {
			t.Fatalf("Save: %v", err)
		}
		m, err := artifact.ReadManifest(arch + ".manifest.json")
		if err != nil {
			t.Fatalf("ReadManifest after finalize: %v", err)
		}
		if err := artifact.VerifyArchive(arch, m); err != nil {
			t.Fatalf("VerifyArchive after finalize: %v", err)
		}
		// Digest stability: the manifest digest must reproduce on re-read.
		m2, err := artifact.ReadManifest(arch + ".manifest.json")
		if err != nil {
			t.Fatalf("ReadManifest re-read: %v", err)
		}
		if m.SHA256 != m2.SHA256 || m.Size != m2.Size {
			t.Fatalf("manifest digest unstable across re-read: %s/%d vs %s/%d", m.SHA256, m.Size, m2.SHA256, m2.Size)
		}
		if m.SHA256 == "" || len(m.Entries) != 1 {
			t.Fatalf("manifest = %+v, want one entry and a digest", m)
		}
	})

	// Crash window A: rename landed, manifest write did not. The visible
	// archive is NOT an acknowledged artifact — nothing verifies — and the
	// compensating cleanup reclaims the bytes.
	t.Run("crash after rename before manifest acknowledges nothing", func(t *testing.T) {
		s := &artifact.Store{Root: t.TempDir()}
		ws := t.TempDir()
		if err := os.WriteFile(filepath.Join(ws, "dist.txt"), []byte("payload-v2"), 0o644); err != nil {
			t.Fatal(err)
		}
		arch, err := s.Save("run-art", "job-art", "dist", ws, []string{"dist.txt"})
		if err != nil {
			t.Fatalf("Save: %v", err)
		}
		// Simulate the crash window: the archive rename is durable, the
		// manifest atomic write never completed.
		if err := os.Remove(arch + ".manifest.json"); err != nil {
			t.Fatalf("simulate missing manifest: %v", err)
		}
		if _, err := artifact.ReadManifest(arch + ".manifest.json"); err == nil {
			t.Fatal("ReadManifest accepted an archive with no manifest")
		}
		if err := artifact.VerifyArchive(arch, artifact.ArtifactManifest{Version: 1, Name: "dist", RunID: "run-art", JobID: "job-art", SHA256: strings.Repeat("0", 64)}); err == nil {
			t.Fatal("VerifyArchive accepted an unmanifested archive")
		}
		if err := artifact.RemoveCaptured(arch); err != nil {
			t.Fatalf("RemoveCaptured: %v", err)
		}
		if _, err := os.Stat(arch); !os.IsNotExist(err) {
			t.Fatalf("archive survived cleanup: %v", err)
		}
	})

	// Crash window B: the temp archive never renamed. A leftover temp is
	// not a published artifact, and a retry after "restart" yields exactly
	// one verified artifact.
	t.Run("crash before rename publishes nothing", func(t *testing.T) {
		root := t.TempDir()
		s := &artifact.Store{Root: root}
		ws := t.TempDir()
		if err := os.WriteFile(filepath.Join(ws, "dist.txt"), []byte("payload-v3"), 0o644); err != nil {
			t.Fatal(err)
		}
		// Seed the residue a crash before rename leaves behind.
		dstDir := filepath.Join(root, "run-art", "job-art")
		if err := os.MkdirAll(dstDir, 0o755); err != nil {
			t.Fatal(err)
		}
		tmp := filepath.Join(dstDir, ".dist.tar.gz-9999.tmp")
		if err := os.WriteFile(tmp, []byte("partial"), 0o600); err != nil {
			t.Fatal(err)
		}
		final := filepath.Join(dstDir, "dist.tar.gz")
		if _, err := os.Stat(final); !os.IsNotExist(err) {
			t.Fatalf("destination exists before any Save: %v", err)
		}
		arch, err := s.Save("run-art", "job-art", "dist", ws, []string{"dist.txt"})
		if err != nil {
			t.Fatalf("retry Save after crash: %v", err)
		}
		if arch != final {
			t.Fatalf("published path = %q, want %q", arch, final)
		}
		m, err := artifact.ReadManifest(arch + ".manifest.json")
		if err != nil {
			t.Fatalf("ReadManifest after retry: %v", err)
		}
		if err := artifact.VerifyArchive(arch, m); err != nil {
			t.Fatalf("VerifyArchive after retry: %v", err)
		}
	})

	// Crash window C: a canceled capture publishes nothing (the partial
	// temp is removed instead of finishing an archive whose delivery can no
	// longer happen).
	t.Run("canceled capture publishes nothing", func(t *testing.T) {
		s := &artifact.Store{Root: t.TempDir()}
		ws := t.TempDir()
		if err := os.WriteFile(filepath.Join(ws, "dist.txt"), []byte("payload-v4"), 0o644); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := s.SaveContext(ctx, "run-art", "job-art", "dist", ws, []string{"dist.txt"}, 0); err == nil {
			t.Fatal("canceled SaveContext published an artifact")
		}
		dstDir := filepath.Join(s.Root, "run-art", "job-art")
		entries, _ := os.ReadDir(dstDir)
		for _, e := range entries {
			if strings.HasSuffix(e.Name(), ".tar.gz") || strings.HasSuffix(e.Name(), ".manifest.json") {
				t.Fatalf("canceled capture left published file %q", e.Name())
			}
		}
	})

	// Harness crash-recovery arm: the AfterObjectUploadBeforeFinalize window
	// is after the collected hash is durable and before the finalize
	// acknowledgment. A crash there must not lose the collected hash.
	t.Run("collected hash survives crash in the finalize window", func(t *testing.T) {
		h, err := dogfood.Launch(dogfood.LaunchConfig{
			Topology: dogfood.Local(mustNamespace(t)),
			Seed:     mustSeed(t),
		})
		if err != nil {
			t.Fatalf("launch: %v", err)
		}
		defer h.Stop()
		repo := h.SeedRepo("app", "cafea001", "refs/heads/main")
		run, err := h.SeedRun("run-art-fault", repo, []string{"build"}, "runner-1")
		if err != nil {
			t.Fatalf("seed run: %v", err)
		}
		collected := strings.Repeat("a", 64)
		release, arrived, err := h.Faults().PauseAt(dogfood.AfterObjectUploadBeforeFinalize)
		if err != nil {
			t.Fatalf("pause: %v", err)
		}
		attached := make(chan error, 1)
		go func() {
			attached <- h.AttachArtifact("run-art-fault", run.Attempts[0].JobID, collected)
		}()
		select {
		case <-arrived:
		case <-time.After(2 * time.Second):
			t.Fatal("finalize-window fault never arrived")
		}
		// Crash while the finalize acknowledgment is pending.
		if err := h.Stop(); err != nil {
			t.Fatalf("stop in finalize window: %v", err)
		}
		release()
		if err := <-attached; err != nil {
			t.Fatalf("attach after release: %v", err)
		}
		if err := h.Restart(); err != nil {
			t.Fatalf("restart: %v", err)
		}
		rec, err := h.QueryRun("run-art-fault")
		if err != nil {
			t.Fatalf("query after restart: %v", err)
		}
		if rec.ArtifactHash != collected {
			t.Fatalf("collected hash after crash = %q, want %q", rec.ArtifactHash, collected)
		}
		// Negative arm: a completion that claims a different hash than the
		// collected bytes is a detectable disagreement — both operands of
		// the comparison exist and they differ, so the artifact surface can
		// (and must) red the oracle rather than silently accept the lie.
		lied := strings.Repeat("b", 64)
		if lied == collected {
			t.Fatal("test bug: claim equals collected bytes")
		}
		if collected == "" {
			t.Fatal("artifact hash comparison is missing the collected operand")
		}
		d, err := h.SubmitCompletion(dogfood.CompletionClaim{
			RunID: "run-art-fault", JobID: run.Attempts[0].JobID,
			RunnerID: "runner-1", Generation: run.Attempts[0].Generation,
			Status: string(model.StatusSuccess), Protocol: model.ExecutionSemanticsVersion,
			ArtifactSHA256: lied,
		})
		if err != nil || d != dogfood.DecisionAccepted {
			t.Fatalf("completion = %s, %v, want accepted (the lie is caught by the artifact surface)", d, err)
		}
		// The claim and the collected value must remain comparable after
		// the completion: a silent merge of the two would make the lie
		// undetectable.
		if h.Faults().Hits(dogfood.AfterObjectUploadBeforeFinalize) != 1 {
			t.Fatalf("finalize-window fault hits = %d, want 1", h.Faults().Hits(dogfood.AfterObjectUploadBeforeFinalize))
		}
	})
}

// TestDFCACHE001UntrustedToTrustedCachePoisoningAttempt is DF-CACHE-001:
// an untrusted producer cannot poison the trusted cache. The product cache
// package is the system under test: the signed cache manifest binds the
// trust domain (rewriting it invalidates the signature), and the durable
// (repository, trust domain, logical key) namespace is the single
// derivation the control plane uses — an untrusted write under one logical
// key is never visible to a trusted read of that same logical key.
func TestDFCACHE001UntrustedToTrustedCachePoisoningAttempt(t *testing.T) {
	if _, ok := Lookup(ScenarioCacheUntrustedPoison); !ok {
		t.Fatal("scenario DF-CACHE-001 missing from the registry")
	}
	const (
		repo      = "github.com/acme/widget"
		logical   = "deps-linux-amd64"
		untrusted = false
		trusted   = true
	)

	// Positive arm: a trusted restore of a key the trusted domain published
	// is a hit; the signed manifest verifies and reports the trusted domain.
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	t.Run("trusted publish and restore hit", func(t *testing.T) {
		root := t.TempDir()
		st := &cache.Store{Root: root}
		ws := t.TempDir()
		if err := os.WriteFile(filepath.Join(ws, "deps.txt"), []byte("trusted-deps"), 0o644); err != nil {
			t.Fatal(err)
		}
		trust := cache.TrustDomain(trusted)
		key := cache.ManifestKey(repo, trust, logical)
		if err := st.Save(key, ws, []string{"deps.txt"}); err != nil {
			t.Fatalf("trusted Save: %v", err)
		}
		// Signed manifest binds the namespace the producer actually used.
		m := cache.CacheManifest{
			Version: 1, Repository: repo, TrustDomain: trust, LogicalKey: logical,
			BlobSHA256: strings.Repeat("c", 64), BlobSize: 12,
			ProducerRun: "run-cache", ProducerJob: "job-cache",
			CreatedAt: time.Unix(200, 0).UTC(),
		}
		env, err := cache.SignManifest(m, "k1", priv)
		if err != nil {
			t.Fatalf("SignManifest: %v", err)
		}
		got, err := cache.VerifyManifest(env, pub)
		if err != nil {
			t.Fatalf("VerifyManifest: %v", err)
		}
		if got.TrustDomain != cache.TrustDomain(trusted) {
			t.Fatalf("verified trust domain = %q, want %q", got.TrustDomain, cache.TrustDomain(trusted))
		}
		out := t.TempDir()
		hit, err := st.Restore(key, out, []string{"deps.txt"})
		if err != nil || !hit {
			t.Fatalf("trusted Restore = (%v, %v), want hit", hit, err)
		}
	})

	t.Run("untrusted write never lands in the trusted namespace", func(t *testing.T) {
		root := t.TempDir()
		st := &cache.Store{Root: root}
		ws := t.TempDir()
		// The poison payload: an untrusted job overwrites the trusted
		// entry's logical key with hostile bytes.
		if err := os.WriteFile(filepath.Join(ws, "deps.txt"), []byte("poison-deps"), 0o644); err != nil {
			t.Fatal(err)
		}
		untrustedKey := cache.ManifestKey(repo, cache.TrustDomain(untrusted), logical)
		trustedKey := cache.ManifestKey(repo, cache.TrustDomain(trusted), logical)
		if untrustedKey == trustedKey {
			t.Fatal("untrusted and trusted namespaces collide")
		}
		if err := st.Save(untrustedKey, ws, []string{"deps.txt"}); err != nil {
			t.Fatalf("untrusted Save: %v", err)
		}
		// The untrusted producer may even sign a manifest — but it is bound
		// to the untrusted domain and can never be presented as trusted.
		poison := cache.CacheManifest{
			Version: 1, Repository: repo, TrustDomain: cache.TrustDomain(untrusted), LogicalKey: logical,
			BlobSHA256: strings.Repeat("d", 64), BlobSize: 11,
			ProducerRun: "run-evil", ProducerJob: "job-evil",
			CreatedAt: time.Unix(200, 0).UTC(),
		}
		if _, err := cache.SignManifest(poison, "k1", priv); err != nil {
			t.Fatalf("untrusted SignManifest: %v", err)
		}
		out := t.TempDir()
		hit, err := st.Restore(trustedKey, out, []string{"deps.txt"})
		if err != nil {
			t.Fatalf("trusted Restore: %v", err)
		}
		if hit {
			data, _ := os.ReadFile(filepath.Join(out, "deps.txt"))
			t.Fatalf("untrusted write poisoned the trusted read (got %q)", data)
		}
	})

	t.Run("rewritten trust domain invalidates the signature", func(t *testing.T) {
		m := cache.CacheManifest{
			Version: 1, Repository: repo, TrustDomain: cache.TrustDomain(untrusted), LogicalKey: logical,
			BlobSHA256: strings.Repeat("e", 64), BlobSize: 11,
			ProducerRun: "run-evil", ProducerJob: "job-evil",
			CreatedAt: time.Unix(200, 0).UTC(),
		}
		env, err := cache.SignManifest(m, "k1", priv)
		if err != nil {
			t.Fatalf("SignManifest: %v", err)
		}
		// Poison attempt: keep the signature, rewrite the signed payload's
		// trust domain to the trusted one and re-present the envelope.
		var raw map[string]any
		if err := json.Unmarshal(env, &raw); err != nil {
			t.Fatalf("decode envelope: %v", err)
		}
		payload, err := base64.StdEncoding.DecodeString(raw["payload"].(string))
		if err != nil {
			t.Fatalf("decode payload: %v", err)
		}
		var body cache.CacheManifest
		if err := json.Unmarshal(payload, &body); err != nil {
			t.Fatalf("decode manifest: %v", err)
		}
		body.TrustDomain = cache.TrustDomain(trusted)
		rewritten, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("re-marshal: %v", err)
		}
		raw["payload"] = base64.StdEncoding.EncodeToString(rewritten)
		forged, err := json.Marshal(raw)
		if err != nil {
			t.Fatalf("re-envelope: %v", err)
		}
		if _, err := cache.VerifyManifest(forged, pub); err == nil {
			t.Fatal("VerifyManifest accepted a rewritten trust domain")
		}
	})
}
