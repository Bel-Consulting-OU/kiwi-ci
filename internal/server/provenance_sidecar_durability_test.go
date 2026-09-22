package server

// Crash-durability tests for the filesystem-mode provenance sidecar
// (`<artifact>.intoto.json`). The sidecar is now published through
// fsutil.AtomicWriteFile and re-opened/re-hashed before the artifact record
// references it, so a crash can no longer leave a durable artifact record
// whose local provenance envelope is missing, truncated or not durable.
//
// The injected durability-step failures are scoped to the provenance writer
// only (the fsutil hooks are global and would otherwise also fail the payload
// finalization in the same request). Pre-rename failures (write, file fsync,
// close, rename) mean the sidecar was definitely not published: the upload is
// refused, no record is inserted, and readiness is untouched. A post-rename
// failure (the parent-directory fsync) means the sidecar IS visible with
// uncertified durability: the upload is refused, the published sidecar is
// kept, and readiness stays degraded until a later successful persist in the
// same directory reconciles it.

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/fsutil"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// applyProvenanceFault makes the next fs-mode provenance sidecar publication
// run fsutil.AtomicWriteFile under the injected hooks. The restore function
// must be called before any later upload that should use the real writer.
func applyProvenanceFault(t *testing.T, h fsutil.Hooks) (restore func()) {
	t.Helper()
	prev := provenanceSidecarWrite
	provenanceSidecarWrite = func(path string, b []byte, mode os.FileMode) error {
		r := fsutil.SetHooks(h)
		defer r()
		return fsutil.AtomicWriteFile(path, b, mode)
	}
	return func() { provenanceSidecarWrite = prev }
}

// provenanceSidecarFaults injects each durability step in turn. preRename
// reports whether the failure happens before the rename (the sidecar was
// definitely not published).
func provenanceSidecarFaults() []struct {
	name      string
	preRename bool
	hooks     fsutil.Hooks
} {
	return []struct {
		name      string
		preRename bool
		hooks     fsutil.Hooks
	}{
		{"write", true, fsutil.Hooks{Write: func(*os.File, []byte) (int, error) {
			return 0, errors.New("injected write failure")
		}}},
		{"file sync", true, fsutil.Hooks{FileSync: func(*os.File) error {
			return errors.New("injected file fsync failure")
		}}},
		{"close", true, fsutil.Hooks{FileClose: func(f *os.File) error {
			_ = fsutil.RealFileClose(f)
			return errors.New("injected close failure")
		}}},
		{"rename", true, fsutil.Hooks{Rename: func(string, string) error {
			return errors.New("injected rename failure")
		}}},
		{"dir sync", false, fsutil.Hooks{DirSync: func(string) error {
			return errors.New("injected directory fsync failure")
		}}},
	}
}

// filesWithSuffix returns the immediate files under dir whose name ends with
// suffix (a missing directory yields no files).
func filesWithSuffix(t *testing.T, dir, suffix string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		t.Fatal(err)
	}
	var out []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), suffix) {
			out = append(out, filepath.Join(dir, e.Name()))
		}
	}
	return out
}

// requireReadiness asserts the user-observable readiness contract: 200 when
// healthy, or 503 with X-Kiwi-State: degraded when any security-state file was
// published without certified crash durability.
func requireReadiness(t *testing.T, s *Server, wantDegraded bool) {
	t.Helper()
	w := doJSON(t, s, http.MethodGet, "/readiness", "", "")
	if wantDegraded {
		if w.Code != http.StatusServiceUnavailable || w.Header().Get("X-Kiwi-State") != "degraded" {
			t.Fatalf("readiness = %d/%q, want 503 degraded", w.Code, w.Header().Get("X-Kiwi-State"))
		}
		return
	}
	if w.Code != http.StatusOK {
		t.Fatalf("readiness = %d (%s), want 200", w.Code, w.Body.String())
	}
}

// TestProvenanceSidecarDurabilityFailuresRefuseArtifact drives every injected
// durability-step failure through a real fs-mode artifact upload: the upload
// must not be acknowledged, no artifact record (hence no ProvenanceSHA256)
// may exist, the sidecar contract must follow the failed phase, and a later
// successful upload in the same directory must record a re-verified digest
// and clear any armed uncertainty.
func TestProvenanceSidecarDurabilityFailuresRefuseArtifact(t *testing.T) {
	for _, fault := range provenanceSidecarFaults() {
		t.Run(fault.name, func(t *testing.T) {
			s, err := NewPersistent("token", "token", t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			requireReadiness(t, s, false)
			runnerID, task := leaseArtifactJob(t, s, artifactsPipeline)
			hdrs := leaseHeaders(task, runnerID)
			dir := filepath.Join(s.store.Root, "artifacts", task.Job.RunID, task.Job.ID)
			path := "/api/v1/jobs/" + task.Job.ID + "/artifacts/bin"

			restore := applyProvenanceFault(t, fault.hooks)
			w := doJSONHeaders(t, s, http.MethodPut, path, "token", "payload", hdrs)
			restore()

			if w.Code != http.StatusServiceUnavailable {
				t.Fatalf("upload with %s failure = %d, want 503: %s", fault.name, w.Code, w.Body.String())
			}
			if strings.Contains(w.Body.String(), "injected") {
				t.Fatalf("response leaked the raw durability error: %q", w.Body.String())
			}

			// No acknowledged artifact record => no dangling ProvenanceSHA256.
			s.mu.Lock()
			records := len(s.artifacts)
			for _, a := range s.artifacts {
				if a.ProvenanceSHA256 != "" {
					s.mu.Unlock()
					t.Fatalf("refused %s upload left a dangling provenance digest %q", fault.name, a.ProvenanceSHA256)
				}
			}
			s.mu.Unlock()
			if records != 0 {
				t.Fatalf("refused %s upload acknowledged %d artifact record(s)", fault.name, records)
			}

			sidecars := filesWithSuffix(t, dir, ".intoto.json")
			if fault.preRename {
				if len(sidecars) != 0 {
					t.Fatalf("pre-rename %s failure left a sidecar: %v", fault.name, sidecars)
				}
				requireReadiness(t, s, false)
			} else {
				if len(sidecars) != 1 {
					t.Fatalf("post-rename %s failure kept %d sidecar(s), want exactly the published one", fault.name, len(sidecars))
				}
				body, rerr := os.ReadFile(sidecars[0])
				if rerr != nil {
					t.Fatal(rerr)
				}
				if !json.Valid(body) {
					t.Fatalf("kept sidecar %s is not valid JSON", sidecars[0])
				}
				requireReadiness(t, s, true)
			}
			assertNoAtomicScratch(t, dir)

			// A later successful upload in the same directory must record a
			// re-verified digest and reconcile the uncertainty.
			heal := doJSONHeaders(t, s, http.MethodPut, path, "token", "payload", hdrs)
			if heal.Code != http.StatusCreated {
				t.Fatalf("healing upload after %s failure = %d: %s", fault.name, heal.Code, heal.Body.String())
			}
			var rec model.ArtifactRecord
			if err := json.Unmarshal(heal.Body.Bytes(), &rec); err != nil {
				t.Fatal(err)
			}
			if rec.ProvenanceSHA256 == "" || rec.ProvenancePath == "" {
				t.Fatalf("healed artifact record has no provenance: %+v", rec)
			}
			got, herr := fileSHA256(rec.ProvenancePath)
			if herr != nil {
				t.Fatal(herr)
			}
			if got != rec.ProvenanceSHA256 {
				t.Fatalf("recorded provenance digest %s != reopened sidecar digest %s", rec.ProvenanceSHA256, got)
			}
			requireReadiness(t, s, false)
		})
	}
}

// TestProvenanceSidecarSuccessRecordsReopenedDigest proves the success path:
// the sidecar is written durably at mode 0600 and the recorded digest is the
// digest of the bytes reopened from disk, not merely the in-memory envelope.
func TestProvenanceSidecarSuccessRecordsReopenedDigest(t *testing.T) {
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	runnerID, task := leaseArtifactJob(t, s, artifactsPipeline)
	hdrs := leaseHeaders(task, runnerID)
	w := doJSONHeaders(t, s, http.MethodPut, "/api/v1/jobs/"+task.Job.ID+"/artifacts/bin", "token", "payload", hdrs)
	if w.Code != http.StatusCreated {
		t.Fatalf("upload = %d: %s", w.Code, w.Body.String())
	}
	var rec model.ArtifactRecord
	if err := json.Unmarshal(w.Body.Bytes(), &rec); err != nil {
		t.Fatal(err)
	}
	if strings.HasPrefix(rec.ProvenancePath, "cas:") || rec.ProvenancePath == "" {
		t.Fatalf("fs-mode provenance path = %q, want a local file", rec.ProvenancePath)
	}
	if rec.ProvenanceSHA256 == "" {
		t.Fatal("fs-mode provenance digest missing")
	}
	got, herr := fileSHA256(rec.ProvenancePath)
	if herr != nil {
		t.Fatal(herr)
	}
	if got != rec.ProvenanceSHA256 {
		t.Fatalf("recorded provenance digest %s != reopened sidecar digest %s", rec.ProvenanceSHA256, got)
	}
	fi, serr := os.Stat(rec.ProvenancePath)
	if serr != nil {
		t.Fatal(serr)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("sidecar mode = %o, want 600", fi.Mode().Perm())
	}
	requireReadiness(t, s, false)
	dl := doJSON(t, s, http.MethodGet, "/api/v1/artifacts/"+rec.ID+"/provenance", "token", "")
	if dl.Code != http.StatusOK {
		t.Fatalf("provenance download = %d: %s", dl.Code, dl.Body.String())
	}
	if dl.Header().Get("X-Kiwi-Content-SHA256") != rec.ProvenanceSHA256 {
		t.Fatalf("served provenance digest = %q, want %q", dl.Header().Get("X-Kiwi-Content-SHA256"), rec.ProvenanceSHA256)
	}
}

// TestProvenanceSidecarReHashMismatchRefusesArtifact proves the residual
// invariant: a sidecar whose published bytes re-hash to something other than
// the envelope digest is never recorded and the artifact is not acknowledged.
func TestProvenanceSidecarReHashMismatchRefusesArtifact(t *testing.T) {
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	runnerID, task := leaseArtifactJob(t, s, artifactsPipeline)
	hdrs := leaseHeaders(task, runnerID)

	prev := provenanceSidecarWrite
	provenanceSidecarWrite = func(path string, _ []byte, mode os.FileMode) error {
		// Valid durable write of the WRONG bytes: the re-open must catch it.
		return fsutil.AtomicWriteFile(path, []byte(`{"tampered":true}`), mode)
	}
	w := doJSONHeaders(t, s, http.MethodPut, "/api/v1/jobs/"+task.Job.ID+"/artifacts/bin", "token", "payload", hdrs)
	provenanceSidecarWrite = prev

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("upload with mismatched sidecar bytes = %d, want 503: %s", w.Code, w.Body.String())
	}
	s.mu.Lock()
	records := len(s.artifacts)
	for _, a := range s.artifacts {
		if a.ProvenanceSHA256 != "" {
			s.mu.Unlock()
			t.Fatalf("recorded an unverified provenance digest %q", a.ProvenanceSHA256)
		}
	}
	s.mu.Unlock()
	if records != 0 {
		t.Fatalf("mismatched sidecar bytes acknowledged %d artifact record(s)", records)
	}
}

// TestProvenanceSidecarCrashRestartConsistency proves the crash-restart
// invariant: a record that is durably committed always has its sidecar, and a
// refused upload never leaves a record that lacks one.
func TestProvenanceSidecarCrashRestartConsistency(t *testing.T) {
	t.Run("committed record keeps its sidecar", func(t *testing.T) {
		dir := t.TempDir()
		s, err := NewPersistent("token", "token", dir)
		if err != nil {
			t.Fatal(err)
		}
		runnerID, task := leaseArtifactJob(t, s, artifactsPipeline)
		hdrs := leaseHeaders(task, runnerID)
		w := doJSONHeaders(t, s, http.MethodPut, "/api/v1/jobs/"+task.Job.ID+"/artifacts/bin", "token", "payload", hdrs)
		if w.Code != http.StatusCreated {
			t.Fatalf("upload = %d: %s", w.Code, w.Body.String())
		}
		var rec model.ArtifactRecord
		if err := json.Unmarshal(w.Body.Bytes(), &rec); err != nil {
			t.Fatal(err)
		}

		restarted, err := NewPersistent("token", "token", dir)
		if err != nil {
			t.Fatal(err)
		}
		restarted.mu.Lock()
		var restored *model.ArtifactRecord
		for _, a := range restarted.artifacts {
			c := a
			restored = &c
		}
		restarted.mu.Unlock()
		if restored == nil {
			t.Fatal("restart lost the committed artifact record")
		}
		if restored.ProvenanceSHA256 == "" || restored.ProvenancePath == "" {
			t.Fatalf("restart lost the provenance reference: %+v", restored)
		}
		got, herr := fileSHA256(restored.ProvenancePath)
		if herr != nil {
			t.Fatalf("crash-restart left a record without its sidecar: %v", herr)
		}
		if got != restored.ProvenanceSHA256 {
			t.Fatalf("after restart, recorded digest %s != sidecar digest %s", restored.ProvenanceSHA256, got)
		}
	})

	t.Run("refused upload leaves no record", func(t *testing.T) {
		dir := t.TempDir()
		s, err := NewPersistent("token", "token", dir)
		if err != nil {
			t.Fatal(err)
		}
		runnerID, task := leaseArtifactJob(t, s, artifactsPipeline)
		hdrs := leaseHeaders(task, runnerID)
		restore := applyProvenanceFault(t, fsutil.Hooks{DirSync: func(string) error {
			return errors.New("injected directory fsync failure")
		}})
		w := doJSONHeaders(t, s, http.MethodPut, "/api/v1/jobs/"+task.Job.ID+"/artifacts/bin", "token", "payload", hdrs)
		restore()
		if w.Code != http.StatusServiceUnavailable {
			t.Fatalf("upload with dir-sync failure = %d, want 503: %s", w.Code, w.Body.String())
		}

		restarted, err := NewPersistent("token", "token", dir)
		if err != nil {
			t.Fatal(err)
		}
		restarted.mu.Lock()
		records := len(restarted.artifacts)
		restarted.mu.Unlock()
		if records != 0 {
			t.Fatalf("crash-restart resurrected %d artifact record(s) from a refused upload", records)
		}
	})
}
