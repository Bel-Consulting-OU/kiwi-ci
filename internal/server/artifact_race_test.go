package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/blob"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/cas"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// artifactRaceReplicas builds two DB-mode servers over one DB fake and one
// shared CAS, with one leased job whose artifacts both replicas may upload.
func artifactRaceReplicas(t *testing.T) (*Server, *Server, *dbFakeStore, string, Task) {
	t.Helper()
	f := newDBFakeStore()
	sharedCAS := cas.New(blob.NewFS(t.TempDir()))
	s1, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s1.SetBlobStore(sharedCAS.Blobs)
	if err := s1.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	s2, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s2.SetBlobStore(sharedCAS.Blobs)
	if err := s2.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	// Production replicas share the lease HMAC key (dataDir); the test pins
	// them together so one lease token validates on both.
	s2.leaseKey = s1.leaseKey
	runnerID, task := leaseArtifactJob(t, s1, artifactsPipeline)
	return s1, s2, f, runnerID, task
}

// TestArtifactUploadCrossReplicaSameDigest: two replicas race the same
// (job, generation, name) with identical bytes. Exactly one 201 commits the
// record; the loser returns 200 with the SAME stored record, and the store
// holds exactly one row.
func TestArtifactUploadCrossReplicaSameDigest(t *testing.T) {
	s1, s2, f, runnerID, task := artifactRaceReplicas(t)
	path := "/api/v1/jobs/" + task.Job.ID + "/artifacts/bin"
	hdrs := leaseHeaders(task, runnerID)
	payload := "identical-artifact-bytes"
	var wg sync.WaitGroup
	results := make(chan *httptest.ResponseRecorder, 2)
	for _, s := range []*Server{s1, s2} {
		wg.Add(1)
		go func(s *Server) {
			defer wg.Done()
			results <- doJSONHeaders(t, s, http.MethodPut, path, "token", payload, hdrs)
		}(s)
	}
	wg.Wait()
	close(results)
	codes := map[int]int{}
	var records []model.ArtifactRecord
	for r := range results {
		codes[r.Code]++
		var rec model.ArtifactRecord
		if err := json.Unmarshal(r.Body.Bytes(), &rec); err != nil {
			t.Fatalf("decode artifact response: %v", err)
		}
		records = append(records, rec)
	}
	if codes[http.StatusCreated] != 1 || codes[http.StatusOK] != 1 {
		t.Fatalf("race codes = %v, want one 201 and one 200", codes)
	}
	if records[0].ID != records[1].ID {
		t.Fatalf("loser returned a different record: %s vs %s", records[0].ID, records[1].ID)
	}
	f.mu.Lock()
	rows := len(f.artifacts)
	f.mu.Unlock()
	if rows != 1 {
		t.Fatalf("artifact rows = %d, want exactly 1 across replicas", rows)
	}
}

// TestArtifactUploadCrossReplicaDigestConflict: two replicas race the same
// key with DIFFERENT bytes. One commits 201; the loser gets 409, the stored
// record is never overwritten, and exactly one row exists.
func TestArtifactUploadCrossReplicaDigestConflict(t *testing.T) {
	s1, s2, f, runnerID, task := artifactRaceReplicas(t)
	path := "/api/v1/jobs/" + task.Job.ID + "/artifacts/bin"
	hdrs := leaseHeaders(task, runnerID)
	payloads := []string{"first-replica-bytes", "second-replica-bytes"}
	var wg sync.WaitGroup
	results := make(chan int, 2)
	for i, s := range []*Server{s1, s2} {
		wg.Add(1)
		go func(s *Server, payload string) {
			defer wg.Done()
			results <- doJSONHeaders(t, s, http.MethodPut, path, "token", payload, hdrs).Code
		}(s, payloads[i])
	}
	wg.Wait()
	close(results)
	codes := map[int]int{}
	for code := range results {
		codes[code]++
	}
	if codes[http.StatusCreated] != 1 || codes[http.StatusConflict] != 1 {
		t.Fatalf("race codes = %v, want one 201 and one 409", codes)
	}
	f.mu.Lock()
	rows := len(f.artifacts)
	var stored model.ArtifactRecord
	if rows > 0 {
		stored = f.artifacts[0]
	}
	f.mu.Unlock()
	if rows != 1 {
		t.Fatalf("artifact rows = %d, want exactly 1", rows)
	}
	if stored.SHA256 != sha256Hex([]byte(payloads[0])) && stored.SHA256 != sha256Hex([]byte(payloads[1])) {
		t.Fatalf("stored digest %q matches neither payload", stored.SHA256)
	}
}

// TestArtifactUploadMemoryModeEquivalent: memory mode applies the same
// (job, generation, name)/digest semantics under s.mu: one 201 + one 200 for
// identical bytes, one 201 + one 409 for different bytes, one row each.
func TestArtifactUploadMemoryModeEquivalent(t *testing.T) {
	run := func(t *testing.T, payloads [2]string, want [2]int) {
		t.Helper()
		s, err := NewPersistent("token", "token", t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		runnerID, task := leaseArtifactJob(t, s, artifactsPipeline)
		path := "/api/v1/jobs/" + task.Job.ID + "/artifacts/bin"
		hdrs := leaseHeaders(task, runnerID)
		var wg sync.WaitGroup
		results := make(chan int, 2)
		for i := 0; i < 2; i++ {
			wg.Add(1)
			go func(payload string) {
				defer wg.Done()
				results <- doJSONHeaders(t, s, http.MethodPut, path, "token", payload, hdrs).Code
			}(payloads[i])
		}
		wg.Wait()
		close(results)
		codes := map[int]int{}
		for code := range results {
			codes[code]++
		}
		for _, code := range want {
			if codes[code] == 0 {
				t.Fatalf("race codes = %v, want one of each of %v", codes, want)
			}
		}
		s.mu.Lock()
		rows := len(s.artifacts)
		s.mu.Unlock()
		if rows != 1 {
			t.Fatalf("memory artifact rows = %d, want exactly 1", rows)
		}
	}
	t.Run("same digest", func(t *testing.T) {
		run(t, [2]string{"same-bytes", "same-bytes"}, [2]int{http.StatusCreated, http.StatusOK})
	})
	t.Run("digest conflict", func(t *testing.T) {
		run(t, [2]string{"bytes-a", "bytes-b"}, [2]int{http.StatusCreated, http.StatusConflict})
	})
}
