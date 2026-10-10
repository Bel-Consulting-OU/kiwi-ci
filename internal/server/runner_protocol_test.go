package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// legacyRegisterBody is a legacy (v1) registration: it speaks the OLD runner
// API protocol range but omits the wire-semantic protocol_version, so the
// server must treat it as version 1.
const legacyRegisterBody = `{"id":"legacy-runner","name":"legacy","protocol_min":3,"protocol_max":3,"labels":["container"],"capacity":1}`

// TestRegisterRefusesLegacyProtocolByDefault pins the fail-closed default:
// with the built-in minimum (model.RunnerProtocolVersion) a registration that
// omits protocol_version — or explicitly declares 1 — is refused 400 with a
// body naming the required minimum and the runner's version, and no runner
// row is stored.
func TestRegisterRefusesLegacyProtocolByDefault(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
	}{
		{"absent protocol_version", legacyRegisterBody},
		{"explicit v1", `{"id":"legacy-runner","name":"legacy","protocol_min":3,"protocol_max":3,"protocol_version":1,"labels":["container"],"capacity":1}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := New("token")
			if s.minRunnerProtocol() != model.RunnerProtocolVersion {
				t.Fatalf("effective default minimum = %d, want %d", s.minRunnerProtocol(), model.RunnerProtocolVersion)
			}
			w := doJSON(t, s, http.MethodPost, "/api/v1/runners/register", "token", tc.body)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("legacy register = %d, want 400: %s", w.Code, w.Body.String())
			}
			body := w.Body.String()
			if !strings.Contains(body, "runner protocol version 1") || !strings.Contains(body, "minimum required 2") {
				t.Fatalf("refusal body does not name both versions: %q", body)
			}
			s.mu.Lock()
			_, stored := s.runners["legacy-runner"]
			s.mu.Unlock()
			if stored {
				t.Fatal("refused legacy registration was stored")
			}
		})
	}
	// A negative version is malformed input, not a legacy runner.
	s := New("token")
	if w := doJSON(t, s, http.MethodPost, "/api/v1/runners/register", "token",
		`{"id":"negative-runner","name":"n","protocol_min":3,"protocol_max":3,"protocol_version":-1}`); w.Code != http.StatusBadRequest {
		t.Fatalf("negative protocol_version = %d, want 400: %s", w.Code, w.Body.String())
	}
}

// TestRegisterNegotiatesDownToServerProtocol pins the negotiation rule: a
// runner declaring a protocol ABOVE what this binary implements is accepted
// and the server stores the negotiated (server-current) version, because the
// server can serve those semantics; the runner refuses to start only when
// the server is NEWER than the runner.
func TestRegisterNegotiatesDownToServerProtocol(t *testing.T) {
	s := New("token")
	future := model.RunnerProtocolVersion + 1
	body := fmt.Sprintf(`{"id":"future-runner","name":"f","protocol_min":3,"protocol_max":3,"protocol_version":%d}`, future)
	if w := doJSON(t, s, http.MethodPost, "/api/v1/runners/register", "token", body); w.Code != http.StatusOK {
		t.Fatalf("future-declared runner = %d, want 200: %s", w.Code, w.Body.String())
	}
	s.mu.Lock()
	stored := s.runners["future-runner"]
	s.mu.Unlock()
	if stored.ProtocolVersion != model.RunnerProtocolVersion {
		t.Fatalf("negotiated protocol = %d, want %d", stored.ProtocolVersion, model.RunnerProtocolVersion)
	}
}

// TestRegisterLegacyDuringUpgradeWindow proves the controlled window: with
// min_runner_protocol = 1 the legacy runner registers, the row stores the
// NEGOTIATED version 1, and the response advertises the server's current
// protocol plus the configured minimum.
func TestRegisterLegacyDuringUpgradeWindow(t *testing.T) {
	s := New("token")
	s.MinRunnerProtocol = 1
	w := doJSON(t, s, http.MethodPost, "/api/v1/runners/register", "token", legacyRegisterBody)
	if w.Code != http.StatusOK {
		t.Fatalf("legacy register with min=1 = %d, want 200: %s", w.Code, w.Body.String())
	}
	var out registerResponse
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.ProtocolVersion != model.RunnerProtocolVersion {
		t.Fatalf("response protocol_version = %d, want the server's current %d", out.ProtocolVersion, model.RunnerProtocolVersion)
	}
	if out.MinRunnerProtocol != 1 {
		t.Fatalf("response min_runner_protocol = %d, want 1", out.MinRunnerProtocol)
	}
	s.mu.Lock()
	stored, ok := s.runners["legacy-runner"]
	s.mu.Unlock()
	if !ok {
		t.Fatal("legacy runner not stored during the upgrade window")
	}
	if stored.ProtocolVersion != 1 {
		t.Fatalf("stored negotiated protocol = %d, want 1", stored.ProtocolVersion)
	}
}

// TestNextRefusesLegacyRunnerButDrainsClaimedWork proves the upgrade-window
// split: the legacy runner's poll is refused 409 RUNNER_PROTOCOL_UNSUPPORTED
// with no lease, attempt, reservation or runner-slot change, while
// heartbeat and completion for work it already claimed keep working under
// the generation fence.
func TestNextRefusesLegacyRunnerButDrainsClaimedWork(t *testing.T) {
	s := New("token")
	s.MinRunnerProtocol = 1
	if w := doJSON(t, s, http.MethodPost, "/api/v1/runners/register", "token", legacyRegisterBody); w.Code != http.StatusOK {
		t.Fatalf("legacy register = %d: %s", w.Code, w.Body.String())
	}
	run := submitLeaseRun(t, s, "token", "https://github.com/o/r.git")
	s.mu.Lock()
	var jobID string
	for id, j := range s.jobs {
		if j.RunID == run.ID {
			jobID = id
		}
	}
	if jobID == "" {
		s.mu.Unlock()
		t.Fatal("queued job not found")
	}
	pre := s.jobs[jobID]
	s.mu.Unlock()

	w := doJSON(t, s, http.MethodPost, "/api/v1/runners/legacy-runner/next", "token", "")
	if w.Code != http.StatusConflict {
		t.Fatalf("legacy next = %d, want 409: %s", w.Code, w.Body.String())
	}
	if ct := w.Header().Get("Content-Type"); !strings.Contains(ct, "application/json") {
		t.Fatalf("refusal content type = %q, want application/json", ct)
	}
	var refusal struct {
		Error             string `json:"error"`
		Reason            string `json:"reason"`
		MinRunnerProtocol int    `json:"min_runner_protocol"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &refusal); err != nil {
		t.Fatalf("refusal body is not JSON: %v: %s", err, w.Body.String())
	}
	if refusal.Reason != "RUNNER_PROTOCOL_UNSUPPORTED" {
		t.Fatalf("refusal reason = %q", refusal.Reason)
	}
	if refusal.MinRunnerProtocol != model.JobRequiresProtocol {
		t.Fatalf("refusal min_runner_protocol = %d, want %d", refusal.MinRunnerProtocol, model.JobRequiresProtocol)
	}
	// No claim/reservation/event side effects: the job is byte-for-byte the
	// queued pre-state and the runner holds no slot.
	s.mu.Lock()
	post := s.jobs[jobID]
	ri := s.runners["legacy-runner"]
	s.mu.Unlock()
	if post.Status != model.StatusQueued || post.Attempts != pre.Attempts || post.LeaseGeneration != pre.LeaseGeneration ||
		post.LeaseRunnerID != "" || post.LeaseTokenHash != nil || post.LeaseExpiresAt != nil {
		t.Fatalf("refused poll mutated the job: %+v", post)
	}
	if len(ri.ActiveJobs) != 0 || ri.Busy || ri.CurrentJob != "" {
		t.Fatalf("refused poll mutated the runner: active=%v busy=%v current=%q", ri.ActiveJobs, ri.Busy, ri.CurrentJob)
	}

	// Drain path: a job claimed BEFORE the upgrade (seeded running under the
	// legacy runner) can still heartbeat and complete. Fencing is
	// generation-based, so the window never strands in-flight work.
	const rawToken = "legacy-lease-token"
	s.mu.Lock()
	j := s.jobs[jobID]
	exp := time.Now().UTC().Add(time.Minute)
	j.Status = model.StatusRunning
	j.Attempts++
	j.LeaseRunnerID = "legacy-runner"
	j.LeaseTokenHash = hashLeaseToken(s.leaseKey, rawToken)
	j.LeaseGeneration = 1
	j.LeaseExpiresAt = &exp
	s.jobs[jobID] = j
	ri = s.runners["legacy-runner"]
	ri.ActiveJobs = []string{jobID}
	ri.CurrentJob = jobID
	s.runners["legacy-runner"] = ri
	s.mu.Unlock()

	hb := `{"runner_id":"legacy-runner","lease_token":"` + rawToken + `","lease_generation":1}`
	if w := doJSON(t, s, http.MethodPost, "/api/v1/jobs/"+jobID+"/heartbeat", "token", hb); w.Code != http.StatusOK {
		t.Fatalf("legacy heartbeat = %d, want 200: %s", w.Code, w.Body.String())
	}
	complete := `{"runner_id":"legacy-runner","lease_token":"` + rawToken + `","lease_generation":1,"status":"success"}`
	if w := doJSON(t, s, http.MethodPost, "/api/v1/jobs/"+jobID+"/complete", "token", complete); w.Code != http.StatusNoContent {
		t.Fatalf("legacy complete = %d, want 204: %s", w.Code, w.Body.String())
	}
	s.mu.Lock()
	done := s.jobs[jobID]
	s.mu.Unlock()
	if done.Status != model.StatusSuccess {
		t.Fatalf("completed job status = %q, want success", done.Status)
	}
}

// TestLeaseAdvertisesProtocolVersion proves a v2 runner is leased normally
// and the task carries the protocol semantics it requires.
func TestLeaseAdvertisesProtocolVersion(t *testing.T) {
	s := New("token")
	ri := registerLeaseRunner(t, s, "token")
	s.mu.Lock()
	stored := s.runners[ri.ID]
	s.mu.Unlock()
	if stored.ProtocolVersion != model.RunnerProtocolVersion {
		t.Fatalf("stored negotiated protocol = %d, want %d", stored.ProtocolVersion, model.RunnerProtocolVersion)
	}
	submitLeaseRun(t, s, "token", "https://github.com/o/r.git")
	w := doJSON(t, s, http.MethodPost, "/api/v1/runners/"+ri.ID+"/next", "token", "")
	if w.Code != http.StatusOK {
		t.Fatalf("v2 next = %d, want 200: %s", w.Code, w.Body.String())
	}
	var task Task
	if err := json.Unmarshal(w.Body.Bytes(), &task); err != nil {
		t.Fatal(err)
	}
	if task.ProtocolVersion != model.JobRequiresProtocol {
		t.Fatalf("task protocol_version = %d, want %d", task.ProtocolVersion, model.JobRequiresProtocol)
	}
}
