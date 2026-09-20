package server

// fs_failure_matrix_test.go is the exhaustive fs-mode snapshot-persist
// failure matrix. Every authoritative fs-mode mutation that rides the
// state snapshot is driven with s.persistFailForTest armed (the same seam the
// production persist path consults; see server.go persistLocked) and must
// satisfy three properties:
//
//	(a) the request is refused (503 for the transactional handlers) and no
//	    success body/token/id is acknowledged;
//	(b) the in-memory authoritative maps equal their pre-mutation state
//	    (captureStateForTest, the production rollback capture) and
//	    /readiness answers 503 with X-Kiwi-State: degraded;
//	(c) after the seam is cleared the same mutation succeeds, heals the
//	    degraded signal, and the change is durable across a reload over the
//	    same data directory.
//
// Inventory of the persistChecked/persistCheckedErrLocked call sites and the
// handler matrix they feed (non-test files):
//
//	run.enqueue            server.go:1374   submit 503 (server.go:1081) / webhook 503 (github.go:141)
//	runner.register        server.go:1988   intentional 200 + degraded (comment server.go:1985-1988)
//	runner.drain           server.go:2138   503
//	runner.disable         server.go:2251   503
//	runner.enable          server.go:2311   503
//	runner.lease_skip      server.go:2378/2389/2399/2406 204 annotations, not driven (see report)
//	runner.queue_reasons   server.go:2474   204 annotations, not driven (see report)
//	job.lease              server.go:2633   503 fixed body, token withheld, claim rolled back (job queued, attempt unconsumed, runner slot free; rollback at server.go:2402)
//	job.heartbeat          server.go:2697   503 "heartbeat not durable"
//	job.complete           server.go:3095   503
//	job.complete.replay    server.go:3530   503
//	job.approve            server.go:3704   503
//	job.cancel             server.go:3948   503
//	maintain.lease_recovery server.go:5034  no HTTP; rollback + degraded (driven directly)
//	snapshot.upload        snapshots.go:141 503 + record/file cleanup
//	artifact.upload        blobs.go:371     503 + record/blob rollback (TestFSFindingsArtifactUploadAcknowledgesOnPersistFailure)
//	artifact.sidecar       supplychain_gate.go:474 503 + digest rollback (TestFSFindingsArtifactSidecarAcknowledgesOnPersistFailure)
//	deployment.record      deployments.go:104 503 + record rollback; Deployments now part of storage.Snapshot (TestFSFindingsDeploymentRecordAcknowledgesOnPersistFailure)
//	test report upload     testintel.go:71  500 + report rollback (TestFSFindingsTestReportLeavesGhostOnPersistFailure)
//	runner profile upsert  profiles.go:81   500 + profile rollback (TestFSFindingsProfileUpsertLeavesGhostOnPersistFailure)
//	cert profile bind      profiles.go:138  503 + binding rollback (TestFSFindingsCertProfileBindLeavesGhostOnPersistFailure)
//	generated fragment     dynamic.go:438   503 + map rollback, receipt only after persist (TestFSFindingsGeneratedFragmentLeavesGhostAndReplayAck)
//	schedule create        schedules.go:580 500 + schedule rollback (TestFSFindingsScheduleCreateLeavesGhostOnJournalFailure)
//	schedule fire          schedules.go:946 -> run.enqueue (covered by schedule.fire)
//	downstream.*           downstream.go:286/523/535/562/592/622 internal outbox/maintenance paths, never client-acknowledged; fail-closed by error return
//	job.deployment_finish  completion_effects.go:114 returned to completion/outbox; covered by job.complete
//	job.usage_account      completion_effects.go:240 returned to completion/outbox; covered by job.complete
//	job.run_aggregate      completion_effects.go:270 returned to completion/outbox; covered by job.complete
//	log batch              own journal (internal/storage/logbatch.go), not the snapshot seam — not driven
//	secret delivery        own receipt file (secret.go persistSecretReceiptsLocked), not the snapshot seam — not driven
//	check publication      own atomic mapping file (checkruns.go:53-108) + outbox, not the snapshot seam — not driven
//	job cache upload       separate local blob store, no snapshot write — not driven
//
// The run.enqueue path maps a snapshot persistence failure to 503 in submit
// and the webhook (the enqueue rolls back exactly and never returns a run
// body). The ACK/ghost findings above are asserted by the TestFSFindings*
// tests, which fail until the handlers fail closed.

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/snapshot"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// errFSMatrixSeam is the synthetic snapshot write failure armed through
// s.persistFailForTest.
var errFSMatrixSeam = errors.New("synthetic fs-matrix snapshot write failure")

// fsMutationDrive drives one mutation through phases (a)-(c). The closures
// capture the fixture the setup built against the freshly created server.
type fsMutationDrive struct {
	// invoke drives the mutation while s.persistFailForTest is armed and
	// asserts the exact refusal: the expected status, the fixed body where
	// the handler defines one, and that no success body/token/id leaks.
	invoke func(t *testing.T, s *Server)
	// rolledBack selects the phase-(b) state assertion. true compares the
	// complete captureStateForTest snapshot before/after for drift. false
	// means the handler has a DOCUMENTED intentional retention contract and
	// drift asserts it instead.
	rolledBack bool
	// drift asserts the documented intentional deviation when rolledBack is
	// false.
	drift func(t *testing.T, s *Server, pre stateRollback)
	// heal re-drives the same mutation after the seam is cleared; it must
	// leave the server healthy (readiness 200) and the mutation durable.
	heal func(t *testing.T, s *Server)
	// durable verifies the healed change through a fresh snapshot reload.
	durable func(t *testing.T, dir string, s *Server)
}

type fsMutationCase struct {
	name  string
	drive func(t *testing.T, s *Server) *fsMutationDrive
}

// fsMatrixAssertStatus fails unless the response has the exact status.
func fsMatrixAssertStatus(t *testing.T, w *httptest.ResponseRecorder, want int) {
	t.Helper()
	if w.Code != want {
		t.Fatalf("status = %d, want %d: %s", w.Code, want, w.Body.String())
	}
}

// fsMatrixAssertBody fails unless the response body is exactly want.
func fsMatrixAssertBody(t *testing.T, w *httptest.ResponseRecorder, want string) {
	t.Helper()
	if got := w.Body.String(); got != want {
		t.Fatalf("body = %q, want %q", got, want)
	}
}

// fsMatrixAssertNoLeaseLeak fails if a refusal echoed a capability.
func fsMatrixAssertNoLeaseLeak(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	if strings.Contains(w.Body.String(), "lease_token") || strings.Contains(w.Body.String(), "LeaseToken") {
		t.Fatalf("refusal leaked a lease token: %q", w.Body.String())
	}
}

// fsMatrixAssertDegraded pins the phase-(b) readiness contract: 503, the
// degraded header, and the fixed body that never echoes the store error.
func fsMatrixAssertDegraded(t *testing.T, s *Server) {
	t.Helper()
	w := doJSON(t, s, http.MethodGet, "/readiness", "", "")
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("readiness after a failed persist = %d, want 503: %s", w.Code, w.Body.String())
	}
	if got := w.Header().Get("X-Kiwi-State"); got != "degraded" {
		t.Fatalf("X-Kiwi-State after a failed persist = %q, want degraded", got)
	}
	if got := w.Body.String(); got != statePersistenceDegradedBody+"\n" {
		t.Fatalf("readiness body = %q, want the fixed %q", got, statePersistenceDegradedBody)
	}
	if strings.Contains(w.Body.String(), errFSMatrixSeam.Error()) {
		t.Fatalf("readiness leaked the raw persist error: %q", w.Body.String())
	}
}

// fsMatrixAssertReady pins the healed contract: 200 with no degraded header.
func fsMatrixAssertReady(t *testing.T, s *Server) {
	t.Helper()
	if s.stateDegraded.Load() {
		t.Fatal("stateDegraded still set after a successful persist")
	}
	w := doJSON(t, s, http.MethodGet, "/readiness", "", "")
	if w.Code != http.StatusOK {
		t.Fatalf("readiness after heal = %d, want 200: %s", w.Code, w.Body.String())
	}
	if got := w.Header().Get("X-Kiwi-State"); got != "" {
		t.Fatalf("X-Kiwi-State after heal = %q, want empty", got)
	}
}

// fsMatrixAssertNoDrift compares the whole production rollback capture.
func fsMatrixAssertNoDrift(t *testing.T, pre, post stateRollback) {
	t.Helper()
	if reflect.DeepEqual(pre, post) {
		return
	}
	t.Logf("pre  runs=%v\njobs=%v\nrunners=%v\ncontracts=%v\ndeliveries=%v\nlinks=%v\noccurrences=%v\ndeployments=%v",
		pre.runs, pre.jobs, pre.runners, pre.contracts, pre.deliveries, pre.downstreamLinks, pre.occurrences, pre.deployments)
	t.Logf("post runs=%v\njobs=%v\nrunners=%v\ncontracts=%v\ndeliveries=%v\nlinks=%v\noccurrences=%v\ndeployments=%v",
		post.runs, post.jobs, post.runners, post.contracts, post.deliveries, post.downstreamLinks, post.occurrences, post.deployments)
	t.Fatalf("in-memory state drifted after a failed persist")
}

// fsMatrixReload opens a fresh persistent server over the same data dir, so
// the durable snapshot (and the schedules file) is re-read from disk.
func fsMatrixReload(t *testing.T, dir string) *Server {
	t.Helper()
	s2, err := NewPersistent("token", "token", dir)
	if err != nil {
		t.Fatalf("reload over %s: %v", dir, err)
	}
	return s2
}

// fsMatrixGitHubAPI serves the pipeline contents and compare response the
// GitHub webhook path resolves (same fixture as newGitHubHookServer).
func fsMatrixGitHubAPI(t *testing.T) *httptest.Server {
	t.Helper()
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/contents/.kiwi/pipeline.yaml"):
			_ = json.NewEncoder(w).Encode(map[string]string{
				"content":  base64.StdEncoding.EncodeToString([]byte(webhookPipeline)),
				"encoding": "base64",
			})
		case strings.Contains(r.URL.Path, "/compare/"):
			_ = json.NewEncoder(w).Encode(map[string]any{"files": []map[string]string{{"filename": "src/main.go"}}})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(api.Close)
	return api
}

// TestFSFailureMatrixEveryMutationFailsClosed is the passing table: every
// authoritative fs-mode mutation is driven through (a) refusal, (b) no
// drift + degraded readiness, and (c) healed, durable success.
func TestFSFailureMatrixEveryMutationFailsClosed(t *testing.T) {
	cases := []fsMutationCase{
		fsCaseRunEnqueueAPI(),
		fsCaseRunEnqueueWebhook(),
		fsCaseJobLease(),
		fsCaseJobHeartbeat(),
		fsCaseJobApprove(),
		fsCaseJobCancel(),
		fsCaseJobComplete(),
		fsCaseJobCompleteReplay(),
		fsCaseRunnerRegister(),
		fsCaseRunnerDrain(),
		fsCaseRunnerDisable(),
		fsCaseRunnerEnable(),
		fsCaseMaintainLeaseRecovery(),
		fsCaseScheduleFire(),
		fsCaseSnapshotUpload(),
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// One fresh server per case: the case consumes its fixture when
			// healing, and a shared server would couple the matrix entries.
			// TestFSFailureMatrixNoDegradedLeakAcrossMutations covers the
			// shared-server sequence.
			dir := t.TempDir()
			s, err := NewPersistent("token", "token", dir)
			if err != nil {
				t.Fatal(err)
			}
			drive := tc.drive(t, s)
			pre := captureStateForTest(t, s)
			s.persistFailForTest = errFSMatrixSeam
			drive.invoke(t, s)
			fsMatrixAssertDegraded(t, s)
			post := captureStateForTest(t, s)
			if drive.rolledBack {
				fsMatrixAssertNoDrift(t, pre, post)
			} else if drive.drift != nil {
				drive.drift(t, s, pre)
			}
			s.persistFailForTest = nil
			drive.heal(t, s)
			fsMatrixAssertReady(t, s)
			if drive.durable != nil {
				drive.durable(t, dir, s)
			}
		})
	}
}

// fsCaseRunEnqueueAPI drives POST /api/v1/runs.
func fsCaseRunEnqueueAPI() fsMutationCase {
	return fsMutationCase{
		name: "run.enqueue_api",
		drive: func(t *testing.T, s *Server) *fsMutationDrive {
			var runID string
			submit := `{"repo_url":"https://example.com/o/r.git","repo_full_name":"o/r","ref":"refs/heads/main","sha":"abc","event":"push","pipeline":` + jsonString(smokePipeline) + `}`
			return &fsMutationDrive{
				invoke: func(t *testing.T, s *Server) {
					w := doJSON(t, s, http.MethodPost, "/api/v1/runs", "token", submit)
					// W3A fix: a persistence failure is mapped to 503 (the
					// enqueue itself still failed closed: rollbackStateLocked
					// restored the maps and no run body is returned).
					fsMatrixAssertStatus(t, w, http.StatusServiceUnavailable)
					if strings.Contains(w.Body.String(), `"id"`) {
						t.Fatalf("refused enqueue leaked a run body: %q", w.Body.String())
					}
				},
				rolledBack: true,
				heal: func(t *testing.T, s *Server) {
					w := doJSON(t, s, http.MethodPost, "/api/v1/runs", "token", submit)
					fsMatrixAssertStatus(t, w, http.StatusAccepted)
					var run model.Run
					if err := json.Unmarshal(w.Body.Bytes(), &run); err != nil {
						t.Fatal(err)
					}
					runID = run.ID
				},
				durable: func(t *testing.T, dir string, s *Server) {
					s2 := fsMatrixReload(t, dir)
					s2.mu.Lock()
					_, ok := s2.runs[runID]
					s2.mu.Unlock()
					if !ok {
						t.Fatalf("enqueue not durable: run %s missing from the reloaded snapshot", runID)
					}
				},
			}
		},
	}
}

// fsCaseRunEnqueueWebhook drives POST /hooks/github.
func fsCaseRunEnqueueWebhook() fsMutationCase {
	return fsMutationCase{
		name: "run.enqueue_webhook",
		drive: func(t *testing.T, s *Server) *fsMutationDrive {
			s.GitHubWebhookSecret = "hunter2"
			s.gitHubAPIBase = fsMatrixGitHubAPI(t).URL
			s.PipelinePath = ".kiwi/pipeline.yaml"
			body := pushPayload("9049f1265b7d61be4a8904a9a27120d2064dab3b")
			const delivery = "fs-matrix-webhook-delivery"
			var runID string
			return &fsMutationDrive{
				invoke: func(t *testing.T, s *Server) {
					w := postWebhook(t, s, "hunter2", "push", delivery, body)
					// W3A fix: githubWebhook maps a durability failure to 503
					// (same fail-closed enqueue rollback as run.enqueue_api).
					fsMatrixAssertStatus(t, w, http.StatusServiceUnavailable)
					if strings.Contains(w.Body.String(), `"id"`) {
						t.Fatalf("refused webhook leaked a run body: %q", w.Body.String())
					}
				},
				rolledBack: true,
				heal: func(t *testing.T, s *Server) {
					w := postWebhook(t, s, "hunter2", "push", delivery, body)
					fsMatrixAssertStatus(t, w, http.StatusAccepted)
					runID, _ = decodeRun(t, w)
					if runID == "" {
						t.Fatal("healed webhook returned no run id")
					}
				},
				durable: func(t *testing.T, dir string, s *Server) {
					s2 := fsMatrixReload(t, dir)
					s2.mu.Lock()
					_, ok := s2.runs[runID]
					s2.mu.Unlock()
					if !ok {
						t.Fatalf("webhook enqueue not durable: run %s missing from the reloaded snapshot", runID)
					}
				},
			}
		},
	}
}

// fsCaseJobLease drives POST /api/v1/runners/{id}/next. The claim's snapshot
// write fails after the in-memory claim was installed: the handler rolls the
// claim back wholesale (job stays queued, attempt unconsumed, runner slot
// free), withholds the token and answers 503. Healing lets the SAME job lease
// exactly once and the durable snapshot then contains that one claim.
func fsCaseJobLease() fsMutationCase {
	return fsMutationCase{
		name: "job.lease",
		drive: func(t *testing.T, s *Server) *fsMutationDrive {
			run, err := s.enqueue(context.Background(), SubmitRun{
				RepoURL: "https://example.com/o/r.git", RepoFullName: "o/r",
				Ref: "refs/heads/main", Event: "push", Pipeline: smokePipeline,
			})
			if err != nil {
				t.Fatal(err)
			}
			job := queuedJobForRun(t, s, run)
			runnerID := registerRollbackRunner(t, s, 1)
			s.mu.Lock()
			preActive := len(s.runners[runnerID].ActiveJobs)
			s.mu.Unlock()
			return &fsMutationDrive{
				invoke: func(t *testing.T, s *Server) {
					w := doJSON(t, s, http.MethodPost, "/api/v1/runners/"+runnerID+"/next", "token", "")
					fsMatrixAssertStatus(t, w, http.StatusServiceUnavailable)
					fsMatrixAssertBody(t, w, statePersistenceDegradedBody+"\n")
					if got := w.Header().Get("X-Kiwi-State"); got != "degraded" {
						t.Fatalf("refused lease X-Kiwi-State = %q, want degraded", got)
					}
					fsMatrixAssertNoLeaseLeak(t, w)
					s.mu.Lock()
					got := s.jobs[job.ID]
					active := len(s.runners[runnerID].ActiveJobs)
					s.mu.Unlock()
					if got.Status != model.StatusQueued || got.Attempts != job.Attempts || got.LeaseTokenHash != nil || got.LeaseRunnerID != "" {
						t.Fatalf("failed-persist claim not rolled back: %+v", got)
					}
					if active != preActive {
						t.Fatalf("failed-persist claim changed the runner slots: %d -> %d", preActive, active)
					}
				},
				rolledBack: true,
				heal: func(t *testing.T, s *Server) {
					// The job is still queued, so healing the store lets the
					// same job lease normally; the failed write armed the
					// degraded gate, so a succeeding persist (a healing
					// registration) must clear it before /next is accepted.
					if w := doJSON(t, s, http.MethodPost, "/api/v1/runners/register", "token",
						`{"name":"lease-heal","protocol_min":3,"protocol_max":3,"labels":["container"],"capacity":1}`); w.Code != http.StatusOK {
						t.Fatalf("healing register: %d %s", w.Code, w.Body.String())
					}
					w := doJSON(t, s, http.MethodPost, "/api/v1/runners/"+runnerID+"/next", "token", "")
					fsMatrixAssertStatus(t, w, http.StatusOK)
					var task Task
					if err := json.Unmarshal(w.Body.Bytes(), &task); err != nil {
						t.Fatal(err)
					}
					if task.LeaseToken == "" || task.Job.ID != job.ID {
						t.Fatalf("healed lease = %+v, want a token for %s", task, job.ID)
					}
					if task.Job.Attempts != job.Attempts+1 {
						t.Fatalf("healed lease attempts = %d, want exactly %d (the failed claim must not consume one)", task.Job.Attempts, job.Attempts+1)
					}
				},
				durable: func(t *testing.T, dir string, s *Server) {
					s2 := fsMatrixReload(t, dir)
					s2.mu.Lock()
					got := s2.jobs[job.ID]
					s2.mu.Unlock()
					if got.Status != model.StatusRunning || got.LeaseRunnerID != runnerID || len(got.LeaseTokenHash) == 0 {
						t.Fatalf("healed lease not durable: %+v", got)
					}
					if got.Attempts != job.Attempts+1 {
						t.Fatalf("durable lease attempts = %d, want exactly %d", got.Attempts, job.Attempts+1)
					}
				},
			}
		},
	}
}

// fsCaseJobHeartbeat drives POST /api/v1/jobs/{id}/heartbeat.
func fsCaseJobHeartbeat() fsMutationCase {
	return fsMutationCase{
		name: "job.heartbeat",
		drive: func(t *testing.T, s *Server) *fsMutationDrive {
			if _, err := s.enqueue(context.Background(), SubmitRun{
				RepoURL: "https://example.com/o/r.git", RepoFullName: "o/r",
				Ref: "refs/heads/main", Event: "push", Pipeline: smokePipeline,
			}); err != nil {
				t.Fatal(err)
			}
			runnerID, task := leaseRunJob(t, s)
			return &fsMutationDrive{
				invoke: func(t *testing.T, s *Server) {
					w := doJSON(t, s, http.MethodPost, "/api/v1/jobs/"+task.Job.ID+"/heartbeat", "token",
						string(leaseBodyFor(t, runnerID, task.LeaseToken, task.LeaseGeneration, nil)))
					fsMatrixAssertStatus(t, w, http.StatusServiceUnavailable)
					fsMatrixAssertBody(t, w, "heartbeat not durable\n")
				},
				rolledBack: true,
				heal: func(t *testing.T, s *Server) {
					w := doJSON(t, s, http.MethodPost, "/api/v1/jobs/"+task.Job.ID+"/heartbeat", "token",
						string(leaseBodyFor(t, runnerID, task.LeaseToken, task.LeaseGeneration, nil)))
					fsMatrixAssertStatus(t, w, http.StatusOK)
					var hb HeartbeatResponse
					if err := json.Unmarshal(w.Body.Bytes(), &hb); err != nil {
						t.Fatal(err)
					}
					if hb.LeaseExpiresAt.IsZero() {
						t.Fatalf("healed heartbeat = %+v, want an extended deadline", hb)
					}
					snap, err := s.store.Load()
					if err != nil {
						t.Fatal(err)
					}
					disk := snap.Jobs[task.Job.ID].LeaseExpiresAt
					if disk == nil || !disk.Equal(hb.LeaseExpiresAt) {
						t.Fatalf("durable lease expiry %v != acknowledged %v", disk, hb.LeaseExpiresAt)
					}
				},
			}
		},
	}
}

// fsCaseJobApprove drives POST /api/v1/jobs/{id}/approve.
func fsCaseJobApprove() fsMutationCase {
	return fsMutationCase{
		name: "job.approve",
		drive: func(t *testing.T, s *Server) *fsMutationDrive {
			if _, err := s.enqueue(context.Background(), SubmitRun{
				RepoURL: "https://example.com/o/r.git", RepoFullName: "o/r",
				Ref: "refs/heads/main", Event: "push", Pipeline: approvalPipeline,
			}); err != nil {
				t.Fatal(err)
			}
			var jobID string
			s.mu.Lock()
			for id, j := range s.jobs {
				if j.ApprovalRequired {
					jobID = id
				}
			}
			s.mu.Unlock()
			if jobID == "" {
				t.Fatal("approval fixture job not found")
			}
			return &fsMutationDrive{
				invoke: func(t *testing.T, s *Server) {
					w := doJSON(t, s, http.MethodPost, "/api/v1/jobs/"+jobID+"/approve", "token", "")
					fsMatrixAssertStatus(t, w, http.StatusServiceUnavailable)
					fsMatrixAssertBody(t, w, "approval not durable\n")
				},
				rolledBack: true,
				heal: func(t *testing.T, s *Server) {
					w := doJSON(t, s, http.MethodPost, "/api/v1/jobs/"+jobID+"/approve", "token", "")
					fsMatrixAssertStatus(t, w, http.StatusOK)
				},
				durable: func(t *testing.T, dir string, s *Server) {
					s2 := fsMatrixReload(t, dir)
					s2.mu.Lock()
					got := s2.jobs[jobID]
					s2.mu.Unlock()
					if got.Status != model.StatusQueued || got.ApprovedBy == "" || got.WaitingSince != nil {
						t.Fatalf("approval not durable across reload: %+v", got)
					}
				},
			}
		},
	}
}

// fsCaseJobCancel drives POST /api/v1/runs/{id}/cancel.
func fsCaseJobCancel() fsMutationCase {
	return fsMutationCase{
		name: "job.cancel",
		drive: func(t *testing.T, s *Server) *fsMutationDrive {
			run, err := s.enqueue(context.Background(), SubmitRun{
				RepoURL: "https://example.com/o/r.git", RepoFullName: "o/r",
				Ref: "refs/heads/main", Event: "push", Pipeline: smokePipeline,
			})
			if err != nil {
				t.Fatal(err)
			}
			leaseRunJob(t, s)
			return &fsMutationDrive{
				invoke: func(t *testing.T, s *Server) {
					w := doJSON(t, s, http.MethodPost, "/api/v1/runs/"+run.ID+"/cancel", "token", "")
					fsMatrixAssertStatus(t, w, http.StatusServiceUnavailable)
					fsMatrixAssertBody(t, w, "cancel state not durable\n")
				},
				rolledBack: true,
				heal: func(t *testing.T, s *Server) {
					w := doJSON(t, s, http.MethodPost, "/api/v1/runs/"+run.ID+"/cancel", "token", "")
					fsMatrixAssertStatus(t, w, http.StatusOK)
				},
				durable: func(t *testing.T, dir string, s *Server) {
					s2 := fsMatrixReload(t, dir)
					s2.mu.Lock()
					got := s2.runs[run.ID]
					s2.mu.Unlock()
					if got.Status != model.StatusCancelled || got.FinishedAt == nil {
						t.Fatalf("cancel not durable across reload: %+v", got)
					}
				},
			}
		},
	}
}

// fsCaseJobComplete drives the primary POST /api/v1/jobs/{id}/complete path.
func fsCaseJobComplete() fsMutationCase {
	return fsMutationCase{
		name: "job.complete",
		drive: func(t *testing.T, s *Server) *fsMutationDrive {
			if _, err := s.enqueue(context.Background(), SubmitRun{
				RepoURL: "https://example.com/o/r.git", RepoFullName: "o/r",
				Ref: "refs/heads/main", Event: "push", Pipeline: smokePipeline,
			}); err != nil {
				t.Fatal(err)
			}
			runnerID, task := registerUsageRunner(t, s)
			return &fsMutationDrive{
				invoke: func(t *testing.T, s *Server) {
					w := completeTask(t, s, task, runnerID, "success")
					fsMatrixAssertStatus(t, w, http.StatusServiceUnavailable)
					// Hardened 5xx body: the persist error used to be appended
					// to the fixed prefix, leaking fs paths to the runner. The
					// detail now stays in the server log (see serverError) and
					// the caller gets exactly the fixed message.
					if w.Body.String() != "completion state not durable\n" {
						t.Fatalf("refused completion body = %q", w.Body.String())
					}
					// The completion rollback captures maps the generic
					// stateRollback does not (receipts); assert them here.
					s.mu.Lock()
					receipts := len(s.completions)
					job := s.jobs[task.Job.ID]
					s.mu.Unlock()
					if receipts != 0 {
						t.Fatalf("failed completion left %d receipt(s)", receipts)
					}
					if job.Status != model.StatusRunning || job.UsageRecorded {
						t.Fatalf("failed completion left job state behind: %+v", job)
					}
					if cost, energy := usageMetricsSnapshot(s); cost != 0 || energy != 0 {
						t.Fatalf("failed completion moved usage metrics: cost=%v energy=%v", cost, energy)
					}
				},
				rolledBack: true,
				heal: func(t *testing.T, s *Server) {
					w := completeTask(t, s, task, runnerID, "success")
					fsMatrixAssertStatus(t, w, http.StatusNoContent)
				},
				durable: func(t *testing.T, dir string, s *Server) {
					s2 := fsMatrixReload(t, dir)
					s2.mu.Lock()
					job := s2.jobs[task.Job.ID]
					receipts := len(s2.completions)
					s2.mu.Unlock()
					if job.Status != model.StatusSuccess || !job.UsageRecorded {
						t.Fatalf("completion not durable across reload: %+v", job)
					}
					if receipts != 1 {
						t.Fatalf("durable completion receipts = %d, want 1", receipts)
					}
				},
			}
		},
	}
}

// fsCaseJobCompleteReplay drives the idempotent completion replay path
// (server.go:2969-2981 / completionReplayReadyLocked), which re-persists the
// receipt before running effects.
func fsCaseJobCompleteReplay() fsMutationCase {
	return fsMutationCase{
		name: "job.complete_replay",
		drive: func(t *testing.T, s *Server) *fsMutationDrive {
			if _, err := s.enqueue(context.Background(), SubmitRun{
				RepoURL: "https://example.com/o/r.git", RepoFullName: "o/r",
				Ref: "refs/heads/main", Event: "push", Pipeline: smokePipeline,
			}); err != nil {
				t.Fatal(err)
			}
			runnerID, task := registerUsageRunner(t, s)
			if w := completeTask(t, s, task, runnerID, "success"); w.Code != http.StatusNoContent {
				t.Fatalf("fixture completion = %d: %s", w.Code, w.Body.String())
			}
			return &fsMutationDrive{
				invoke: func(t *testing.T, s *Server) {
					w := completeTask(t, s, task, runnerID, "success")
					fsMatrixAssertStatus(t, w, http.StatusServiceUnavailable)
					// Hardened 5xx body: see fsCaseJobComplete — fixed opaque
					// message, detail only in the server log.
					if w.Body.String() != "completion state not durable\n" {
						t.Fatalf("refused replay body = %q", w.Body.String())
					}
				},
				rolledBack: true,
				heal: func(t *testing.T, s *Server) {
					w := completeTask(t, s, task, runnerID, "success")
					fsMatrixAssertStatus(t, w, http.StatusNoContent)
				},
				durable: func(t *testing.T, dir string, s *Server) {
					s2 := fsMatrixReload(t, dir)
					s2.mu.Lock()
					receipts := len(s2.completions)
					s2.mu.Unlock()
					if receipts != 1 {
						t.Fatalf("durable completion receipts after replay = %d, want 1", receipts)
					}
				},
			}
		},
	}
}

// fsCaseRunnerRegister drives POST /api/v1/runners/register. Registration is
// the one DOCUMENTED deliberate deviation (server.go:1985-1988): the
// in-memory registration is kept and 200 is answered, with /readiness 503 +
// degraded as the compensating control until the store heals and the runner
// re-registers.
func fsCaseRunnerRegister() fsMutationCase {
	return fsMutationCase{
		name: "runner.register",
		drive: func(t *testing.T, s *Server) *fsMutationDrive {
			const body = `{"name":"fs-matrix-register","protocol_min":3,"protocol_max":3,"labels":["container"],"capacity":1}`
			var runnerID string
			return &fsMutationDrive{
				invoke: func(t *testing.T, s *Server) {
					w := doJSON(t, s, http.MethodPost, "/api/v1/runners/register", "token", body)
					fsMatrixAssertStatus(t, w, http.StatusOK)
					var ri model.Runner
					if err := json.Unmarshal(w.Body.Bytes(), &ri); err != nil {
						t.Fatal(err)
					}
					runnerID = ri.ID
					if runnerID == "" {
						t.Fatal("degraded registration returned no runner id")
					}
					s.mu.Lock()
					_, inMemory := s.runners[runnerID]
					s.mu.Unlock()
					if !inMemory {
						t.Fatal("documented in-memory registration missing after a failed persist")
					}
				},
				rolledBack: false,
				drift: func(t *testing.T, s *Server, pre stateRollback) {
					s.mu.Lock()
					_, inMemory := s.runners[runnerID]
					s.mu.Unlock()
					if !inMemory {
						t.Fatal("documented compensating-control registration missing")
					}
				},
				heal: func(t *testing.T, s *Server) {
					w := doJSON(t, s, http.MethodPost, "/api/v1/runners/register", "token",
						fmt.Sprintf(`{"id":%q,"name":"fs-matrix-register","protocol_min":3,"protocol_max":3,"labels":["container"],"capacity":1}`, runnerID))
					fsMatrixAssertStatus(t, w, http.StatusOK)
				},
				durable: func(t *testing.T, dir string, s *Server) {
					s2 := fsMatrixReload(t, dir)
					s2.mu.Lock()
					_, ok := s2.runners[runnerID]
					s2.mu.Unlock()
					if !ok {
						t.Fatalf("re-registration not durable: runner %s missing from the reloaded snapshot", runnerID)
					}
				},
			}
		},
	}
}

// fsCaseRunnerDrain drives POST /api/v1/runners/{id}/drain.
func fsCaseRunnerDrain() fsMutationCase {
	return fsMutationCase{
		name: "runner.drain",
		drive: func(t *testing.T, s *Server) *fsMutationDrive {
			runnerID := registerRollbackRunner(t, s, 1)
			return &fsMutationDrive{
				invoke: func(t *testing.T, s *Server) {
					w := doJSON(t, s, http.MethodPost, "/api/v1/runners/"+runnerID+"/drain", "token", "")
					fsMatrixAssertStatus(t, w, http.StatusServiceUnavailable)
					fsMatrixAssertBody(t, w, "runner drain not durable\n")
				},
				rolledBack: true,
				heal: func(t *testing.T, s *Server) {
					w := doJSON(t, s, http.MethodPost, "/api/v1/runners/"+runnerID+"/drain", "token", "")
					fsMatrixAssertStatus(t, w, http.StatusOK)
				},
				durable: func(t *testing.T, dir string, s *Server) {
					s2 := fsMatrixReload(t, dir)
					s2.mu.Lock()
					got := s2.runners[runnerID]
					s2.mu.Unlock()
					if !got.Draining {
						t.Fatalf("drain not durable across reload: %+v", got)
					}
				},
			}
		},
	}
}

// fsCaseRunnerDisable drives POST /api/v1/runners/{id}/disable with an active
// lease, so the whole kill-switch rollback is exercised.
func fsCaseRunnerDisable() fsMutationCase {
	return fsMutationCase{
		name: "runner.disable",
		drive: func(t *testing.T, s *Server) *fsMutationDrive {
			if _, err := s.enqueue(context.Background(), SubmitRun{
				RepoURL: "https://example.com/o/r.git", RepoFullName: "o/r",
				Ref: "refs/heads/main", Event: "push", Pipeline: smokePipeline,
			}); err != nil {
				t.Fatal(err)
			}
			runnerID := registerRollbackRunner(t, s, 1)
			task := leaseNextRollbackTask(t, s, runnerID)
			return &fsMutationDrive{
				invoke: func(t *testing.T, s *Server) {
					w := doJSON(t, s, http.MethodPost, "/api/v1/runners/"+runnerID+"/disable", "token", "")
					fsMatrixAssertStatus(t, w, http.StatusServiceUnavailable)
					fsMatrixAssertBody(t, w, "runner disable not durable\n")
				},
				rolledBack: true,
				heal: func(t *testing.T, s *Server) {
					w := doJSON(t, s, http.MethodPost, "/api/v1/runners/"+runnerID+"/disable", "token", "")
					fsMatrixAssertStatus(t, w, http.StatusOK)
				},
				durable: func(t *testing.T, dir string, s *Server) {
					s2 := fsMatrixReload(t, dir)
					s2.mu.Lock()
					runner := s2.runners[runnerID]
					job := s2.jobs[task.Job.ID]
					s2.mu.Unlock()
					if !runner.Disabled || job.Status != model.StatusCancelled || job.LeaseTokenHash != nil {
						t.Fatalf("disable not durable across reload: runner=%+v job=%+v", runner, job)
					}
				},
			}
		},
	}
}

// fsCaseRunnerEnable drives POST /api/v1/runners/{id}/enable from the
// disabled state.
func fsCaseRunnerEnable() fsMutationCase {
	return fsMutationCase{
		name: "runner.enable",
		drive: func(t *testing.T, s *Server) *fsMutationDrive {
			runnerID := registerRollbackRunner(t, s, 1)
			if w := doJSON(t, s, http.MethodPost, "/api/v1/runners/"+runnerID+"/disable", "token", ""); w.Code != http.StatusOK {
				t.Fatalf("disable fixture = %d: %s", w.Code, w.Body.String())
			}
			return &fsMutationDrive{
				invoke: func(t *testing.T, s *Server) {
					w := doJSON(t, s, http.MethodPost, "/api/v1/runners/"+runnerID+"/enable", "token", "")
					fsMatrixAssertStatus(t, w, http.StatusServiceUnavailable)
					fsMatrixAssertBody(t, w, "runner enable not durable\n")
				},
				rolledBack: true,
				heal: func(t *testing.T, s *Server) {
					w := doJSON(t, s, http.MethodPost, "/api/v1/runners/"+runnerID+"/enable", "token", "")
					fsMatrixAssertStatus(t, w, http.StatusOK)
				},
				durable: func(t *testing.T, dir string, s *Server) {
					s2 := fsMatrixReload(t, dir)
					s2.mu.Lock()
					got := s2.runners[runnerID]
					s2.mu.Unlock()
					if got.Disabled || got.Draining {
						t.Fatalf("enable not durable across reload: %+v", got)
					}
				},
			}
		},
	}
}

// fsCaseMaintainLeaseRecovery drives one maintainMemoryTick with an expired
// lease. There is no HTTP status; the rollback plus the degraded flag are the
// fail-closed signal (server.go:5017-5057).
func fsCaseMaintainLeaseRecovery() fsMutationCase {
	return fsMutationCase{
		name: "maintain.lease_recovery",
		drive: func(t *testing.T, s *Server) *fsMutationDrive {
			if _, err := s.enqueue(context.Background(), SubmitRun{
				RepoURL: "https://example.com/o/r.git", RepoFullName: "o/r",
				Ref: "refs/heads/main", Event: "push", Pipeline: smokePipeline,
			}); err != nil {
				t.Fatal(err)
			}
			runnerID := registerRollbackRunner(t, s, 1)
			task := leaseNextRollbackTask(t, s, runnerID)
			now := time.Now().UTC()
			past := now.Add(-time.Minute)
			s.mu.Lock()
			expired := s.jobs[task.Job.ID]
			expired.LeaseExpiresAt = &past
			s.jobs[task.Job.ID] = expired
			err := s.persistLocked()
			s.mu.Unlock()
			if err != nil {
				t.Fatal(err)
			}
			return &fsMutationDrive{
				invoke: func(t *testing.T, s *Server) {
					s.maintainMemoryTick(context.Background(), now)
					if !s.stateDegraded.Load() {
						t.Fatal("failed recovery persist did not arm the degraded state")
					}
					s.mu.Lock()
					job := s.jobs[task.Job.ID]
					active := len(s.runners[runnerID].ActiveJobs)
					s.mu.Unlock()
					if job.Status != model.StatusRunning || job.LeaseTokenHash == nil || active != 1 {
						t.Fatalf("failed recovery was not rolled back: job=%+v active=%d", job, active)
					}
				},
				rolledBack: true,
				heal: func(t *testing.T, s *Server) {
					s.maintainMemoryTick(context.Background(), now)
					s.mu.Lock()
					job := s.jobs[task.Job.ID]
					active := len(s.runners[runnerID].ActiveJobs)
					s.mu.Unlock()
					if job.Status != model.StatusQueued || job.LeaseTokenHash != nil || job.LeaseRunnerID != "" {
						t.Fatalf("healed recovery did not requeue the job: %+v", job)
					}
					if active != 0 {
						t.Fatalf("healed recovery left %d active job(s) on the runner", active)
					}
				},
				durable: func(t *testing.T, dir string, s *Server) {
					snap, err := s.store.Load()
					if err != nil {
						t.Fatal(err)
					}
					if got := snap.Jobs[task.Job.ID]; got.Status != model.StatusQueued {
						t.Fatalf("recovery not durable: job = %+v, want queued", got)
					}
				},
			}
		},
	}
}

// fsCaseScheduleFire drives POST /api/v1/schedules/{id}/trigger, whose
// occurrence claim rides the enqueue snapshot write (fireSchedule ->
// enqueueID -> persistCheckedErrLocked) and therefore rolls back with it. The
// non-durable enqueue goes through the shared enqueue-error mapping: 503 with
// the fixed opaque body, never a raw store error and never a run body.
func fsCaseScheduleFire() fsMutationCase {
	return fsMutationCase{
		name: "schedule.fire",
		drive: func(t *testing.T, s *Server) *fsMutationDrive {
			w := doJSON(t, s, http.MethodPut, "/api/v1/schedules", "token",
				`{"repository":"https://example.com/o/r.git","spec":`+jsonString(scheduleSpec)+`}`)
			if w.Code != http.StatusOK {
				t.Fatalf("schedule fixture = %d: %s", w.Code, w.Body.String())
			}
			var sc storage.Schedule
			if err := json.Unmarshal(w.Body.Bytes(), &sc); err != nil {
				t.Fatal(err)
			}
			var runID string
			return &fsMutationDrive{
				invoke: func(t *testing.T, s *Server) {
					w := doJSON(t, s, http.MethodPost, "/api/v1/schedules/"+sc.ID+"/trigger", "token", "")
					fsMatrixAssertStatus(t, w, http.StatusServiceUnavailable)
					if got := w.Body.String(); got != "state not durable\n" {
						t.Fatalf("refused trigger body = %q, want the fixed %q", got, "state not durable\n")
					}
					if strings.Contains(w.Body.String(), errFSMatrixSeam.Error()) {
						t.Fatalf("refused trigger leaked the persist error: %q", w.Body.String())
					}
					if strings.Contains(w.Body.String(), `"id"`) {
						t.Fatalf("refused trigger leaked a run body: %q", w.Body.String())
					}
					s.mu.Lock()
					runs, occ := len(s.runs), len(s.occurrences[sc.ID])
					lastRun := s.schedules[sc.ID].LastRun
					s.mu.Unlock()
					if runs != 0 || occ != 0 {
						t.Fatalf("failed trigger left %d run(s) and %d occurrence claim(s)", runs, occ)
					}
					if lastRun != nil {
						t.Fatalf("failed trigger advanced last_run to %v", lastRun)
					}
				},
				rolledBack: true,
				heal: func(t *testing.T, s *Server) {
					w := doJSON(t, s, http.MethodPost, "/api/v1/schedules/"+sc.ID+"/trigger", "token", "")
					fsMatrixAssertStatus(t, w, http.StatusAccepted)
					var run model.Run
					if err := json.Unmarshal(w.Body.Bytes(), &run); err != nil {
						t.Fatal(err)
					}
					runID = run.ID
				},
				durable: func(t *testing.T, dir string, s *Server) {
					s2 := fsMatrixReload(t, dir)
					s2.mu.Lock()
					_, runOK := s2.runs[runID]
					claims := len(s2.occurrences[sc.ID])
					lastRun := s2.schedules[sc.ID].LastRun
					s2.mu.Unlock()
					if !runOK || claims == 0 || lastRun == nil {
						t.Fatalf("schedule fire not durable: run=%v claims=%d last_run=%v", runOK, claims, lastRun)
					}
				},
			}
		},
	}
}

// fsCaseSnapshotUpload drives POST /api/v1/jobs/{id}/snapshots, which commits
// the record into the snapshot only after the archive pair is durable
// (snapshots.go:134-151).
func fsCaseSnapshotUpload() fsMutationCase {
	return fsMutationCase{
		name: "snapshot.upload",
		drive: func(t *testing.T, s *Server) *fsMutationDrive {
			if _, err := s.enqueue(context.Background(), SubmitRun{
				RepoURL: "https://example.com/o/r.git", RepoFullName: "o/r",
				Ref: "refs/heads/main", Event: "push", Pipeline: smokePipeline,
			}); err != nil {
				t.Fatal(err)
			}
			runnerID, task := leaseRunJob(t, s)
			ws := t.TempDir()
			if err := os.WriteFile(filepath.Join(ws, "out.txt"), []byte("fs failure matrix snapshot"), 0o644); err != nil {
				t.Fatal(err)
			}
			var buf bytes.Buffer
			if _, err := snapshot.Create(ws, &buf); err != nil {
				t.Fatal(err)
			}
			hdrs := leaseHeaders(task, runnerID)
			hdrs["Content-Type"] = "application/gzip"
			path := "/api/v1/jobs/" + task.Job.ID + "/snapshots"
			var recID string
			return &fsMutationDrive{
				invoke: func(t *testing.T, s *Server) {
					w := doJSONHeaders(t, s, http.MethodPost, path, "token", buf.String(), hdrs)
					fsMatrixAssertStatus(t, w, http.StatusServiceUnavailable)
					fsMatrixAssertBody(t, w, "snapshot record persistence failed\n")
					s.mu.Lock()
					records := len(s.snapshots)
					s.mu.Unlock()
					if records != 0 {
						t.Fatalf("failed snapshot upload left %d in-memory record(s)", records)
					}
				},
				rolledBack: true,
				heal: func(t *testing.T, s *Server) {
					w := doJSONHeaders(t, s, http.MethodPost, path, "token", buf.String(), hdrs)
					fsMatrixAssertStatus(t, w, http.StatusCreated)
					var rec struct {
						ID string `json:"id"`
					}
					if err := json.Unmarshal(w.Body.Bytes(), &rec); err != nil {
						t.Fatal(err)
					}
					recID = rec.ID
					if recID == "" {
						t.Fatal("healed snapshot upload returned no record id")
					}
				},
				durable: func(t *testing.T, dir string, s *Server) {
					s2 := fsMatrixReload(t, dir)
					s2.mu.Lock()
					_, ok := s2.snapshots[recID]
					s2.mu.Unlock()
					if !ok {
						t.Fatalf("snapshot record %s not durable across reload", recID)
					}
				},
			}
		},
	}
}

// TestFSFailureMatrixNoDegradedLeakAcrossMutations reuses one server across
// mutations: a failed drain degrades readiness, the healed drain clears it,
// and an unrelated mutation then succeeds and stays durable. The degraded
// signal must not leak past the next successful persist or block other
// handlers.
func TestFSFailureMatrixNoDegradedLeakAcrossMutations(t *testing.T) {
	dir := t.TempDir()
	s, err := NewPersistent("token", "token", dir)
	if err != nil {
		t.Fatal(err)
	}
	run, err := s.enqueue(context.Background(), SubmitRun{
		RepoURL: "https://example.com/o/r.git", RepoFullName: "o/r",
		Ref: "refs/heads/main", Event: "push", Pipeline: smokePipeline,
	})
	if err != nil {
		t.Fatal(err)
	}
	runnerID := registerRollbackRunner(t, s, 1)

	// (a) a failed drain degrades readiness.
	s.persistFailForTest = errFSMatrixSeam
	if w := doJSON(t, s, http.MethodPost, "/api/v1/runners/"+runnerID+"/drain", "token", ""); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("drain with a broken snapshot = %d: %s", w.Code, w.Body.String())
	}
	fsMatrixAssertDegraded(t, s)

	// (b) healing the seam and re-running the SAME mutation clears degraded.
	s.persistFailForTest = nil
	if w := doJSON(t, s, http.MethodPost, "/api/v1/runners/"+runnerID+"/drain", "token", ""); w.Code != http.StatusOK {
		t.Fatalf("healed drain = %d: %s", w.Code, w.Body.String())
	}
	fsMatrixAssertReady(t, s)

	// (c) a different mutation then succeeds on the same server and its
	// change survives a reload.
	if w := doJSON(t, s, http.MethodPost, "/api/v1/runs/"+run.ID+"/cancel", "token", ""); w.Code != http.StatusOK {
		t.Fatalf("cancel after heal = %d: %s", w.Code, w.Body.String())
	}
	fsMatrixAssertReady(t, s)
	s2 := fsMatrixReload(t, dir)
	s2.mu.Lock()
	got := s2.runs[run.ID]
	s2.mu.Unlock()
	if got.Status != model.StatusCancelled {
		t.Fatalf("post-heal cancel not durable: %+v", got)
	}
}

// ---------------------------------------------------------------------------
// Documented findings: handlers that acknowledge a failed persist or leave
// in-memory ghosts. These tests assert the fail-closed contract and therefore
// FAIL against the current code; they are the deliverable evidence for the
// findings in the report. They hold no t.Skip: once the handlers fail closed
// they pass.
// ---------------------------------------------------------------------------

// TestFSFindingsArtifactUploadAcknowledgesOnPersistFailure is finding 1:
// blobs.go:371 ignores persistCheckedLocked("artifact.upload") and answers
// 201 with the record, which lives only in memory until an unrelated
// successful persist. The retry after heal replays from the ghost record and
// no write ever happens, so a restart loses an acknowledged artifact.
func TestFSFindingsArtifactUploadAcknowledgesOnPersistFailure(t *testing.T) {
	dir := t.TempDir()
	s, err := NewPersistent("token", "token", dir)
	if err != nil {
		t.Fatal(err)
	}
	runnerID, task := leaseArtifactJob(t, s, artifactsPipeline)
	hdrs := leaseHeaders(task, runnerID)
	path := "/api/v1/jobs/" + task.Job.ID + "/artifacts/bin"

	s.persistFailForTest = errFSMatrixSeam
	w := doJSONHeaders(t, s, http.MethodPut, path, "token", "payload-bytes", hdrs)
	if w.Code == http.StatusServiceUnavailable {
		// Contract already holds: assert no drift and a durable heal.
		s.mu.Lock()
		records := len(s.artifacts)
		s.mu.Unlock()
		if records != 0 {
			t.Fatalf("refused upload left %d in-memory artifact record(s)", records)
		}
		s.persistFailForTest = nil
		retry := doJSONHeaders(t, s, http.MethodPut, path, "token", "payload-bytes", hdrs)
		if retry.Code != http.StatusCreated {
			t.Fatalf("healed upload = %d: %s", retry.Code, retry.Body.String())
		}
		var rec model.ArtifactRecord
		if err := json.Unmarshal(retry.Body.Bytes(), &rec); err != nil {
			t.Fatal(err)
		}
		s2 := fsMatrixReload(t, dir)
		s2.mu.Lock()
		_, ok := s2.artifacts[rec.ID]
		s2.mu.Unlock()
		if !ok {
			t.Fatalf("healed artifact upload not durable: %s", rec.ID)
		}
		return
	}

	var rec model.ArtifactRecord
	_ = json.Unmarshal(w.Body.Bytes(), &rec)
	s.mu.Lock()
	_, inMemory := s.artifacts[rec.ID]
	s.mu.Unlock()
	t.Errorf("FINDING artifact.upload (internal/server/blobs.go:371): a snapshot persist failure answered %d (want 503 fail closed) and left in-memory artifact record %q (present=%v); the 201 acknowledges an artifact the snapshot does not contain",
		w.Code, rec.ID, inMemory)

	s.persistFailForTest = nil
	retry := doJSONHeaders(t, s, http.MethodPut, path, "token", "payload-bytes", hdrs)
	s2 := fsMatrixReload(t, dir)
	s2.mu.Lock()
	_, durable := s2.artifacts[rec.ID]
	s2.mu.Unlock()
	t.Errorf("FINDING artifact.upload: retry after heal answered %d (idempotent replay from the ghost record, no persist) and the reloaded snapshot contains the record: %v", retry.Code, durable)
}

// TestFSFindingsArtifactSidecarAcknowledgesOnPersistFailure is finding 2:
// attachSidecarToArtifact silently swallows the failed snapshot write
// (supplychain_gate.go:474) and uploadSBOM answers 201, so the acknowledged
// sidecar digest reference exists only in memory until an unrelated persist.
func TestFSFindingsArtifactSidecarAcknowledgesOnPersistFailure(t *testing.T) {
	const sbomPipeline = `version: 1
jobs:
  build:
    runtime: container
    image: alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    artifacts:
      - name: bin
        sbom: cyclonedx-json
    steps:
      - run: echo hi
`
	dir := t.TempDir()
	s, err := NewPersistent("token", "token", dir)
	if err != nil {
		t.Fatal(err)
	}
	runnerID, task := leaseArtifactJob(t, s, sbomPipeline)
	hdrs := leaseHeaders(task, runnerID)
	sbomPath := "/api/v1/jobs/" + task.Job.ID + "/artifacts/bin.sbom"
	artPath := "/api/v1/jobs/" + task.Job.ID + "/artifacts/bin"
	first := `{"bomFormat":"CycloneDX","specVersion":"1.5","components":[]}`
	if w := doJSONHeaders(t, s, http.MethodPut, sbomPath, "token", first, hdrs); w.Code != http.StatusCreated {
		t.Fatalf("sbom fixture = %d: %s", w.Code, w.Body.String())
	}
	up := doJSONHeaders(t, s, http.MethodPut, artPath, "token", "payload", hdrs)
	if up.Code != http.StatusCreated {
		t.Fatalf("artifact fixture = %d: %s", up.Code, up.Body.String())
	}
	var rec model.ArtifactRecord
	if err := json.Unmarshal(up.Body.Bytes(), &rec); err != nil {
		t.Fatal(err)
	}
	original := rec.SBOMSHA256

	second := `{"bomFormat":"CycloneDX","specVersion":"1.5","components":[{"name":"lib"}]}`
	secondDigest := sha256Hex([]byte(second))
	s.persistFailForTest = errFSMatrixSeam
	w := doJSONHeaders(t, s, http.MethodPut, sbomPath, "token", second, hdrs)
	if w.Code == http.StatusServiceUnavailable {
		s.mu.Lock()
		got := s.artifacts[rec.ID].SBOMSHA256
		s.mu.Unlock()
		if got != original {
			t.Fatalf("refused sidecar mutated the record digest %s -> %s", original, got)
		}
		s.persistFailForTest = nil
		if retry := doJSONHeaders(t, s, http.MethodPut, sbomPath, "token", second, hdrs); retry.Code != http.StatusCreated {
			t.Fatalf("healed sidecar upload = %d: %s", retry.Code, retry.Body.String())
		}
		s2 := fsMatrixReload(t, dir)
		s2.mu.Lock()
		disk := s2.artifacts[rec.ID].SBOMSHA256
		s2.mu.Unlock()
		if disk != secondDigest {
			t.Fatalf("healed sidecar reference not durable: %s", disk)
		}
		return
	}

	s.mu.Lock()
	got := s.artifacts[rec.ID].SBOMSHA256
	s.mu.Unlock()
	t.Errorf("FINDING artifact.sidecar (internal/server/supplychain_gate.go:474): a snapshot persist failure answered %d (want 503) and mutated the in-memory record digest %s -> %s (acknowledged sidecar)", w.Code, original, got)

	s.persistFailForTest = nil
	s2 := fsMatrixReload(t, dir)
	s2.mu.Lock()
	disk := s2.artifacts[rec.ID].SBOMSHA256
	s2.mu.Unlock()
	t.Errorf("FINDING artifact.sidecar: the reloaded record keeps %s, so the acknowledged digest %s was never durable", disk, secondDigest)
}

// TestFSFindingsDeploymentRecordAcknowledgesOnPersistFailure is finding 3,
// in two parts:
//
//	(a) deployments.go:104 ignores persistCheckedLocked("deployment.record")
//	    and answers 201, unlike the DB path which documents fail-closed with
//	    500 (deployments.go:83-88); and
//	(b) the deployment map is NOT part of storage.Snapshot at all, so even a
//	    healthy 201 is lost on restart — contradicting docs/environments.md:67
//	    ("Deployment records persist durably ... through the data-dir state
//	    file in filesystem mode").
func TestFSFindingsDeploymentRecordAcknowledgesOnPersistFailure(t *testing.T) {
	// Part (b): a HEALTHY 201 does not survive a reload.
	dir := t.TempDir()
	s, err := NewPersistent("token", "token", dir)
	if err != nil {
		t.Fatal(err)
	}
	grantDeployments(s)
	run, err := s.enqueue(context.Background(), SubmitRun{
		RepoURL: "https://github.com/kiwi/repo.git", Ref: "main",
		Pipeline: deploymentPipeline, Trusted: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	job := queuedJobForRun(t, s, run)
	if w := doJSON(t, s, http.MethodPost, "/api/v1/jobs/"+job.ID+"/deployments", "token", ""); w.Code != http.StatusCreated {
		t.Fatalf("healthy deployment record = %d: %s", w.Code, w.Body.String())
	}
	s2 := fsMatrixReload(t, dir)
	s2.mu.Lock()
	_, durable := s2.deployments[job.ID]
	s2.mu.Unlock()
	if !durable {
		t.Errorf("FINDING deployment.record: a healthy 201 is not durable in fs mode — storage.Snapshot has no deployments field, so the reloaded server loses the record, contradicting docs/environments.md:67")
	}

	// Part (a): arming the snapshot seam still answers 201 with an
	// in-memory ghost.
	dir2 := t.TempDir()
	s3, err := NewPersistent("token", "token", dir2)
	if err != nil {
		t.Fatal(err)
	}
	grantDeployments(s3)
	run3, err := s3.enqueue(context.Background(), SubmitRun{
		RepoURL: "https://github.com/kiwi/repo.git", Ref: "main",
		Pipeline: deploymentPipeline, Trusted: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	job3 := queuedJobForRun(t, s3, run3)
	s3.persistFailForTest = errFSMatrixSeam
	w := doJSON(t, s3, http.MethodPost, "/api/v1/jobs/"+job3.ID+"/deployments", "token", "")
	if w.Code == http.StatusServiceUnavailable {
		s3.mu.Lock()
		_, ghost := s3.deployments[job3.ID]
		s3.mu.Unlock()
		if ghost {
			t.Fatalf("refused deployment record left an in-memory ghost: %+v", s3.deployments[job3.ID])
		}
		return
	}
	s3.mu.Lock()
	_, ghost := s3.deployments[job3.ID]
	s3.mu.Unlock()
	t.Errorf("FINDING deployment.record (internal/server/deployments.go:104): a snapshot persist failure answered %d (want 503 fail closed) and left an in-memory deployment record: %v; the DB path fails closed for the same write", w.Code, ghost)
}

// TestFSFindingsTestReportLeavesGhostOnPersistFailure is finding 4:
// testintel.go:71-75 answers 500 but never removes s.reports[rep.ID], so a
// refused report is durably committed by the next successful persist and the
// runner's retry duplicates it.
func TestFSFindingsTestReportLeavesGhostOnPersistFailure(t *testing.T) {
	dir := t.TempDir()
	s, err := NewPersistent("token", "token", dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.enqueue(context.Background(), SubmitRun{
		RepoURL: "https://example.com/o/r.git", RepoFullName: "o/r",
		Ref: "refs/heads/main", Event: "push", Pipeline: smokePipeline,
	}); err != nil {
		t.Fatal(err)
	}
	runnerID, task := leaseRunJob(t, s)
	body := uploadReportBody(task, runnerID, []map[string]any{{"name": "alpha", "duration": 1.0, "passed": true}})

	s.persistFailForTest = errFSMatrixSeam
	w := doJSON(t, s, http.MethodPost, "/api/v1/jobs/"+task.Job.ID+"/tests", "token", body)
	s.mu.Lock()
	ghostID := ""
	for id := range s.reports {
		ghostID = id
	}
	ghostCount := len(s.reports)
	s.mu.Unlock()
	if ghostCount == 0 {
		if w.Code < 500 {
			t.Fatalf("test report upload = %d, want 5xx: %s", w.Code, w.Body.String())
		}
		s.persistFailForTest = nil
		if retry := doJSON(t, s, http.MethodPost, "/api/v1/jobs/"+task.Job.ID+"/tests", "token", body); retry.Code != http.StatusCreated {
			t.Fatalf("healed report upload = %d: %s", retry.Code, retry.Body.String())
		}
		s2 := fsMatrixReload(t, dir)
		s2.mu.Lock()
		n := len(s2.reports)
		s2.mu.Unlock()
		if n != 1 {
			t.Fatalf("durable reports after heal = %d, want exactly 1", n)
		}
		return
	}

	t.Errorf("FINDING test report upload (internal/server/testintel.go:71-75): a snapshot persist failure answered %d (no ack) but left %d in-memory report(s) (id %q); any later successful persist commits a report the runner was told failed", w.Code, ghostCount, ghostID)

	s.persistFailForTest = nil
	retry := doJSON(t, s, http.MethodPost, "/api/v1/jobs/"+task.Job.ID+"/tests", "token", body)
	s2 := fsMatrixReload(t, dir)
	s2.mu.Lock()
	n := len(s2.reports)
	_, ghostDurable := s2.reports[ghostID]
	s2.mu.Unlock()
	t.Errorf("FINDING test report upload: retry after heal answered %d and the reloaded snapshot holds %d report(s); the refused ghost %q is durable=%v", retry.Code, n, ghostID, ghostDurable)
}

// TestFSFindingsProfileUpsertLeavesGhostOnPersistFailure is finding 5:
// profiles.go:80-81 inserts into s.profiles before persistLocked and never
// rolls the entry back.
func TestFSFindingsProfileUpsertLeavesGhostOnPersistFailure(t *testing.T) {
	dir := t.TempDir()
	s, err := NewPersistent("token", "token", dir)
	if err != nil {
		t.Fatal(err)
	}
	const profileID = "fs-finding-profile"
	body := fmt.Sprintf(`{"id":%q,"labels":["container"],"max_capacity":1}`, profileID)

	s.persistFailForTest = errFSMatrixSeam
	w := doJSON(t, s, http.MethodPost, "/api/v1/runner-profiles", "token", body)
	s.mu.Lock()
	_, ghost := s.profiles[profileID]
	s.mu.Unlock()
	if !ghost {
		if w.Code < 500 {
			t.Fatalf("profile upsert = %d, want 5xx: %s", w.Code, w.Body.String())
		}
		s.persistFailForTest = nil
		if retry := doJSON(t, s, http.MethodPost, "/api/v1/runner-profiles", "token", body); retry.Code != http.StatusCreated {
			t.Fatalf("healed profile upsert = %d: %s", retry.Code, retry.Body.String())
		}
		s2 := fsMatrixReload(t, dir)
		s2.mu.Lock()
		_, ok := s2.profiles[profileID]
		s2.mu.Unlock()
		if !ok {
			t.Fatal("healed profile upsert not durable")
		}
		return
	}

	t.Errorf("FINDING runner profile upsert (internal/server/profiles.go:80-81): a snapshot persist failure answered %d but left profile %q in memory; the next successful persist commits a profile the admin was told failed", w.Code, profileID)

	s.persistFailForTest = nil
	retry := doJSON(t, s, http.MethodPost, "/api/v1/runner-profiles", "token", body)
	s2 := fsMatrixReload(t, dir)
	s2.mu.Lock()
	_, durable := s2.profiles[profileID]
	s2.mu.Unlock()
	t.Errorf("FINDING runner profile upsert: retry after heal answered %d and the reloaded snapshot contains the refused profile: %v", retry.Code, durable)
}

// TestFSFindingsCertProfileBindLeavesGhostOnPersistFailure is finding 5b:
// profiles.go:137-138 inserts the serial→profile mapping before
// persistLocked and bindRunnerProfileCert maps the failure to 400
// (profiles.go:300-303), leaving an in-memory mapping the snapshot does not
// contain.
func TestFSFindingsCertProfileBindLeavesGhostOnPersistFailure(t *testing.T) {
	dir := t.TempDir()
	s, err := NewPersistent("token", "token", dir)
	if err != nil {
		t.Fatal(err)
	}
	const profileID = "fs-finding-cert-profile"
	const serial = "0cafe"
	body := fmt.Sprintf(`{"id":%q,"labels":["container"],"max_capacity":1}`, profileID)
	if w := doJSON(t, s, http.MethodPost, "/api/v1/runner-profiles", "token", body); w.Code != http.StatusCreated {
		t.Fatalf("profile fixture = %d: %s", w.Code, w.Body.String())
	}

	s.persistFailForTest = errFSMatrixSeam
	w := doJSON(t, s, http.MethodPut, "/api/v1/runner-profiles/"+profileID+"/cert/"+serial, "token", "{}")
	s.mu.Lock()
	bound := s.certProfiles[serial]
	s.mu.Unlock()
	if bound == "" {
		if w.Code < 500 {
			t.Fatalf("cert bind = %d, want 5xx: %s", w.Code, w.Body.String())
		}
		s.persistFailForTest = nil
		if retry := doJSON(t, s, http.MethodPut, "/api/v1/runner-profiles/"+profileID+"/cert/"+serial, "token", "{}"); retry.Code != http.StatusOK {
			t.Fatalf("healed cert bind = %d: %s", retry.Code, retry.Body.String())
		}
		s2 := fsMatrixReload(t, dir)
		s2.mu.Lock()
		got := s2.certProfiles[serial]
		s2.mu.Unlock()
		if got != profileID {
			t.Fatalf("healed cert bind not durable: %q", got)
		}
		return
	}

	t.Errorf("FINDING cert profile bind (internal/server/profiles.go:137-138, profiles.go:300-303): a snapshot persist failure answered %d (not 5xx) and left serial %q bound to %q in memory; the retry after heal commits the binding the client was told failed", w.Code, serial, bound)

	s.persistFailForTest = nil
	retry := doJSON(t, s, http.MethodPut, "/api/v1/runner-profiles/"+profileID+"/cert/"+serial, "token", "{}")
	s2 := fsMatrixReload(t, dir)
	s2.mu.Lock()
	durable := s2.certProfiles[serial]
	s2.mu.Unlock()
	t.Errorf("FINDING cert profile bind: retry after heal answered %d and the reloaded snapshot binds serial %q to %q", retry.Code, serial, durable)
}

// TestFSFindingsGeneratedFragmentLeavesGhostAndReplayAck is finding 6:
// dynamic.go:425-441 inserts the child jobs, contracts and fragment receipt
// before persistLocked, answers 400 on the failure, and then ACKs a retry
// from the in-memory receipt (200 replay) although nothing was ever durable.
func TestFSFindingsGeneratedFragmentLeavesGhostAndReplayAck(t *testing.T) {
	s, _ := trustedGenerateServer(t)
	runnerID, task := leaseRunJob(t, s)
	const frag = `{"jobs":{"child-a":{"runtime":"container","image":"alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","steps":[{"run":"echo child"}]}},"deps":{}}`
	body := fragmentBody(t, frag)
	hdrs := leaseHeaders(task, runnerID)
	path := "/api/v1/jobs/" + task.Job.ID + "/generated"

	s.persistFailForTest = errFSMatrixSeam
	w := doJSONHeaders(t, s, http.MethodPost, path, "token", body, hdrs)
	s.mu.Lock()
	children := 0
	for _, j := range s.jobs {
		if j.DynamicDepth == 1 {
			children++
		}
	}
	s.mu.Unlock()
	if children == 0 {
		if w.Code < 500 {
			t.Fatalf("generated fragment = %d, want 5xx: %s", w.Code, w.Body.String())
		}
		s.persistFailForTest = nil
		if retry := doJSONHeaders(t, s, http.MethodPost, path, "token", body, hdrs); retry.Code != http.StatusCreated {
			t.Fatalf("healed fragment = %d: %s", retry.Code, retry.Body.String())
		}
		s2 := fsMatrixReload(t, s.dataDir)
		s2.mu.Lock()
		n := 0
		for _, j := range s2.jobs {
			if j.DynamicDepth == 1 {
				n++
			}
		}
		s2.mu.Unlock()
		if n == 0 {
			t.Fatal("healed fragment children not durable")
		}
		return
	}

	t.Errorf("FINDING generated fragment (internal/server/dynamic.go:425-441): a snapshot persist failure answered %d but left %d child job(s) in memory", w.Code, children)

	s.persistFailForTest = nil
	retry := doJSONHeaders(t, s, http.MethodPost, path, "token", body, hdrs)
	s2 := fsMatrixReload(t, s.dataDir)
	s2.mu.Lock()
	durableChildren := 0
	for _, j := range s2.jobs {
		if j.DynamicDepth == 1 {
			durableChildren++
		}
	}
	s2.mu.Unlock()
	t.Errorf("FINDING generated fragment: retry after heal answered %d (replayed from the in-memory receipt without persisting) and the reloaded snapshot holds %d dynamic child job(s)", retry.Code, durableChildren)
}

// TestFSFindingsScheduleCreateLeavesGhostOnJournalFailure is finding 7:
// schedules.go:579-585 inserts s.schedules[sc.ID] before
// persistSchedulesLocked and answers 500 without removing the entry, so the
// next successful schedules write commits a schedule the client was told
// failed. This journal is the schedules file, not the state snapshot, so the
// writeSchedulesFile test seam is used instead of s.persistFailForTest.
func TestFSFindingsScheduleCreateLeavesGhostOnJournalFailure(t *testing.T) {
	dir := t.TempDir()
	s, err := NewPersistent("token", "token", dir)
	if err != nil {
		t.Fatal(err)
	}
	old := writeSchedulesFile
	writeSchedulesFile = func(string, any) error { return errFSMatrixSeam }
	defer func() { writeSchedulesFile = old }()
	body := `{"repository":"https://example.com/o/r.git","spec":` + jsonString(scheduleSpec) + `}`

	w := doJSON(t, s, http.MethodPut, "/api/v1/schedules", "token", body)
	s.mu.Lock()
	ghosts := len(s.schedules)
	s.mu.Unlock()
	if ghosts == 0 {
		if w.Code < 500 {
			t.Fatalf("schedule create = %d, want 5xx: %s", w.Code, w.Body.String())
		}
		writeSchedulesFile = old
		if retry := doJSON(t, s, http.MethodPut, "/api/v1/schedules", "token", body); retry.Code != http.StatusOK {
			t.Fatalf("healed schedule create = %d: %s", retry.Code, retry.Body.String())
		}
		s2 := fsMatrixReload(t, dir)
		s2.mu.Lock()
		n := len(s2.schedules)
		s2.mu.Unlock()
		if n != 1 {
			t.Fatalf("durable schedules after heal = %d, want exactly 1", n)
		}
		return
	}

	t.Errorf("FINDING schedule create (internal/server/schedules.go:579-585): a schedules-journal persist failure answered %d but left %d in-memory schedule(s)", w.Code, ghosts)

	writeSchedulesFile = old
	second := `{"repository":"https://example.com/o/r.git","spec":` + jsonString(scheduleSpec) + `}`
	if retry := doJSON(t, s, http.MethodPut, "/api/v1/schedules", "token", second); retry.Code != http.StatusOK {
		t.Fatalf("second schedule create = %d: %s", retry.Code, retry.Body.String())
	}
	s2 := fsMatrixReload(t, dir)
	s2.mu.Lock()
	n := len(s2.schedules)
	s2.mu.Unlock()
	t.Errorf("FINDING schedule create: the next successful schedules write committed %d schedule(s); the first write the client was told failed is now durable", n)
}
