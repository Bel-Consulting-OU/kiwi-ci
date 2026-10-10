package storage

// Real-PostgreSQL tests for the graph-causality stamping of dynamically
// generated jobs: the CreatedByNode/CreatedByMutation/ExternalContext fields
// are payload-additive (they survive the jobs payload round trip) and the
// graph.mutation_committed event carries the mutation identity and the
// bounded opaque external context. Gated on KIWI_TEST_POSTGRES_URL like the
// other storage integration tests.

import (
	"context"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// TestPostgresIntegrationGeneratedFragmentCausalityRoundTrip proves the
// canonical store persists the causality stamp and the graph.mutation event
// payload: an ordinary enqueued job keeps the fields empty, a generated child
// recovers them from the jobs payload, and the event records the mutation id,
// the attached flag and the bounded opaque context.
func TestPostgresIntegrationGeneratedFragmentCausalityRoundTrip(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()

	runID, parentID := pgITNewID(t), pgITNewID(t)
	parent := pgITJob(runID, parentID, pgITRepo)
	if err := st.InsertCompiledRun(ctx, InsertCompiledRunRequest{
		Run:  pgITRun(runID, model.StatusQueued),
		Jobs: map[string]model.Job{parentID: parent},
	}); err != nil {
		t.Fatalf("compiled run: %v", err)
	}
	runnerID := pgITNewID(t)
	leased, err := st.AcquireLease(ctx, parentID, runnerID, []byte("causality-token"), 1, time.Now().UTC().Add(time.Hour))
	if err != nil {
		t.Fatalf("AcquireLease: %v", err)
	}

	childID := pgITNewID(t)
	child := pgITJob(runID, childID, pgITRepo)
	child.Key = "generated-" + childID
	child.CreatedByNode = parentID
	child.CreatedByMutation = parentID + ":" + GeneratedFragmentMutationSlotDefault
	child.ExternalContext = "plan-42/correlation"
	req := GeneratedFragmentRequest{
		ParentJobID: parentID, RunnerID: leased.LeaseRunnerID, LeaseGeneration: leased.LeaseGeneration,
		LeaseTokenHash: leased.LeaseTokenHash, Depth: 1, FragmentID: "frag-causality",
		MutationSlot:    GeneratedFragmentMutationSlotDefault,
		ExternalContext: "plan-42/correlation",
		Jobs:            map[string]model.Job{childID: child},
		Children:        []GeneratedFragmentChild{{Key: child.Key, ID: childID}},
	}
	if _, replayed, err := st.InsertGeneratedFragmentTx(ctx, req, nil); err != nil || replayed {
		t.Fatalf("fragment insert = replayed %v err %v", replayed, err)
	}

	jobs, err := st.ListJobsByRun(ctx, runID)
	if err != nil {
		t.Fatalf("ListJobsByRun: %v", err)
	}
	byKey := map[string]model.Job{}
	for _, j := range jobs {
		byKey[j.Key] = j
	}
	persistedParent := byKey[parent.Key]
	if persistedParent.CreatedByNode != "" || persistedParent.CreatedByMutation != "" || persistedParent.ExternalContext != "" {
		t.Fatalf("ordinary enqueued job carries causality fields: %+v", persistedParent)
	}
	persisted, ok := byKey[child.Key]
	if !ok {
		t.Fatalf("generated child %q missing from the run's jobs", child.Key)
	}
	if persisted.CreatedByNode != parentID ||
		persisted.CreatedByMutation != parentID+":"+GeneratedFragmentMutationSlotDefault ||
		persisted.ExternalContext != "plan-42/correlation" {
		t.Fatalf("causality fields not persisted: %+v", persisted)
	}

	committed := pgITEventByType(t, st, model.EventGraphMutationCommitted)
	if committed.JobID != parentID || committed.Attempt != leased.LeaseGeneration {
		t.Fatalf("graph.mutation_committed identity = %+v", committed)
	}
	if committed.Payload["mutation"] != parentID+":"+GeneratedFragmentMutationSlotDefault ||
		committed.Payload["external_context_attached"] != "true" ||
		committed.Payload["external_context"] != "plan-42/correlation" {
		t.Fatalf("graph.mutation_committed payload = %+v", committed.Payload)
	}
}
