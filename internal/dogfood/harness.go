package dogfood

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/provenance"
)

// Harness is one dogfood invocation's handle on the system under test: it
// launches the declared topology, seeds repositories and runs, answers
// public-API queries, exposes the read-only state oracle, and verifies
// evidence. Everything a scenario does to the system goes through this
// handle; the oracle only ever reads it.
//
// The in-process control plane below is the hermetic reference backend: it
// implements the acceptance rules the distributed control plane enforces
// (lease generation, ownership, duplicate completion, protocol floor) so the
// scenario suite can prove the rules without a postgres deployment. The
// oracle contract does not change when a real deployment is substituted.
type Harness struct {
	ns       Namespace
	topology Topology
	seed     Seed
	faults   *FaultInjector

	mu      sync.Mutex
	running bool
	repos   map[string]Repo
	runs    map[string]*RunRecord
	ledger  []LedgerEntry
	events  []EventEntry
	clock   func() time.Time
	// generation is the dogfood self-host generation (G0/G1/G2). The
	// harness refuses anything past MaxDogfoodGeneration so a self-hosting
	// pipeline cannot recurse without bound.
	generation string
}

// Repo is a seeded source repository.
type Repo struct {
	Name   string `json:"name"`
	Commit string `json:"commit"`
	Ref    string `json:"ref"`
}

// RunRecord is the authoritative control-plane record of one seeded run.
// Terminal is "" while the run is open. ClientResult mirrors what the
// public API returns; the state oracle compares it against the record.
type RunRecord struct {
	ID           string          `json:"id"`
	Repo         string          `json:"repo"`
	Commit       string          `json:"commit"`
	Attempts     []AttemptRecord `json:"attempts"`
	Terminal     string          `json:"terminal"`
	ArtifactHash string          `json:"artifact_hash,omitempty"`
	EffectCount  int             `json:"effect_count"`
	ClientResult string          `json:"client_result"`
}

// AttemptRecord is one job attempt under a run: the lease ownership the
// control plane currently recognises and the terminal report it accepted.
type AttemptRecord struct {
	JobID      string    `json:"job_id"`
	JobKey     string    `json:"job_key"`
	RunnerID   string    `json:"runner_id"`
	Generation int64     `json:"generation"`
	ExpiresAt  time.Time `json:"expires_at"`
	// Reassigned marks that the lease moved (the previous holder is stale).
	Reassigned bool   `json:"reassigned,omitempty"`
	Status     string `json:"status,omitempty"`
	// Completed marks a terminal completion was accepted; the second
	// completion for the same attempt is a duplicate.
	Completed      bool                           `json:"completed"`
	Protocol       string                         `json:"protocol,omitempty"`
	ArtifactSHA256 string                         `json:"artifact_sha256,omitempty"`
	Receipt        *model.ExecutionControlReceipt `json:"receipt,omitempty"`
}

// LedgerEntry is a crash-recovery ledger record. The harness appends one for
// every durable ownership/effect so the ledger surface of the oracle has an
// independent account.
type LedgerEntry struct {
	Kind   string    `json:"kind"`
	JobID  string    `json:"job_id,omitempty"`
	Detail string    `json:"detail"`
	At     time.Time `json:"at"`
}

// EventEntry is the event-ledger timeline of the run (the frontier the
// attestation's eventFrontier field anchors to).
type EventEntry struct {
	Seq   int64  `json:"seq"`
	Kind  string `json:"kind"`
	JobID string `json:"job_id"`
}

// CompletionClaim is a runner's terminal report of an attempt — the wire
// surface a hostile runner mutates.
type CompletionClaim struct {
	RunID      string
	JobID      string
	RunnerID   string
	Generation int64
	Status     string
	// Protocol is the runner protocol / execution-semantics version the
	// completion was produced under.
	Protocol string
	// ArtifactSHA256 is the hash the runner claims for the attempt's
	// artifact; the state oracle compares it against the collected bytes.
	ArtifactSHA256 string
	Receipt        *model.ExecutionControlReceipt
	// AttemptID, when set, must be the job's own id (wrong-job rejection).
	AttemptID string
}

// LaunchConfig configures one harness invocation.
type LaunchConfig struct {
	Topology Topology
	Seed     Seed
	Now      func() time.Time
}

// Launch brings up the declared topology and returns the harness handle.
// The namespace is derived per invocation (never reused across Launch
// calls) and the seed is validated first: an unattributable run must not
// start.
func Launch(cfg LaunchConfig) (*Harness, error) {
	if err := cfg.Topology.Validate(); err != nil {
		return nil, err
	}
	if err := cfg.Seed.Validate(); err != nil {
		return nil, err
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	ns, err := NewNamespace(now(), defaultEntropy())
	if err != nil {
		return nil, err
	}
	return &Harness{
		ns:       ns,
		topology: cfg.Topology,
		seed:     cfg.Seed,
		faults:   NewFaultInjector(),
		repos:    make(map[string]Repo),
		runs:     make(map[string]*RunRecord),
		running:  true,
		clock:    now,
	}, nil
}

// Stop tears the invocation down. It is idempotent and safe after a partial
// launch: the dogfood program must never leave topology components running.
// Durable state is retained: Stop models a process exit, not a data wipe.
func (h *Harness) Stop() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.running {
		return nil
	}
	h.running = false
	h.ledger = append(h.ledger, LedgerEntry{Kind: "stop", At: h.clock()})
	return nil
}

// Restart resumes the invocation after Stop: the process relaunches over the
// same durable stores (repos, runs, ledger) under the same namespace and
// seed. This is the DF-BOOT-001 recovery surface — a restart must not lose
// or double-count anything the first incarnation recorded.
func (h *Harness) Restart() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.running {
		return fmt.Errorf("dogfood: harness is already running")
	}
	h.running = true
	h.ledger = append(h.ledger, LedgerEntry{Kind: "restart", At: h.clock()})
	return nil
}

// Namespace returns the invocation's isolation identity.
// MaxDogfoodGeneration is the highest self-host generation the harness
// records. G0 is the external bootstrap; each subsequent generation is a
// Kiwi-built Kiwi. G3+ is unintended recursion and is refused.
const MaxDogfoodGeneration = "G2"

// BeginGeneration records the self-host generation under test. The first
// call must be G0; later calls must be the next generation and must not
// exceed MaxDogfoodGeneration (DF-SELF-001).
func (h *Harness) BeginGeneration(gen string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	switch gen {
	case "G0":
		if h.generation != "" {
			return fmt.Errorf("dogfood: generation already started at %s", h.generation)
		}
	case "G1":
		if h.generation != "G0" {
			return fmt.Errorf("dogfood: G1 requires G0 (have %q)", h.generation)
		}
	case "G2":
		if h.generation != "G1" {
			return fmt.Errorf("dogfood: G2 requires G1 (have %q)", h.generation)
		}
	default:
		return fmt.Errorf("dogfood: generation %q is past the %s limit (refusing self-host recursion)", gen, MaxDogfoodGeneration)
	}
	h.generation = gen
	h.ledger = append(h.ledger, LedgerEntry{Kind: "dogfood-generation", JobID: gen, At: h.clock()})
	return nil
}

// Generation returns the current self-host generation ("" before Begin).
func (h *Harness) Generation() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.generation
}

func (h *Harness) Namespace() Namespace { return h.ns }

// Topology returns the declared shape under test.
func (h *Harness) Topology() Topology { return h.topology }

// Seed returns the captured reproducibility record.
func (h *Harness) Seed() Seed { return h.seed }

// Faults returns the deterministic pause-hook injector of this invocation.
func (h *Harness) Faults() *FaultInjector { return h.faults }

// SeedRepo seeds one source repository under the invocation namespace.
func (h *Harness) SeedRepo(base, commit, ref string) Repo {
	h.mu.Lock()
	defer h.mu.Unlock()
	r := Repo{Name: h.ns.RepoName(base), Commit: commit, Ref: ref}
	h.repos[r.Name] = r
	return r
}

// SeedRun seeds one run with one attempt per job key, starting at lease
// generation 1 held by owner. It is the only write path the dogfood program
// uses; the state oracle never writes.
func (h *Harness) SeedRun(id string, repo Repo, jobKeys []string, owner string) (*RunRecord, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.running {
		return nil, fmt.Errorf("dogfood: harness is stopped")
	}
	if _, ok := h.repos[repo.Name]; !ok {
		return nil, fmt.Errorf("dogfood: repo %q is not seeded", repo.Name)
	}
	if _, ok := h.runs[id]; ok {
		return nil, fmt.Errorf("dogfood: run %q is already seeded", id)
	}
	rec := &RunRecord{ID: id, Repo: repo.Name, Commit: repo.Commit, ClientResult: "running"}
	for i, key := range jobKeys {
		rec.Attempts = append(rec.Attempts, AttemptRecord{
			JobID:      fmt.Sprintf("%s-%d", id, i+1),
			JobKey:     key,
			RunnerID:   owner,
			Generation: 1,
			ExpiresAt:  h.clock().Add(time.Hour),
			Protocol:   model.ExecutionSemanticsVersion,
		})
	}
	h.runs[id] = rec
	h.ledger = append(h.ledger, LedgerEntry{Kind: "run-seeded", Detail: id, At: h.clock()})
	h.events = append(h.events, EventEntry{Seq: int64(len(h.events)) + 1, Kind: "run-seeded"})
	return rec, nil
}

// ReassignLease moves the attempt's lease to runner next at the next
// generation. The previous holder becomes stale: any later completion from
// it must be rejected while the new holder can still complete (safety AND
// liveness).
func (h *Harness) ReassignLease(runID, jobID, next string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	rec, att, err := h.find(runID, jobID)
	if err != nil {
		return err
	}
	if att.Completed {
		return fmt.Errorf("dogfood: attempt %s already completed", jobID)
	}
	att.Reassigned = true
	att.RunnerID = next
	att.Generation++
	att.ExpiresAt = h.clock().Add(time.Hour)
	h.ledger = append(h.ledger, LedgerEntry{Kind: "lease-reassign", JobID: jobID, Detail: next, At: h.clock()})
	h.events = append(h.events, EventEntry{Seq: int64(len(h.events)) + 1, Kind: "lease-reassign", JobID: jobID})
	_ = rec
	return nil
}

// ExpireLease moves the attempt's lease expiry into the past without a
// reclaim yet — the AfterLeaseExpirationBeforeReclaim window. The fault is
// hit AFTER the lock is released so a pause hook can safely drive the
// harness from another goroutine.
func (h *Harness) ExpireLease(runID, jobID string) error {
	h.mu.Lock()
	_, att, err := h.find(runID, jobID)
	if err != nil {
		h.mu.Unlock()
		return err
	}
	att.ExpiresAt = h.clock().Add(-time.Minute)
	h.mu.Unlock()
	return h.faults.Hit(AfterLeaseExpirationBeforeReclaim)
}

// ReclaimLease reclaims an expired lease into the next generation for
// runner next — what the control plane does after the expiry window.
func (h *Harness) ReclaimLease(runID, jobID, next string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	_, att, err := h.find(runID, jobID)
	if err != nil {
		return err
	}
	if !att.ExpiresAt.Before(h.clock()) {
		return fmt.Errorf("dogfood: lease for %s is not expired", jobID)
	}
	att.RunnerID = next
	att.Generation++
	att.ExpiresAt = h.clock().Add(time.Hour)
	att.Reassigned = true
	h.ledger = append(h.ledger, LedgerEntry{Kind: "lease-reclaim", JobID: jobID, Detail: next, At: h.clock()})
	h.events = append(h.events, EventEntry{Seq: int64(len(h.events)) + 1, Kind: "lease-reclaim", JobID: jobID})
	return nil
}

// AcceptanceDecision is the control-plane gate's verdict on a completion.
type AcceptanceDecision string

const (
	// DecisionAccepted: the completion became the attempt's terminal report.
	DecisionAccepted AcceptanceDecision = "accepted"
	// DecisionRejected: the completion was refused; the attempt stays open
	// for the legitimate holder (safety must not cost liveness).
	DecisionRejected AcceptanceDecision = "rejected"
)

// SubmitCompletion runs a completion through the control-plane acceptance
// gate. The gate mirrors the production rules the audit named:
//
//   - wrong job / unknown attempt          -> reject
//   - stale lease generation               -> reject
//   - completion from a reassigned holder  -> reject
//   - completion after lease expiry        -> reject
//   - duplicate completion                 -> reject
//   - protocol below the execution floor   -> reject
//
// A rejection never mutates the attempt: the current holder can still
// complete afterwards. An acceptance CAS-wins the attempt exactly once
// (AfterWinnerCAS), mutates state (AfterStateMutationBeforeLedger) and only
// then appends the ledger entry — the crash windows a fault can freeze.
func (h *Harness) SubmitCompletion(c CompletionClaim) (AcceptanceDecision, error) {
	h.mu.Lock()
	rec, att, err := h.find(c.RunID, c.JobID)
	if err != nil {
		h.mu.Unlock()
		return DecisionRejected, nil
	}
	if c.AttemptID != "" && c.AttemptID != att.JobID {
		h.mu.Unlock()
		return DecisionRejected, nil
	}
	if c.Generation != att.Generation {
		h.mu.Unlock()
		return DecisionRejected, nil
	}
	if c.RunnerID != att.RunnerID {
		h.mu.Unlock()
		return DecisionRejected, nil
	}
	if att.ExpiresAt.Before(h.clock()) {
		h.mu.Unlock()
		return DecisionRejected, nil
	}
	if att.Completed {
		h.mu.Unlock()
		return DecisionRejected, nil
	}
	if c.Protocol != "" && c.Protocol != model.ExecutionSemanticsVersion {
		h.mu.Unlock()
		return DecisionRejected, nil
	}
	// Winner CAS: the attempt flips to completed here and nowhere else, so
	// a competing completion that arrives later is a duplicate by state,
	// not by a check that could race.
	att.Completed = true
	h.mu.Unlock()
	if err := h.faults.Hit(AfterWinnerCAS); err != nil {
		return DecisionRejected, err
	}
	h.mu.Lock()
	att.Status = c.Status
	att.ArtifactSHA256 = c.ArtifactSHA256
	att.Receipt = c.Receipt
	rec.Terminal = c.Status
	rec.ClientResult = c.Status
	rec.ArtifactHash = c.ArtifactSHA256
	h.mu.Unlock()
	if err := h.faults.Hit(AfterStateMutationBeforeLedger); err != nil {
		return DecisionRejected, err
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.ledger = append(h.ledger, LedgerEntry{Kind: "completion", JobID: c.JobID, Detail: c.Status, At: h.clock()})
	h.events = append(h.events, EventEntry{Seq: int64(len(h.events)) + 1, Kind: "completion", JobID: c.JobID})
	return DecisionAccepted, nil
}

// AttachArtifact records the artifact bytes hash the control plane
// collected for an attempt. The evidence oracle and the artifact surface
// compare a completion's claim against this collected value. The
// AfterObjectUploadBeforeFinalize fault is hit with the lock released so a
// pause hook can drive the harness concurrently.
func (h *Harness) AttachArtifact(runID, jobID, sha256 string) error {
	h.mu.Lock()
	_, att, err := h.find(runID, jobID)
	if err != nil {
		h.mu.Unlock()
		return err
	}
	att.ArtifactSHA256 = sha256
	h.runs[runID].ArtifactHash = sha256
	h.events = append(h.events, EventEntry{Seq: int64(len(h.events)) + 1, Kind: "artifact-attached", JobID: jobID})
	h.mu.Unlock()
	return h.faults.Hit(AfterObjectUploadBeforeFinalize)
}

// QueryRun is the PUBLIC API view of a run: the client-result surface of
// the oracle. It never exposes fields the API would not return and it never
// mutates state.
func (h *Harness) QueryRun(id string) (RunRecord, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	rec, ok := h.runs[id]
	if !ok {
		return RunRecord{}, fmt.Errorf("dogfood: run %q not found", id)
	}
	out := *rec
	out.Attempts = append([]AttemptRecord(nil), rec.Attempts...)
	return out, nil
}

// StateOracle returns a read-only snapshot of the authoritative durable
// state. The eight-oracle rule treats it as an independent surface; the
// dogfood program must never write through it (there is no write method).
type StateSnapshot struct {
	Runs   map[string]RunRecord `json:"runs"`
	Ledger []LedgerEntry        `json:"ledger"`
	Events []EventEntry         `json:"events"`
}

// StateOracle snapshots the authoritative state read-only.
func (h *Harness) StateOracle() StateSnapshot {
	h.mu.Lock()
	defer h.mu.Unlock()
	snap := StateSnapshot{
		Runs:   make(map[string]RunRecord, len(h.runs)),
		Ledger: append([]LedgerEntry(nil), h.ledger...),
		Events: append([]EventEntry(nil), h.events...),
	}
	for id, rec := range h.runs {
		out := *rec
		out.Attempts = append([]AttemptRecord(nil), rec.Attempts...)
		snap.Runs[id] = out
	}
	return snap
}

// EventFrontier returns the event ledger's latest sequence number — the
// value a real attestation binds as eventFrontier.
func (h *Harness) EventFrontier() int64 {
	h.mu.Lock()
	defer h.mu.Unlock()
	return int64(len(h.events))
}

// SignEvidence signs an execution-attestation statement after passing the
// BeforeEvidenceSignature pause hook. Nothing may be observable as evidence
// in that window; a hook error refuses to sign rather than emitting a
// partial envelope.
func (h *Harness) SignEvidence(st provenance.Statement, keyID string, priv ed25519.PrivateKey) (provenance.Envelope, error) {
	if err := h.faults.Hit(BeforeEvidenceSignature); err != nil {
		return provenance.Envelope{}, err
	}
	return provenance.Sign(st, keyID, priv)
}

// VerifyEvidence verifies a signed execution-attestation envelope against
// the pinned key and then proves the statement binds its own evidence block
// (provenance.VerifyExecutionAttestation). Both layers are required: a
// valid signature over a self-contradictory block must not pass.
func (h *Harness) VerifyEvidence(env provenance.Envelope, pub ed25519.PublicKey) (provenance.Statement, error) {
	if err := provenance.Verify(env, pub); err != nil {
		return provenance.Statement{}, err
	}
	raw, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return provenance.Statement{}, err
	}
	var st provenance.Statement
	if err := json.Unmarshal(raw, &st); err != nil {
		return provenance.Statement{}, err
	}
	if err := provenance.VerifyExecutionAttestation(st); err != nil {
		return provenance.Statement{}, err
	}
	return st, nil
}

// ScanSecretMarkers reports which forbidden markers appear in serialized
// evidence. The evidence contract is that a signed envelope must carry
// facts and identities, never credential material; a marker hit is a leak
// the scenario reddens on.
func ScanSecretMarkers(data []byte, markers []string) []string {
	var hits []string
	for _, m := range markers {
		if m == "" {
			continue
		}
		if bytes.Contains(data, []byte(m)) {
			hits = append(hits, m)
		}
	}
	return hits
}

// Observations assembles the eight-oracle panel for a run from the
// harness's independent surfaces. External effects come from the sink the
// scenario wired in (the only authority on effect count); recovery is the
// state snapshot after a restart/reclaim pass.
func (h *Harness) Observations(runID string, externalEffectCount int) ([]Observation, error) {
	client, err := h.QueryRun(runID)
	if err != nil {
		return nil, err
	}
	snap := h.StateOracle()
	state, ok := snap.Runs[runID]
	if !ok {
		return nil, fmt.Errorf("dogfood: state oracle has no run %q", runID)
	}
	var runnerTerminal string
	var artifactHash string
	for _, a := range state.Attempts {
		if a.Completed {
			runnerTerminal = a.Status
			artifactHash = a.ArtifactSHA256
		}
	}
	ledgerTerminal := ""
	for _, e := range snap.Ledger {
		if e.Kind == "completion" {
			ledgerTerminal = e.Detail
		}
	}
	obs := []Observation{
		{Surface: SurfaceClientResult, Terminal: client.ClientResult, EffectCount: externalEffectCount},
		{Surface: SurfaceAuthoritativeState, Terminal: state.Terminal, EffectCount: externalEffectCount},
		{Surface: SurfaceLedger, Terminal: ledgerTerminal, EffectCount: externalEffectCount},
		{Surface: SurfaceRunnerAuthority, Terminal: runnerTerminal, EffectCount: externalEffectCount, Detail: "artifact=" + artifactHash},
		{Surface: SurfaceArtifacts, Terminal: state.Terminal, EffectCount: externalEffectCount, Detail: "artifact=" + artifactHash},
		{Surface: SurfaceEvidence, Terminal: state.Terminal, EffectCount: externalEffectCount},
		{Surface: SurfaceExternalEffects, Terminal: state.Terminal, EffectCount: externalEffectCount},
		{Surface: SurfaceRecovery, Terminal: state.Terminal, EffectCount: externalEffectCount},
	}
	sort.SliceStable(obs, func(i, j int) bool { return obs[i].Surface < obs[j].Surface })
	return obs, nil
}

func (h *Harness) find(runID, jobID string) (*RunRecord, *AttemptRecord, error) {
	rec, ok := h.runs[runID]
	if !ok {
		return nil, nil, fmt.Errorf("dogfood: run %q not found", runID)
	}
	for i := range rec.Attempts {
		if rec.Attempts[i].JobID == jobID {
			return rec, &rec.Attempts[i], nil
		}
	}
	return nil, nil, fmt.Errorf("dogfood: job %q not found in run %q", jobID, runID)
}

// QuotaGateInput is the pre-checkout hard-quota admission input: the trust
// of the job, the operator escape hatch, whether a hard bound was actually
// established, and the effective runtime the checkout would run under.
type QuotaGateInput struct {
	// Untrusted is the inverse of the job's persisted trust bit.
	Untrusted bool
	// OperatorEscape is the KIWI_ALLOW_UNQUOTAED_UNTRUSTED_DISK opt-out
	// (trusted-only self-hosted runners). The requirement is derived as
	// Untrusted && !OperatorEscape, never stated twice.
	OperatorEscape bool
	// HardAvailable is the executor-observed hard-quota fact
	// (executor.DiskQuotaStatus.Hard / receipt.WorkspaceQuotaEnforced):
	// true ONLY when a hard OS-level bound was installed before the
	// workspace was populated. Fallback accounting and setup failure are
	// false.
	HardAvailable bool
	// Runtime is the effective runtime resolved fail-closed from the
	// persisted pipeline. Empty means "could not be resolved", which is
	// never interpreted as "not container".
	Runtime string
	// Detail is the quota setup detail surfaced on rejection.
	Detail string
}

// AdmitQuota is the pure decision of the runner's pre-checkout hard-quota
// gate (internal/runner execute): an untrusted job that requires a hard
// bound must not check out when none could be established on the container
// backend — the checkout itself is the window the quota protects. The
// function is total and deterministic so the scenario suite can table-test
// the gate's truth table without a runner process.
func AdmitQuota(in QuotaGateInput) error {
	requireHard := in.Untrusted && !in.OperatorEscape
	if !requireHard || in.HardAvailable {
		return nil
	}
	// Only the container backend requires the hard bound; but a runtime
	// that could not be resolved fails closed (the gate does not depend on
	// the compatibility field being trustworthy).
	if in.Runtime == "" {
		return fmt.Errorf("untrusted job requires a hard workspace disk quota, but none could be established: %s; effective runtime could not be resolved", in.Detail)
	}
	if in.Runtime != "container" {
		return nil
	}
	return fmt.Errorf("untrusted job requires a hard workspace disk quota, but none could be established: %s", in.Detail)
}
