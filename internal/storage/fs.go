package storage

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// Snapshot is the durable control-plane state. The filesystem implementation is
// intentionally boring: one atomically replaced JSON snapshot plus append-only
// log/audit files. It keeps Kiwi single-binary and dependency-free while making
// crashes recoverable. A SQL store can implement the same Repository contract.
type Snapshot struct {
	Version   int                             `json:"version"`
	Runs      map[string]model.Run            `json:"runs"`
	Jobs      map[string]model.Job            `json:"jobs"`
	Runners   map[string]model.Runner         `json:"runners"`
	Artifacts map[string]model.ArtifactRecord `json:"artifacts,omitempty"`
	Reports   map[string]model.TestReport     `json:"reports,omitempty"`
	// DownstreamLinks persists the fs-mode downstream dispatch claims
	// (downstream_links equivalents) so a restarted control plane cannot
	// launch the same child run twice. Additive; older snapshots load with
	// a nil map.
	DownstreamLinks map[string]DownstreamLink `json:"downstream_links,omitempty"`
	// Profiles persists the fs-mode server-owned runner profiles and their
	// certificate-serial bindings (runner_profiles/cert_profile_links
	// equivalents). Additive; older snapshots load with nil maps.
	Profiles         map[string]model.RunnerProfile `json:"profiles,omitempty"`
	CertProfileLinks map[string]string              `json:"cert_profile_links,omitempty"`
	// Snapshots persists the fs-mode uploaded workspace snapshot records
	// (workspace_snapshots equivalents) so the archives written under the
	// data dir stay addressable across restarts instead of becoming
	// unreferenced orphans. Additive; older snapshots load with a nil map.
	// The server validates every referenced archive/manifest pair at load
	// and drops records whose files no longer match.
	Snapshots map[string]model.SnapshotRecord `json:"snapshots,omitempty"`
}

type Repository struct {
	Root string
	mu   sync.Mutex
}

func New(root string) *Repository { return &Repository{Root: root} }

func (r *Repository) Load() (Snapshot, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.loadLocked()
}

func (r *Repository) loadLocked() (Snapshot, error) {
	s := Snapshot{Version: 1, Runs: map[string]model.Run{}, Jobs: map[string]model.Job{}, Runners: map[string]model.Runner{}, Artifacts: map[string]model.ArtifactRecord{}, Reports: map[string]model.TestReport{}}
	b, err := os.ReadFile(filepath.Join(r.Root, "state.json"))
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return s, err
	}
	if err := json.Unmarshal(b, &s); err != nil {
		return s, fmt.Errorf("decode state: %w", err)
	}
	if s.Runs == nil {
		s.Runs = map[string]model.Run{}
	}
	if s.Jobs == nil {
		s.Jobs = map[string]model.Job{}
	}
	if s.Runners == nil {
		s.Runners = map[string]model.Runner{}
	}
	if s.Artifacts == nil {
		s.Artifacts = map[string]model.ArtifactRecord{}
	}
	if s.Reports == nil {
		s.Reports = map[string]model.TestReport{}
	}
	if s.DownstreamLinks == nil {
		s.DownstreamLinks = map[string]DownstreamLink{}
	}
	if s.Profiles == nil {
		s.Profiles = map[string]model.RunnerProfile{}
	}
	if s.CertProfileLinks == nil {
		s.CertProfileLinks = map[string]string{}
	}
	if s.Snapshots == nil {
		s.Snapshots = map[string]model.SnapshotRecord{}
	}
	return s, nil
}

func (r *Repository) Save(s Snapshot) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := os.MkdirAll(r.Root, 0o700); err != nil {
		return err
	}
	s.Version = 1
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	// AtomicWriteFile checks the temp file's Sync/Close errors and fsyncs
	// the parent directory after the rename: a state snapshot is only
	// reported written when it is durable, and a crash can never leave a
	// truncated or half-renamed state.json.
	return AtomicWriteFile(filepath.Join(r.Root, "state.json"), b, 0o600)
}

func (r *Repository) AppendLog(e model.LogEntry) error {
	return r.appendJSONL("logs.jsonl", e)
}
func (r *Repository) AppendAudit(e model.AuditEvent) error {
	return r.appendJSONL("audit.jsonl", e)
}
func (r *Repository) appendJSONL(name string, v any) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := os.MkdirAll(r.Root, 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(filepath.Join(r.Root, name), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	if err := enc.Encode(v); err != nil {
		return err
	}
	return f.Sync()
}

func (r *Repository) ReadLogs(runID string, after int64, limit int) ([]model.LogEntry, error) {
	if limit <= 0 || limit > 10000 {
		limit = 2000
	}
	return readJSONL[model.LogEntry](filepath.Join(r.Root, "logs.jsonl"), limit, func(e model.LogEntry) bool { return e.RunID == runID && e.Seq > after })
}
func (r *Repository) ReadAudit(limit int) ([]model.AuditEvent, error) {
	if limit <= 0 || limit > 10000 {
		limit = 1000
	}
	return readJSONL[model.AuditEvent](filepath.Join(r.Root, "audit.jsonl"), limit, func(model.AuditEvent) bool { return true })
}
func readJSONL[T any](path string, limit int, keep func(T) bool) ([]T, error) {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	dec := json.NewDecoder(f)
	out := make([]T, 0)
	for {
		var v T
		if err := dec.Decode(&v); err != nil {
			if jsonlStreamFinished(err) {
				return out, nil
			}
			return out, err
		}
		if keep(v) {
			out = append(out, v)
			if len(out) > limit {
				out = out[len(out)-limit:]
			}
		}
	}
}

// jsonlStreamFinished reports whether a JSON-lines decode error means the
// stream ended cleanly (EOF or an already-closed file) rather than a
// malformed record. Both cases are the normal end of a log file.
func jsonlStreamFinished(err error) bool {
	return errors.Is(err, os.ErrClosed) || errors.Is(err, io.EOF)
}

// MaxLogSeq returns the highest durable log sequence so a restarted control
// plane can continue the monotonic stream without reusing cursor values.
func (r *Repository) MaxLogSeq() (int64, error) {
	f, err := os.Open(filepath.Join(r.Root, "logs.jsonl"))
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	defer f.Close()
	dec := json.NewDecoder(f)
	var maxSeq int64
	for {
		var e model.LogEntry
		if err := dec.Decode(&e); err != nil {
			if errors.Is(err, io.EOF) {
				return maxSeq, nil
			}
			return 0, err
		}
		if e.Seq > maxSeq {
			maxSeq = e.Seq
		}
	}
}
