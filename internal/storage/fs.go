package storage

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/kiwici/kiwi/internal/model"
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
	tmp := filepath.Join(r.Root, fmt.Sprintf("state.%d.tmp", time.Now().UnixNano()))
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	f, err := os.OpenFile(tmp, os.O_RDWR, 0)
	if err == nil {
		_ = f.Sync()
		_ = f.Close()
	}
	return os.Rename(tmp, filepath.Join(r.Root, "state.json"))
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
			if errors.Is(err, os.ErrClosed) {
				return out, nil
			}
			if errors.Is(err, io.EOF) {
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
