package server

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/kiwici/kiwi/internal/forge"
	"github.com/kiwici/kiwi/internal/storage"
)

const (
	outboxFile     = "outbox.jsonl"
	outboxDoneFile = "outbox.done.jsonl"
)

// Outbox is a durable FIFO of forge-publish intents. Items are held in
// memory and, when a storage.Repository is attached, persisted as JSONL
// lines so a restarted control plane replays unflushed intents. Processed
// item IDs are recorded in a second JSONL file; replay filters enqueued
// intents against that done set. Dispatch is expected to be idempotent by
// item ID (forge check runs use stable external_ids), so an at-least-once
// replay cannot duplicate published state.
type Outbox struct {
	mu    sync.Mutex
	items []forge.OutboxItem
	store *storage.Repository
	done  map[string]bool
}

// NewOutbox creates an outbox. When store is non-nil, unflushed intents
// from a previous process are replayed into the queue.
func NewOutbox(store *storage.Repository) *Outbox {
	o := &Outbox{store: store, done: map[string]bool{}}
	if store == nil {
		return o
	}
	if err := o.loadLocked(); err != nil {
		log.Printf("outbox: replay failed, starting empty: %v", err)
	}
	return o
}

func (o *Outbox) loadLocked() error {
	done := map[string]bool{}
	f, err := os.Open(filepath.Join(o.store.Root, outboxDoneFile))
	if err == nil {
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			var rec struct {
				ID string `json:"id"`
			}
			if json.Unmarshal(sc.Bytes(), &rec) == nil && rec.ID != "" {
				done[rec.ID] = true
			}
		}
		_ = f.Close()
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	o.done = done

	items, err := o.readItems()
	if err != nil {
		return err
	}
	o.items = o.items[:0]
	for _, it := range items {
		if done[it.ID] {
			continue
		}
		o.items = append(o.items, it)
	}
	return nil
}

func (o *Outbox) readItems() ([]forge.OutboxItem, error) {
	f, err := os.Open(filepath.Join(o.store.Root, outboxFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []forge.OutboxItem
	dec := json.NewDecoder(f)
	for {
		var it forge.OutboxItem
		if err := dec.Decode(&it); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return out, err
		}
		out = append(out, it)
	}
	return out, nil
}

// Enqueue appends one intent to the queue and, when persistent, to the
// outbox.jsonl file. It returns an error only when persistence fails; the
// item is still queued in memory in that case.
func (o *Outbox) Enqueue(item forge.OutboxItem) error {
	if item.ID == "" {
		id, err := newID()
		if err != nil {
			return err
		}
		item.ID = id
	}
	if item.CreatedAt.IsZero() {
		item.CreatedAt = time.Now().UTC()
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	o.items = append(o.items, item)
	if o.store == nil {
		return nil
	}
	return o.appendJSONLLocked(outboxFile, item)
}

func (o *Outbox) appendJSONLLocked(name string, v any) error {
	if o.store == nil {
		return nil
	}
	if err := os.MkdirAll(o.store.Root, 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(filepath.Join(o.store.Root, name), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := json.NewEncoder(f).Encode(v); err != nil {
		return err
	}
	return f.Sync()
}

// Pending returns a snapshot of the queued intents.
func (o *Outbox) Pending() []forge.OutboxItem {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]forge.OutboxItem(nil), o.items...)
}

// Flush dispatches queued intents in FIFO order. A failed dispatch stops
// the batch and leaves the item (and everything after it) queued for the
// next flush; a successful dispatch removes the item and records its ID in
// the done file so replay skips it. Returns the number of intents dispatched.
func (o *Outbox) Flush(ctx context.Context, dispatch func(context.Context, forge.OutboxItem) error) (int, error) {
	if dispatch == nil {
		return 0, nil
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	dispatched := 0
	for len(o.items) > 0 {
		it := o.items[0]
		if err := dispatch(ctx, it); err != nil {
			return dispatched, err
		}
		o.items = o.items[1:]
		o.done[it.ID] = true
		dispatched++
		if err := o.appendJSONLLocked(outboxDoneFile, struct {
			ID string `json:"id"`
		}{ID: it.ID}); err != nil {
			return dispatched, err
		}
	}
	return dispatched, nil
}

// flushOutbox drains the server's outbox through the forge dispatch path.
// It is called from the Maintain loop; unhandled intents are dropped with a
// log line rather than blocking the queue forever.
func (s *Server) flushOutbox() {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if _, err := s.outbox.Flush(ctx, s.dispatchOutbox); err != nil {
		log.Printf("outbox: flush stopped: %v", err)
	}
}

func (s *Server) dispatchOutbox(ctx context.Context, item forge.OutboxItem) error {
	switch item.Kind {
	case forge.OutboxKindGitHubCheck:
		var p forge.CheckPayload
		if err := json.Unmarshal(item.Payload, &p); err != nil {
			return err
		}
		return s.gitHubForge().PublishCheck(ctx, p.RepoFullName, p.SHA, p.Name, p.Status, p.Conclusion, p.DetailsURL, p.Summary, p.Annotations)
	case forge.OutboxKindGitHubStatus:
		var p forge.StatusPayload
		if err := json.Unmarshal(item.Payload, &p); err != nil {
			return err
		}
		return s.publishGitHubStatusFromPayload(ctx, p)
	case forge.OutboxKindDownstream, forge.OutboxKindWebhookCall:
		log.Printf("outbox: dropping reserved intent %s (kind %s)", item.ID, item.Kind)
		return nil
	default:
		log.Printf("outbox: dropping unknown intent %s (kind %s)", item.ID, item.Kind)
		return nil
	}
}
