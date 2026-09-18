package server

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/forge"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
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
//
// In DB mode the outbox delegates persistence to storage.OutboxStore:
// OutboxAppend on enqueue, OutboxPending on startup, ClaimOutbox before a
// flush dispatches (cross-replica claim lease, migration 0010) and OutboxAck
// after a successful dispatch. The filesystem JSONL stays the fs-mode store.
//
// Flush always acks durably BEFORE removing an item from the local queue: a
// failed ack leaves the intent queued (and un-dispatched-but-idempotent) for
// the next tick instead of losing it from this process.
type Outbox struct {
	mu    sync.Mutex
	items []forge.OutboxItem
	store *storage.Repository
	db    storage.OutboxStore
	done  map[string]bool
	// localOnly marks DB-mode items whose durable append failed: they have
	// no row to claim, so they are dispatched directly (at-least-once),
	// preserving Enqueue's "persistence failed but still queued" contract.
	localOnly map[string]bool
	// claimer uniquely identifies this process in the durable outbox claim
	// lease. Lazily initialized.
	claimer string
	// flushMu serializes flushes on one instance so two concurrent Flush
	// calls cannot dispatch the same claimed/local-only item twice.
	flushMu sync.Mutex
}

// NewOutbox creates an outbox. When store is non-nil, unflushed intents
// from a previous process are replayed into the queue.
func NewOutbox(store *storage.Repository) *Outbox {
	o := &Outbox{store: store, done: map[string]bool{}, localOnly: map[string]bool{}}
	if store == nil {
		return o
	}
	if err := o.loadLocked(); err != nil {
		log.Printf("outbox: replay failed, starting empty: %v", err)
	}
	return o
}

// AttachDB wires a durable SQL outbox store. DB and fs persistence are
// mutually exclusive: once attached, intents flow through the store.
func (o *Outbox) AttachDB(db storage.Store) {
	if ds, ok := db.(storage.OutboxStore); ok {
		o.db = ds
	}
}

// ReplayDB loads unacked intents from the SQL store into memory (FIFO).
func (o *Outbox) ReplayDB(ctx context.Context) error {
	if o.db == nil {
		return nil
	}
	items, err := o.db.OutboxPending(ctx)
	if err != nil {
		return err
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	seen := map[string]bool{}
	for _, it := range o.items {
		seen[it.ID] = true
	}
	for _, it := range items {
		if seen[it.ID] {
			continue
		}
		o.items = append(o.items, forge.OutboxItem{ID: it.ID, Kind: it.Kind, Payload: it.Payload, CreatedAt: it.CreatedAt})
	}
	return nil
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
// durable store (SQL in DB mode, outbox.jsonl in fs mode). It returns an
// error only when persistence fails; the item is still queued in memory in
// that case.
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
	// Idempotent by ID: deterministic intents (downstream launches keyed by
	// the link's stable key) are replayed after lost ACKs and must converge
	// on ONE durable intent.
	for _, it := range o.items {
		if it.ID == item.ID {
			return nil
		}
	}
	o.items = append(o.items, item)
	if o.db != nil {
		if err := o.db.OutboxAppend(context.Background(), storage.OutboxItem{
			ID: item.ID, Kind: item.Kind, Payload: item.Payload, CreatedAt: item.CreatedAt,
		}); err != nil {
			// The durable append failed, but the caller was promised the
			// intent stays queued in memory: mark it local-only so the
			// claim-gated flush still dispatches it.
			o.localOnly[item.ID] = true
			return err
		}
		return nil
	}
	if o.store == nil {
		return nil
	}
	return o.appendJSONLLocked(outboxFile, item)
}

// EnqueueLocal queues one intent in memory only, without touching the
// durable store. It is used for intents whose rows were already created
// inside another transaction (completion effect intents written by
// storage.CompleteJob): the local copy lets this instance dispatch and ack
// the pre-existing rows under the same IDs.
// HasIntent reports whether an intent with this ID is already queued,
// durably appended or currently in flight. Recovery paths use it to treat a
// duplicate enqueue as success.
func (o *Outbox) HasIntent(id string) bool {
	if id == "" {
		return false
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	for _, it := range o.items {
		if it.ID == id {
			return true
		}
	}
	return false
}

func (o *Outbox) EnqueueLocal(item forge.OutboxItem) {
	if item.CreatedAt.IsZero() {
		item.CreatedAt = time.Now().UTC()
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	for _, it := range o.items {
		if it.ID == item.ID {
			return
		}
	}
	o.items = append(o.items, item)
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

// Flush dispatches queued intents in FIFO order. The order is always
// dispatch (idempotent by stable item ID) → durable ACK (DB OutboxAck /
// fs done-file append) → local removal: an ACK failure keeps the item queued
// so the intent can never be lost from this process by a failed ack, and the
// next tick retries the dispatch idempotently.
//
// In DB mode each flush first claims a batch of rows atomically
// (storage.ClaimOutbox): rows claimed by another replica within
// storage.OutboxClaimTTL are skipped, so two control planes flush disjoint
// batches and never double-dispatch. A claim is released on dispatch or ack
// failure so the retry does not wait out the TTL. Local-only items (durable
// append failed at enqueue time) are dispatched directly, since there is no
// row to claim.
//
// The dispatch runs WITHOUT the outbox lock so dispatched intents may
// enqueue follow-up intents (e.g. a completion effect recording downstream
// launch intents) without deadlocking. Returns the number of intents
// dispatched.
func (o *Outbox) Flush(ctx context.Context, dispatch func(context.Context, forge.OutboxItem) error) (int, error) {
	if dispatch == nil {
		return 0, nil
	}
	o.flushMu.Lock()
	defer o.flushMu.Unlock()
	if o.db != nil {
		return o.flushDB(ctx, dispatch)
	}
	return o.flushLocal(ctx, dispatch)
}

// flushLocal drains the in-memory/fs queue: dispatch → durable done-file
// ack → local pop.
func (o *Outbox) flushLocal(ctx context.Context, dispatch func(context.Context, forge.OutboxItem) error) (int, error) {
	dispatched := 0
	for {
		o.mu.Lock()
		if len(o.items) == 0 {
			o.mu.Unlock()
			return dispatched, nil
		}
		it := o.items[0]
		o.mu.Unlock()

		if err := dispatch(ctx, it); err != nil {
			return dispatched, err
		}
		// Durable ack BEFORE the local removal: a failed ack leaves the
		// intent queued and it is retried (idempotently) next tick.
		if o.store != nil {
			if err := o.appendJSONLLocked(outboxDoneFile, struct {
				ID string `json:"id"`
			}{ID: it.ID}); err != nil {
				return dispatched, err
			}
		}
		o.mu.Lock()
		// Remove the dispatched item when it is still at the head (a
		// concurrent enqueue only ever appends, so the head is stable
		// between the peek above and this point).
		if len(o.items) > 0 && o.items[0].ID == it.ID {
			o.items = o.items[1:]
		}
		o.done[it.ID] = true
		dispatched++
		o.mu.Unlock()
	}
}

// outboxFlushMaxBatches bounds how many claim batches one Flush call
// processes, so a dispatch path that keeps enqueueing follow-up intents can
// never trap the flush in an unbounded loop (the remainder waits for the
// next tick).
const outboxFlushMaxBatches = 64

// flushDB claims and dispatches batches of durable rows until no more rows
// are claimable, dispatching exactly the items this flusher owns: its fresh
// claims plus local-only items. Claiming before each batch is what keeps
// concurrent replicas on disjoint work while still draining follow-up
// intents queued during dispatch.
func (o *Outbox) flushDB(ctx context.Context, dispatch func(context.Context, forge.OutboxItem) error) (int, error) {
	total := 0
	for batch := 0; batch < outboxFlushMaxBatches; batch++ {
		n, claimed, err := o.flushDBBatch(ctx, dispatch)
		total += n
		if err != nil {
			return total, err
		}
		if claimed == 0 {
			return total, nil
		}
	}
	return total, nil
}

// flushDBBatch claims one batch of durable rows and dispatches the items this
// flusher owns. claimed reports how many rows the claim covered (zero means
// the durable outbox is fully claimed or empty).
func (o *Outbox) flushDBBatch(ctx context.Context, dispatch func(context.Context, forge.OutboxItem) error) (int, int, error) {
	claimer := o.claimerID()
	claimed, err := o.db.ClaimOutbox(ctx, claimer, storage.OutboxClaimBatch)
	if err != nil {
		return 0, 0, err
	}
	// Even with an empty claim, local-only items (durable append failed at
	// enqueue time) are dispatched below: they have no row to claim.
	owned := make(map[string]bool, len(claimed))
	o.mu.Lock()
	known := make(map[string]bool, len(o.items))
	for _, it := range o.items {
		known[it.ID] = true
	}
	for _, it := range claimed {
		owned[it.ID] = true
		if !known[it.ID] {
			o.items = append(o.items, forge.OutboxItem{ID: it.ID, Kind: it.Kind, Payload: it.Payload, CreatedAt: it.CreatedAt})
		}
	}
	o.mu.Unlock()

	dispatched := 0
	for {
		o.mu.Lock()
		idx := -1
		for i, it := range o.items {
			if owned[it.ID] || o.localOnly[it.ID] {
				idx = i
				break
			}
		}
		if idx < 0 {
			o.mu.Unlock()
			break
		}
		it := o.items[idx]
		o.mu.Unlock()

		if err := dispatch(ctx, it); err != nil {
			if owned[it.ID] {
				_ = o.db.ReleaseOutboxClaim(ctx, it.ID, claimer)
			}
			return dispatched, len(claimed), err
		}
		// Durable ACK BEFORE the local removal (and before the claim is
		// considered satisfied): an ack failure keeps the item queued and
		// releases the claim so the retry does not wait out the TTL.
		if err := o.db.OutboxAck(ctx, it.ID); err != nil {
			if owned[it.ID] {
				_ = o.db.ReleaseOutboxClaim(ctx, it.ID, claimer)
			}
			return dispatched, len(claimed), err
		}
		o.mu.Lock()
		o.removeLocked(it.ID)
		o.done[it.ID] = true
		delete(o.localOnly, it.ID)
		dispatched++
		o.mu.Unlock()
	}
	o.pruneDB(ctx)
	return dispatched, len(claimed), nil
}

// removeLocked drops one item from the local queue. The caller holds o.mu.
func (o *Outbox) removeLocked(id string) {
	for i, it := range o.items {
		if it.ID == id {
			o.items = append(o.items[:i], o.items[i+1:]...)
			return
		}
	}
}

// pruneDB drops local copies of rows another replica has acknowledged, so
// the in-memory queue does not grow without bound in HA. Local-only items
// (no durable row) are never pruned.
func (o *Outbox) pruneDB(ctx context.Context) {
	pending, err := o.db.OutboxPending(ctx)
	if err != nil {
		return
	}
	live := make(map[string]bool, len(pending))
	for _, it := range pending {
		live[it.ID] = true
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	kept := o.items[:0]
	for _, it := range o.items {
		if live[it.ID] || o.localOnly[it.ID] {
			kept = append(kept, it)
		}
	}
	o.items = kept
}

// claimerID lazily derives this process's unique outbox claim identity.
func (o *Outbox) claimerID() string {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.claimer == "" {
		if id, err := newID(); err == nil {
			o.claimer = "outbox-" + id
		} else {
			o.claimer = fmt.Sprintf("outbox-%d", time.Now().UnixNano())
		}
	}
	return o.claimer
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
		// Defense in depth: a github_check intent whose payload names a
		// different forge is dropped, never sent to the GitHub API.
		if p.ForgeKind != "" && p.ForgeKind != "github" {
			log.Printf("outbox: dropping github_check for %s run %s", p.ForgeKind, p.RepoFullName)
			return nil
		}
		publisher := s.gitHubForge()
		if idp, ok := interface{}(publisher).(forge.CheckRunPublisher); ok && p.RunID != "" {
			key := s.checkRunKey(p.RunID, p.Name)
			// One publication at a time per logical check: two dispatchers
			// seeing "no mapping" would otherwise both POST before either
			// mapping is installed.
			unlock := s.lockCheckRunKey(key)
			defer unlock()
			existing, err := s.getCheckRunID(ctx, key)
			if err != nil {
				// Fail the dispatch (no ACK): retrying with a read error must
				// not POST a duplicate.
				return err
			}
			id, err := idp.PublishCheckRun(ctx, p.RepoFullName, p.SHA, p.Name, p.Status, p.Conclusion, p.DetailsURL, p.Summary, p.Annotations, existing)
			if err != nil {
				return err
			}
			if id != "" && id != existing {
				// Durably record BEFORE the intent can be ACKed; a failure
				// here fails the dispatch so the retry reconciles instead of
				// losing the remote ID.
				if err := s.putCheckRunID(ctx, key, id); err != nil {
					return err
				}
			}
			return nil
		}
		return publisher.PublishCheck(ctx, p.RepoFullName, p.SHA, p.Name, p.Status, p.Conclusion, p.DetailsURL, p.Summary, p.Annotations)
	case forge.OutboxKindGitLabCheck:
		var p forge.CheckPayload
		if err := json.Unmarshal(item.Payload, &p); err != nil {
			return err
		}
		if p.ForgeKind != "gitlab" {
			log.Printf("outbox: dropping gitlab_check with forge kind %q", p.ForgeKind)
			return nil
		}
		return s.gitLabForge().PublishCheck(ctx, p.RepoFullName, p.SHA, p.Name, p.Status, p.Conclusion, p.DetailsURL, p.Summary, p.Annotations)
	case forge.OutboxKindForgejoCheck:
		var p forge.CheckPayload
		if err := json.Unmarshal(item.Payload, &p); err != nil {
			return err
		}
		if p.ForgeKind != "forgejo" {
			log.Printf("outbox: dropping forgejo_check with forge kind %q", p.ForgeKind)
			return nil
		}
		return s.forgejoForge().PublishCheck(ctx, p.RepoFullName, p.SHA, p.Name, p.Status, p.Conclusion, p.DetailsURL, p.Summary, p.Annotations)
	case forge.OutboxKindGitHubStatus:
		var p forge.StatusPayload
		if err := json.Unmarshal(item.Payload, &p); err != nil {
			return err
		}
		return s.publishGitHubStatusFromPayload(ctx, p)
	case forge.OutboxKindDownstream:
		return s.dispatchDownstream(ctx, item)
	case storage.OutboxKindDownstreamCheck, storage.OutboxKindDeploymentFinish,
		storage.OutboxKindUsageAccount, storage.OutboxKindRunAggregate, storage.OutboxKindForgeStatus:
		var p storage.CompletionEffectsPayload
		if err := json.Unmarshal(item.Payload, &p); err != nil {
			return err
		}
		if p.JobID == "" {
			log.Printf("outbox: dropping completion effect %s with empty job id", item.Kind)
			return nil
		}
		return s.reconcileCompletionEffects(ctx, p.JobID)
	case forge.OutboxKindWebhookCall:
		log.Printf("outbox: dropping reserved intent %s (kind %s)", item.ID, item.Kind)
		return nil
	default:
		log.Printf("outbox: dropping unknown intent %s (kind %s)", item.ID, item.Kind)
		return nil
	}
}
