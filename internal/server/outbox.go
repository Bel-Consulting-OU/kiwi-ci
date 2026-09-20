package server

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/forge"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

const (
	outboxFile     = "outbox.jsonl"
	outboxDoneFile = "outbox.done.jsonl"
)

// outboxDoneRecord is one line of the fs done journal. ID is the acked
// intent. LogicalKey/StateVersion form an optional DELIVERED WATERMARK marker:
// legacy (pre-0018) forge-check rows carry no versioned identity on their own
// ack, so the dispatcher stamps the derived identity here after a successful
// publication; a restart rebuilds the fs-mode watermark from these records
// (versioned rows also rebuild it from their versioned IDs, keeping older
// journals readable).
type outboxDoneRecord struct {
	ID           string `json:"id,omitempty"`
	LogicalKey   string `json:"logical_key,omitempty"`
	StateVersion int64  `json:"state_version,omitempty"`
}

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
	// delivered is the highest state_version acknowledged per logical key.
	// It mirrors forge_check_state in DB mode (where the durable guard is
	// authoritative) and is the fs-mode supersede watermark: it is rebuilt
	// from the done file on load, so a stale state re-enqueued after a newer
	// one was delivered is dropped instead of published late.
	delivered map[string]int64
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
	o := &Outbox{store: store, done: map[string]bool{}, localOnly: map[string]bool{}, delivered: map[string]int64{}}
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

// outboxDueStore is the optional due-filtered active read: rows that are not
// dead-lettered AND dispatchable now (next_attempt_at <= now()). PostgresStore
// implements it; stores that cannot express the due filter fall back to
// OutboxPending in dbMirrorItems.
type outboxDueStore interface {
	OutboxDue(ctx context.Context) ([]storage.OutboxItem, error)
}

// dbMirrorItems returns the durable rows ReplayDB and pruneDB may mirror in
// memory. INVARIANT: o.items holds only currently-due, non-dead intents.
// Dead letters are operator-visible only through the dead-letter API, and a
// delayed row (retry backoff in the future) must not stay resident: it is not
// dispatchable yet, so it is not mirrored. Dispatchability itself is always
// decided by ClaimOutbox; a delayed row becomes claimable on the flush tick
// whose due time has arrived, and that claim appends it to o.items then.
//
// A store without OutboxDue (legacy/test stores) can only expose its active
// set: dead letters are still excluded, but rows whose backoff has not
// elapsed cannot be told apart there, so those stay claim-gated like every
// other durable row.
func (o *Outbox) dbMirrorItems(ctx context.Context) ([]storage.OutboxItem, error) {
	if due, ok := o.db.(outboxDueStore); ok {
		return due.OutboxDue(ctx)
	}
	return o.db.OutboxPending(ctx)
}

// ReplayDB loads unacked intents from the SQL store into memory (FIFO).
// Only intents dispatchable now are mirrored (see dbMirrorItems): a delayed
// row is left to the durable claim that fires once its backoff elapses, and
// a dead letter is never resident.
func (o *Outbox) ReplayDB(ctx context.Context) error {
	if o.db == nil {
		return nil
	}
	items, err := o.dbMirrorItems(ctx)
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
		o.items = append(o.items, forge.OutboxItem{
			ID: it.ID, Kind: it.Kind, Payload: it.Payload, CreatedAt: it.CreatedAt,
			LogicalKey: it.LogicalKey, StateVersion: it.StateVersion,
		})
	}
	return nil
}

func (o *Outbox) loadLocked() error {
	done := map[string]bool{}
	delivered := map[string]int64{}
	f, err := os.Open(filepath.Join(o.store.Root, outboxDoneFile))
	if err == nil {
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			var rec outboxDoneRecord
			if json.Unmarshal(sc.Bytes(), &rec) != nil {
				continue
			}
			if rec.ID != "" {
				done[rec.ID] = true
			}
			if rec.LogicalKey != "" && rec.StateVersion > 0 && rec.StateVersion > delivered[rec.LogicalKey] {
				delivered[rec.LogicalKey] = rec.StateVersion
			}
		}
		_ = f.Close()
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	o.done = done
	// Rebuild the fs-mode delivered watermark from the done IDs too: versioned
	// IDs carry their logical key and version, so a stale state re-enqueued
	// after a restart is still recognized as older than what was delivered.
	// This keeps journals written before the explicit watermark records above
	// readable.
	for id := range done {
		if key, version, ok := parseVersionedRowID(id); ok && version > delivered[key] {
			delivered[key] = version
		}
	}
	o.delivered = delivered

	items, err := o.readItems()
	if err != nil {
		return err
	}
	o.items = o.items[:0]
	for _, it := range items {
		if done[it.ID] {
			continue
		}
		// Superseded-but-unacked lines survive in the append-only JSONL:
		// drop them at load when a newer version of the same logical key was
		// already delivered, so a restart can never publish an older state
		// after a newer one.
		if it.LogicalKey != "" && it.StateVersion > 0 && o.delivered[it.LogicalKey] >= it.StateVersion {
			continue
		}
		o.items = append(o.items, it)
	}
	return nil
}

// parseVersionedRowID splits a versioned outbox row ID (logicalKey#version)
// back into its parts. Non-versioned IDs (random hex) report ok=false.
func parseVersionedRowID(id string) (key string, version int64, ok bool) {
	i := strings.LastIndexByte(id, '#')
	if i <= 0 || i == len(id)-1 {
		return "", 0, false
	}
	v, err := strconv.ParseInt(id[i+1:], 10, 64)
	if err != nil || v <= 0 {
		return "", 0, false
	}
	return id[:i], v, true
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

// ErrOutboxIDConflict marks an invariant violation: an intent ID that is
// already queued was enqueued again with DIFFERENT content. Deterministic IDs
// make replays idempotent (same ID + same content is success), but reusing an
// ID for a different operation would map two distinct effects onto one durable
// intent, so it must fail loudly instead of silently succeeding.
var ErrOutboxIDConflict = errors.New("outbox: intent ID reused with different content")

// outboxIDConflictError names the conflicting intent ID; it unwraps to
// ErrOutboxIDConflict so callers can match with errors.Is.
type outboxIDConflictError struct{ id string }

func (e *outboxIDConflictError) Error() string {
	return fmt.Sprintf("outbox: intent %s already exists with different content", e.id)
}

func (e *outboxIDConflictError) Unwrap() error { return ErrOutboxIDConflict }

// sameOutboxContent mirrors the durable OutboxAppend idempotency rule: the
// same ID with the same kind, payload and versioned identity is a replay;
// anything else is an invariant conflict. Payloads compare semantically
// because durable JSON columns normalize whitespace/key order on read, and an
// empty payload is normalized to "{}" exactly like OutboxAppend does.
func sameOutboxContent(existing, incoming forge.OutboxItem) bool {
	if existing.Kind != incoming.Kind {
		return false
	}
	if existing.LogicalKey != incoming.LogicalKey || existing.StateVersion != incoming.StateVersion {
		return false
	}
	a, b := existing.Payload, incoming.Payload
	if len(a) == 0 {
		a = []byte("{}")
	}
	if len(b) == 0 {
		b = []byte("{}")
	}
	if bytes.Equal(a, b) {
		return true
	}
	var x, y any
	if json.Unmarshal(a, &x) != nil || json.Unmarshal(b, &y) != nil {
		return false
	}
	return reflect.DeepEqual(x, y)
}

// Enqueue appends one intent DURABLY FIRST and only then makes it
// dispatchable. In DB mode a failed durable write returns the error and the
// item is NOT queued: an external side effect must never be dispatchable
// from RAM alone, because a crash would erase the record of work that
// already happened. Callers retry the whole operation; deterministic IDs
// make the retry converge on one row.
//
// ctx is the caller's REQUEST or RECONCILIATION context and is threaded into
// the durable store call: a canceled request aborts the enqueue before
// anything becomes durable or dispatchable (the caller's retry re-runs the
// whole operation; deterministic IDs converge on one row). The fs path is
// synchronous and not interruptible, so cancellation is honored at the
// operation boundary — before any mutation — and never leaves a partial
// JSONL line behind. A caller that intentionally wants the intent recorded
// even though its own request is gone must pass a bounded detach
// (boundedDetach), never a bare Background.
//
// VERSIONED intents (LogicalKey + StateVersion, forge checks) additionally
// SUPERSEDE older pending versions of the same logical key durably in the
// same operation as the insert. A version that is not newer than the
// delivered watermark is dropped (the newer state is already published or
// pending), and a newer version is never blocked by an older dead-lettered
// row because the row ID is versioned.
func (o *Outbox) Enqueue(ctx context.Context, item forge.OutboxItem) error {
	if err := ctx.Err(); err != nil {
		return err
	}
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
	if item.LogicalKey != "" && item.StateVersion > 0 {
		return o.enqueueVersionedLocked(ctx, item)
	}
	// Idempotent by ID: deterministic intents (downstream launches keyed by
	// the link's stable key, completion effects keyed by job/generation/kind)
	// are replayed after lost ACKs and must converge on ONE durable intent. An
	// ID already in the done set was DELIVERED and retired: re-enqueueing it
	// would dispatch the same effect a second time.
	if o.done[item.ID] {
		return nil
	}
	for _, it := range o.items {
		if it.ID == item.ID {
			// An ID already queued is a replay only when the content matches.
			// A reused ID with a different payload/kind is an invariant
			// conflict (two operations mapped onto one durable intent) and
			// must never be silently acknowledged as success.
			if !sameOutboxContent(it, item) {
				return &outboxIDConflictError{id: item.ID}
			}
			return nil
		}
	}
	if o.db != nil {
		if err := o.db.OutboxAppend(ctx, storage.OutboxItem{
			ID: item.ID, Kind: item.Kind, Payload: item.Payload, CreatedAt: item.CreatedAt,
		}); err != nil {
			return err
		}
		o.items = append(o.items, item)
		return nil
	}
	if o.store == nil {
		o.items = append(o.items, item)
		return nil
	}
	if err := o.appendJSONLLocked(outboxFile, item); err != nil {
		return err
	}
	o.items = append(o.items, item)
	return nil
}

// enqueueVersionedLocked applies the versioned durable-first contract. The
// caller holds o.mu. ctx is the caller's request/reconciliation context and
// reaches the durable versioned enqueue, which is where the supersede and the
// watermark guard run; a canceled context aborts before that statement so no
// row is inserted or superseded. The fs path checks ctx at the boundary only
// (see Enqueue).
func (o *Outbox) enqueueVersionedLocked(ctx context.Context, item forge.OutboxItem) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if o.db != nil {
		vgs, ok := o.db.(storage.ForgeCheckStateStore)
		if !ok {
			// Fail closed: without the versioned contract the durable store
			// cannot supersede older pending rows or enforce the delivered
			// watermark, which is exactly the P1 defect. Every shipped store
			// implements it; this is a programming-error guard, not a
			// supported mode.
			return fmt.Errorf("outbox: store lacks the versioned forge-check enqueue contract for logical key %q", item.LogicalKey)
		}
		outcome, err := vgs.OutboxEnqueueVersioned(ctx, storage.OutboxItem{
			ID: item.ID, Kind: item.Kind, Payload: item.Payload, CreatedAt: item.CreatedAt,
			LogicalKey: item.LogicalKey, StateVersion: item.StateVersion,
		})
		if err != nil {
			return err
		}
		// Mirror the durable supersede locally regardless of the outcome:
		// older local copies are never dispatchable once a newer state is
		// visible.
		o.supersedeLocked(item.LogicalKey, item.StateVersion)
		if outcome == storage.VersionedSuperseded {
			return nil
		}
		o.items = append(o.items, item)
		return nil
	}
	// fs mode: the local queue is the durable store. Drop a version at or
	// below the delivered watermark (rebuilding it from the done file is
	// what makes this survive a restart), then supersede older pending
	// versions. The supersede is durable: the superseded lines are retired
	// through the done file in the SAME operation as the new line, so a
	// restart can never replay an older state.
	if o.delivered[item.LogicalKey] >= item.StateVersion {
		o.retireSupersededLocked(o.supersededIDsLocked(item.ID, item.LogicalKey, item.StateVersion))
		return nil
	}
	superseded := o.supersededIDsLocked(item.ID, item.LogicalKey, item.StateVersion)
	if o.store != nil {
		if err := o.appendJSONLLocked(outboxFile, item); err != nil {
			return err
		}
		for _, id := range superseded {
			if err := o.appendJSONLLocked(outboxDoneFile, outboxDoneRecord{ID: id}); err != nil {
				return err
			}
		}
	}
	o.retireSupersededLocked(superseded)
	// An equal-version copy is replaced in place (fresh payload), never
	// duplicated in the queue.
	o.removeLocked(item.ID)
	o.items = append(o.items, item)
	return nil
}

// supersededIDsLocked returns the queued IDs of the same logical key whose
// state version is at or below the new version, EXCLUDING an item with the
// incoming row's exact ID (an equal-version payload refresh replaces that
// copy in place instead of retiring it). The caller holds o.mu.
func (o *Outbox) supersededIDsLocked(newID, logicalKey string, version int64) []string {
	var ids []string
	for _, it := range o.items {
		if it.LogicalKey == logicalKey && it.StateVersion <= version && it.ID != newID {
			ids = append(ids, it.ID)
		}
	}
	return ids
}

// retireSupersededLocked removes superseded intents from the queue and marks
// them retired locally. The caller holds o.mu.
func (o *Outbox) retireSupersededLocked(ids []string) {
	if len(ids) == 0 {
		return
	}
	if o.done == nil {
		o.done = map[string]bool{}
	}
	for _, id := range ids {
		o.removeLocked(id)
		o.done[id] = true
		delete(o.localOnly, id)
	}
}

// supersedeLocked removes every queued intent of the same logical key whose
// state version is at or below the new version. The caller holds o.mu.
func (o *Outbox) supersedeLocked(logicalKey string, version int64) {
	kept := o.items[:0]
	for _, it := range o.items {
		if it.LogicalKey == logicalKey && it.StateVersion <= version {
			delete(o.localOnly, it.ID)
			continue
		}
		kept = append(kept, it)
	}
	o.items = kept
}

// recordDeliveredLocked advances the local delivered watermark for a
// versioned item. The caller holds o.mu.
func (o *Outbox) recordDeliveredLocked(it forge.OutboxItem) {
	if it.LogicalKey == "" || it.StateVersion <= 0 {
		return
	}
	if o.delivered == nil {
		o.delivered = map[string]int64{}
	}
	if it.StateVersion > o.delivered[it.LogicalKey] {
		o.delivered[it.LogicalKey] = it.StateVersion
	}
}

// Superseded reports whether a forge-check state must not be published in
// fs/memory mode: a version at or below the delivered watermark, or a
// strictly newer version still queued. It is the fs-mode version guard for
// LEGACY (unversioned) rows, whose payload carries no identity of its own, so
// the dispatcher derives the identity and asks here before publishing.
func (o *Outbox) Superseded(logicalKey string, version int64) bool {
	if logicalKey == "" || version <= 0 {
		return false
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.delivered[logicalKey] >= version {
		return true
	}
	for _, it := range o.items {
		if it.LogicalKey == logicalKey && it.StateVersion > version {
			return true
		}
	}
	return false
}

// MarkDelivered durably advances the fs-mode delivered watermark for one
// logical key after a successful publication. It is used for LEGACY
// (unversioned) forge-check rows: their own ack carries no identity, so
// without this stamp a stale state re-enqueued after the restart could
// publish over a newer delivered one. Versioned items keep advancing the
// watermark through their ack (recordDeliveredLocked); this method is
// idempotent and never lowers it.
func (o *Outbox) MarkDelivered(logicalKey string, version int64) error {
	if logicalKey == "" || version <= 0 {
		return nil
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.delivered[logicalKey] >= version {
		return nil
	}
	// Durability first: a watermark the journal does not hold must not be
	// reported as delivered, or a restart would allow the stale publication
	// this guard exists to prevent.
	if o.store != nil {
		if err := o.appendJSONLLocked(outboxDoneFile, outboxDoneRecord{LogicalKey: logicalKey, StateVersion: version}); err != nil {
			return err
		}
	}
	if o.delivered == nil {
		o.delivered = map[string]int64{}
	}
	o.delivered[logicalKey] = version
	return nil
}

// QueueKnownDurable registers an intent whose durable row was ALREADY
// appended (the downstream path writes the row inside its own critical
// section). It never re-appends and never marks anything process-local, so
// misuse cannot double-insert an ID or dispatch outside the DB claim.
func (o *Outbox) QueueKnownDurable(item forge.OutboxItem) {
	o.mu.Lock()
	defer o.mu.Unlock()
	for _, it := range o.items {
		if it.ID == item.ID {
			return
		}
	}
	o.items = append(o.items, item)
}

// EnqueueLocal queues one intent in memory only, without touching the
// durable store. It is used for intents whose rows were already created
// inside another transaction (completion effect intents written by
// storage.CompleteJob): the local copy lets this instance dispatch and ack
// the pre-existing rows under the same IDs.
//
// HasIntent reports whether an intent with this ID is currently queued in
// this process (a durable local mirror, a local-only item or a pre-existing
// row registered through QueueKnownDurable). It compares IDs only, never
// content, so it must NOT be used to treat a duplicate enqueue as success:
// Outbox.Enqueue already returns nil for an identical-content replay and
// ErrOutboxIDConflict when the ID carries different content.
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

		// Defense in depth for the fs queue: never publish a version at or
		// below the delivered watermark, and never publish an older version
		// while a newer one of the same logical key is still queued (a stale
		// line replayed from a previous process, or an older version that
		// lost a supersede race).
		if it.LogicalKey != "" && it.StateVersion > 0 {
			o.mu.Lock()
			stale := o.delivered[it.LogicalKey] >= it.StateVersion
			if !stale {
				for _, other := range o.items {
					if other.LogicalKey == it.LogicalKey && other.StateVersion > it.StateVersion {
						stale = true
						break
					}
				}
			}
			if stale {
				o.removeLocked(it.ID)
				o.done[it.ID] = true
				o.mu.Unlock()
				continue
			}
			o.mu.Unlock()
		}

		if err := dispatch(ctx, it); err != nil {
			return dispatched, err
		}
		// Durable ack BEFORE the local removal: a failed ack leaves the
		// intent queued and it is retried (idempotently) next tick.
		if o.store != nil {
			rec := outboxDoneRecord{ID: it.ID}
			if it.LogicalKey != "" && it.StateVersion > 0 {
				// Persist the versioned identity explicitly so the watermark
				// rebuild does not depend on parsing the row ID alone.
				rec.LogicalKey = it.LogicalKey
				rec.StateVersion = it.StateVersion
			}
			if err := o.appendJSONLLocked(outboxDoneFile, rec); err != nil {
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
		o.recordDeliveredLocked(it)
		dispatched++
		o.mu.Unlock()
	}
}

// outboxFlushMaxBatches bounds how many claim batches one Flush call
// processes, so a dispatch path that keeps enqueueing follow-up intents can
// never trap the flush in an unbounded loop (the remainder waits for the
// next tick).
const outboxFlushMaxBatches = 64

// outboxClaimReleaseTimeout bounds one claim-cleanup statement issued after
// dispatch (see releaseOutboxClaimCleanup).
const outboxClaimReleaseTimeout = 5 * time.Second

// outboxFlushTimeout bounds one outbox flush cycle (see flushOutbox).
const outboxFlushTimeout = 2 * time.Minute

// outboxDetachTimeout bounds an enqueue that intentionally outlives the
// request that triggered it (boundedDetach call sites).
const outboxDetachTimeout = 5 * time.Second

// boundedDetach derives the context for a durable operation that deliberately
// OUTLIVES its origin: the request may be gone (client hung up) while the
// intent must still be recorded, so cancellation is dropped. The detach is
// never unbounded — a stalled store must not pin the goroutine forever — so a
// fresh timeout is imposed around the derived context. Values (tracing,
// request IDs) are preserved when an origin exists. origin may be nil for
// call paths that have no caller context to thread (the shared run-enqueue
// plumbing); the detach is still bounded. This is the ONLY sanctioned way to
// detach in this package: a bare Background at a request-coupled call site is
// the defect this helper exists to prevent.
func boundedDetach(origin context.Context, bound time.Duration) (context.Context, context.CancelFunc) {
	if origin == nil {
		origin = context.Background() // allow-background: detach root for context-free call paths
	}
	return context.WithTimeout(context.WithoutCancel(origin), bound)
}

// releaseOutboxClaimCleanup releases one claimed-but-unhandled outbox row
// with a context that OUTLIVES the dispatch context. flushOutbox bounds the
// dispatch to two minutes and the caller may cancel it sooner; a release on
// that context reaches PostgreSQL already cancelled, so pgx refuses it and
// (if the error were discarded) up to OutboxClaimBatch claimed rows would stay
// invisible to every other replica until OutboxClaimTTL. The boundedDetach
// helper is the ONLY sanctioned detach in this package: it drops cancellation
// while preserving values and imposes a FRESH timeout per release (rather than
// one per flush), so each release gets a full window even though the deferred
// cleanup runs after the batch dispatch, when a context created at claim time
// could already be expired. Failures are logged with the row ID instead of
// discarded: the row stays durable and is reclaimed after the TTL, but the
// operator must see why the retry is delayed.
func (o *Outbox) releaseOutboxClaimCleanup(ctx context.Context, id, claimer string) {
	cleanupCtx, cancel := boundedDetach(ctx, outboxClaimReleaseTimeout)
	defer cancel()
	if err := o.db.ReleaseOutboxClaim(cleanupCtx, id, claimer); err != nil {
		log.Printf("outbox: release claim for %s: %v (row stays claimed until OutboxClaimTTL)", id, err)
	}
}

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
			o.items = append(o.items, forge.OutboxItem{
				ID: it.ID, Kind: it.Kind, Payload: it.Payload, CreatedAt: it.CreatedAt,
				LogicalKey: it.LogicalKey, StateVersion: it.StateVersion,
			})
		}
	}
	o.mu.Unlock()

	dispatched := 0
	var failed []string
	// acked records the claimed rows this call ACKed durably. The deferred
	// release then covers EVERY OTHER claimed row, so the batch invariant is
	// simply "every claimed row ends this call ACKed or released". Deciding
	// "handled" from local-queue membership was wrong: after an early ACK
	// error every not-yet-dispatched claimed row is still queued locally and
	// its claim was left held until OutboxClaimTTL expired. Every release (the
	// explicit ones above/below and this deferred sweep) runs through
	// releaseOutboxClaimCleanup, whose context survives the dispatch context:
	// this cleanup runs exactly when that context may already be cancelled or
	// expired, and a claim stranded there hides the row from every other
	// replica for the whole TTL. Releasing an already-ACKed row or a claim
	// this call already released is a no-op in every store (they clear only
	// the caller's own claim).
	acked := make(map[string]bool, len(claimed))
	defer func() {
		for _, it := range claimed {
			if acked[it.ID] {
				continue
			}
			o.releaseOutboxClaimCleanup(ctx, it.ID, claimer)
		}
	}()
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

		if derr := dispatch(ctx, it); derr != nil {
			// Record the attempt with bounded backoff (dead-letter after
			// maxOutboxAttempts) instead of hot-looping, then CONTINUE with
			// the other independent rows in this batch. Internal
			// consistency rows retry WITHOUT a dead-letter cap: their
			// invariants must converge, and an operator can still see the
			// row as pending (with its last error) forever.
			if owned[it.ID] {
				if rerr := o.retryOutboxRow(ctx, it, derr); rerr != nil {
					log.Printf("outbox: retry record %s: %v", it.ID, rerr)
				}
				o.releaseOutboxClaimCleanup(ctx, it.ID, claimer)
			}
			// Drop the FAILED attempt from the local queue: the durable row
			// (with next_attempt_at) is the retry vehicle, and leaving it
			// queued would make this loop re-pick it forever.
			o.mu.Lock()
			o.removeLocked(it.ID)
			o.mu.Unlock()
			failed = append(failed, it.ID)
			continue
		}
		// Durable ACK BEFORE the local removal (and before the claim is
		// considered satisfied): an ack failure keeps the item queued and
		// releases the claim so the retry does not wait out the TTL.
		if err := o.db.OutboxAck(ctx, it.ID); err != nil {
			if owned[it.ID] {
				o.releaseOutboxClaimCleanup(ctx, it.ID, claimer)
			}
			return dispatched, len(claimed), err
		}
		// Durable ACK succeeded: this claim is satisfied and must not be
		// released by the deferred cleanup.
		acked[it.ID] = true
		o.mu.Lock()
		o.removeLocked(it.ID)
		o.done[it.ID] = true
		o.recordDeliveredLocked(it)
		delete(o.localOnly, it.ID)
		dispatched++
		o.mu.Unlock()
	}
	o.pruneDB(ctx)
	if len(failed) > 0 {
		// Per-row failures are durably recorded with backoff (or
		// dead-lettered); the error is still returned AFTER the batch so the
		// caller can log/alert without stopping unrelated rows.
		return dispatched, len(claimed), fmt.Errorf("outbox: %d intent(s) failed dispatch and were recorded for retry: %v", len(failed), failed)
	}
	return dispatched, len(claimed), nil
}

// maxOutboxAttempts is the dead-letter threshold: a dispatch that keeps
// failing (permanent auth misconfiguration, invalid payload) is parked with
// its error instead of retried forever.
const maxOutboxAttempts = 8

// errUnknownOutboxKind marks a durable intent whose kind this binary does not
// know (a NEWER replica's row during a rolling upgrade, or a downgrade). It
// must never be dropped (ACK) or dead-lettered by an older replica: the row
// has to survive until a replica that understands it claims it.
var errUnknownOutboxKind = errors.New("outbox: unknown intent kind")

// unknownOutboxKindError names the kind that could not be dispatched.
type unknownOutboxKindError struct{ kind string }

func (e *unknownOutboxKindError) Error() string {
	return fmt.Sprintf("outbox: unknown intent kind %q left pending for a newer replica", e.kind)
}

func (e *unknownOutboxKindError) Unwrap() error { return errUnknownOutboxKind }

// retryOutboxRow records a failed attempt through the store when it supports
// retry metadata; older stores simply keep the row claimed/released as
// before. Two classes never consume the dead-letter budget:
//
//   - internal consistency rows (completion effects whose dispatch runs the
//     marker-guarded reconciliation chain): a persistently failing dependency
//     must not retire the row that converges internal markers/effects; it
//     keeps backing off and stays visible as pending with its last error.
//   - UNKNOWN kinds: an old replica must neither ACK nor dead-letter a row
//     only a newer replica can process, so the row survives the rolling
//     upgrade with bounded backoff instead of hot-looping.
func (o *Outbox) retryOutboxRow(ctx context.Context, it forge.OutboxItem, dispatchErr error) error {
	if rs, ok := o.db.(interface {
		OutboxRetry(context.Context, string, error, int) error
	}); ok {
		maxAttempts := maxOutboxAttempts
		if errors.Is(dispatchErr, errUnknownOutboxKind) || storage.InternalCompletionEffectKind(it.Kind) {
			maxAttempts = 0
		}
		return rs.OutboxRetry(ctx, it.ID, dispatchErr, maxAttempts)
	}
	return nil
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
// (no durable row) are never pruned. The live set is the SAME due-only set
// ReplayDB mirrors (dbMirrorItems), so a row that stopped being dispatchable
// (retry backoff) is not kept resident, and a dead letter is dropped.
func (o *Outbox) pruneDB(ctx context.Context) {
	pending, err := o.dbMirrorItems(ctx)
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

// flushOutbox drains the server's outbox through the forge dispatch path. It
// is called from the Maintain loop with the loop's lifecycle context; a
// canceled/expired tick context therefore does not abort a cycle that already
// started (a claim released mid-cycle, or an ACK skipped after a successful
// forge POST, forces a full retry and hides the row from other replicas until
// the claim TTL). The detach is BOUNDED: a stalled store or forge cannot pin
// the maintain loop forever. Unhandled intents are dropped with a log line
// rather than blocking the queue forever.
func (s *Server) flushOutbox(ctx context.Context) {
	flushCtx, cancel := boundedDetach(ctx, outboxFlushTimeout)
	defer cancel()
	if _, err := s.outbox.Flush(flushCtx, s.dispatchOutbox); err != nil {
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
		if ok, gerr := s.forgeCheckDispatchable(ctx, item, p); gerr != nil {
			return gerr
		} else if !ok {
			log.Printf("outbox: skipping superseded forge check %s", item.ID)
			return nil
		}
		publisher := s.gitHubForge()
		if p.RunID != "" {
			// One publication at a time per logical check: two dispatchers
			// seeing "no mapping" would otherwise both POST before either
			// mapping is installed. Re-check the version guard INSIDE the
			// fence: a newer version may have been enqueued while this
			// dispatcher waited, and the fence makes the newer publication
			// wait for this one, so the final remote state is the newest.
			publish, release, ferr := s.fenceVersionedCheck(ctx, item, p)
			if ferr != nil {
				return ferr
			}
			defer release()
			if !publish {
				log.Printf("outbox: skipping superseded forge check %s", item.ID)
				return nil
			}
			if idp, ok := interface{}(publisher).(forge.CheckRunPublisher); ok {
				key := s.checkRunKey(p.RunID, p.Name)
				existing, err := s.getCheckRunID(ctx, key)
				if err != nil {
					// Fail the dispatch (no ACK): retrying with a read error must
					// not POST a duplicate.
					return err
				}
				logicalID := p.RunID + "\x00" + p.Name
				id, err := idp.PublishCheckRun(ctx, logicalID, p.RepoFullName, p.SHA, p.Name, p.Status, p.Conclusion, p.DetailsURL, p.Summary, p.Annotations, existing)
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
				return s.markForgeCheckDelivered(ctx, item, p)
			}
		}
		if err := publisher.PublishCheck(ctx, p.RepoFullName, p.SHA, p.Name, p.Status, p.Conclusion, p.DetailsURL, p.Summary, p.Annotations); err != nil {
			return err
		}
		return s.markForgeCheckDelivered(ctx, item, p)
	case forge.OutboxKindGitLabCheck:
		var p forge.CheckPayload
		if err := json.Unmarshal(item.Payload, &p); err != nil {
			return err
		}
		if p.ForgeKind != "gitlab" {
			log.Printf("outbox: dropping gitlab_check with forge kind %q", p.ForgeKind)
			return nil
		}
		if ok, gerr := s.forgeCheckDispatchable(ctx, item, p); gerr != nil {
			return gerr
		} else if !ok {
			log.Printf("outbox: skipping superseded forge check %s", item.ID)
			return nil
		}
		publish, release, ferr := s.fenceVersionedCheck(ctx, item, p)
		if ferr != nil {
			return ferr
		}
		defer release()
		if !publish {
			log.Printf("outbox: skipping superseded forge check %s", item.ID)
			return nil
		}
		if err := s.gitLabForge().PublishCheck(ctx, p.RepoFullName, p.SHA, p.Name, p.Status, p.Conclusion, p.DetailsURL, p.Summary, p.Annotations); err != nil {
			return err
		}
		return s.markForgeCheckDelivered(ctx, item, p)
	case forge.OutboxKindForgejoCheck:
		var p forge.CheckPayload
		if err := json.Unmarshal(item.Payload, &p); err != nil {
			return err
		}
		if p.ForgeKind != "forgejo" {
			log.Printf("outbox: dropping forgejo_check with forge kind %q", p.ForgeKind)
			return nil
		}
		if ok, gerr := s.forgeCheckDispatchable(ctx, item, p); gerr != nil {
			return gerr
		} else if !ok {
			log.Printf("outbox: skipping superseded forge check %s", item.ID)
			return nil
		}
		publish, release, ferr := s.fenceVersionedCheck(ctx, item, p)
		if ferr != nil {
			return ferr
		}
		defer release()
		if !publish {
			log.Printf("outbox: skipping superseded forge check %s", item.ID)
			return nil
		}
		if err := s.forgejoForge().PublishCheck(ctx, p.RepoFullName, p.SHA, p.Name, p.Status, p.Conclusion, p.DetailsURL, p.Summary, p.Annotations); err != nil {
			return err
		}
		return s.markForgeCheckDelivered(ctx, item, p)
	case forge.OutboxKindGitHubStatus:
		var p forge.StatusPayload
		if err := json.Unmarshal(item.Payload, &p); err != nil {
			return err
		}
		return s.publishGitHubStatusFromPayload(ctx, p)
	case forge.OutboxKindDownstream:
		return s.dispatchDownstream(ctx, item)
	case storage.OutboxKindCompletionReconcile:
		var p storage.CompletionEffectsPayload
		if err := json.Unmarshal(item.Payload, &p); err != nil {
			return err
		}
		if p.JobID == "" {
			log.Printf("outbox: dropping completion reconcile with empty job id")
			return nil
		}
		return s.reconcileCompletionEffects(ctx, p.JobID)
	case storage.OutboxKindForgeDelivery:
		// External forge publication is its OWN intent: a persistently
		// failing forge backs off and may dead-letter here without ever
		// retiring the internal completion_reconcile row.
		var p storage.CompletionEffectsPayload
		if err := json.Unmarshal(item.Payload, &p); err != nil {
			return err
		}
		if p.JobID == "" {
			log.Printf("outbox: dropping forge delivery with empty job id")
			return nil
		}
		return s.dispatchForgeDelivery(ctx, p.JobID)
	case storage.OutboxKindForgeStatus:
		// Legacy pre-split forge_status rows publish the run's terminal
		// state, exactly like the new forge_delivery kind.
		var p storage.CompletionEffectsPayload
		if err := json.Unmarshal(item.Payload, &p); err != nil {
			return err
		}
		if p.JobID == "" {
			log.Printf("outbox: dropping legacy forge status with empty job id")
			return nil
		}
		return s.dispatchForgeDelivery(ctx, p.JobID)
	case storage.OutboxKindDownstreamCheck, storage.OutboxKindDeploymentFinish,
		storage.OutboxKindUsageAccount, storage.OutboxKindRunAggregate:
		// Legacy rows persisted before the single-row design: run the same
		// idempotent internal chain (markers make the extra kinds no-ops).
		var p storage.CompletionEffectsPayload
		if err := json.Unmarshal(item.Payload, &p); err != nil {
			return err
		}
		if p.JobID == "" {
			log.Printf("outbox: dropping legacy completion effect %s with empty job id", item.Kind)
			return nil
		}
		return s.reconcileCompletionEffects(ctx, p.JobID)
	case forge.OutboxKindWebhookCall:
		log.Printf("outbox: dropping reserved intent %s (kind %s)", item.ID, item.Kind)
		return nil
	default:
		// An unknown kind (a newer binary's row during a rolling upgrade) is
		// never dropped or dead-lettered by this replica: return the typed
		// error so the flush releases the claim and the row survives with
		// backoff until a replica that understands it processes it.
		return &unknownOutboxKindError{kind: item.Kind}
	}
}

// fenceVersionedCheck acquires the per-logical-check publication fence (when
// the payload carries a run identity) and re-applies the version guard INSIDE
// it. Two publications for one logical check are therefore serialized and the
// version check is made against committed state, so an older state can never
// be published after a newer one was enqueued or delivered. The returned
// release is idempotent; publish=false means the guard retired this row.
func (s *Server) fenceVersionedCheck(ctx context.Context, item forge.OutboxItem, p forge.CheckPayload) (publish bool, release func(), err error) {
	if p.RunID == "" {
		return true, func() {}, nil
	}
	unlock, lerr := s.lockCheckRunKey(ctx, s.checkRunKey(p.RunID, p.Name))
	if lerr != nil {
		return false, nil, lerr
	}
	publish, gerr := s.forgeCheckDispatchable(ctx, item, p)
	if gerr != nil {
		unlock()
		return false, nil, gerr
	}
	if !publish {
		unlock()
		return false, func() {}, nil
	}
	return true, unlock, nil
}

// forgeCheckIdentity resolves the versioned delivery identity of a
// forge-check intent. Versioned rows carry it in the durable columns and/or
// the payload. LEGACY pre-0018 rows carry neither: their identity is DERIVED
// from the payload's stable coordinates (forge host + run + check name) and
// the status rank, so the same durable watermark guard (and the same
// post-publication stamp) applies to them. ok=false means the payload does
// not even carry the coordinates to derive from; legacy=true marks a derived
// identity whose publication must stamp the watermark explicitly.
func forgeCheckIdentity(item forge.OutboxItem, p forge.CheckPayload) (logicalKey string, version int64, legacy bool, ok bool) {
	if item.LogicalKey != "" && item.StateVersion > 0 {
		return item.LogicalKey, item.StateVersion, false, true
	}
	if p.LogicalKey != "" && p.StateVersion > 0 {
		return p.LogicalKey, p.StateVersion, false, true
	}
	if p.RunID == "" || p.Name == "" {
		return "", 0, false, false
	}
	return forgeCheckLogicalKey(p.ForgeHost, p.RunID, p.Name), checkStateVersion(p.Status), true, true
}

// markForgeCheckDelivered stamps the durable delivered watermark after a
// successful forge publication of a LEGACY (pre-0018) forge-check row: its
// own ack carries no logical_key/state_version columns, so without this stamp
// a stale legacy state re-enqueued later (or a versioned state enqueued after
// it) could regress a newer delivered state. Versioned rows return
// immediately: OutboxAck advances their watermark atomically. A stamp failure
// fails the dispatch (no ACK) so the retry repeats the idempotent publication
// and the stamp together.
func (s *Server) markForgeCheckDelivered(ctx context.Context, item forge.OutboxItem, p forge.CheckPayload) error {
	logicalKey, version, legacy, ok := forgeCheckIdentity(item, p)
	if !ok || !legacy {
		return nil
	}
	if s.DB == nil {
		return s.outbox.MarkDelivered(logicalKey, version)
	}
	vgs, ok := s.DB.(storage.ForgeCheckStateStore)
	if !ok {
		return fmt.Errorf("outbox: store lacks the versioned forge-check guard contract")
	}
	return vgs.OutboxMarkDelivered(ctx, logicalKey, version)
}

// forgeCheckDispatchable applies the durable version guard to a forge-check
// intent, deriving the delivery identity for legacy unversioned rows. In DB
// mode the guard is authoritative across replicas: a row that no longer
// exists (superseded), a delivered version at or above this one, or a newer
// pending version all mean this publication must be skipped. A guard failure
// fails the dispatch (never publish without the guard). In fs/memory mode the
// in-process queue already superseded older pending versions at enqueue time
// and dispatches FIFO; its delivered watermark (rebuilt from the done
// journal) is consulted here so a legacy row cannot regress it either.
func (s *Server) forgeCheckDispatchable(ctx context.Context, item forge.OutboxItem, p forge.CheckPayload) (bool, error) {
	logicalKey, version, _, ok := forgeCheckIdentity(item, p)
	if !ok {
		// No identity to guard on (malformed legacy payload): preserve the
		// historical behavior instead of blocking the row forever.
		return true, nil
	}
	if s.DB == nil {
		return !s.outbox.Superseded(logicalKey, version), nil
	}
	vgs, ok := s.DB.(storage.ForgeCheckStateStore)
	if !ok {
		// Fail closed: a store without the versioned guard cannot prove the
		// state ordering the P1 fix requires. Every shipped store implements
		// it; this is a programming-error guard, not a supported mode.
		return false, fmt.Errorf("outbox: store lacks the versioned forge-check guard contract")
	}
	publish, err := vgs.OutboxVersionGuard(ctx, item.ID, logicalKey, version)
	if err != nil {
		return false, err
	}
	return publish, nil
}
