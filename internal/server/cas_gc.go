package server

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/blob"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/cache"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// Reference-aware CAS garbage collection.
//
// The content-addressed store is append/deduplicate only: no write path ever
// deletes an object, and a failed Put or metadata commit leaves at most an
// unreferenced object. This file is the only deleter. It computes the set of
// live digests from every durable reference source (artifact records and
// their provenance/SBOM/sigstore sidecars, snapshot records, shared-cache
// manifests, durable pending-sidecar rows, and the fs-mode mirrors), then
// deletes every enumerated object that is absent from that set.
//
// Policy:
//   - Age floor (default 24h, CASGCMinAge): only objects whose last write is
//     older than the floor are candidates. Every upload writes the object
//     BEFORE recording the reference, so a reference created concurrently
//     with a pass names an object that is either brand-new (protected by the
//     floor) or was re-put, which refreshes the object's mtime on both
//     backends (FS touches the file, S3 PutObject rewrites it).
//   - Batch bound (default 1000, CASGCBatch): a single pass removes at most
//     this many objects, so a GC bug or a misconfigured reference source can
//     never mass-delete a store in one tick.
//   - HA lease: in DB mode a dedicated transaction-scoped Postgres advisory
//     lock (storage.CASGCLeaseStore) lets exactly one replica collect; in
//     memory/fs mode a single-flight mutex does the same within the
//     process. A replica that cannot take the lease skips the pass.
//   - Fail closed: any reference-read error, enumeration error, or missing
//     enumeration capability aborts the pass before deleting anything.
//   - Staging files (".tmp" scratch files) are never enumerated, and
//     pending-sidecar digests are part of the reference set, so an upload
//     window can never be collected.
//
// Residual race, documented rather than hidden: reference collection and the
// delete sweep are not atomic. The dangerous interleaving is a long-dead
// object (older than the floor) being re-put at the same moment a pass
// decides to delete it: the reference is recorded after the pass read the
// reference set, and on the FS backend a deduplicated re-put only refreshes
// the mtime, which the pass may already have observed as old. The window is
// bounded by one pass (a single enumeration, at most CASGCBatch deletes) and
// by the hourly Maintain cadence; an object caught in it is restored by the
// next upload of the same content, since CAS Put is idempotent. Every
// reference created by a NEW upload names a fresh object and is fully
// protected by the age floor.

// casGCAfterEnumeration is a test seam invoked between reference
// collection and the delete sweep, so tests can publish a digest in exactly
// the window the fence must protect. Production leaves it nil.
var casGCAfterEnumeration func()

const (
	// defaultCASGCInterval is how often Maintain runs a CAS GC pass.
	defaultCASGCInterval = time.Hour
	// defaultCASGCMinAge is the default object age floor.
	defaultCASGCMinAge = 24 * time.Hour
	// defaultCASGCBatch bounds the objects removed by one pass.
	defaultCASGCBatch = 1000
	// casGCLeaseKey is the advisory-lock slot that serializes collectors.
	casGCLeaseKey = "kiwi-cas-gc"
)

// casDigestRE matches the canonical lowercase-hex SHA-256 digest form used by
// every reference field.
var casDigestRE = regexp.MustCompile(`^[a-f0-9]{64}$`)

// errCASGCBatchDone stops the enumeration once the batch bound is reached;
// it is a sentinel internal to one pass, never surfaced to callers.
var errCASGCBatchDone = errors.New("cas gc: batch bound reached")

// casGCOptions configures one collection pass. Zero values resolve to the
// package defaults.
type casGCOptions struct {
	// MinAge is the object age floor: objects written more recently are
	// never deleted.
	MinAge time.Duration
	// Batch bounds the number of objects one pass may delete.
	Batch int
	// Now is the pass clock (tests pin it); zero means time.Now().
	Now time.Time
}

// casGCStats reports what one pass observed and removed.
type casGCStats struct {
	// Enumerated is the number of stored objects the pass walked.
	Enumerated int
	// Referenced is the size of the durable reference set.
	Referenced int
	// Deleted/Bytes are the objects removed by this pass.
	Deleted int
	Bytes   int64
}

// maybeRunCASGC is the Maintain hook: it rate-limits passes to
// CASGCInterval (default hourly), then runs one collection. The first tick
// after a start only arms the timer, so a fresh replica never collects with
// a cold reference view on its first housekeeping tick.
func (s *Server) maybeRunCASGC(ctx context.Context, now time.Time) {
	if s.CAS == nil && s.BlobStore == nil {
		return
	}
	interval := s.CASGCInterval
	if interval <= 0 {
		interval = defaultCASGCInterval
	}
	s.mu.Lock()
	if s.casGCLast.IsZero() {
		s.casGCLast = now
		s.mu.Unlock()
		return
	}
	if now.Sub(s.casGCLast) < interval {
		s.mu.Unlock()
		return
	}
	s.casGCLast = now
	s.mu.Unlock()
	if _, err := s.runCASGC(ctx, casGCOptions{MinAge: s.CASGCMinAge, Batch: s.CASGCBatch, Now: now}); err != nil {
		s.logError("cas gc: pass failed", "error", err.Error())
	}
}

// runCASGC deletes every blob that is outside the durable reference set and
// older than the age floor, under the HA lease and the batch bound. It
// returns the observed statistics; an error means nothing further was
// deleted (the collector fails closed).
// verifyCASObjectContent streams the stored object and compares its SHA-256
// with the digest the garbage collector enumerated, so a replaced or corrupted
// object is never unlinked. It returns an error when the content cannot be
// verified; callers treat that as "skip, do not delete".
func verifyCASObjectContent(ctx context.Context, store blob.Store, key, enumerated, backendSHA string) error {
	want := enumerated
	if want == "" || !looksLikeSHA256Hex(want) {
		want = backendSHA
	}
	if want == "" || !looksLikeSHA256Hex(want) {
		return fmt.Errorf("no verifiable digest for %q (enumerated %q, backend %q)", key, enumerated, backendSHA)
	}
	rc, _, err := store.Open(ctx, key)
	if err != nil {
		return err
	}
	defer func() { _ = rc.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, rc); err != nil {
		return fmt.Errorf("hash %q: %w", key, err)
	}
	got := hex.EncodeToString(h.Sum(nil))
	if got != strings.ToLower(want) {
		return fmt.Errorf("content digest mismatch for %q: got %s want %s", key, got, want)
	}
	return nil
}

func looksLikeSHA256Hex(v string) bool {
	if len(v) != 64 {
		return false
	}
	for _, c := range v {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

func (s *Server) runCASGC(ctx context.Context, opts casGCOptions) (casGCStats, error) {
	var stats casGCStats
	store := s.BlobStore
	if store == nil && s.CAS != nil {
		store = s.CAS.Blobs
	}
	if store == nil {
		return stats, nil
	}
	enum, ok := store.(blob.Enumerator)
	if !ok {
		return stats, fmt.Errorf("cas gc: blob store does not implement blob.Enumerator")
	}
	if opts.MinAge <= 0 {
		opts.MinAge = defaultCASGCMinAge
	}
	if opts.Batch <= 0 {
		opts.Batch = defaultCASGCBatch
	}
	if opts.Now.IsZero() {
		opts.Now = time.Now()
	}

	release, ok, err := s.acquireCASGCLease(ctx)
	if err != nil {
		return stats, err
	}
	if !ok {
		return stats, nil
	}
	defer release()

	refs, err := s.collectCASReferences(ctx)
	if err != nil {
		return stats, fmt.Errorf("cas gc: collect references: %w", err)
	}
	stats.Referenced = len(refs)
	cutoff := opts.Now.Add(-opts.MinAge)
	if casGCAfterEnumeration != nil {
		casGCAfterEnumeration()
	}

	enumErr := enum.List(ctx, func(obj blob.Object) error {
		stats.Enumerated++
		if stats.Deleted >= opts.Batch {
			return errCASGCBatchDone
		}
		digest := obj.SHA256
		if digest == "" {
			digest = obj.Key
		}
		if _, live := refs[digest]; live {
			return nil
		}
		if obj.ModTime.IsZero() {
			// The backend cannot report age: an object of unknown age is
			// never deleted.
			return nil
		}
		if !obj.ModTime.Before(cutoff) {
			return nil
		}
		// Fence the delete against publication for this digest: a writer
		// holds the same fence across "publish + commit reference", so
		// re-reading the durable references UNDER the fence makes a
		// concurrent re-publication either visible (skip) or blocked until
		// this delete completes (its own put then recreates the object and
		// records the reference, which is safe).
		return s.withDigestFence(ctx, digest, func() error {
			fresh, ferr := s.collectCASReferences(ctx)
			if ferr != nil {
				return ferr
			}
			if _, live := fresh[digest]; live {
				return nil
			}
			freshStat := obj
			if st, ok := store.(blob.Statter); ok {
				got, statErr := st.Stat(ctx, obj.Key)
				if statErr != nil {
					if errors.Is(statErr, blob.ErrNotFound) {
						return nil
					}
					return statErr
				}
				freshStat = got
			}
			if freshStat.ModTime.IsZero() || !freshStat.ModTime.Before(cutoff) {
				return nil
			}
			// Re-verify the object's CONTENT digest immediately before the
			// unlink. A concurrent publisher that replaced the object after
			// our reference re-read would otherwise have its live object
			// deleted; comparing the bytes we are about to remove against the
			// digest we enumerated catches that. An object whose digest cannot
			// be verified from content is never deleted.
			if err := verifyCASObjectContent(ctx, store, obj.Key, digest, obj.SHA256); err != nil {
				if errors.Is(err, blob.ErrNotFound) {
					return nil
				}
				s.logError("cas gc: skipping unverifiable object", "key", obj.Key, "digest", digest, "error", err.Error())
				return nil
			}
			if err := store.Delete(ctx, obj.Key); err != nil {
				if errors.Is(err, blob.ErrNotFound) {
					return nil
				}
				return err
			}
			stats.Deleted++
			stats.Bytes += freshStat.Size
			return nil
		})
	})
	if enumErr != nil && !errors.Is(enumErr, errCASGCBatchDone) {
		return stats, fmt.Errorf("cas gc: enumerate: %w", enumErr)
	}
	if stats.Deleted > 0 {
		s.metricAdd("kiwi_cas_gc_deleted_objects_total", float64(stats.Deleted), nil)
		s.metricAdd("kiwi_cas_gc_deleted_bytes_total", float64(stats.Bytes), nil)
		s.auditLocked("cas.gc", "system", "", "", fmt.Sprintf(
			"CAS GC deleted %d unreferenced object(s) (%d bytes); %d referenced, %d enumerated",
			stats.Deleted, stats.Bytes, stats.Referenced, stats.Enumerated),
			map[string]string{
				"deleted_objects": fmt.Sprintf("%d", stats.Deleted),
				"deleted_bytes":   fmt.Sprintf("%d", stats.Bytes),
				"referenced":      fmt.Sprintf("%d", stats.Referenced),
			})
	}
	return stats, nil
}

// acquireCASGCLease takes the collector lease: the store's dedicated
// advisory lock in DB mode, the in-process single-flight mutex otherwise.
// ok=false means another collector is active and the caller must skip the
// pass. The returned release is always non-nil when ok is true.
//
// The lease is NOT the scheduler leadership claim: TryAcquireLeadership
// keeps one shared connection per store, so taking it under a second key
// would evict the scheduler's lock. The collector lease is a
// transaction-scoped advisory lock on its own connection (see
// storage.CASGCLeaseStore).
func (s *Server) acquireCASGCLease(ctx context.Context) (release func(), ok bool, err error) {
	if s.DB != nil {
		leaseStore, supported := s.DB.(storage.CASGCLeaseStore)
		if !supported {
			return nil, false, fmt.Errorf("cas gc: store does not expose an advisory collector lease")
		}
		lease, acquired, err := leaseStore.TryAcquireCASGCLease(ctx, casGCLeaseKey)
		if err != nil {
			return nil, false, fmt.Errorf("cas gc: acquire lease: %w", err)
		}
		if !acquired {
			return nil, false, nil
		}
		return func() {
			// The release must survive a cancelled pass context: the lock
			// outlives the pass it guards.
			relCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
			defer cancel()
			if err := lease.Release(relCtx); err != nil {
				s.logError("cas gc: release lease", "error", err.Error())
			}
		}, true, nil
	}
	if !s.casGCMu.TryLock() {
		return nil, false, nil
	}
	return s.casGCMu.Unlock, true, nil
}

// collectCASReferences gathers every durable digest the CAS must keep. It
// reads the in-memory mirrors (dev mode) and the durable store read paths
// (DB mode) when present. The walk fails closed: an unreadable reference
// source aborts the pass instead of shrinking the live set.
func (s *Server) collectCASReferences(ctx context.Context) (map[string]struct{}, error) {
	refs := map[string]struct{}{}

	s.mu.Lock()
	artifacts := make([]model.ArtifactRecord, 0, len(s.artifacts))
	for _, a := range s.artifacts {
		artifacts = append(artifacts, a)
	}
	snapshots := make([]model.SnapshotRecord, 0, len(s.snapshots))
	for _, rec := range s.snapshots {
		snapshots = append(snapshots, rec)
	}
	pending := make([]string, 0, len(s.pendingSidecars))
	for _, digest := range s.pendingSidecars {
		pending = append(pending, digest)
	}
	s.mu.Unlock()

	for _, a := range artifacts {
		addArtifactRefs(refs, a)
	}
	for _, rec := range snapshots {
		addSnapshotRefs(refs, rec)
	}
	for _, digest := range pending {
		addCASRef(refs, digest)
	}

	if s.DB != nil {
		refStore, ok := s.DB.(storage.CASReferenceStore)
		if !ok {
			return nil, fmt.Errorf("cas gc: store does not expose CAS reference enumeration")
		}
		dbArtifacts, err := refStore.ListAllArtifacts(ctx)
		if err != nil {
			return nil, fmt.Errorf("list artifacts: %w", err)
		}
		for _, a := range dbArtifacts {
			addArtifactRefs(refs, a)
		}
		dbSnapshots, err := refStore.ListAllSnapshots(ctx)
		if err != nil {
			return nil, fmt.Errorf("list snapshots: %w", err)
		}
		for _, rec := range dbSnapshots {
			addSnapshotRefs(refs, rec)
		}
		manifests, err := refStore.ListAllCacheManifests(ctx)
		if err != nil {
			return nil, fmt.Errorf("list cache manifests: %w", err)
		}
		for _, rec := range manifests {
			addCASRef(refs, rec.BlobSHA256)
		}
		pendingDigests, err := refStore.ListAllPendingSidecarDigests(ctx)
		if err != nil {
			return nil, fmt.Errorf("list pending sidecars: %w", err)
		}
		for _, digest := range pendingDigests {
			addCASRef(refs, digest)
		}
	}

	// fs-mode cache manifests are signed envelopes next to the data dir.
	// The payload digest is read without verifying the signature: GC only
	// ever RETAINS an object from this hint, so an unverifiable or tampered
	// manifest can at worst keep a dead blob alive until the next pass, and
	// an unreadable one aborts the pass (fail closed) rather than risking a
	// live blob.
	if s.store != nil {
		matches, err := filepath.Glob(filepath.Join(s.store.Root, "cache", "*.manifest.json"))
		if err != nil {
			return nil, fmt.Errorf("scan cache manifests: %w", err)
		}
		for _, path := range matches {
			digest, err := cacheManifestRef(path)
			if err != nil {
				return nil, err
			}
			addCASRef(refs, digest)
		}
	}
	return refs, nil
}

// addArtifactRefs adds every digest an artifact record points at: the
// payload digest, the provenance statement, the SBOM and sigstore sidecar
// digests, plus any "cas:"-prefixed path reference (the DB-mode locator).
func addArtifactRefs(refs map[string]struct{}, a model.ArtifactRecord) {
	addCASRef(refs, a.SHA256)
	addCASRef(refs, a.ProvenanceSHA256)
	addCASRef(refs, a.SBOMSHA256)
	addCASRef(refs, a.SigstoreSHA256)
	addCASRef(refs, a.Path)
	addCASRef(refs, a.ProvenancePath)
	addCASRef(refs, a.SBOMPath)
	addCASRef(refs, a.SigstorePath)
}

// addSnapshotRefs adds a snapshot's archive digest, manifest root digest and
// CAS path reference. Entry digests are content hashes inside the archive,
// never CAS object keys, so they are not references.
func addSnapshotRefs(refs map[string]struct{}, rec model.SnapshotRecord) {
	addCASRef(refs, rec.SHA256)
	addCASRef(refs, rec.RootSHA256)
	addCASRef(refs, rec.Path)
}

// addCASRef records ref as a live digest when it is a canonical digest or a
// "cas:"-prefixed/"sha256:"-prefixed digest locator. Anything else (a local
// path, an empty field, a malformed digest) is ignored.
func addCASRef(refs map[string]struct{}, ref string) {
	ref = strings.TrimSpace(ref)
	ref = strings.TrimPrefix(ref, "cas:")
	ref = strings.TrimPrefix(ref, "sha256:")
	if casDigestRE.MatchString(ref) {
		refs[ref] = struct{}{}
	}
}

// cacheManifestRef decodes the payload digest out of one fs-mode manifest
// envelope file.
func cacheManifestRef(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read cache manifest %s: %w", path, err)
	}
	var envelope struct {
		Payload string `json:"payload"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return "", fmt.Errorf("decode cache manifest %s: %w", path, err)
	}
	if envelope.Payload == "" {
		return "", fmt.Errorf("cache manifest %s has no signed payload", path)
	}
	payload, err := base64.StdEncoding.DecodeString(envelope.Payload)
	if err != nil {
		return "", fmt.Errorf("decode cache manifest payload %s: %w", path, err)
	}
	var manifest cache.CacheManifest
	if err := json.Unmarshal(payload, &manifest); err != nil {
		return "", fmt.Errorf("decode cache manifest statement %s: %w", path, err)
	}
	return manifest.BlobSHA256, nil
}
