package server

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/supplychain"
)

// SBOM and Sigstore attestation wiring. The runner uploads these as
// conventional sibling names of the artifact: `<name>.sbom` and
// `<name>.sigstore`. The server validates them against the job's artifact
// contract and gates the artifact payload itself, so a required-but-missing
// attestation can never ship.

const (
	maxSBOMBytes     = 8 << 20
	maxSigstoreBytes = 8 << 20
)

// FS/dev sidecar layout. In dev mode the `<name>.sbom` / `<name>.sigstore`
// uploads are persisted as local files next to the job's artifacts. The
// layout is generation- and digest-qualified:
//
//	<dir>/g-<generation>/<base>.<kind>.<sha256>.json
//
// <generation> is the lease generation the sidecar was uploaded under and
// <sha256> is the digest of its exact bytes, so a sidecar file is IMMUTABLE:
// a retry generation writes into its own directory and can never overwrite
// (or otherwise mutate) the file an older generation's artifact record still
// points at, and the digest in the name always matches the bytes the owning
// record references (record.SBOMSHA256/SigstoreSHA256). Re-uploading the
// same content is an idempotent no-op; a re-upload with different content
// inside ONE generation appends a second digest-qualified file instead of
// rewriting the first.
//
// artifactSidecarDir is the per-generation sidecar directory.
func artifactSidecarDir(dir string, generation int64) string {
	return filepath.Join(dir, "g-"+strconv.FormatInt(generation, 10))
}

// artifactSidecarPath is the immutable path of one sidecar object.
func artifactSidecarPath(dir string, generation int64, base, kind, digest string) string {
	return filepath.Join(artifactSidecarDir(dir, generation), cleanBlobName(base)+"."+kind+"."+digest+".json")
}

// writeArtifactSidecar persists one sidecar object immutably: it creates the
// generation directory and returns the existing path untouched when the
// content-addressed file already exists (same bytes by construction), so no
// write can ever replace another generation's file. It returns the sidecar
// path stored on the artifact record.
func writeArtifactSidecar(dir string, generation int64, base, kind, digest string, body []byte) (string, error) {
	if err := os.MkdirAll(artifactSidecarDir(dir, generation), 0o700); err != nil {
		return "", err
	}
	path := artifactSidecarPath(dir, generation, base, kind, digest)
	if fi, err := os.Stat(path); err == nil && !fi.IsDir() {
		return path, nil
	}
	if err := writeFileAtomic(path, body, 0o600); err != nil {
		return "", err
	}
	return path, nil
}

// errAmbiguousArtifactSidecar reports that more than one digest-qualified
// sidecar file exists for one (generation, base, kind) identity and no
// durable pending pointer names the accepted digest. The immutable files are
// digest-qualified but their names carry no "latest" relationship, so
// picking the lexicographically first one after a restart could attach an
// older re-upload's attestation to the artifact. Resolution fails closed.
var errAmbiguousArtifactSidecar = errors.New("artifact sidecar is ambiguous: multiple candidates and no durable pending pointer")

// findArtifactSidecar resolves the readable sidecar file of one
// (generation, base, kind) identity:
//
//   - digest non-empty: the EXACT digest-qualified path must exist. There is
//     no fallback scan: a durable pointer that names a missing file is a
//     broken pointer, and substituting another digest's bytes would attach
//     an attestation the control plane never accepted;
//   - digest empty (legacy/unindexed state): exactly ONE candidate file in
//     the generation directory is the unambiguous legacy layout and is
//     returned; ZERO returns os.ErrNotExist; TWO OR MORE are ambiguous and
//     FAIL CLOSED with errAmbiguousArtifactSidecar instead of arbitrarily
//     selecting one.
//
// The GENERATION boundary is never crossed either way. Whichever file is
// returned is still validated by the caller (SBOM document validation /
// sigstore bundle verification).
func findArtifactSidecar(dir string, generation int64, base, kind, digest string) (string, error) {
	if digest != "" {
		path := artifactSidecarPath(dir, generation, base, kind, digest)
		if fi, err := os.Stat(path); err == nil && !fi.IsDir() {
			return path, nil
		}
		return "", os.ErrNotExist
	}
	genDir := artifactSidecarDir(dir, generation)
	entries, err := os.ReadDir(genDir)
	if err != nil {
		return "", os.ErrNotExist
	}
	prefix := cleanBlobName(base) + "." + kind + "."
	candidates := []string{}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasPrefix(name, prefix) || !strings.HasSuffix(name, ".json") {
			continue
		}
		candidates = append(candidates, name)
	}
	switch len(candidates) {
	case 0:
		return "", os.ErrNotExist
	case 1:
		return filepath.Join(genDir, candidates[0]), nil
	default:
		return "", fmt.Errorf("%w: %d candidates for %s.%s in generation %d", errAmbiguousArtifactSidecar, len(candidates), cleanBlobName(base), kind, generation)
	}
}

// SetSigstoreTrustRoot pins the Sigstore verification trust root: the
// accepted signing keys (keyed by key ID) and, when both rekorPub and
// rekorBaseURL are set, the Rekor transparency log used for inclusion
// verification. Without any configured root, sigstore uploads fail closed
// (422). Configure before serving traffic.
func (s *Server) SetSigstoreTrustRoot(keys map[string]ed25519.PublicKey, rekorPub ed25519.PublicKey, rekorBaseURL string) {
	if keys == nil {
		s.SigstoreTrustedKeys = nil
	} else {
		m := make(map[string]ed25519.PublicKey, len(keys))
		for id, k := range keys {
			m[id] = append(ed25519.PublicKey(nil), k...)
		}
		s.SigstoreTrustedKeys = m
	}
	s.RekorPublicKey = append(ed25519.PublicKey(nil), rekorPub...)
	s.RekorBaseURL = rekorBaseURL
}

// sigstoreTrustRoot returns the configured Sigstore verification trust
// root. Rekor inclusion verification is active only when both the Rekor
// public key and the base URL are configured.
func (s *Server) sigstoreTrustRoot() supplychain.SigstoreTrustRoot {
	root := supplychain.SigstoreTrustRoot{Keys: s.SigstoreTrustedKeys}
	if len(s.RekorPublicKey) == ed25519.PublicKeySize && s.RekorBaseURL != "" {
		root.Rekor = &supplychain.RekorConfig{PublicKey: s.RekorPublicKey, BaseURL: s.RekorBaseURL}
	}
	return root
}

// hasSigstoreTrustRoot reports whether any Sigstore trust root is
// configured. Without one, sigstore gates fail closed.
func (s *Server) hasSigstoreTrustRoot() bool {
	return len(s.SigstoreTrustedKeys) > 0 || (len(s.RekorPublicKey) == ed25519.PublicKeySize && s.RekorBaseURL != "")
}

// validateSBOMDocument checks the payload parses as JSON in the declared
// format and carries the format's required identity fields.
func validateSBOMDocument(b []byte, format supplychain.SBOMFormat) error {
	if len(b) == 0 || len(b) > maxSBOMBytes {
		return errors.New("sbom payload is empty or exceeds 8 MiB")
	}
	if !json.Valid(b) {
		return errors.New("sbom payload is not valid JSON")
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return err
	}
	switch format {
	case supplychain.SBOMSPDX:
		if v, _ := m["spdxVersion"].(string); v != "SPDX-2.3" {
			return errors.New("spdx-json document must declare spdxVersion \"SPDX-2.3\"")
		}
		if id, _ := m["SPDXID"].(string); id == "" {
			return errors.New("spdx-json document must declare an SPDXID")
		}
	case supplychain.SBOMCycloneDX:
		if v, _ := m["bomFormat"].(string); v != "CycloneDX" {
			return errors.New("cyclonedx-json document must declare bomFormat \"CycloneDX\"")
		}
		if v, _ := m["specVersion"].(string); v != "1.5" {
			return errors.New("cyclonedx-json document must declare specVersion \"1.5\"")
		}
	default:
		return errors.New("unknown sbom format")
	}
	return nil
}

// sigstoreVerifyConfig derives the verification expectations for an
// artifact from its frozen contract declaration, anchored in the server's
// configured Sigstore trust root.
func (s *Server) sigstoreVerifyConfig(c storage.ArtifactContract) supplychain.SigstoreVerifyConfig {
	return supplychain.SigstoreVerifyConfig{
		ExpectedIssuer:   c.SigstoreIssuer,
		ExpectedIdentity: c.SigstoreIdentity,
		TrustRoot:        s.sigstoreTrustRoot(),
	}
}

// uploadSBOM accepts a `<name>.sbom` upload: it must correspond to a
// declared artifact whose contract declares an sbom format, and the payload
// must parse as that format. FS dev mode stores the document as a local
// sidecar next to the job's artifacts; DB mode stores the bytes in the
// shared CAS store and keeps only the digest (the record and the payload
// upload gate resolve it through CAS — no node-local sidecar files).
func (s *Server) uploadSBOM(w http.ResponseWriter, r *http.Request, j model.Job, c storage.ArtifactContract, base string) {
	start := time.Now()
	if strings.TrimSpace(c.SBOM) == "" {
		s.auditLocked("artifact.sbom_rejected", j.LeaseRunnerID, j.RunID, j.ID, "sbom upload without declared sbom format", map[string]string{"name": base})
		http.Error(w, "artifact contract does not declare an sbom format", http.StatusUnprocessableEntity)
		return
	}
	format, err := supplychain.ParseSBOMFormat(c.SBOM)
	if err != nil {
		s.auditLocked("artifact.sbom_rejected", j.LeaseRunnerID, j.RunID, j.ID, "invalid declared sbom format", map[string]string{"name": base, "format": c.SBOM})
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxSBOMBytes))
	if err != nil {
		http.Error(w, "invalid sbom payload", http.StatusBadRequest)
		return
	}
	if err := validateSBOMDocument(body, format); err != nil {
		s.auditLocked("artifact.sbom_rejected", j.LeaseRunnerID, j.RunID, j.ID, "sbom payload rejected", map[string]string{"name": base, "error": err.Error()})
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	sum := sha256Hex(body)
	ctx := r.Context()
	if s.DB != nil {
		if s.CAS == nil {
			http.Error(w, "sidecar storage requires a blob store", http.StatusServiceUnavailable)
			return
		}
		releaseGate, ferr := s.acquireDigestFence(ctx, sum)
		if ferr != nil {
			s.internalError(w, r, ferr, "")
			return
		}
		defer releaseGate()
		if _, perr := s.CAS.Put(ctx, bytes.NewReader(body)); perr != nil {
			s.internalError(w, r, perr, "")
			return
		}
		// Durable pending state BEFORE the 201: a replica restart or a
		// different replica must still resolve the sidecar for the payload
		// gate. The CAS blob is content-addressed and is never deleted on a
		// later failure (it may be referenced elsewhere).
		if err := s.rememberPendingSidecar(ctx, j, base, storage.ArtifactSidecarKindSBOM, sum); err != nil {
			s.logError("artifact: sbom pending state persist failed", "job", j.ID, "error", err.Error())
			http.Error(w, "sbom pending state persist failed", http.StatusServiceUnavailable)
			return
		}
		if err := s.attachSidecarToArtifact(ctx, j, base, storage.ArtifactSidecarKindSBOM, "cas:"+sum, sum); err != nil {
			// Fail closed: a sidecar that cannot be attached to an existing
			// artifact record must never be acknowledged as stored.
			s.logError("artifact: sbom attach failed", "job", j.ID, "error", err.Error())
			http.Error(w, "sbom attachment failed", http.StatusServiceUnavailable)
			return
		}
		s.metricObserve("kiwi_cas_latency_seconds", time.Since(start).Seconds(), nil)
		writeJSON(w, http.StatusCreated, map[string]any{"name": base + sbomSuffix, "sha256": sum, "format": string(format)})
		return
	}
	dir := filepath.Join(s.store.Root, "artifacts", j.RunID, j.ID)
	sidecar, err := writeArtifactSidecar(dir, j.LeaseGeneration, base, "sbom", sum, body)
	if err != nil {
		s.internalError(w, r, err, "")
		return
	}
	// Dev-mode mirror of the durable pending row (fs mode has no shared
	// store): the payload gate and the record attachment can resolve the
	// digest when a CAS backend is attached, and fall back to the local
	// sidecar file otherwise. The mirror entry rides the same atomic state
	// snapshot as everything else, so a persist failure fails the upload
	// closed (503) — a 201 without durable pending state would let a restart
	// guess between candidate files.
	if err := s.rememberPendingSidecar(ctx, j, base, storage.ArtifactSidecarKindSBOM, sum); err != nil {
		s.logError("artifact: sbom pending state persist failed", "job", j.ID, "error", err.Error())
		http.Error(w, "sbom pending state persist failed", http.StatusServiceUnavailable)
		return
	}
	if err := s.attachSidecarToArtifact(ctx, j, base, storage.ArtifactSidecarKindSBOM, sidecar, sum); err != nil {
		s.logError("artifact: sbom attach failed", "job", j.ID, "error", err.Error())
		http.Error(w, "sbom attachment failed", http.StatusServiceUnavailable)
		return
	}
	s.metricObserve("kiwi_cas_latency_seconds", time.Since(start).Seconds(), nil)
	writeJSON(w, http.StatusCreated, map[string]any{"name": base + sbomSuffix, "sha256": sum, "format": string(format)})
}

// uploadSigstore accepts a `<name>.sigstore` Sigstore bundle upload. When
// the artifact payload already exists the bundle is verified immediately
// against its digest; otherwise it is stored and the artifact upload gate
// verifies it. A bundle that fails verification is rejected (422) and
// never stored. DB mode stores the bytes in CAS; fs mode keeps the local
// sidecar file.
func (s *Server) uploadSigstore(w http.ResponseWriter, r *http.Request, j model.Job, c storage.ArtifactContract, base string) {
	if !c.SigstoreRequired && c.SigstoreIssuer == "" && c.SigstoreIdentity == "" {
		s.auditLocked("artifact.sigstore_rejected", j.LeaseRunnerID, j.RunID, j.ID, "sigstore upload without declared sigstore gate", map[string]string{"name": base})
		http.Error(w, "artifact contract does not declare a sigstore gate", http.StatusUnprocessableEntity)
		return
	}
	if !s.hasSigstoreTrustRoot() {
		s.auditLocked("artifact.sigstore_rejected", j.LeaseRunnerID, j.RunID, j.ID, "sigstore upload without configured trust root", map[string]string{"name": base})
		http.Error(w, "sigstore trust root is not configured", http.StatusUnprocessableEntity)
		return
	}
	// Dedicated bound applied before any allocation: oversized bundles are
	// rejected without reading the full body.
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxSigstoreBytes))
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			http.Error(w, "sigstore bundle exceeds 8 MiB limit", http.StatusUnprocessableEntity)
			return
		}
		http.Error(w, "invalid sigstore bundle", http.StatusBadRequest)
		return
	}
	cfg := s.sigstoreVerifyConfig(c)
	// Immediate verification is generation-qualified: the bundle can only be
	// verified against the artifact uploaded under THIS lease generation. A
	// previous generation's record (same artifact name) is never inspected —
	// a retry generation must not be able to pass its bundle on the prior
	// payload's digest. When no record exists for this generation yet (the
	// documented bundle-before-payload order) verification is deferred to the
	// artifact upload gate, which resolves the exact generation's digest.
	if recs, lerr := s.findArtifactByJobName(r.Context(), j.RunID, j.ID, base); lerr == nil {
		if current, found := existingArtifactForGeneration(recs, j.LeaseGeneration); found {
			if err := supplychain.VerifySigstoreBundle(body, current.SHA256, cfg); err != nil {
				s.auditLocked("artifact.sigstore_rejected", j.LeaseRunnerID, j.RunID, j.ID, "sigstore bundle verification failed", map[string]string{"name": base, "error": err.Error()})
				http.Error(w, err.Error(), http.StatusUnprocessableEntity)
				return
			}
		}
	}
	sum := sha256Hex(body)
	ctx := r.Context()
	if s.DB != nil {
		if s.CAS == nil {
			http.Error(w, "sidecar storage requires a blob store", http.StatusServiceUnavailable)
			return
		}
		releaseGate, ferr := s.acquireDigestFence(ctx, sum)
		if ferr != nil {
			s.internalError(w, r, ferr, "")
			return
		}
		defer releaseGate()
		if _, perr := s.CAS.Put(ctx, bytes.NewReader(body)); perr != nil {
			s.internalError(w, r, perr, "")
			return
		}
		if err := s.rememberPendingSidecar(ctx, j, base, storage.ArtifactSidecarKindSigstore, sum); err != nil {
			s.logError("artifact: sigstore pending state persist failed", "job", j.ID, "error", err.Error())
			http.Error(w, "sigstore pending state persist failed", http.StatusServiceUnavailable)
			return
		}
		if err := s.attachSidecarToArtifact(ctx, j, base, storage.ArtifactSidecarKindSigstore, "cas:"+sum, sum); err != nil {
			s.logError("artifact: sigstore attach failed", "job", j.ID, "error", err.Error())
			http.Error(w, "sigstore attachment failed", http.StatusServiceUnavailable)
			return
		}
		s.auditLocked("artifact.sigstore_stored", j.LeaseRunnerID, j.RunID, j.ID, "sigstore bundle stored", map[string]string{"name": base, "sha256": sum})
		writeJSON(w, http.StatusCreated, map[string]any{"name": base + sigstoreSuffix, "sha256": sum})
		return
	}
	dir := filepath.Join(s.store.Root, "artifacts", j.RunID, j.ID)
	sidecar, err := writeArtifactSidecar(dir, j.LeaseGeneration, base, "sigstore", sum, body)
	if err != nil {
		s.internalError(w, r, err, "")
		return
	}
	// Dev-mode mirror of the durable pending row: see uploadSBOM.
	if err := s.rememberPendingSidecar(ctx, j, base, storage.ArtifactSidecarKindSigstore, sum); err != nil {
		s.logError("artifact: sigstore pending state persist failed", "job", j.ID, "error", err.Error())
		http.Error(w, "sigstore pending state persist failed", http.StatusServiceUnavailable)
		return
	}
	if err := s.attachSidecarToArtifact(ctx, j, base, storage.ArtifactSidecarKindSigstore, sidecar, sum); err != nil {
		s.logError("artifact: sigstore attach failed", "job", j.ID, "error", err.Error())
		http.Error(w, "sigstore attachment failed", http.StatusServiceUnavailable)
		return
	}
	s.auditLocked("artifact.sigstore_stored", j.LeaseRunnerID, j.RunID, j.ID, "sigstore bundle stored", map[string]string{"name": base, "sha256": sum})
	writeJSON(w, http.StatusCreated, map[string]any{"name": base + sigstoreSuffix, "sha256": sum})
}

// pendingSidecarMaxAge is the retention window of a pending sidecar:
// sidecars uploaded for an artifact payload that never arrives are
// unreachable long before this, so the maintenance tick (PrunePendingSidecars
// in DB mode, the in-memory mirror otherwise) drops them.
const pendingSidecarMaxAge = 7 * 24 * time.Hour

// sidecarPendingKey names one pending sidecar in the dev-mode in-memory
// mirror. DB mode keys the durable row by the same full artifact identity
// (job, lease generation, artifact, kind) — migration 0028 — directly: a
// retry generation must never collide with (or resolve) a previous
// generation's pending sidecar. The canonical encoding lives in
// storage.PendingSidecarKey so the fs snapshot's durable pointers and the
// in-memory mirror can never drift.
func sidecarPendingKey(jobID string, generation int64, base, kind string) string {
	return storage.PendingSidecarKey(jobID, generation, cleanBlobName(base), kind)
}

// encodePendingSidecar packs a dev-mode mirror entry: the digest plus its
// creation time, so the memory tick can age out stale entries. The encoding
// is storage.EncodePendingSidecarValue, which is also what the durable fs
// snapshot pointers decode/encode through.
func encodePendingSidecar(digest string, created time.Time) string {
	return storage.EncodePendingSidecarValue(digest, created)
}

// decodePendingSidecar unpacks a dev-mode mirror entry. Entries written in
// the legacy bare-digest form decode as digest-only.
func decodePendingSidecar(v string) (digest string, created time.Time, ok bool) {
	return storage.DecodePendingSidecarValue(v)
}

// pendingSidecarSnapshotLocked renders the in-memory mirror as the durable,
// deterministically ordered pointer slice the fs snapshot persists. The
// caller holds s.mu (persistLocked callers do); the returned slice is a
// fresh allocation, never aliasing the map.
func (s *Server) pendingSidecarSnapshotLocked() []storage.PendingSidecarPointer {
	return storage.SnapshotPendingSidecarPointers(s.pendingSidecars)
}

// restorePendingSidecarPointers installs the durable fs-mode pointers after a
// restart. The durable snapshot is the restart-authoritative source: every
// pointer it carries is installed, and a key it does not carry is left
// untouched (a union with any legacy in-memory state, which today is empty
// at load). The legacy on-disk case — exactly one sidecar file per identity
// with no pointer — stays resolvable through findArtifactSidecar's
// unambiguous-candidate path; several candidates without a pointer fail
// closed there.
func (s *Server) restorePendingSidecarPointers(snap storage.Snapshot) {
	state := snap.PendingSidecarState()
	s.mu.Lock()
	defer s.mu.Unlock()
	for key, val := range state {
		s.pendingSidecars[key] = val
	}
}

// sidecarStore resolves the durable pending-sidecar store in DB mode.
func (s *Server) sidecarStore() (storage.ArtifactSidecarStore, bool) {
	if s.DB == nil {
		return nil, false
	}
	ss, ok := s.DB.(storage.ArtifactSidecarStore)
	return ss, ok
}

// rememberPendingSidecar records a sidecar digest uploaded before its
// artifact payload, so the payload upload gate can resolve the bytes
// through CAS. The row is keyed by the FULL artifact identity
// (job, lease generation, artifact, kind): a retry generation's sidecar can
// never overwrite or masquerade as another generation's pending state. DB
// mode writes the DURABLE artifact_pending_sidecars row (visible to every
// replica, survives restarts); fs mode persists the mirror entry in the SAME
// atomic state snapshot as the rest of the control-plane state (so a restart
// restores the exact accepted digest instead of guessing between candidate
// files); a pure-memory server keeps the in-memory mirror only. A store or
// state-persist failure is returned so the caller fails closed — never a
// 201 without pending state.
func (s *Server) rememberPendingSidecar(ctx context.Context, j model.Job, base, kind, digest string) error {
	if ss, ok := s.sidecarStore(); ok {
		return ss.RememberPendingSidecar(ctx, j.ID, j.LeaseGeneration, cleanBlobName(base), kind, digest)
	}
	if s.DB != nil {
		return fmt.Errorf("artifact sidecar store unavailable")
	}
	key := sidecarPendingKey(j.ID, j.LeaseGeneration, base, kind)
	value := encodePendingSidecar(digest, time.Now().UTC())
	s.mu.Lock()
	prev, hadPrev := s.pendingSidecars[key]
	s.pendingSidecars[key] = value
	perr := s.persistCheckedErrLocked("artifact.sidecar_pending")
	if perr != nil {
		// Durability first: a pointer the snapshot does not contain must not
		// survive in memory, or the next unrelated persist commits pending
		// state the uploader was told failed.
		if hadPrev {
			s.pendingSidecars[key] = prev
		} else {
			delete(s.pendingSidecars, key)
		}
		s.mu.Unlock()
		return perr
	}
	s.mu.Unlock()
	return nil
}

// pendingSidecarDigest resolves the CAS digest of a pending sidecar for the
// EXACT (job, lease generation, artifact, kind) identity: from the durable
// store in DB mode, from the in-memory mirror otherwise. A row for another
// generation is never a fallback — the caller fails closed when this
// generation has no pending sidecar.
func (s *Server) pendingSidecarDigest(ctx context.Context, jobID string, generation int64, base, kind string) (string, bool, error) {
	if ss, ok := s.sidecarStore(); ok {
		return ss.PendingSidecar(ctx, jobID, generation, cleanBlobName(base), kind)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.pendingSidecars[sidecarPendingKey(jobID, generation, base, kind)]
	if !ok {
		return "", false, nil
	}
	digest, _, ok := decodePendingSidecar(v)
	return digest, ok && digest != "", nil
}

// consumeArtifactPendingSidecars deletes ONLY the pending rows whose digests
// were copied into a durably committed artifact record: the exact
// (job, lease generation, artifact, kind) rows the record references. There
// is deliberately no job-wide delete — another artifact's (or another
// generation's) pending sidecar survives its own commit or the 7-day prune.
// It MUST run only after the record insert committed; a crash in between
// leaves the pending rows in place for the retry. Failures are the caller's
// to log: the record is already durable and the maintenance tick prunes
// leftovers.
func (s *Server) consumeArtifactPendingSidecars(ctx context.Context, rec model.ArtifactRecord) error {
	if ss, ok := s.sidecarStore(); ok {
		name := cleanBlobName(rec.Name)
		if rec.SBOMSHA256 != "" {
			if err := ss.ConsumePendingSidecar(ctx, rec.JobID, rec.LeaseGeneration, name, storage.ArtifactSidecarKindSBOM, rec.SBOMSHA256); err != nil {
				return err
			}
		}
		if rec.SigstoreSHA256 != "" {
			if err := ss.ConsumePendingSidecar(ctx, rec.JobID, rec.LeaseGeneration, name, storage.ArtifactSidecarKindSigstore, rec.SigstoreSHA256); err != nil {
				return err
			}
		}
		return nil
	}
	if s.DB != nil {
		// DB mode without the sidecar store extension has no durable rows to
		// consume; the fs mirror is not the source of truth here.
		return nil
	}
	// fs/memory mode: drop the committed record's OWN mirror entries and
	// persist the drop so a restart does not resurrect a consumed pointer.
	// The record is already durable and carries the digests, so a persist
	// failure is returned for the caller to log (never silently ignored).
	name := cleanBlobName(rec.Name)
	var keys []string
	if rec.SBOMSHA256 != "" {
		keys = append(keys, sidecarPendingKey(rec.JobID, rec.LeaseGeneration, name, storage.ArtifactSidecarKindSBOM))
	}
	if rec.SigstoreSHA256 != "" {
		keys = append(keys, sidecarPendingKey(rec.JobID, rec.LeaseGeneration, name, storage.ArtifactSidecarKindSigstore))
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	changed := false
	for _, key := range keys {
		if _, ok := s.pendingSidecars[key]; ok {
			delete(s.pendingSidecars, key)
			changed = true
		}
	}
	if !changed {
		return nil
	}
	return s.persistCheckedErrLocked("artifact.sidecar_consume")
}

// pruneExpiredPendingSidecars drops pending sidecar rows older than
// pendingSidecarMaxAge. The maintenance tick calls it in both modes: DB
// mode prunes the shared table, memory mode ages out the mirror. It never
// deletes a CAS blob (digests may be referenced elsewhere).
func (s *Server) pruneExpiredPendingSidecars(ctx context.Context, now time.Time) {
	cutoff := now.UTC().Add(-pendingSidecarMaxAge)
	if ss, ok := s.sidecarStore(); ok {
		pctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		if _, err := ss.PrunePendingSidecars(pctx, cutoff); err != nil {
			s.logError("sidecars: pending prune failed", "error", err.Error())
		}
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	changed := false
	for key, v := range s.pendingSidecars {
		_, created, ok := decodePendingSidecar(v)
		if !ok || created.Before(cutoff) {
			delete(s.pendingSidecars, key)
			changed = true
		}
	}
	if changed {
		// Persist the pruned mirror so a restart cannot resurrect entries
		// the maintenance tick already dropped. Failures are logged by
		// persistCheckedErrLocked and arm the degraded state; they never
		// re-add the pruned entries.
		_ = s.persistCheckedErrLocked("artifact.sidecar_prune")
	}
}

// attachSidecarToArtifact links a verified sidecar (sbom/sigstore) to the
// artifact record of the CURRENT lease generation and returns an error when
// the link cannot be durably recorded: DB mode persists the digest
// references through the store (ArtifactSidecarStore), and a persistence
// failure must fail the request closed (503) instead of acknowledging a
// sidecar the record does not carry. Selection is generation-qualified: a
// record uploaded under another lease generation is NEVER a candidate (that
// would attach this generation's attestation to the previous generation's
// payload). No record yet for this generation is not a failure: the sidecar
// stays pending and is resolved when the payload is recorded. Memory mode
// updates the in-memory record.
func (s *Server) attachSidecarToArtifact(ctx context.Context, j model.Job, base, kind, path, sum string) error {
	recs, err := s.findArtifactByJobName(ctx, j.RunID, j.ID, base)
	if err != nil {
		return err
	}
	rec, found := existingArtifactForGeneration(recs, j.LeaseGeneration)
	if !found {
		return nil
	}
	if s.DB != nil {
		ss, ok := s.sidecarStore()
		if !ok {
			return fmt.Errorf("artifact sidecar store unavailable")
		}
		sbomPath, sbomSum, sigPath, sigSum := "", "", "", ""
		if kind == storage.ArtifactSidecarKindSBOM {
			sbomPath, sbomSum = path, sum
		} else {
			sigPath, sigSum = path, sum
		}
		return ss.SetArtifactSidecars(ctx, rec.ID, sbomPath, sbomSum, sigPath, sigSum)
	}
	s.mu.Lock()
	if cur, ok := s.artifacts[rec.ID]; ok {
		prev := cur
		if kind == storage.ArtifactSidecarKindSBOM {
			cur.SBOMPath = path
			cur.SBOMSHA256 = sum
		} else {
			cur.SigstorePath = path
			cur.SigstoreSHA256 = sum
		}
		s.artifacts[rec.ID] = cur
		if perr := s.persistCheckedErrLocked("artifact.sidecar"); perr != nil {
			// Durability first: an attachment the snapshot does not contain
			// must not survive in memory, or the next unrelated persist
			// commits a sidecar the uploader was told failed.
			s.artifacts[rec.ID] = prev
			s.mu.Unlock()
			return perr
		}
	}
	s.mu.Unlock()
	return nil
}

// gateArtifactAttestations enforces the SBOM/sigstore requirements at
// artifact-payload upload time. The frozen contract is authoritative; the
// pipeline text is never re-parsed. DB mode resolves the sidecar bytes
// through CAS via the DURABLE pending rows (any replica, surviving
// restarts); fs/memory mode resolves the pending mirror or the local
// sidecar files. It returns an HTTP error string on failure.
func (s *Server) gateArtifactAttestations(ctx context.Context, c storage.ArtifactContract, j model.Job, base string, digest string, dir string) (int, string) {
	if strings.TrimSpace(c.SBOM) != "" {
		format, err := supplychain.ParseSBOMFormat(c.SBOM)
		if err != nil {
			return http.StatusUnprocessableEntity, err.Error()
		}
		b, rerr := s.sidecarBytes(ctx, j, base, "sbom", dir)
		if rerr != nil {
			if errors.Is(rerr, errAmbiguousArtifactSidecar) {
				s.auditLocked("artifact.sbom_rejected", j.LeaseRunnerID, j.RunID, j.ID, "required sbom ambiguous at artifact upload", map[string]string{"name": base, "error": rerr.Error()})
				return http.StatusUnprocessableEntity, "required sbom is ambiguous: " + rerr.Error()
			}
			s.auditLocked("artifact.sbom_missing", j.LeaseRunnerID, j.RunID, j.ID, "required sbom missing at artifact upload", map[string]string{"name": base})
			return http.StatusUnprocessableEntity, "required sbom missing: upload <name>.sbom before the artifact"
		}
		if verr := validateSBOMDocument(b, format); verr != nil {
			s.auditLocked("artifact.sbom_rejected", j.LeaseRunnerID, j.RunID, j.ID, "required sbom invalid", map[string]string{"name": base, "error": verr.Error()})
			return http.StatusUnprocessableEntity, verr.Error()
		}
	}
	if c.SigstoreRequired {
		if !s.hasSigstoreTrustRoot() {
			s.auditLocked("artifact.sigstore_rejected", j.LeaseRunnerID, j.RunID, j.ID, "required sigstore gate without configured trust root", map[string]string{"name": base})
			return http.StatusUnprocessableEntity, "sigstore trust root is not configured"
		}
		b, rerr := s.sidecarBytes(ctx, j, base, "sigstore", dir)
		if rerr != nil {
			if errors.Is(rerr, errAmbiguousArtifactSidecar) {
				s.auditLocked("artifact.sigstore_rejected", j.LeaseRunnerID, j.RunID, j.ID, "required sigstore ambiguous at artifact upload", map[string]string{"name": base, "error": rerr.Error()})
				return http.StatusUnprocessableEntity, "required sigstore bundle is ambiguous: " + rerr.Error()
			}
			s.auditLocked("artifact.sigstore_missing", j.LeaseRunnerID, j.RunID, j.ID, "required sigstore missing at artifact upload", map[string]string{"name": base})
			return http.StatusUnprocessableEntity, "required sigstore bundle missing: upload <name>.sigstore before the artifact"
		}
		if verr := supplychain.VerifySigstoreBundle(b, digest, s.sigstoreVerifyConfig(c)); verr != nil {
			s.auditLocked("artifact.sigstore_rejected", j.LeaseRunnerID, j.RunID, j.ID, "required sigstore bundle failed verification", map[string]string{"name": base, "error": verr.Error()})
			return http.StatusUnprocessableEntity, verr.Error()
		}
	}
	return 0, ""
}

// sidecarBytes resolves one sidecar's bytes for the upload gate: from the
// durable pending row of the EXACT (job, lease generation, artifact, kind)
// identity in DB mode (the digest points into the shared CAS), from the
// pending map when present, from the local sidecar file in fs/memory mode
// otherwise. Another generation's pending row is never used. An
// unresolvable sidecar is reported as an error so the gate fails closed.
func (s *Server) sidecarBytes(ctx context.Context, j model.Job, base, kind, dir string) ([]byte, error) {
	if s.DB != nil {
		d, ok, err := s.pendingSidecarDigest(ctx, j.ID, j.LeaseGeneration, base, kind)
		if err != nil {
			return nil, err
		}
		if ok && d != "" && s.CAS != nil {
			rc, _, err := s.CAS.Open(ctx, d)
			if err != nil {
				return nil, err
			}
			defer rc.Close()
			return io.ReadAll(io.LimitReader(rc, maxSBOMBytes+1))
		}
		return nil, os.ErrNotExist
	}
	d, ok, _ := s.pendingSidecarDigest(ctx, j.ID, j.LeaseGeneration, base, kind)
	if ok && d != "" && s.CAS != nil {
		if rc, _, oerr := s.CAS.Open(ctx, d); oerr == nil {
			defer rc.Close()
			return io.ReadAll(io.LimitReader(rc, maxSBOMBytes+1))
		}
	}
	// fs/dev fallback: the exact digest-qualified file when the pending
	// mirror knows the digest, else this generation's unique candidate. Two
	// or more candidates without a durable pointer are ambiguous and fail
	// closed (errAmbiguousArtifactSidecar), never an arbitrary pick.
	path, ferr := findArtifactSidecar(dir, j.LeaseGeneration, base, kind, d)
	if ferr != nil {
		return nil, ferr
	}
	return os.ReadFile(path)
}

// attachSidecarsToRecord fills the sidecar fields of a freshly built
// artifact record: from the DURABLE pending-sidecar rows of the record's
// exact (job, lease generation, artifact, kind) identity in DB mode (their
// CAS digest references), from the pending mirror / local sidecar files in
// fs mode. The generation is part of the lookup, so a retry generation never
// picks up the previous generation's pending sidecar. A store lookup failure
// is returned so the caller fails the upload instead of recording an
// artifact that silently lost its attested sidecars.
func (s *Server) attachSidecarsToRecord(ctx context.Context, rec *model.ArtifactRecord, j model.Job, base, dir string) error {
	if s.DB != nil {
		ss, ok := s.sidecarStore()
		if !ok {
			return fmt.Errorf("artifact sidecar store unavailable")
		}
		if d, ok, err := ss.PendingSidecar(ctx, j.ID, j.LeaseGeneration, cleanBlobName(base), storage.ArtifactSidecarKindSBOM); err != nil {
			return err
		} else if ok && d != "" {
			rec.SBOMPath = "cas:" + d
			rec.SBOMSHA256 = d
		}
		if d, ok, err := ss.PendingSidecar(ctx, j.ID, j.LeaseGeneration, cleanBlobName(base), storage.ArtifactSidecarKindSigstore); err != nil {
			return err
		} else if ok && d != "" {
			rec.SigstorePath = "cas:" + d
			rec.SigstoreSHA256 = d
		}
		return nil
	}
	// The fs resolution is sourced EXACTLY like the gate's: the durable
	// pending digest when present (exact file only), else the single
	// unambiguous legacy candidate. An ambiguous identity (several files,
	// no pointer) is returned as an error so the caller fails the upload
	// instead of recording one of the candidates arbitrarily.
	sbomPending, sbomOK, _ := s.pendingSidecarDigest(ctx, j.ID, j.LeaseGeneration, base, storage.ArtifactSidecarKindSBOM)
	if sbomOK && sbomPending != "" && s.CAS != nil {
		rec.SBOMPath = "cas:" + sbomPending
		rec.SBOMSHA256 = sbomPending
	} else {
		path, ferr := findArtifactSidecar(dir, j.LeaseGeneration, base, "sbom", sbomPending)
		switch {
		case ferr == nil:
			if b, err := os.ReadFile(path); err == nil && json.Valid(b) {
				rec.SBOMPath = path
				rec.SBOMSHA256 = sha256Hex(b)
			}
		case errors.Is(ferr, os.ErrNotExist):
			// No sidecar for this identity: a non-required gate stays empty.
		default:
			return ferr
		}
	}
	sigPending, sigOK, _ := s.pendingSidecarDigest(ctx, j.ID, j.LeaseGeneration, base, storage.ArtifactSidecarKindSigstore)
	if sigOK && sigPending != "" && s.CAS != nil {
		rec.SigstorePath = "cas:" + sigPending
		rec.SigstoreSHA256 = sigPending
	} else {
		path, ferr := findArtifactSidecar(dir, j.LeaseGeneration, base, "sigstore", sigPending)
		switch {
		case ferr == nil:
			if b, err := os.ReadFile(path); err == nil && json.Valid(b) {
				rec.SigstorePath = path
				rec.SigstoreSHA256 = sha256Hex(b)
			}
		case errors.Is(ferr, os.ErrNotExist):
			// No sidecar for this identity: a non-required gate stays empty.
		default:
			return ferr
		}
	}
	return nil
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
