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

// artifactSidecarPath is the deterministic sidecar location next to a job's
// artifacts: <dir>/<base>.<kind>.json.
func artifactSidecarPath(dir, base, kind string) string {
	return filepath.Join(dir, cleanBlobName(base)+"."+kind+".json")
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
		if _, perr := s.CAS.Put(ctx, bytes.NewReader(body)); perr != nil {
			http.Error(w, perr.Error(), 500)
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
	if err := os.MkdirAll(dir, 0o700); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	sidecar := artifactSidecarPath(dir, base, "sbom")
	if err := writeFileAtomic(sidecar, body, 0o600); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	// Dev-mode mirror of the durable pending row (fs mode has no shared
	// store): the payload gate and the record attachment can resolve the
	// digest when a CAS backend is attached, and fall back to the local
	// sidecar file otherwise. The map write never fails.
	_ = s.rememberPendingSidecar(ctx, j, base, storage.ArtifactSidecarKindSBOM, sum)
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
	if recs, lerr := s.findArtifactByJobName(r.Context(), j.RunID, j.ID, base); lerr == nil && len(recs) > 0 {
		latest := recs[len(recs)-1]
		if err := supplychain.VerifySigstoreBundle(body, latest.SHA256, cfg); err != nil {
			s.auditLocked("artifact.sigstore_rejected", j.LeaseRunnerID, j.RunID, j.ID, "sigstore bundle verification failed", map[string]string{"name": base, "error": err.Error()})
			http.Error(w, err.Error(), http.StatusUnprocessableEntity)
			return
		}
	}
	sum := sha256Hex(body)
	ctx := r.Context()
	if s.DB != nil {
		if s.CAS == nil {
			http.Error(w, "sidecar storage requires a blob store", http.StatusServiceUnavailable)
			return
		}
		if _, perr := s.CAS.Put(ctx, bytes.NewReader(body)); perr != nil {
			http.Error(w, perr.Error(), 500)
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
	if err := os.MkdirAll(dir, 0o700); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	sidecar := artifactSidecarPath(dir, base, "sigstore")
	if err := writeFileAtomic(sidecar, body, 0o600); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	// Dev-mode mirror of the durable pending row: see uploadSBOM.
	_ = s.rememberPendingSidecar(ctx, j, base, storage.ArtifactSidecarKindSigstore, sum)
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
// mirror. DB mode keys the durable row by (job, artifact, kind) directly.
func sidecarPendingKey(jobID, base, kind string) string {
	return jobID + "\x00" + cleanBlobName(base) + "\x00" + kind
}

// encodePendingSidecar packs a dev-mode mirror entry: the CAS digest plus
// its creation time, so the memory tick can age out stale entries without
// widening the shared Server struct.
func encodePendingSidecar(digest string, created time.Time) string {
	return strconv.FormatInt(created.UTC().UnixNano(), 10) + "\x00" + digest
}

// decodePendingSidecar unpacks a dev-mode mirror entry. Entries written in
// the legacy bare-digest form decode as digest-only.
func decodePendingSidecar(v string) (digest string, created time.Time, ok bool) {
	idx := strings.IndexByte(v, 0)
	if idx <= 0 {
		if v == "" {
			return "", time.Time{}, false
		}
		return v, time.Time{}, true
	}
	ns, err := strconv.ParseInt(v[:idx], 10, 64)
	if err != nil {
		return v, time.Time{}, true
	}
	return v[idx+1:], time.Unix(0, ns).UTC(), true
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
// through CAS. DB mode writes the DURABLE artifact_pending_sidecars row
// (visible to every replica, survives restarts); fs/memory mode keeps the
// in-memory mirror, which is dev-mode state only. A DB-mode store failure
// is returned so the caller fails closed — never a 201 without pending
// state.
func (s *Server) rememberPendingSidecar(ctx context.Context, j model.Job, base, kind, digest string) error {
	if ss, ok := s.sidecarStore(); ok {
		return ss.RememberPendingSidecar(ctx, j.ID, cleanBlobName(base), kind, digest)
	}
	if s.DB != nil {
		return fmt.Errorf("artifact sidecar store unavailable")
	}
	s.mu.Lock()
	s.pendingSidecars[sidecarPendingKey(j.ID, base, kind)] = encodePendingSidecar(digest, time.Now().UTC())
	s.mu.Unlock()
	return nil
}

// pendingSidecarDigest resolves the CAS digest of a pending sidecar: from
// the durable store in DB mode, from the in-memory mirror otherwise.
func (s *Server) pendingSidecarDigest(ctx context.Context, jobID, base, kind string) (string, bool, error) {
	if ss, ok := s.sidecarStore(); ok {
		return ss.PendingSidecar(ctx, jobID, cleanBlobName(base), kind)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.pendingSidecars[sidecarPendingKey(jobID, base, kind)]
	if !ok {
		return "", false, nil
	}
	digest, _, ok := decodePendingSidecar(v)
	return digest, ok && digest != "", nil
}

// consumeArtifactPendingSidecars deletes the pending rows whose digests
// were copied into a durably committed artifact record, then clears the
// job's leftover rows (DeletePendingSidecars): every remaining digest was
// either attached to the record or is expendable. It MUST run only after
// the record insert committed; a crash in between leaves the pending rows
// in place for the retry. Failures are the caller's to log: the record is
// already durable and the maintenance tick prunes leftovers.
func (s *Server) consumeArtifactPendingSidecars(ctx context.Context, jobID string, rec model.ArtifactRecord) error {
	ss, ok := s.sidecarStore()
	if !ok {
		return nil
	}
	name := cleanBlobName(rec.Name)
	if rec.SBOMSHA256 != "" {
		if err := ss.ConsumePendingSidecar(ctx, jobID, name, storage.ArtifactSidecarKindSBOM, rec.SBOMSHA256); err != nil {
			return err
		}
	}
	if rec.SigstoreSHA256 != "" {
		if err := ss.ConsumePendingSidecar(ctx, jobID, name, storage.ArtifactSidecarKindSigstore, rec.SigstoreSHA256); err != nil {
			return err
		}
	}
	return ss.DeletePendingSidecars(ctx, jobID)
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
	for key, v := range s.pendingSidecars {
		_, created, ok := decodePendingSidecar(v)
		if !ok || created.Before(cutoff) {
			delete(s.pendingSidecars, key)
		}
	}
}

// attachSidecarToArtifact links a verified sidecar (sbom/sigstore) to the
// existing artifact record for base and returns an error when the link
// cannot be durably recorded: DB mode persists the digest references
// through the store (ArtifactSidecarStore), and a persistence failure must
// fail the request closed (503) instead of acknowledging a sidecar the
// record does not carry. No record yet is not a failure: the pending row
// is resolved when the artifact payload is recorded. Memory mode updates
// the in-memory record.
func (s *Server) attachSidecarToArtifact(ctx context.Context, j model.Job, base, kind, path, sum string) error {
	recs, err := s.findArtifactByJobName(ctx, j.RunID, j.ID, base)
	if err != nil {
		return err
	}
	if len(recs) == 0 {
		return nil
	}
	rec := recs[len(recs)-1]
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
		if kind == storage.ArtifactSidecarKindSBOM {
			cur.SBOMPath = path
			cur.SBOMSHA256 = sum
		} else {
			cur.SigstorePath = path
			cur.SigstoreSHA256 = sum
		}
		s.artifacts[rec.ID] = cur
		_ = s.persistLocked()
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
// durable pending row in DB mode (the digest points into the shared CAS),
// from the pending map when present, from the local sidecar file in
// fs/memory mode otherwise. An unresolvable sidecar is reported as an
// error so the gate fails closed.
func (s *Server) sidecarBytes(ctx context.Context, j model.Job, base, kind, dir string) ([]byte, error) {
	if s.DB != nil {
		d, ok, err := s.pendingSidecarDigest(ctx, j.ID, base, kind)
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
	if d, ok, err := s.pendingSidecarDigest(ctx, j.ID, base, kind); err == nil && ok && d != "" && s.CAS != nil {
		if rc, _, oerr := s.CAS.Open(ctx, d); oerr == nil {
			defer rc.Close()
			return io.ReadAll(io.LimitReader(rc, maxSBOMBytes+1))
		}
	}
	return os.ReadFile(artifactSidecarPath(dir, base, kind))
}

// attachSidecarsToRecord fills the sidecar fields of a freshly built
// artifact record: from the DURABLE pending-sidecar rows in DB mode (their
// CAS digest references), from the pending mirror / local sidecar files in
// fs mode. A store lookup failure is returned so the caller fails the
// upload instead of recording an artifact that silently lost its attested
// sidecars.
func (s *Server) attachSidecarsToRecord(ctx context.Context, rec *model.ArtifactRecord, j model.Job, base, dir string) error {
	if s.DB != nil {
		ss, ok := s.sidecarStore()
		if !ok {
			return fmt.Errorf("artifact sidecar store unavailable")
		}
		if d, ok, err := ss.PendingSidecar(ctx, j.ID, cleanBlobName(base), storage.ArtifactSidecarKindSBOM); err != nil {
			return err
		} else if ok && d != "" {
			rec.SBOMPath = "cas:" + d
			rec.SBOMSHA256 = d
		}
		if d, ok, err := ss.PendingSidecar(ctx, j.ID, cleanBlobName(base), storage.ArtifactSidecarKindSigstore); err != nil {
			return err
		} else if ok && d != "" {
			rec.SigstorePath = "cas:" + d
			rec.SigstoreSHA256 = d
		}
		return nil
	}
	if d, ok, _ := s.pendingSidecarDigest(ctx, j.ID, base, storage.ArtifactSidecarKindSBOM); ok && d != "" && s.CAS != nil {
		rec.SBOMPath = "cas:" + d
		rec.SBOMSHA256 = d
	} else if b, err := os.ReadFile(artifactSidecarPath(dir, base, "sbom")); err == nil && json.Valid(b) {
		rec.SBOMPath = artifactSidecarPath(dir, base, "sbom")
		rec.SBOMSHA256 = sha256Hex(b)
	}
	if d, ok, _ := s.pendingSidecarDigest(ctx, j.ID, base, storage.ArtifactSidecarKindSigstore); ok && d != "" && s.CAS != nil {
		rec.SigstorePath = "cas:" + d
		rec.SigstoreSHA256 = d
	} else if b, err := os.ReadFile(artifactSidecarPath(dir, base, "sigstore")); err == nil && json.Valid(b) {
		rec.SigstorePath = artifactSidecarPath(dir, base, "sigstore")
		rec.SigstoreSHA256 = sha256Hex(b)
	}
	return nil
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
