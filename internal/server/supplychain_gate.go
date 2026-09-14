package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
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

const maxSBOMBytes = 8 << 20

// artifactSidecarPath is the deterministic sidecar location next to a job's
// artifacts: <dir>/<base>.<kind>.json.
func artifactSidecarPath(dir, base, kind string) string {
	return filepath.Join(dir, cleanBlobName(base)+"."+kind+".json")
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
// artifact from its frozen contract declaration.
func sigstoreVerifyConfig(c storage.ArtifactContract) supplychain.SigstoreVerifyConfig {
	return supplychain.SigstoreVerifyConfig{
		ExpectedIssuer:   c.SigstoreIssuer,
		ExpectedIdentity: c.SigstoreIdentity,
	}
}

// uploadSBOM accepts a `<name>.sbom` upload: it must correspond to a
// declared artifact whose contract declares an sbom format, and the payload
// must parse as that format. The document is stored as a sidecar next to
// the job's artifacts and attached to the artifact record when it exists.
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
	sum := sha256Hex(body)
	s.attachSidecarToArtifact(r.Context(), j, base, "sbom", sidecar, sum)
	s.metricObserve("kiwi_cas_latency_seconds", time.Since(start).Seconds(), nil)
	writeJSON(w, http.StatusCreated, map[string]any{"name": base + sbomSuffix, "sha256": sum, "format": string(format)})
}

// uploadSigstore accepts a `<name>.sigstore` Sigstore bundle upload. When
// the artifact payload already exists the bundle is verified immediately
// against its digest; otherwise it is stored and the artifact upload gate
// verifies it. A bundle that fails verification is rejected (422) and
// never stored.
func (s *Server) uploadSigstore(w http.ResponseWriter, r *http.Request, j model.Job, c storage.ArtifactContract, base string) {
	if !c.SigstoreRequired && c.SigstoreIssuer == "" && c.SigstoreIdentity == "" {
		s.auditLocked("artifact.sigstore_rejected", j.LeaseRunnerID, j.RunID, j.ID, "sigstore upload without declared sigstore gate", map[string]string{"name": base})
		http.Error(w, "artifact contract does not declare a sigstore gate", http.StatusUnprocessableEntity)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBlobBytes))
	if err != nil {
		http.Error(w, "invalid sigstore bundle", http.StatusBadRequest)
		return
	}
	cfg := sigstoreVerifyConfig(c)
	if recs, lerr := s.findArtifactByJobName(r.Context(), j.RunID, j.ID, base); lerr == nil && len(recs) > 0 {
		latest := recs[len(recs)-1]
		if err := supplychain.VerifySigstoreBundle(body, latest.SHA256, cfg); err != nil {
			s.auditLocked("artifact.sigstore_rejected", j.LeaseRunnerID, j.RunID, j.ID, "sigstore bundle verification failed", map[string]string{"name": base, "error": err.Error()})
			http.Error(w, err.Error(), http.StatusUnprocessableEntity)
			return
		}
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
	sum := sha256Hex(body)
	s.attachSidecarToArtifact(r.Context(), j, base, "sigstore", sidecar, sum)
	s.auditLocked("artifact.sigstore_stored", j.LeaseRunnerID, j.RunID, j.ID, "sigstore bundle stored", map[string]string{"name": base, "sha256": sum})
	writeJSON(w, http.StatusCreated, map[string]any{"name": base + sigstoreSuffix, "sha256": sum})
}

// attachSidecarToArtifact links a verified sidecar (sbom/sigstore) to the
// existing artifact record for base. Memory mode updates the record and
// persists; DB mode updates the in-memory copy (the SQL store has no
// artifact update path, so uploads should send sidecars before the payload).
func (s *Server) attachSidecarToArtifact(ctx context.Context, j model.Job, base, kind, path, sum string) {
	recs, err := s.findArtifactByJobName(ctx, j.RunID, j.ID, base)
	if err != nil || len(recs) == 0 {
		return
	}
	rec := recs[len(recs)-1]
	if kind == "sbom" {
		rec.SBOMPath = path
		rec.SBOMSHA256 = sum
	} else {
		rec.SigstorePath = path
		rec.SigstoreSHA256 = sum
	}
	if s.DB != nil {
		return
	}
	s.mu.Lock()
	if cur, ok := s.artifacts[rec.ID]; ok {
		rec.Path = cur.Path
		rec.ProvenancePath = cur.ProvenancePath
		s.artifacts[rec.ID] = rec
		_ = s.persistLocked()
	}
	s.mu.Unlock()
}

// gateArtifactAttestations enforces the SBOM/sigstore requirements at
// artifact-payload upload time. The frozen contract is authoritative; the
// pipeline text is never re-parsed. It returns an HTTP error string on
// failure.
func (s *Server) gateArtifactAttestations(c storage.ArtifactContract, j model.Job, base string, digest string, dir string) (int, string) {
	if strings.TrimSpace(c.SBOM) != "" {
		format, err := supplychain.ParseSBOMFormat(c.SBOM)
		if err != nil {
			return http.StatusUnprocessableEntity, err.Error()
		}
		sidecar := artifactSidecarPath(dir, base, "sbom")
		b, rerr := os.ReadFile(sidecar)
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
		sidecar := artifactSidecarPath(dir, base, "sigstore")
		b, rerr := os.ReadFile(sidecar)
		if rerr != nil {
			s.auditLocked("artifact.sigstore_missing", j.LeaseRunnerID, j.RunID, j.ID, "required sigstore missing at artifact upload", map[string]string{"name": base})
			return http.StatusUnprocessableEntity, "required sigstore bundle missing: upload <name>.sigstore before the artifact"
		}
		if verr := supplychain.VerifySigstoreBundle(b, digest, sigstoreVerifyConfig(c)); verr != nil {
			s.auditLocked("artifact.sigstore_rejected", j.LeaseRunnerID, j.RunID, j.ID, "required sigstore bundle failed verification", map[string]string{"name": base, "error": verr.Error()})
			return http.StatusUnprocessableEntity, verr.Error()
		}
	}
	return 0, ""
}

// attachSidecarsToRecord fills the sidecar fields of a freshly built
// artifact record from the on-disk sidecars.
func attachSidecarsToRecord(rec *model.ArtifactRecord, j model.Job, base, dir string) {
	if b, err := os.ReadFile(artifactSidecarPath(dir, base, "sbom")); err == nil && json.Valid(b) {
		rec.SBOMPath = artifactSidecarPath(dir, base, "sbom")
		rec.SBOMSHA256 = sha256Hex(b)
	}
	if b, err := os.ReadFile(artifactSidecarPath(dir, base, "sigstore")); err == nil && json.Valid(b) {
		rec.SigstorePath = artifactSidecarPath(dir, base, "sigstore")
		rec.SigstoreSHA256 = sha256Hex(b)
	}
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
