package runner

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/artifact"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/server"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/supplychain"
	"gopkg.in/yaml.v3"
)

// declaredArtifactFor resolves the artifact declaration for name on the
// effective compiled job. When the strict schema lacks the declaration
// (matrix variants or pipelines parsed before sbom/sigstore rollout), the
// raw pipeline YAML is parsed leniently for the sbom/sigstore keys, exactly
// like the control plane does.
func declaredArtifactFor(j model.Job, cj pipeline.CompiledJob, name string) (pipeline.Artifact, bool) {
	for _, a := range cj.Job.Artifacts {
		if a.Name == name {
			return a, true
		}
	}
	var raw struct {
		Jobs map[string]struct {
			Artifacts []struct {
				Name     string                   `yaml:"name"`
				SBOM     string                   `yaml:"sbom"`
				Sigstore *pipeline.SigstoreConfig `yaml:"sigstore"`
			} `yaml:"artifacts"`
		} `yaml:"jobs"`
	}
	if err := yaml.Unmarshal([]byte(j.Pipeline), &raw); err != nil {
		return pipeline.Artifact{}, false
	}
	lookup := []string{j.Key}
	if j.BaseKey != "" && j.BaseKey != j.Key {
		lookup = append(lookup, j.BaseKey)
	}
	for _, key := range lookup {
		job, ok := raw.Jobs[key]
		if !ok {
			continue
		}
		for _, a := range job.Artifacts {
			if a.Name == name {
				return pipeline.Artifact{Name: a.Name, SBOM: a.SBOM, Sigstore: a.Sigstore}, true
			}
		}
	}
	return pipeline.Artifact{}, false
}

// uploadArtifactWithAttestations uploads one captured artifact honoring the
// control plane's contract enforcement order: the declared <name>.sbom and
// <name>.sigstore attestations go up BEFORE the payload, which the server
// gates on their presence.
func (r *Runner) uploadArtifactWithAttestations(ctx context.Context, t server.Task, cj pipeline.CompiledJob, name, path string) error {
	decl, ok := declaredArtifactFor(t.Job, cj, name)
	if ok && strings.TrimSpace(decl.SBOM) != "" {
		format, err := supplychain.ParseSBOMFormat(decl.SBOM)
		if err != nil {
			return fmt.Errorf("artifact %s sbom: %w", name, err)
		}
		sbom, err := r.buildSBOM(name, t.Job, format, path)
		if err != nil {
			return fmt.Errorf("artifact %s sbom: %w", name, err)
		}
		if err := r.putArtifactBytes(ctx, t, name+".sbom", sbom, "application/json"); err != nil {
			return err
		}
	}
	if ok && decl.Sigstore != nil {
		if r.Cfg.SigstoreKeyPath == "" {
			if decl.Sigstore.Required {
				return fmt.Errorf("artifact %s: sigstore gate required but no signing key configured (--sigstore-key)", name)
			}
			fmt.Fprintf(os.Stderr, "kiwi runner: artifact %s declares a sigstore gate but no signing key is configured; skipping attestation\n", name)
		} else {
			bundle, err := r.signArtifactBundle(name, t.Job, path, decl.Sigstore)
			if err != nil {
				return fmt.Errorf("artifact %s sigstore: %w", name, err)
			}
			if err := r.putArtifactBytes(ctx, t, name+".sigstore", bundle, "application/json"); err != nil {
				return err
			}
		}
	}
	return r.uploadArtifact(ctx, t, name, path)
}

// buildSBOM renders an SBOM for the captured artifact archive from its
// manifest entries in the declared format.
func (r *Runner) buildSBOM(name string, j model.Job, format supplychain.SBOMFormat, path string) ([]byte, error) {
	man, err := artifact.ReadManifest(path + ".manifest.json")
	if err != nil {
		return nil, err
	}
	entries := make([]supplychain.ArtifactEntry, 0, len(man.Entries))
	for _, e := range man.Entries {
		entries = append(entries, supplychain.ArtifactEntry{Path: e.Path, SHA256: e.SHA256, Size: e.Size})
	}
	commit := j.SHA
	if commit == "" {
		commit = j.Ref
	}
	switch format {
	case supplychain.SBOMSPDX:
		return supplychain.GenerateSPDXJSON(name, "1", j.RepoURL, commit, entries)
	case supplychain.SBOMCycloneDX:
		return supplychain.GenerateCycloneDXJSON(name, "1", j.RepoURL, commit, entries)
	}
	return nil, fmt.Errorf("unsupported sbom format %q", format)
}

// signArtifactBundle signs the artifact digest with the configured Ed25519
// signing key and wraps the DSSE envelope in a Sigstore bundle carrying the
// verification material (embedded public key), which is the format the
// control plane's attestation gate verifies.
func (r *Runner) signArtifactBundle(name string, j model.Job, path string, cfg *pipeline.SigstoreConfig) ([]byte, error) {
	keyPEM, err := loadPEM(r.Cfg.SigstoreKeyPath)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(keyPEM)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("sigstore key: invalid PEM (want PKCS8 PRIVATE KEY)")
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("sigstore key: %w", err)
	}
	priv, ok := k.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("sigstore key is not Ed25519")
	}
	pub := priv.Public().(ed25519.PublicKey)
	digest, err := sha256File(path)
	if err != nil {
		return nil, err
	}
	kidSum := sha256.Sum256(pub)
	kid := hex.EncodeToString(kidSum[:8])
	env, err := supplychain.SignArtifact(priv, kid, digest, j.RepoURL, j.Ref, supplychain.SignOptions{
		Issuer:   cfg.Issuer,
		Identity: cfg.Identity,
		Builder:  "kiwi-runner",
	})
	if err != nil {
		return nil, err
	}
	bundle := map[string]any{
		"mediaType":    supplychain.SigstoreBundleMediaType,
		"dsseEnvelope": json.RawMessage(env),
		"verificationMaterial": map[string]any{
			"publicKey": map[string]any{
				"rawBytes": base64.StdEncoding.EncodeToString(pub),
			},
		},
	}
	return json.Marshal(bundle)
}

func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// putArtifactBytes PUTs an in-memory artifact sibling (sbom/sigstore) under
// the job lease.
func (r *Runner) putArtifactBytes(ctx context.Context, t server.Task, name string, body []byte, contentType string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, r.Cfg.Server+"/api/v1/jobs/"+t.Job.ID+"/artifacts/"+name, strings.NewReader(string(body)))
	if err != nil {
		return err
	}
	r.auth(req)
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("X-Kiwi-Runner-ID", r.ID)
	req.Header.Set("X-Kiwi-Lease-Token", t.LeaseToken)
	req.Header.Set("X-Kiwi-Lease-Generation", fmt.Sprint(t.LeaseGeneration))
	resp, err := r.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("artifact upload %s: %s", resp.Status, strings.TrimSpace(string(b)))
	}
	return nil
}
