package app

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/provenance"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/server"
)

// VerifyArtifact downloads an artifact and its DSSE provenance, verifies the
// server's Ed25519 signature (or the pinned --trusted-key), then binds the
// attestation subject digest to the bytes that were actually downloaded.
// Non-empty --repository/--commit/--ref/--job/--builder/--issuer/--attempt/
// --capsule-digest/--execution-capsule-digest flags are enforced as statement
// constraints via provenance.VerifyWith.
//
// With --attestation JOB_ID (or --attestation-file PATH) it instead verifies
// the job's FINAL EXECUTION ATTESTATION: the signed envelope is fetched from
// the server (GET /api/v1/jobs/{id}/attestation) or read from disk, the
// signature is verified with the same trust root, and the --attempt /
// --capsule-digest / --execution-capsule-digest constraints are honored.
func VerifyArtifact(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	serverURL := fs.String("server", "http://127.0.0.1:8080", "Kiwi server URL")
	token := fs.String("token", os.Getenv("KIWI_ADMIN_TOKEN"), "admin token")
	repository := fs.String("repository", "", "required provenance repository (constraint)")
	commit := fs.String("commit", "", "required provenance commit (constraint)")
	ref := fs.String("ref", "", "required provenance ref (constraint)")
	job := fs.String("job", "", "required provenance job key (constraint)")
	builder := fs.String("builder", "", "required provenance builder (constraint)")
	issuer := fs.String("issuer", "", "required provenance issuer (constraint)")
	attempt := fs.String("attempt", "", "required provenance attempt ID (constraint, <jobID>:<leaseGeneration>)")
	capsuleDigest := fs.String("capsule-digest", "", "required provenance capsule digest (constraint, sha256 of the persisted compiled job payload)")
	executionCapsuleDigest := fs.String("execution-capsule-digest", "", "required provenance execution capsule digest (constraint, sha256 of the materialized effective execution)")
	trustedKey := fs.String("trusted-key", "", "path to a PEM Ed25519 public key that pins the verification key")
	attestation := fs.String("attestation", "", "job ID whose final execution attestation to fetch and verify (attestation mode)")
	attestationFile := fs.String("attestation-file", "", "path to a saved execution attestation envelope (attestation mode)")
	generation := fs.Int64("generation", 0, "attempt (lease generation) to fetch with --attestation (default: the job's current generation)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *attestation != "" || *attestationFile != "" {
		if *attestation != "" && *attestationFile != "" {
			return fmt.Errorf("--attestation and --attestation-file are mutually exclusive")
		}
		if fs.NArg() != 0 {
			return fmt.Errorf("usage: kiwi verify --attestation JOB_ID [--server URL] [--token TOKEN] [--trusted-key PATH] [--generation N] [--attempt ID] [--capsule-digest D] [--execution-capsule-digest D]")
		}
		if *generation < 0 {
			return fmt.Errorf("--generation must not be negative")
		}
		return verifyExecutionAttestation(*serverURL, *token, *attestation, *attestationFile, *generation, *trustedKey, provenance.VerifyOptions{
			AttemptID:              *attempt,
			CapsuleDigest:          *capsuleDigest,
			ExecutionCapsuleDigest: *executionCapsuleDigest,
		})
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: kiwi verify [--server URL] ARTIFACT_ID")
	}
	id := fs.Arg(0)
	base := strings.TrimRight(*serverURL, "/")
	// The token is a bearer credential: redirects must never be followed.
	client := server.NoRedirectClient(&http.Client{Timeout: 10 * time.Minute})

	req, err := http.NewRequest(http.MethodGet, base+"/api/v1/artifacts/"+id, nil)
	if err != nil {
		return err
	}
	if *token != "" {
		req.Header.Set("Authorization", "Bearer "+*token)
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
		resp.Body.Close()
		return fmt.Errorf("artifact: %s: %s", resp.Status, strings.TrimSpace(string(b)))
	}
	h := sha256.New()
	_, cpErr := io.Copy(h, resp.Body)
	resp.Body.Close()
	if cpErr != nil {
		return cpErr
	}
	artifactSHA := hex.EncodeToString(h.Sum(nil))
	if advertised := strings.TrimSpace(resp.Header.Get("X-Kiwi-Content-SHA256")); advertised != "" && advertised != artifactSHA {
		return fmt.Errorf("artifact digest mismatch: got %s want %s", artifactSHA, advertised)
	}

	envBytes, err := fetchBytes(client, base+"/api/v1/artifacts/"+id+"/provenance", *token)
	if err != nil {
		return err
	}
	opts := provenance.VerifyOptions{
		Repository:             *repository,
		Commit:                 *commit,
		Ref:                    *ref,
		Job:                    *job,
		Builder:                *builder,
		Issuer:                 *issuer,
		AttemptID:              *attempt,
		CapsuleDigest:          *capsuleDigest,
		ExecutionCapsuleDigest: *executionCapsuleDigest,
	}
	resolver, err := verifyKeyResolver(client, base, *trustedKey, &opts)
	if err != nil {
		return err
	}
	st, err := provenance.VerifyWith(envBytes, resolver, opts)
	if err != nil {
		return err
	}
	matched := false
	for _, subject := range st.Subject {
		if subject.Digest["sha256"] == artifactSHA {
			matched = true
			break
		}
	}
	if !matched {
		return fmt.Errorf("signed provenance does not bind artifact digest %s", artifactSHA)
	}
	var env provenance.Envelope
	signer := "unknown"
	if json.Unmarshal(envBytes, &env) == nil && len(env.Signatures) > 0 {
		signer = env.Signatures[0].KeyID
	}
	fmt.Printf("verified artifact %s\n  sha256: %s\n  signer: %s\n", id, artifactSHA, signer)
	return nil
}

// verifyKeyResolver builds the DSSE verification key resolution for one verify
// run: a pinned --trusted-key replaces JWKS lookup entirely (opts.TrustedKey is
// set and the returned resolver is nil), otherwise the server JWKS is fetched
// and a kid resolver is returned.
func verifyKeyResolver(client *http.Client, base, trustedKey string, opts *provenance.VerifyOptions) (func(kid string) (ed25519.PublicKey, bool), error) {
	if trustedKey != "" {
		pub, err := loadTrustedPublicKey(trustedKey)
		if err != nil {
			return nil, err
		}
		opts.TrustedKey = pub
		return nil, nil
	}
	var jwks struct {
		Keys []struct {
			KID string `json:"kid"`
			X   string `json:"x"`
		} `json:"keys"`
	}
	if err := fetchJSON(client, base+"/api/v1/oidc/jwks", "", &jwks); err != nil {
		return nil, err
	}
	keys := map[string]ed25519.PublicKey{}
	for _, k := range jwks.Keys {
		b, err := base64.RawURLEncoding.DecodeString(k.X)
		if err != nil || len(b) != ed25519.PublicKeySize {
			continue
		}
		keys[k.KID] = ed25519.PublicKey(b)
	}
	return func(kid string) (ed25519.PublicKey, bool) {
		pub, ok := keys[kid]
		return pub, ok
	}, nil
}

// verifyExecutionAttestation fetches (or reads) one final execution
// attestation envelope, verifies its signature with the same trust root as
// artifact provenance, enforces the internal consistency of the attestation
// block against its subject, applies the attempt/capsule digest constraints
// and prints the verified identity. Errors are returned (non-zero exit).
func verifyExecutionAttestation(serverURL, token, jobID, file string, generation int64, trustedKey string, opts provenance.VerifyOptions) error {
	var envBytes []byte
	var err error
	base := strings.TrimRight(serverURL, "/")
	client := server.NoRedirectClient(&http.Client{Timeout: 10 * time.Minute})
	display := jobID
	if file != "" {
		envBytes, err = os.ReadFile(file)
		if err != nil {
			return err
		}
		display = file
	} else {
		url := base + "/api/v1/jobs/" + url.PathEscape(jobID) + "/attestation"
		if generation > 0 {
			url += "?generation=" + strconv.FormatInt(generation, 10)
		}
		envBytes, err = fetchBytes(client, url, token)
		if err != nil {
			return err
		}
	}
	resolver, err := verifyKeyResolver(client, base, trustedKey, &opts)
	if err != nil {
		return err
	}
	st, err := provenance.VerifyWith(envBytes, resolver, opts)
	if err != nil {
		return err
	}
	if err := provenance.VerifyExecutionAttestation(st); err != nil {
		return err
	}
	artifacts := 0
	if st.Attestation != nil {
		artifacts = len(st.Attestation.Artifacts)
	}
	var env provenance.Envelope
	signer := "unknown"
	if json.Unmarshal(envBytes, &env) == nil && len(env.Signatures) > 0 {
		signer = env.Signatures[0].KeyID
	}
	fmt.Printf("verified execution attestation %s\n  status: %s\n  attempt: %s\n  capsule digest: %s\n  execution capsule digest: %s\n  artifacts: %d\n  signer: %s\n",
		display, st.Attestation.Status, st.AttemptID, st.CapsuleDigest, st.ExecutionCapsuleDigest, artifacts, signer)
	return nil
}

// loadTrustedPublicKey loads a PKIX "PUBLIC KEY" PEM holding an Ed25519
// public key.
func loadTrustedPublicKey(path string) (ed25519.PublicKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(b)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("trusted key: invalid PEM (want PUBLIC KEY)")
	}
	k, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("trusted key: %w", err)
	}
	pub, ok := k.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("trusted key is not Ed25519")
	}
	return pub, nil
}

func fetchBytes(client *http.Client, url, token string) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
		return nil, fmt.Errorf("GET %s: %s: %s", url, resp.Status, strings.TrimSpace(string(b)))
	}
	return io.ReadAll(io.LimitReader(resp.Body, 8<<20))
}

func fetchJSON(client *http.Client, url, token string, out any) error {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
		return fmt.Errorf("GET %s: %s: %s", url, resp.Status, strings.TrimSpace(string(b)))
	}
	return json.NewDecoder(resp.Body).Decode(out)
}
