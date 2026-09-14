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
	"os"
	"strings"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/provenance"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/server"
)

// VerifyArtifact downloads an artifact and its DSSE provenance, verifies the
// server's Ed25519 signature (or the pinned --trusted-key), then binds the
// attestation subject digest to the bytes that were actually downloaded.
// Non-empty --repository/--commit/--ref/--job/--builder/--issuer flags are
// enforced as statement constraints via provenance.VerifyWith.
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
	trustedKey := fs.String("trusted-key", "", "path to a PEM Ed25519 public key that pins the verification key")
	if err := fs.Parse(args); err != nil {
		return err
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
		Repository: *repository,
		Commit:     *commit,
		Ref:        *ref,
		Job:        *job,
		Builder:    *builder,
		Issuer:     *issuer,
	}
	var resolver func(kid string) (ed25519.PublicKey, bool)
	if *trustedKey != "" {
		pub, err := loadTrustedPublicKey(*trustedKey)
		if err != nil {
			return err
		}
		opts.TrustedKey = pub
	} else {
		var jwks struct {
			Keys []struct {
				KID string `json:"kid"`
				X   string `json:"x"`
			} `json:"keys"`
		}
		if err := fetchJSON(client, base+"/api/v1/oidc/jwks", "", &jwks); err != nil {
			return err
		}
		keys := map[string]ed25519.PublicKey{}
		for _, k := range jwks.Keys {
			b, err := base64.RawURLEncoding.DecodeString(k.X)
			if err != nil || len(b) != ed25519.PublicKeySize {
				continue
			}
			keys[k.KID] = ed25519.PublicKey(b)
		}
		resolver = func(kid string) (ed25519.PublicKey, bool) {
			pub, ok := keys[kid]
			return pub, ok
		}
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
