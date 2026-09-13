package app

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
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
// server's Ed25519 signature, then binds the attestation subject digest to the
// bytes that were actually downloaded.
func VerifyArtifact(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	serverURL := fs.String("server", "http://127.0.0.1:8080", "Kiwi server URL")
	token := fs.String("token", os.Getenv("KIWI_ADMIN_TOKEN"), "admin token")
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

	var env provenance.Envelope
	if err := fetchJSON(client, base+"/api/v1/artifacts/"+id+"/provenance", *token, &env); err != nil {
		return err
	}
	var jwks struct {
		Keys []struct {
			KID string `json:"kid"`
			X   string `json:"x"`
		} `json:"keys"`
	}
	if err := fetchJSON(client, base+"/api/v1/oidc/jwks", "", &jwks); err != nil {
		return err
	}
	if len(env.Signatures) == 0 {
		return fmt.Errorf("provenance has no signature")
	}
	kid := env.Signatures[0].KeyID
	var pub ed25519.PublicKey
	for _, k := range jwks.Keys {
		if k.KID != kid {
			continue
		}
		b, err := base64.RawURLEncoding.DecodeString(k.X)
		if err != nil {
			return err
		}
		if len(b) != ed25519.PublicKeySize {
			return fmt.Errorf("invalid Ed25519 public key length")
		}
		pub = ed25519.PublicKey(b)
		break
	}
	if pub == nil {
		return fmt.Errorf("provenance signing key %q not present in server JWKS", kid)
	}
	if err := provenance.Verify(env, pub); err != nil {
		return err
	}
	payload, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return err
	}
	var st provenance.Statement
	if err := json.Unmarshal(payload, &st); err != nil {
		return fmt.Errorf("decode provenance statement: %w", err)
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
	fmt.Printf("verified artifact %s\n  sha256: %s\n  signer: %s\n", id, artifactSHA, kid)
	return nil
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
