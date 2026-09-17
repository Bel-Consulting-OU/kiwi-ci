// release-tool is a small release helper invoked by scripts/release.sh. It
// reads one built kiwi binary and emits, next to it:
//
//   - <binary>.sbom.cdx.json     a CycloneDX 1.5 SBOM for the binary
//   - <binary>.provenance.json   a DSSE envelope over an in-toto statement
//     (SLSA provenance v1 predicate) signed with a caller-supplied Ed25519
//     key in PKCS#8 PEM form
//
// The provenance file is skipped when no signing key is provided.
package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/provenance"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/supplychain"
)

type releaseInput struct {
	Binary  string
	Name    string
	Version string
	Commit  string
	Repo    string
	Ref     string
	OutDir  string
	KeyFile string
}

func main() {
	os.Exit(runCLI(os.Args[1:]))
}

// runCLI parses args, runs the release pipeline and returns the process exit
// code: 2 for flag errors, 1 for failures, 0 on success.
func runCLI(args []string) int {
	in, err := parseFlags(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "release-tool: %v\n", err)
		return 2
	}
	if err := run(in); err != nil {
		fmt.Fprintf(os.Stderr, "release-tool: %v\n", err)
		return 1
	}
	return 0
}

func parseFlags(args []string) (releaseInput, error) {
	fs := flag.NewFlagSet("release-tool", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	in := releaseInput{}
	fs.StringVar(&in.Binary, "binary", "", "path to the built kiwi binary")
	fs.StringVar(&in.Name, "name", "kiwi", "artifact name used in the SBOM")
	fs.StringVar(&in.Version, "version", "", "release version")
	fs.StringVar(&in.Commit, "commit", "", "git commit of the build")
	fs.StringVar(&in.Repo, "repo", "", "repository URL of the build")
	fs.StringVar(&in.Ref, "ref", "", "git ref/tag of the build")
	fs.StringVar(&in.OutDir, "out", ".", "directory to write SBOM/provenance into")
	fs.StringVar(&in.KeyFile, "key", "", "path to an Ed25519 PKCS#8 PEM signing key (optional)")
	if err := fs.Parse(args); err != nil {
		return in, err
	}
	if fs.NArg() > 0 {
		return in, fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	if in.Binary == "" {
		return in, fmt.Errorf("-binary is required")
	}
	return in, nil
}

func run(in releaseInput) error {
	sum, size, err := sha256File(in.Binary)
	if err != nil {
		return err
	}
	base := filepath.Base(in.Binary)

	sbom, err := emitSBOM(in, base, sum, size)
	if err != nil {
		return err
	}
	sbomPath := filepath.Join(in.OutDir, base+".sbom.cdx.json")
	if err := os.WriteFile(sbomPath, sbom, 0o644); err != nil {
		return err
	}
	fmt.Printf("wrote %s\n", sbomPath)

	if in.KeyFile == "" {
		fmt.Fprintf(os.Stderr, "release-tool: no signing key (-key); skipping provenance for %s\n", base)
		return nil
	}
	priv, keyID, err := loadSigningKey(in.KeyFile)
	if err != nil {
		return err
	}
	env, err := emitProvenance(in, base, sum, priv, keyID)
	if err != nil {
		return err
	}
	envPath := filepath.Join(in.OutDir, base+".provenance.json")
	if err := os.WriteFile(envPath, env, 0o644); err != nil {
		return err
	}
	fmt.Printf("wrote %s\n", envPath)
	return nil
}

func sha256File(path string) ([32]byte, int64, error) {
	var sum [32]byte
	b, err := os.ReadFile(path)
	if err != nil {
		return sum, 0, err
	}
	return sha256.Sum256(b), int64(len(b)), nil
}

// emitSBOM renders the CycloneDX 1.5 SBOM for one release binary.
func emitSBOM(in releaseInput, base string, sum [32]byte, size int64) ([]byte, error) {
	entries := []supplychain.ArtifactEntry{{
		Path:   base,
		SHA256: hex.EncodeToString(sum[:]),
		Size:   size,
	}}
	return supplychain.GenerateCycloneDXJSON(in.Name, in.Version, in.Repo, in.Commit, entries)
}

// emitProvenance builds an in-toto statement (SLSA provenance v1 predicate)
// binding the binary digest to the repository/ref/commit and signs it into a
// DSSE envelope with the release Ed25519 key.
func emitProvenance(in releaseInput, base string, sum [32]byte, priv ed25519.PrivateKey, keyID string) ([]byte, error) {
	st := provenance.ArtifactStatement(provenance.ArtifactInput{
		Name:       base,
		SHA256:     hex.EncodeToString(sum[:]),
		RunID:      "release",
		JobID:      base,
		JobKey:     in.Ref,
		Repository: in.Repo,
		Ref:        in.Ref,
		Commit:     in.Commit,
		Runner:     "release-tool",
		Trusted:    true,
		Started:    time.Now().UTC(),
		Finished:   time.Now().UTC(),
	})
	env, err := provenance.SignWith(st, keyID, priv, provenance.SignOptions{
		Builder: "kiwi-ci@" + in.Version,
	})
	if err != nil {
		return nil, err
	}
	return json.MarshalIndent(env, "", "  ")
}

// loadSigningKey parses an Ed25519 PKCS#8 private key PEM and derives the
// keyid from the public half (first 8 bytes of its SHA-256, hex).
func loadSigningKey(path string) (ed25519.PrivateKey, string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, "", err
	}
	block, _ := pem.Decode(b)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, "", fmt.Errorf("release-tool: key %s is not a PEM private key", path)
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, "", fmt.Errorf("release-tool: parse key %s: %w", path, err)
	}
	priv, ok := k.(ed25519.PrivateKey)
	if !ok {
		return nil, "", fmt.Errorf("release-tool: key %s is not Ed25519", path)
	}
	pub := priv.Public().(ed25519.PublicKey)
	kid := sha256.Sum256(pub)
	return priv, hex.EncodeToString(kid[:8]), nil
}
