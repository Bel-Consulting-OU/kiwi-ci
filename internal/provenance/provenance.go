package provenance

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/version"
)

const StatementType = "https://in-toto.io/Statement/v1"
const PredicateType = "https://slsa.dev/provenance/v1"
const PayloadType = "application/vnd.in-toto+json"

const (
	provenanceKeyFile = "provenance.key"
	provenancePubFile = "provenance.pub"

	maxEnvelopeBytes = 8 << 20
)

// BuilderPlaceholder identifies the kiwi builder version. Callers pass it via
// SignOptions at signing time until a stable builder identity exists.
var BuilderPlaceholder = "kiwi-ci@" + version.Version

type Statement struct {
	Type          string    `json:"_type"`
	Subject       []Subject `json:"subject"`
	PredicateType string    `json:"predicateType"`
	Predicate     Predicate `json:"predicate"`

	ResolvedPipelineSHA256 string          `json:"resolvedPipelineSHA256,omitempty"`
	PipelineDigest         string          `json:"pipelineDigest,omitempty"`
	Builder                string          `json:"builder,omitempty"`
	CompilerVersion        string          `json:"compilerVersion,omitempty"`
	RunnerIdentity         string          `json:"runnerIdentity,omitempty"`
	Runtime                string          `json:"runtime,omitempty"`
	ImageDigest            string          `json:"imageDigest,omitempty"`
	Issuer                 string          `json:"issuer,omitempty"`
	Materials              []MaterialEntry `json:"materials,omitempty"`
	EffectivePolicyDigest  string          `json:"effectivePolicyDigest,omitempty"`
	StartTime              *time.Time      `json:"startTime,omitempty"`
	EndTime                *time.Time      `json:"endTime,omitempty"`
	ArtifactSize           int64           `json:"artifactSize,omitempty"`
}

// MaterialEntry records one consumed input file and its digest.
type MaterialEntry struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

// SignOptions carries optional statement fields applied at signing time.
type SignOptions struct {
	Builder string
}

type Subject struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}
type Predicate struct {
	BuildDefinition BuildDefinition `json:"buildDefinition"`
	RunDetails      RunDetails      `json:"runDetails"`
}
type BuildDefinition struct {
	BuildType          string         `json:"buildType"`
	ExternalParameters map[string]any `json:"externalParameters,omitempty"`
}
type RunDetails struct {
	Builder  Builder  `json:"builder"`
	Metadata Metadata `json:"metadata"`
}
type Builder struct {
	ID string `json:"id"`
}
type Metadata struct {
	InvocationID string    `json:"invocationId"`
	StartedOn    time.Time `json:"startedOn,omitempty"`
	FinishedOn   time.Time `json:"finishedOn"`
}
type Signature struct {
	KeyID string `json:"keyid"`
	Sig   string `json:"sig"`
}
type Envelope struct {
	PayloadType string      `json:"payloadType"`
	Payload     string      `json:"payload"`
	Signatures  []Signature `json:"signatures"`
}

type ArtifactInput struct {
	Name, SHA256, RunID, JobID, JobKey, Repository, Ref, Commit, Runner string
	// Builder, when non-empty, overrides the default runner-derived
	// RunDetails.Builder.ID in the SLSA predicate. Release tooling uses it to
	// record a stable builder identity such as
	// "https://kiwi-ci.dev/builders/release-tool@1.2.3" instead of a runner
	// URL that only exists inside the control plane.
	Builder           string
	Trusted           bool
	Started, Finished time.Time
}

func ArtifactStatement(in ArtifactInput) Statement {
	builderID := in.Builder
	if builderID == "" {
		builderID = "https://kiwi-ci.dev/runner/" + in.Runner
	}
	return Statement{Type: StatementType, Subject: []Subject{{Name: in.Name, Digest: map[string]string{"sha256": in.SHA256}}}, PredicateType: PredicateType, Predicate: Predicate{BuildDefinition: BuildDefinition{BuildType: "https://kiwi-ci.dev/build/v1", ExternalParameters: map[string]any{"repository": in.Repository, "ref": in.Ref, "commit": in.Commit, "job": in.JobKey, "trusted": in.Trusted}}, RunDetails: RunDetails{Builder: Builder{ID: builderID}, Metadata: Metadata{InvocationID: in.RunID + "/" + in.JobID, StartedOn: in.Started, FinishedOn: in.Finished}}}}
}
func Sign(st Statement, keyID string, priv ed25519.PrivateKey) (Envelope, error) {
	return SignWith(st, keyID, priv, SignOptions{})
}
func SignWith(st Statement, keyID string, priv ed25519.PrivateKey, opts SignOptions) (Envelope, error) {
	if opts.Builder != "" {
		st.Builder = opts.Builder
	}
	b, err := json.Marshal(st)
	if err != nil {
		return Envelope{}, err
	}
	payload := base64.StdEncoding.EncodeToString(b)
	preauth := dssePAE(PayloadType, []byte(b))
	sig := ed25519.Sign(priv, preauth)
	return Envelope{PayloadType: PayloadType, Payload: payload, Signatures: []Signature{{KeyID: keyID, Sig: base64.StdEncoding.EncodeToString(sig)}}}, nil
}
func Verify(env Envelope, pub ed25519.PublicKey) error {
	if env.PayloadType != PayloadType {
		return fmt.Errorf("unexpected payload type %q", env.PayloadType)
	}
	b, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return err
	}
	if len(env.Signatures) == 0 {
		return fmt.Errorf("missing signature")
	}
	sig, err := base64.StdEncoding.DecodeString(env.Signatures[0].Sig)
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub, dssePAE(env.PayloadType, b), sig) {
		return fmt.Errorf("invalid provenance signature")
	}
	return nil
}
func dssePAE(t string, p []byte) []byte {
	return []byte(fmt.Sprintf("DSSEv1 %d %s %d %s", len(t), t, len(p), p))
}

// VerifyOptions declares non-empty constraints that must all match the
// verified statement, plus an optional pinned trust root.
type VerifyOptions struct {
	Repository string
	Commit     string
	Ref        string
	Job        string
	Builder    string
	Issuer     string
	// Digest, when non-empty, must equal the sha256 digest of the first
	// subject. Callers that consumed artifact bytes should always set it so
	// the signature is bound to exactly those bytes.
	Digest     string
	TrustedKey ed25519.PublicKey
}

// VerifyWith parses, verifies and constraint-checks a serialized DSSE
// envelope. When TrustedKey is set it is the only accepted verification key
// and jwksOrKey is never consulted; otherwise the key is resolved through
// jwksOrKey using the signature keyid.
func VerifyWith(envelope []byte, jwksOrKey func(kid string) (ed25519.PublicKey, bool), opts VerifyOptions) (Statement, error) {
	if len(envelope) > maxEnvelopeBytes {
		return Statement{}, fmt.Errorf("provenance envelope exceeds %d byte limit", maxEnvelopeBytes)
	}
	var env Envelope
	if err := json.Unmarshal(envelope, &env); err != nil {
		return Statement{}, fmt.Errorf("provenance: decode envelope: %w", err)
	}
	if env.PayloadType != PayloadType {
		return Statement{}, fmt.Errorf("provenance: unexpected payload type %q", env.PayloadType)
	}
	payload, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return Statement{}, fmt.Errorf("provenance: decode payload: %w", err)
	}
	if len(env.Signatures) == 0 {
		return Statement{}, fmt.Errorf("provenance: missing signature")
	}
	sig, err := base64.StdEncoding.DecodeString(env.Signatures[0].Sig)
	if err != nil {
		return Statement{}, fmt.Errorf("provenance: decode signature: %w", err)
	}
	var pub ed25519.PublicKey
	if len(opts.TrustedKey) > 0 {
		pub = opts.TrustedKey
	} else {
		if jwksOrKey == nil {
			return Statement{}, fmt.Errorf("provenance: no trusted key and no key resolver")
		}
		var ok bool
		if pub, ok = jwksOrKey(env.Signatures[0].KeyID); !ok {
			return Statement{}, fmt.Errorf("provenance: unknown verification key %q", env.Signatures[0].KeyID)
		}
	}
	if len(pub) != ed25519.PublicKeySize {
		return Statement{}, fmt.Errorf("provenance: invalid Ed25519 public key")
	}
	if !ed25519.Verify(pub, dssePAE(env.PayloadType, payload), sig) {
		return Statement{}, fmt.Errorf("provenance: invalid provenance signature")
	}
	var st Statement
	if err := json.Unmarshal(payload, &st); err != nil {
		return Statement{}, fmt.Errorf("provenance: decode statement: %w", err)
	}
	if st.Type != StatementType {
		return Statement{}, fmt.Errorf("provenance: unexpected statement type %q", st.Type)
	}
	// A provenance statement without a subject (or with a subject that carries
	// no digest) binds nothing: reject it rather than return a statement that
	// a caller could mistake for a verified artifact binding.
	if len(st.Subject) == 0 {
		return Statement{}, fmt.Errorf("provenance: statement has no subject")
	}
	for _, s := range st.Subject {
		if s.Digest["sha256"] == "" {
			return Statement{}, fmt.Errorf("provenance: subject %q has no sha256 digest", s.Name)
		}
	}
	ep := st.Predicate.BuildDefinition.ExternalParameters
	for _, c := range []struct {
		want, got string
		label     string
	}{
		{opts.Repository, fmt.Sprint(ep["repository"]), "repository"},
		{opts.Commit, fmt.Sprint(ep["commit"]), "commit"},
		{opts.Ref, fmt.Sprint(ep["ref"]), "ref"},
		{opts.Job, fmt.Sprint(ep["job"]), "job"},
		{opts.Builder, st.Predicate.RunDetails.Builder.ID, "builder"},
		{opts.Issuer, st.Issuer, "issuer"},
		{opts.Digest, st.Subject[0].Digest["sha256"], "subject digest"},
	} {
		if c.want != "" && c.got != c.want {
			return Statement{}, fmt.Errorf("provenance: %s mismatch: want %q, got %q", c.label, c.want, c.got)
		}
	}
	return st, nil
}

// randReader is a test-only seam over crypto/rand.Reader. Production
// behavior is unchanged; it lets key-generation failures be exercised.
var randReader io.Reader = rand.Reader

// NewProvenanceKey generates a fresh Ed25519 provenance signing key pair.
func NewProvenanceKey() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	pub, priv, err := ed25519.GenerateKey(randReader)
	if err != nil {
		return nil, nil, err
	}
	return pub, priv, nil
}

// LoadOrCreateProvenanceKey loads provenance.key/provenance.pub from dir,
// generating and persisting them on first use. The file names are distinct
// from the OIDC signing key so the two trust roots never share storage.
func LoadOrCreateProvenanceKey(dir string) (pub ed25519.PublicKey, priv ed25519.PrivateKey, err error) {
	keyPath := filepath.Join(dir, provenanceKeyFile)
	pubPath := filepath.Join(dir, provenancePubFile)
	keyPEM, keyErr := os.ReadFile(keyPath)
	pubPEM, pubErr := os.ReadFile(pubPath)
	if keyErr == nil && pubErr == nil {
		if priv, err = parseProvenancePrivateKey(keyPEM); err == nil {
			if pub, err = parseProvenancePublicKey(pubPEM); err == nil {
				if bytes.Equal(pub, priv.Public().(ed25519.PublicKey)) {
					return pub, priv, nil
				}
				return nil, nil, fmt.Errorf("provenance: key pair in %s does not match", dir)
			}
			return nil, nil, fmt.Errorf("provenance: parse %s: %w", pubPath, err)
		}
		return nil, nil, fmt.Errorf("provenance: parse %s: %w", keyPath, err)
	}
	if keyErr == nil || pubErr == nil {
		return nil, nil, fmt.Errorf("provenance: incomplete key pair in %s", dir)
	}
	pub, priv, err = NewProvenanceKey()
	if err != nil {
		return nil, nil, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, nil, err
	}
	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, nil, err
	}
	keyOut := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	pubOut := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
	if err := os.WriteFile(keyPath, keyOut, 0o600); err != nil {
		return nil, nil, err
	}
	if err := os.WriteFile(pubPath, pubOut, 0o644); err != nil {
		return nil, nil, err
	}
	return pub, priv, nil
}

func parseProvenancePrivateKey(pemBytes []byte) (ed25519.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("provenance: invalid private key PEM")
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	priv, ok := k.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("provenance: key is not Ed25519")
	}
	return priv, nil
}

func parseProvenancePublicKey(pemBytes []byte) (ed25519.PublicKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("provenance: invalid public key PEM")
	}
	k, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	pub, ok := k.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("provenance: key is not Ed25519")
	}
	return pub, nil
}

// SignFile remains useful for local-only builds; the distributed server uses its
// persistent Ed25519 control-plane key instead of generating an ephemeral key.
func SignFile(runID, repo, commit, path string) (*Envelope, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(b)
	pub, priv, err := ed25519.GenerateKey(randReader)
	if err != nil {
		return nil, err
	}
	kidSum := sha256.Sum256(pub)
	st := ArtifactStatement(ArtifactInput{Name: path, SHA256: hex.EncodeToString(sum[:]), RunID: runID, Repository: repo, Commit: commit, Finished: time.Now()})
	env, err := Sign(st, hex.EncodeToString(kidSum[:8]), priv)
	if err != nil {
		return nil, err
	}
	return &env, nil
}
