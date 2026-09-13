package provenance

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"time"
)

const StatementType = "https://in-toto.io/Statement/v1"
const PredicateType = "https://slsa.dev/provenance/v1"
const PayloadType = "application/vnd.in-toto+json"

type Statement struct {
	Type          string    `json:"_type"`
	Subject       []Subject `json:"subject"`
	PredicateType string    `json:"predicateType"`
	Predicate     Predicate `json:"predicate"`
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
	Trusted                                                             bool
	Started, Finished                                                   time.Time
}

func ArtifactStatement(in ArtifactInput) Statement {
	return Statement{Type: StatementType, Subject: []Subject{{Name: in.Name, Digest: map[string]string{"sha256": in.SHA256}}}, PredicateType: PredicateType, Predicate: Predicate{BuildDefinition: BuildDefinition{BuildType: "https://kiwi-ci.dev/build/v1", ExternalParameters: map[string]any{"repository": in.Repository, "ref": in.Ref, "commit": in.Commit, "job": in.JobKey, "trusted": in.Trusted}}, RunDetails: RunDetails{Builder: Builder{ID: "https://kiwi-ci.dev/runner/" + in.Runner}, Metadata: Metadata{InvocationID: in.RunID + "/" + in.JobID, StartedOn: in.Started, FinishedOn: in.Finished}}}}
}
func Sign(st Statement, keyID string, priv ed25519.PrivateKey) (Envelope, error) {
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

// SignFile remains useful for local-only builds; the distributed server uses its
// persistent Ed25519 control-plane key instead of generating an ephemeral key.
func SignFile(runID, repo, commit, path string) (*Envelope, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(b)
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
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
