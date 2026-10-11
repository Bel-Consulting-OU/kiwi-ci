package dogfood

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"path"
	"strings"
	"time"
)

// defaultEntropy is the production namespace entropy source. It is a
// package-level func (not a Harness field) so namespace identity cannot be
// accidentally seeded by the scenario PRNG.
func defaultEntropy() io.Reader { return rand.Reader }

// Namespace is the per-invocation isolation identity of one dogfood run.
// Every mutable surface the harness touches is prefixed or suffixed with it
// so two invocations (or a crashed invocation and its successor) can never
// observe or clobber each other's state: database schema, object-store
// prefix, cache directory, repository names, runner labels, container
// names, OIDC audiences and temporary directories.
//
// The namespace is captured in the run's seed record so a chaos failure is
// reproducible: re-running with the same seed and clock rebuilds the same
// identity, and a live collision is impossible because the random suffix is
// drawn from crypto/rand (not the scenario's deterministic RNG).
type Namespace struct {
	// Prefix is the unique run prefix (df-<utc compact>-<random>).
	Prefix string `json:"prefix"`
	// Schema is the isolated database schema name.
	Schema string `json:"schema"`
	// ObjectPrefix is the isolated object-store key prefix.
	ObjectPrefix string `json:"object_prefix"`
	// CacheDir is the isolated cache root basename (under the invocation tmpdir).
	CacheDir string `json:"cache_dir"`
	// RepoPrefix prefixes every seeded repository name.
	RepoPrefix string `json:"repo_prefix"`
	// RunnerLabels are the labels that isolate this invocation's runners.
	RunnerLabels []string `json:"runner_labels"`
	// ContainerPrefix prefixes every container/VM name the harness starts.
	ContainerPrefix string `json:"container_prefix"`
	// OIDCAudience is the audience this invocation's tokens are minted for.
	OIDCAudience string `json:"oidc_audience"`
	// TmpDir is the isolated temporary root of the invocation.
	TmpDir string `json:"tmpdir"`
}

// NewNamespace builds an isolated namespace. now stamps the human-readable
// time prefix; rand must be a real entropy source (crypto/rand.Reader in
// production) so concurrent invocations cannot collide. The scenario's
// deterministic PRNG is deliberately NOT used here: reproducibility of the
// workload must never imply reproducibility (and therefore collision) of the
// isolation identity.
func NewNamespace(now time.Time, entropy io.Reader) (Namespace, error) {
	if entropy == nil {
		return Namespace{}, fmt.Errorf("dogfood: namespace requires an entropy source")
	}
	var buf [8]byte
	if _, err := io.ReadFull(entropy, buf[:]); err != nil {
		return Namespace{}, fmt.Errorf("dogfood: namespace entropy: %w", err)
	}
	prefix := "df-" + now.UTC().Format("20060102-150405") + "-" + hex.EncodeToString(buf[:])
	return Namespace{
		Prefix:          prefix,
		Schema:          sanitizeIdent(prefix, "schema"),
		ObjectPrefix:    "objects/" + prefix + "/",
		CacheDir:        prefix + "-cache",
		RepoPrefix:      prefix + "-",
		RunnerLabels:    []string{"dogfood", prefix},
		ContainerPrefix: prefix,
		OIDCAudience:    "https://oidc.dogfood.invalid/" + prefix,
		TmpDir:          path.Join("kiwi-dogfood", prefix),
	}, nil
}

// RepoName returns the isolated name of a seeded repository.
func (n Namespace) RepoName(base string) string {
	return n.RepoPrefix + base
}

// ContainerName returns the isolated name of a container/VM.
func (n Namespace) ContainerName(base string) string {
	return n.ContainerPrefix + "-" + base
}

// Valid reports whether every isolation surface is populated. An incomplete
// namespace is refused at launch rather than silently sharing a surface.
func (n Namespace) Valid() bool {
	return n.Prefix != "" && n.Schema != "" && n.ObjectPrefix != "" &&
		n.CacheDir != "" && n.RepoPrefix != "" && len(n.RunnerLabels) > 0 &&
		n.ContainerPrefix != "" && n.OIDCAudience != "" && n.TmpDir != ""
}

// sanitizeIdent derives a database-safe identifier from the prefix. The
// transformation is total and collision-resistant for our generated prefixes
// (which are already [a-z0-9-]); it only guards against a hostile/odd base.
func sanitizeIdent(prefix, suffix string) string {
	var b strings.Builder
	for _, r := range prefix {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '_':
			b.WriteRune(r)
		case r == '-':
			b.WriteRune('_')
		default:
			b.WriteRune('x')
		}
	}
	b.WriteByte('_')
	b.WriteString(suffix)
	return b.String()
}
