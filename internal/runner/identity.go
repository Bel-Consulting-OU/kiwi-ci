package runner

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/runnerpki"
)

const (
	identityIDFile   = "runner-id"
	identityKeyFile  = "key.pem"
	identityCertFile = "cert.pem"
	identityCAFile   = "ca.crt"
	// identityDirMode creates the identity directory owner-only (read,
	// write and traverse for the owner only). On Windows the directory ACL
	// is the owner-only boundary: Windows file modes do not encode access
	// control, so the 0700 directory carries it instead.
	identityDirMode = 0o700
	// identityRenewBefore is the minimum remaining validity a persisted
	// certificate needs to be reused: closer to expiry the runner
	// re-enrolls instead of starting with a certificate that would expire
	// mid-run.
	identityRenewBefore = 24 * time.Hour
)

// Identity is the persisted runner mTLS identity: the server-authoritative
// runner ID and the key/certificate/CA PEM material bound to it.
type Identity struct {
	ID        string
	KeyPEM    []byte
	CertPEM   []byte
	CACertPEM []byte
}

// CertUsable reports whether the identity's certificate still has at least
// identityRenewBefore of validity remaining.
func (id Identity) CertUsable() bool {
	return runnerpki.CertValidFor(id.CertPEM, identityRenewBefore)
}

// IdentityStore persists the runner identity in a directory (default
// ~/.kiwi/runner): runner-id (the stable identity), key.pem (owner-only,
// 0600), cert.pem and ca.crt.
type IdentityStore struct{ Dir string }

func (s IdentityStore) path(name string) string { return filepath.Join(s.Dir, name) }

// LoadID returns the persisted runner ID, if any. The ID survives
// certificate expiry/revocation so a re-enrollment keeps the same identity
// and its audit history.
func (s IdentityStore) LoadID() (string, bool) {
	b, err := os.ReadFile(s.path(identityIDFile))
	if err != nil {
		return "", false
	}
	id := strings.TrimSpace(string(b))
	if id == "" {
		return "", false
	}
	return id, true
}

// Load returns the persisted identity. The boolean reports whether a
// complete identity (ID, key, certificate and CA) is present; a partial
// store still returns the ID when runner-id exists so re-enrollment can
// reuse it.
func (s IdentityStore) Load() (Identity, bool) {
	id := Identity{}
	missing := 0
	if b, err := os.ReadFile(s.path(identityIDFile)); err == nil {
		id.ID = strings.TrimSpace(string(b))
	} else {
		missing++
	}
	if b, err := os.ReadFile(s.path(identityKeyFile)); err == nil {
		id.KeyPEM = b
	} else {
		missing++
	}
	if b, err := os.ReadFile(s.path(identityCertFile)); err == nil {
		id.CertPEM = b
	} else {
		missing++
	}
	if b, err := os.ReadFile(s.path(identityCAFile)); err == nil {
		id.CACertPEM = b
	} else {
		missing++
	}
	return id, missing == 0 && id.ID != ""
}

// Save persists the identity, creating the store directory owner-only
// (0700) on first use. The private key is written with mode 0600. A
// complete identity is required: persisting a partial one would silently
// corrupt the next startup's reuse check.
func (s IdentityStore) Save(id Identity) error {
	if id.ID == "" || len(id.KeyPEM) == 0 || len(id.CertPEM) == 0 {
		return fmt.Errorf("refusing to persist incomplete runner identity")
	}
	if err := os.MkdirAll(s.Dir, identityDirMode); err != nil {
		return err
	}
	if err := os.WriteFile(s.path(identityIDFile), []byte(id.ID+"\n"), 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(s.path(identityCertFile), id.CertPEM, 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(s.path(identityCAFile), id.CACertPEM, 0o644); err != nil {
		return err
	}
	return writeOwnerOnly(s.path(identityKeyFile), id.KeyPEM)
}

// ClearCert removes the persisted certificate but keeps the runner ID (and
// key) so the next startup re-enrolls under the same identity. A missing
// certificate is not an error: clearing is idempotent.
func (s IdentityStore) ClearCert() error {
	err := os.Remove(s.path(identityCertFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

// writeOwnerOnly writes secret material with owner-only access semantics:
// mode 0600 on Unix, where the file mode is the access-control mechanism.
// On Windows the surrounding identity directory (created 0700) carries the
// owner-only ACL, mirroring the executor keyfile approach. The executor's
// WriteOwnerOnly is deliberately not reused: its Windows implementation
// writes into a per-call temporary directory instead of the requested
// path, which would break identity persistence.
func writeOwnerOnly(path string, data []byte) error {
	return os.WriteFile(path, data, 0o600)
}
