package runner

import (
	"crypto/tls"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/fsutil"
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
	if missing == 0 {
		// Cryptographically verify the persisted material as ONE identity: a
		// crash during a cert rotation can leave a NEW cert with the OLD key
		// (all four files present), which would otherwise be reported complete
		// and fail later at TLS setup. A mismatched pair is INCOMPLETE, so the
		// runner re-enrolls instead of bricking.
		if err := verifyIdentityKeyPair(id.CertPEM, id.KeyPEM); err != nil {
			return id, false
		}
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
	if err := secureIdentityDir(s.Dir); err != nil {
		return err
	}
	// Publication order and atomicity matter across a crash: the PRIVATE KEY
	// is written first (0600, atomic), then the certificate, CA and ID. A
	// crash between any two leaves a store whose four files may disagree; the
	// pair verification in Load() then reports it incomplete and the runner
	// re-enrolls. Each individual write is temp+fsync+rename, so no file can
	// be observed torn.
	if err := writeOwnerOnly(s.path(identityKeyFile), id.KeyPEM); err != nil {
		return err
	}
	if err := fsutil.AtomicWriteFile(s.path(identityCertFile), id.CertPEM, 0o644); err != nil {
		return err
	}
	if err := fsutil.AtomicWriteFile(s.path(identityCAFile), id.CACertPEM, 0o644); err != nil {
		return err
	}
	return fsutil.AtomicWriteFile(s.path(identityIDFile), []byte(id.ID+"\n"), 0o644)
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

// verifyIdentityKeyPair checks that the persisted certificate and key form a
// pair; it is a seam so identity-store unit tests can use placeholder PEMs
// while production always performs the real X.509 check.
var verifyIdentityKeyPair = func(certPEM, keyPEM []byte) error {
	_, err := tls.X509KeyPair(certPEM, keyPEM)
	return err
}

// writeOwnerOnly writes secret material atomically with owner-only access
// semantics: mode 0600 on Unix, where the file mode is the access-control
// mechanism. On Windows the surrounding identity directory carries a
// PROTECTED owner-only DACL installed by secureIdentityDir (numeric modes do
// not encode Windows access control).
func writeOwnerOnly(path string, data []byte) error {
	return fsutil.AtomicWriteFile(path, data, 0o600)
}
