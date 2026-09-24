package staging

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/fsutil"
)

// InstanceIDFileName is the file inside a configured staging ROOT that
// persists the generated replica instance id. It deliberately does not match
// FilePrefix, so neither the reclaim nor Prune can remove it, and it never
// carries spool bytes.
const InstanceIDFileName = "staging.instance"

// MaxInstanceIDLen bounds a replica instance id. Ids become directory names
// under the configured root, so they must stay short, path-safe and stable.
const MaxInstanceIDLen = 64

// generatedInstanceIDPrefix marks ids this package generates, so an operator
// can tell a machine-generated replica directory from an explicit one.
const generatedInstanceIDPrefix = "replica-"

// ErrInstanceIDUnpublished reports an id file that exists but has no valid id
// content yet (a concurrent process is still publishing it, or a crash left a
// partial write).
var ErrInstanceIDUnpublished = errors.New("staging: instance id file has no published instance id yet")

// ValidateInstanceID enforces the shape of a replica instance id. An id names
// exactly one directory under the configured staging root, so it must not be
// empty, must not be "." or "..", must not start with "." (a hidden replica
// directory defeats operator visibility) and may only contain ASCII letters,
// digits, '-', '_' and '.' — in particular it may never contain a path
// separator, because an id such as "../../etc" would otherwise escape the
// root.
func ValidateInstanceID(id string) error {
	trimmed := strings.TrimSpace(id)
	if trimmed == "" {
		return fmt.Errorf("staging: instance id must not be empty")
	}
	if len(trimmed) > MaxInstanceIDLen {
		return fmt.Errorf("staging: instance id %q is longer than %d characters", trimmed, MaxInstanceIDLen)
	}
	if trimmed == "." || trimmed == ".." || strings.HasPrefix(trimmed, ".") {
		return fmt.Errorf("staging: instance id %q must not be %q or start with a dot", trimmed, trimmed)
	}
	for _, r := range trimmed {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
		default:
			return fmt.Errorf("staging: instance id %q contains %q; allowed characters are letters, digits, '-', '_' and '.'", trimmed, r)
		}
	}
	return nil
}

// ReplicaDir resolves the replica-private staging directory for a configured
// ROOT: <root>/<instance-id>. The explicit instanceID (flag/env/config) wins;
// when it is empty the process reads the id persisted in the root, or
// generates and persists a fresh one (durable create-if-absent publish, so
// concurrent first starts converge on one id).
//
// Per-replica contract: the configured directory is shared infrastructure,
// never a per-replica budget by itself. Each process stages inside its own
// <root>/<instance-id>, which is what keeps each replica's byte bound exact.
// Replicas that share a root MUST use distinct instance ids; when no id is
// configured the persisted id makes that automatic — a second replica without
// its own id resolves to the same directory and its startup fails with
// ErrStagingDirOwned instead of silently doubling the total footprint.
func ReplicaDir(configuredRoot, instanceID string) (string, string, error) {
	root := strings.TrimSpace(configuredRoot)
	if root == "" {
		return "", "", fmt.Errorf("%w: staging directory is not configured", ErrNoBound)
	}
	explicit := strings.TrimSpace(instanceID)
	if explicit != "" {
		if err := ValidateInstanceID(explicit); err != nil {
			return "", "", err
		}
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return "", "", fmt.Errorf("staging: create staging root %s: %w", root, err)
	}
	id := explicit
	if id == "" {
		generated, err := loadOrCreateInstanceID(root)
		if err != nil {
			return "", "", err
		}
		id = generated
	}
	return filepath.Join(root, id), id, nil
}

// NewReplicaBudget is the production constructor: it resolves the
// replica-private directory under the configured root (see ReplicaDir) and
// then takes ownership of that directory exactly like NewBudget.
//
// It deliberately does NOT reclaim legacy bare spool files that a pre-contract
// process left directly in the shared root. Under the pre-contract layout
// (< commit 72d887d) a live old replica staged its ACTIVE spool files at the
// top level of the root WITH NO ownership lock, so a top-level kiwi-stage-*
// entry is not provably abandoned: unlinking it during a rolling HA upgrade
// would delete a still-running old replica's in-flight upload. Top-level
// legacy files are left untouched until an operator runs the explicit
// MigrateLegacyStagingLayout (kiwi storage migrate-staging-layout), which
// takes the root's ownership lock and requires the operator to confirm that
// every old-layout replica has drained. Only files inside this replica's own
// <root>/<instance-id> directory are reclaimed at construction, under that
// directory's ownership lock.
func NewReplicaBudget(configuredRoot, instanceID string, maxBytes int64) (*Budget, error) {
	root := strings.TrimSpace(configuredRoot)
	if err := validateBound(root, maxBytes); err != nil {
		return nil, err
	}
	dir, _, err := ReplicaDir(root, instanceID)
	if err != nil {
		return nil, err
	}
	key := canonicalDir(dir)
	if existing, rerr := registeredBudget(key, maxBytes); rerr != nil {
		return nil, rerr
	} else if existing != nil {
		return existing, nil
	}
	return newBudget(dir, maxBytes)
}

// loadOrCreateInstanceID returns the persisted instance id of a configured
// root, generating and publishing one when the root has none yet. Publishing
// goes through fsutil.CreateFileCAS: the id is written to a unique temp file
// with a checked write/fsync/close, published create-if-absent (a hard link on
// unix), and only then is the root directory fsynced. The visible
// staging.instance therefore never exists in a torn/empty state, and the old
// sequence that created the destination name first and then unlinked it on a
// failed write (without a parent-directory fsync) is gone.
//
// The failure classes are handled explicitly:
//
//   - os.ErrExist: another process won the create-if-absent publish; adopt it.
//   - fsutil.Renamed (a failed root fsync after the publish): the visible file
//     is valid, so leave it untouched and fail this startup; the next attempt
//     adopts it instead of generating a second id.
//   - any pre-publish failure: the destination was never created and the
//     unique temp file was removed, so fail normally (nothing to adopt).
func loadOrCreateInstanceID(root string) (string, error) {
	path := filepath.Join(root, InstanceIDFileName)
	if id, err := readPublishedInstanceID(path); err == nil {
		return id, nil
	} else if !errors.Is(err, os.ErrNotExist) && !errors.Is(err, ErrInstanceIDUnpublished) {
		return "", err
	}
	id, err := newInstanceID()
	if err != nil {
		return "", err
	}
	switch err := fsutil.CreateFileCAS(path, []byte(id+"\n"), 0o600); {
	case err == nil:
		return id, nil
	case errors.Is(err, os.ErrExist):
		// Another process is publishing an id right now; adopt theirs.
		return readInstanceIDWithRetry(path)
	case fsutil.Renamed(err):
		// Published-uncertain, exactly like fsutil's post-rename PhaseDirSync:
		// the id bytes are visible and readable but their crash durability is
		// not certified. LEAVE the visible file in place so the next start
		// adopts it instead of generating another generation; failing startup
		// is still correct because the id is not certified durable.
		return "", fmt.Errorf("staging: instance id %s is published but its durability is not certified, leaving it for the next start to adopt: %w", path, err)
	default:
		// Pre-publish: the destination was never created and the unique temp
		// file was removed, so there is nothing torn to clean up.
		return "", fmt.Errorf("staging: persist instance id %s: %w", path, err)
	}
}

// readPublishedInstanceID reads and validates the persisted id. A missing
// file reports os.ErrNotExist; a present-but-invalid file reports
// ErrInstanceIDUnpublished, which callers either retry (concurrent publish)
// or fail with a clear operator message.
func readPublishedInstanceID(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	id := strings.TrimSpace(string(data))
	if verr := ValidateInstanceID(id); verr != nil {
		return "", fmt.Errorf("%w: %s (%v)", ErrInstanceIDUnpublished, path, verr)
	}
	return id, nil
}

// readInstanceIDWithRetry waits briefly for a concurrent publisher to finish
// writing the id file. After the window, startup fails with an explicit
// recovery action instead of picking an id that may not be the root's.
func readInstanceIDWithRetry(path string) (string, error) {
	deadline := time.Now().Add(2 * time.Second)
	for {
		id, err := readPublishedInstanceID(path)
		if err == nil {
			return id, nil
		}
		if !errors.Is(err, ErrInstanceIDUnpublished) {
			return "", err
		}
		if time.Now().After(deadline) {
			return "", fmt.Errorf("%w: %s stayed incomplete for 2s (remove the file to regenerate the replica id)", ErrInstanceIDUnpublished, path)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// newInstanceID returns a fresh random replica id.
func newInstanceID() (string, error) {
	var raw [8]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("staging: generate instance id: %w", err)
	}
	return generatedInstanceIDPrefix + hex.EncodeToString(raw[:]), nil
}

// lockOwnerIdentity is the diagnostic identity line written into an ownership
// lock file. It is not the lock itself (the lock is the held flock / the
// exclusive file), only evidence for an operator inspecting the directory.
func lockOwnerIdentity() string {
	host, err := os.Hostname()
	if err != nil || strings.TrimSpace(host) == "" {
		host = "unknown"
	}
	return fmt.Sprintf("pid=%d host=%s started=%s", os.Getpid(), host, time.Now().UTC().Format(time.RFC3339Nano))
}
