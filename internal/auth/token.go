package auth

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/fsutil"
)

// ErrSubjectConflict reports that two tokens define different effective
// principals for the same non-empty subject. The store is fail-closed about
// subject ambiguity: conflicting definitions are rejected when they are
// added (AddToken) or loaded (Load), and a store that somehow holds a
// conflicting pair refuses to resolve the subject (PrincipalBySubject)
// instead of picking one of the principals.
var ErrSubjectConflict = errors.New("auth: conflicting principals for subject")

// atomicWriteFile is the durable-write primitive behind Save. It is a
// package variable so tests can inject storage failures at every durability
// step; production always points it at fsutil.AtomicWriteFile (unique temp
// file in the target directory, checked write/chmod/fsync/close, rename over
// the target, parent-directory fsync). Failures come back as typed
// *fsutil.AtomicWriteError values whose Phase/Renamed report whether the
// rename had already published the new file (see Save).
var atomicWriteFile = fsutil.AtomicWriteFile

// TokenStore maps token digests to principals. Raw tokens are never stored:
// only the hex-encoded SHA-256 digest of a token is kept in memory and
// persisted to disk.
//
// Subject index: each non-empty subject maps to exactly one effective
// principal, maintained in bySubject and rebuilt by AddToken, RemoveToken
// and Load. Several tokens may share a subject only while their effective
// principals are equal (see effectivePrincipalEqual); any other shared
// subject is a conflict and is rejected instead of being merged. A subject
// is omitted from the index when the principal's Subject is empty: anonymous
// principals are never resolvable by subject.
type TokenStore struct {
	mu        sync.RWMutex
	tokens    map[string]Principal
	bySubject map[string]Principal

	// saveMu serializes Save. Concurrent Save calls on one store are legal:
	// each call snapshots, marshals and durably writes its own bytes with no
	// other Save interleaved, so a call can never acknowledge another call's
	// writes and the file at path always matches exactly one call. Save also
	// holds mu's read lock through publication so token mutations cannot
	// complete mid-save (see Save).
	saveMu sync.Mutex
}

func NewTokenStore() *TokenStore {
	return &TokenStore{
		tokens:    map[string]Principal{},
		bySubject: map[string]Principal{},
	}
}

// TokenDigest returns the hex-encoded SHA-256 of a raw token.
func TokenDigest(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// effectivePrincipalEqual reports whether a and b are the same security
// identity, i.e. the same effective Principal. It compares every
// permission-bearing field of Principal:
//
//   - Subject must be identical;
//   - the global roles must form the same set (order and duplicates are
//     irrelevant because every role decision goes through Has);
//   - Repositories must have the same keys and equal RepositoryPermission
//     values (all grant booleans).
//
// The comparison is deliberately value-based rather than json.DeepEqual:
// two tokens authored in different order (roles reordered, repo map
// rebuilt) still carry identical grants and are the same identity. Any
// future permission-bearing field added to Principal or
// RepositoryPermission must be added to this comparison.
func effectivePrincipalEqual(a, b Principal) bool {
	if a.Subject != b.Subject {
		return false
	}
	if !sameRoleSet(a.Roles, b.Roles) {
		return false
	}
	if len(a.Repositories) != len(b.Repositories) {
		return false
	}
	for repo, perm := range a.Repositories {
		other, ok := b.Repositories[repo]
		if !ok || other != perm {
			return false
		}
	}
	return true
}

func sameRoleSet(a, b []Role) bool {
	setA := roleSet(a)
	setB := roleSet(b)
	if len(setA) != len(setB) {
		return false
	}
	for r := range setA {
		if _, ok := setB[r]; !ok {
			return false
		}
	}
	return true
}

func roleSet(roles []Role) map[Role]struct{} {
	set := make(map[Role]struct{}, len(roles))
	for _, r := range roles {
		set[r] = struct{}{}
	}
	return set
}

// buildSubjectIndex returns subject -> unique effective principal for every
// non-empty subject in tokens. Digests are visited in sorted order so a
// persisted conflict always reports the same subject. The first differing
// principal for a shared subject is an error wrapping ErrSubjectConflict;
// nothing is merged or dropped.
func buildSubjectIndex(tokens map[string]Principal) (map[string]Principal, error) {
	digests := make([]string, 0, len(tokens))
	for digest := range tokens {
		digests = append(digests, digest)
	}
	sort.Strings(digests)
	index := make(map[string]Principal, len(tokens))
	for _, digest := range digests {
		p := tokens[digest]
		if p.Subject == "" {
			continue
		}
		if existing, ok := index[p.Subject]; ok {
			if !effectivePrincipalEqual(existing, p) {
				return nil, fmt.Errorf("subject %q has conflicting principals: %w", p.Subject, ErrSubjectConflict)
			}
			continue
		}
		index[p.Subject] = p
	}
	return index, nil
}

// AddToken registers raw with principal, keyed by the token digest. It fails
// with an error wrapping ErrSubjectConflict when the principal's subject
// already maps to a different effective principal; identical definitions
// under one subject may coexist (e.g. a rotation pair). A rejected call
// leaves the store unchanged.
//
// Repository grant keys are kept VERBATIM in the in-memory store. They are
// parsed by the typed positional rule at every decision point
// (ParseStoredRepoID), so a legacy canonical key ("github.com/o/repo-a",
// dotted or dotless) or a bare key addresses the same repository it always
// did. Keys are NOT collapsed to their explicit spelling here: two
// canonically equivalent spellings with DIFFERENT permission sets are a
// conflict the authorization layer must see (they deny every action), and a
// Go map could not hold both collapsed spellings. Save migrates the keys to
// the explicit spelling and fails closed if that migration would merge a
// conflict, so a persisted store always reloads under the strict Load schema.
func (t *TokenStore) AddToken(raw string, p Principal) error {
	if t == nil {
		return fmt.Errorf("auth: nil token store")
	}
	if raw == "" {
		return fmt.Errorf("auth: token must not be empty")
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	next := make(map[string]Principal, len(t.tokens)+1)
	for digest, existing := range t.tokens {
		next[digest] = existing
	}
	next[TokenDigest(raw)] = p
	index, err := buildSubjectIndex(next)
	if err != nil {
		return fmt.Errorf("auth: add token: %w", err)
	}
	t.tokens = next
	t.bySubject = index
	return nil
}

// normalizePrincipalRepoGrants rewrites every repository grant key of p into
// its explicit serialized spelling. Legacy keys are migrated with the
// documented positional rule (ParseRepoGrant); a key that cannot be parsed
// fails closed with the offending string in the error. Two canonically
// equivalent keys with DIFFERENT permission sets also fail closed: collapsing
// them would silently pick one permission set, weakening the operator's
// intent, so the caller must resolve the conflict explicitly.
func normalizePrincipalRepoGrants(p Principal) (Principal, error) {
	if len(p.Repositories) == 0 {
		return p, nil
	}
	normalized := make(map[string]RepositoryPermission, len(p.Repositories))
	for key, perm := range p.Repositories {
		grant, err := ParseRepoGrant(key)
		if err != nil {
			return Principal{}, err
		}
		serialized := grant.Serialized()
		if serialized == "" {
			return Principal{}, &RepoGrantError{Grant: key, Detail: "grant renders no usable identity"}
		}
		if prev, ok := normalized[serialized]; ok {
			if prev != perm {
				return Principal{}, &RepoGrantError{
					Grant:  key,
					Detail: fmt.Sprintf("canonically equivalent grant %q already carries a different permission set", serialized),
				}
			}
			continue
		}
		normalized[serialized] = perm
	}
	p.Repositories = normalized
	return p, nil
}

// RemoveToken revokes the token identified by raw and reports whether it was
// present. Removing a token rebuilds the subject index: a subject that loses
// its last token no longer resolves.
func (t *TokenStore) RemoveToken(raw string) bool {
	if t == nil || raw == "" {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	digest := TokenDigest(raw)
	if _, ok := t.tokens[digest]; !ok {
		return false
	}
	next := make(map[string]Principal, len(t.tokens)-1)
	for d, p := range t.tokens {
		if d != digest {
			next[d] = p
		}
	}
	t.tokens = next
	index, err := buildSubjectIndex(next)
	if err != nil {
		// Unreachable through the public API (conflicts are rejected when
		// added). Fail closed instead of resolving an ambiguous subject.
		t.bySubject = nil
		return true
	}
	t.bySubject = index
	return true
}

// Authenticate resolves raw to its principal.
func (t *TokenStore) Authenticate(raw string) (Principal, bool) {
	if t == nil {
		return Principal{}, false
	}
	t.mu.RLock()
	defer t.mu.RUnlock()
	p, ok := t.tokens[TokenDigest(raw)]
	return p, ok
}

// PrincipalBySubject resolves subject to its unique effective principal.
// Used by revocable delegations (trusted schedules) that must re-check the
// creator's CURRENT grants at execution time.
//
// Resolution is deterministic and fail-closed: the result comes from the
// subject index, and it is returned only when every token sharing the
// subject carries an effectively equal principal. Any disagreement (for
// example a conflict injected straight into the token map) yields
// (Principal{}, false) rather than an arbitrary winner; an empty subject
// never resolves.
func (t *TokenStore) PrincipalBySubject(subject string) (Principal, bool) {
	if t == nil || subject == "" {
		return Principal{}, false
	}
	t.mu.RLock()
	defer t.mu.RUnlock()
	p, ok := t.bySubject[subject]
	if !ok {
		return Principal{}, false
	}
	matches := 0
	for _, q := range t.tokens {
		if q.Subject != subject {
			continue
		}
		matches++
		if !effectivePrincipalEqual(p, q) {
			return Principal{}, false
		}
	}
	if matches == 0 {
		// Index/token desync: never resolve a subject no token carries.
		return Principal{}, false
	}
	return p, true
}

// Empty reports whether no tokens are configured.
func (t *TokenStore) Empty() bool {
	if t == nil {
		return true
	}
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.tokens) == 0
}

// Load replaces the store contents with the JSON token file at path
// (map of token digest to principal). A persisted store whose tokens define
// a subject more than once with different effective principals is rejected
// as a whole with an error wrapping ErrSubjectConflict that names the
// subject; the in-memory contents are left untouched so the conflict is
// never partially loaded.
//
// Repository grant keys are validated against the strict ACL schema
// (ParseRepoGrantConfig): a canonical identity must be the unambiguous r1:
// form and a bare alias must be the plain owner/name or a1: form. A legacy
// ambiguous key — three or more path segments without an explicit tag, which
// could be a dotless host plus a full name or a bare nested group path — is
// refused with ErrRepoGrantAmbiguous naming the offending string and both
// accepted spellings. The migration never guesses: an old token file must be
// edited to the explicit form (or rewritten with AddToken + Save, which
// migrate legacy in-process keys positionally).
func (t *TokenStore) Load(path string) error {
	if t == nil {
		return fmt.Errorf("auth: nil token store")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	m := map[string]Principal{}
	if err := json.Unmarshal(b, &m); err != nil {
		return fmt.Errorf("auth: parse token file %s: %w", path, err)
	}
	for digest, p := range m {
		if err := validatePrincipalRepoGrants(p); err != nil {
			return fmt.Errorf("auth: load token file %s: token %s: %w", path, digest, err)
		}
	}
	index, err := buildSubjectIndex(m)
	if err != nil {
		return fmt.Errorf("auth: load token file %s: %w", path, err)
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.tokens = m
	t.bySubject = index
	return nil
}

// validatePrincipalRepoGrants applies the strict ACL grant schema to every
// repository key of p. It never rewrites the keys: validation and migration
// are separate steps so a load can fail closed with the operator's exact
// string.
func validatePrincipalRepoGrants(p Principal) error {
	for key := range p.Repositories {
		if _, err := ParseRepoGrantConfig(key); err != nil {
			return err
		}
	}
	return nil
}

// Save atomically writes the store as a 0600 JSON file of token digests to
// principals, creating the parent directory (0700) if needed. The write is
// crash-durable: fsutil.AtomicWriteFile uses a unique temp file, fsyncs the
// file, closes it with error checking, renames it over path and fsyncs the
// parent directory.
//
// The failure phases are explicit and callers must not flatten them into
// "the previous durable file is intact": every phase before the rename
// (create/write/chmod/file-sync/close/rename) leaves the previous file at
// path bit-for-bit intact and removes the temp file, so there the new store
// was DEFINITELY NOT PUBLISHED. The parent-directory fsync runs AFTER the
// rename: its failure means the new store IS visible at path while its crash
// durability is uncertified (*fsutil.AtomicWriteError with Renamed=true,
// errors.Is(err, fsutil.ErrPublishedUncertain)). A caller that maintains
// monotonic security state must retain the published state in that case
// rather than roll back to a permissive one; the server paths do this
// through noteFilePersistResult (keys.go), which also keeps readiness
// degraded until a later successful persist reconciles.
//
// Concurrent Save calls are legal and serialized by saveMu; each call
// snapshots and writes its own bytes, so no call can acknowledge or corrupt
// another call's write. Save is ALSO serialized against token mutations: the
// token-state read lock is held from the snapshot through durable publication,
// so AddToken/RemoveToken/Load cannot complete while a Save is in flight. A
// mutation acknowledged before Save began is always in the saved snapshot, and
// a mutation arriving during publication blocks until the file is durable —
// a crash can therefore never restore a state older than a mutation that
// already returned success. (Mutations are administrative and rare, so
// serializing them behind an fsync is the deliberate correctness trade.) The
// on-disk format is unchanged (a JSON map of digest to principal).
func (t *TokenStore) Save(path string) error {
	if t == nil {
		return fmt.Errorf("auth: nil token store")
	}
	t.saveMu.Lock()
	defer t.saveMu.Unlock()
	// Hold the read lock through serialization AND durable publication:
	// AddToken/RemoveToken/Load take the write lock, so no mutation can
	// complete between this snapshot and the rename below. Releasing the lock
	// before publication would allow: snapshot old state -> mutation commits
	// and returns success -> Save publishes the old state -> crash restores
	// the revoked token (or loses the added one).
	t.mu.RLock()
	defer t.mu.RUnlock()
	m := make(map[string]Principal, len(t.tokens))
	for k, v := range t.tokens {
		m[k] = v
	}
	// Migrate any legacy in-process grant keys to the explicit schema so the
	// persisted file always reloads under the strict Load validation.
	for k, v := range m {
		normalized, err := normalizePrincipalRepoGrants(v)
		if err != nil {
			return fmt.Errorf("auth: save token file %s: %w", path, err)
		}
		m[k] = normalized
	}
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	if err := atomicWriteFile(path, b, 0o600); err != nil {
		return fmt.Errorf("auth: save token file %s: %w", path, err)
	}
	return nil
}
