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
// the target, parent-directory fsync).
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
	// writes and the file at path always matches exactly one call.
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

// Save atomically writes the store as a 0600 JSON file of token digests to
// principals, creating the parent directory (0700) if needed. The write is
// crash-durable: fsutil.AtomicWriteFile uses a unique temp file, fsyncs the
// file, closes it with error checking, renames it over path and fsyncs the
// parent directory, so a failure leaves the previous durable file intact.
//
// Concurrent Save calls are legal and serialized by saveMu; each call
// snapshots and writes its own bytes, so no call can acknowledge or corrupt
// another call's write. The on-disk format is unchanged (a JSON map of
// digest to principal).
func (t *TokenStore) Save(path string) error {
	if t == nil {
		return fmt.Errorf("auth: nil token store")
	}
	t.saveMu.Lock()
	defer t.saveMu.Unlock()
	t.mu.RLock()
	m := make(map[string]Principal, len(t.tokens))
	for k, v := range t.tokens {
		m[k] = v
	}
	t.mu.RUnlock()
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
