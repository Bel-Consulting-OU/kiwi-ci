package auth

// Cross-feature composition tests for this round's credential work: the
// subject-conflict fail-closed rule (one subject -> one effective principal)
// composed with the authorization decisions every control-plane route makes,
// the rotation pair (several tokens, one identity) that must answer
// identically, and the token-file Load path the control plane runs at
// startup. The unit tests in token_subject_test.go pin the store primitives;
// these tests pin what the primitives mean for a caller that rotates tokens
// and for a paginated/scoped request surface.

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// composeRotationCanonical is the effective identity shared by the rotation
// pair: repository-scoped read+run on github.com/o/repo-a and NO global role,
// so the difference between an authorized and an unauthorized repository is
// observable on every action.
func composeRotationCanonical() Principal {
	return Principal{
		Subject:      "svc-rotation",
		Repositories: map[string]RepositoryPermission{"github.com/o/repo-a": {Read: true, Run: true}},
	}
}

// composeRotationVariant is the same effective identity spelled differently
// (role/entry authoring order varies), which must remain a legal second
// credential for one subject.
func composeRotationVariant() Principal {
	return Principal{
		Subject:      "svc-rotation",
		Repositories: map[string]RepositoryPermission{"github.com/o/repo-a": {Run: true, Read: true}},
	}
}

// composeLoadRotationPair persists the rotation pair in the on-disk
// digest->principal format (the auth.tokens_file contract) and loads it into
// a store, so the decisions under test come through the same file path the
// control plane uses at startup.
func composeLoadRotationPair(t *testing.T) (*TokenStore, string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "tokens.json")
	m := map[string]Principal{
		TokenDigest("rot-1"): composeRotationCanonical(),
		TokenDigest("rot-2"): composeRotationVariant(),
	}
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	s := NewTokenStore()
	if err := s.Load(path); err != nil {
		t.Fatalf("rotation pair failed to load: %v", err)
	}
	return s, path
}

// composeDecisionMatrix renders every authorization decision the route layer
// can ask for in the shapes this round touched: per action, per repository
// spelling (bare alias, canonical, default port, another forge) and for both
// trust domains.
func composeDecisionMatrix(p Principal) []string {
	repos := []string{
		"o/repo-a",
		"github.com/o/repo-a",
		"github.com:443/o/repo-a",
		"GitHub.com/o/repo-a",
		"gitlab.com/o/repo-a",
		"o/repo-b",
		"github.com/o/repo-b",
		"",
	}
	actions := []Action{
		ActionRead, ActionRun, ActionTrustedRun, ActionApprove, ActionCancel,
		ActionRerun, ActionArtifactRead, ActionRunnerManage, ActionPolicyManage, ActionAdmin,
	}
	out := make([]string, 0, len(repos)*len(actions)*2)
	for _, repo := range repos {
		for _, action := range actions {
			for _, trusted := range []bool{false, true} {
				out = append(out, fmt.Sprintf("%s|repo=%q|trusted=%v=%v", action, repo, trusted, Authorize(p, action, repo, trusted)))
			}
		}
	}
	return out
}

// TestComposeRotationPairAuthorizationParity is the credential-rotation
// composition: two simultaneously valid tokens for one subject with
// identical effective principals must produce identical repository-visibility
// and per-action decisions, and the decisions must follow the shared grants
// (repo-a readable, repo-b and other forges denied by the repository-first
// rule).
func TestComposeRotationPairAuthorizationParity(t *testing.T) {
	s, path := composeLoadRotationPair(t)
	p1, ok := s.Authenticate("rot-1")
	if !ok {
		t.Fatal("rot-1 did not authenticate after load")
	}
	p2, ok := s.Authenticate("rot-2")
	if !ok {
		t.Fatal("rot-2 did not authenticate after load")
	}
	if !effectivePrincipalEqual(p1, p2) {
		t.Fatalf("rotation pair is not one effective identity: %+v vs %+v", p1, p2)
	}
	bySubject, ok := s.PrincipalBySubject("svc-rotation")
	if !ok || !effectivePrincipalEqual(bySubject, composeRotationCanonical()) {
		t.Fatalf("PrincipalBySubject = (%+v, %v), want the shared identity", bySubject, ok)
	}

	m1 := composeDecisionMatrix(p1)
	m2 := composeDecisionMatrix(p2)
	if strings.Join(m1, "\n") != strings.Join(m2, "\n") {
		t.Fatalf("rotation pair disagrees:\nrot-1:\n%s\nrot-2:\n%s", strings.Join(m1, "\n"), strings.Join(m2, "\n"))
	}
	if !CanReadAnyRepo(p1) || !CanReadAnyRepo(p2) {
		t.Fatal("repository-scoped rotation pair lost its read capability")
	}
	// The shared grants decide every repository spelling of repo-a and deny
	// the unseen repositories and forges: the collection the credentials
	// rotate over is exactly this set.
	for _, repo := range []string{"o/repo-a", "github.com/o/repo-a", "github.com:443/o/repo-a", "GitHub.com/o/repo-a"} {
		if !CanReadRepo(p1, repo) || !CanReadRepo(p2, repo) {
			t.Fatalf("repo-a spelling %q not readable by the rotation pair", repo)
		}
	}
	for _, repo := range []string{"o/repo-b", "github.com/o/repo-b", "gitlab.com/o/repo-a", ""} {
		if CanReadRepo(p1, repo) || CanReadRepo(p2, repo) {
			t.Fatalf("repo %q readable although only repo-a is granted", repo)
		}
	}
	if Authorize(p1, ActionAdmin, "github.com/o/repo-a", false) {
		t.Fatal("repository grant satisfied the admin action")
	}

	// Revocation of one half of the pair keeps the identity resolvable; the
	// revoked credential stops authenticating and the other keeps working.
	if !s.RemoveToken("rot-1") {
		t.Fatal("RemoveToken(rot-1) = false")
	}
	if _, ok := s.Authenticate("rot-1"); ok {
		t.Fatal("revoked rotation token still authenticates")
	}
	if _, ok := s.Authenticate("rot-2"); !ok {
		t.Fatal("remaining rotation token stopped authenticating")
	}
	if p, ok := s.PrincipalBySubject("svc-rotation"); !ok || !effectivePrincipalEqual(p, composeRotationCanonical()) {
		t.Fatalf("subject lost while one rotation token remains: (%+v, %v)", p, ok)
	}
	// Reloading the same file restores both.
	if err := s.Load(path); err != nil {
		t.Fatalf("reload after revocation: %v", err)
	}
	if _, ok := s.Authenticate("rot-1"); !ok {
		t.Fatal("reload did not restore rot-1")
	}
}

// TestComposeWeakerSameSubjectTokenRejectedAndPairIntact is the composition
// of the conflict rule with a live rotation pair: a weaker second token for
// the shared subject (fewer grants, same subject) is refused at add, the
// rejection names the subject, the rejected credential never authenticates,
// and both members of the existing pair keep producing the identical
// decisions they had before the attempt.
func TestComposeWeakerSameSubjectTokenRejectedAndPairIntact(t *testing.T) {
	s, _ := composeLoadRotationPair(t)
	before1, _ := s.Authenticate("rot-1")
	before2, _ := s.Authenticate("rot-2")
	weaker := Principal{
		Subject:      "svc-rotation",
		Repositories: map[string]RepositoryPermission{"github.com/o/repo-a": {Read: true}},
	}
	err := s.AddToken("weak", weaker)
	if err == nil {
		t.Fatal("a weaker token for the subject was accepted")
	}
	if !errors.Is(err, ErrSubjectConflict) {
		t.Fatalf("weaker-token rejection %v does not wrap ErrSubjectConflict", err)
	}
	if !strings.Contains(err.Error(), `subject "svc-rotation"`) {
		t.Fatalf("rejection %v does not name the subject", err)
	}
	if _, ok := s.Authenticate("weak"); ok {
		t.Fatal("rejected weaker token was registered")
	}
	after1, ok := s.Authenticate("rot-1")
	if !ok {
		t.Fatal("rejection removed the first rotation token")
	}
	after2, ok := s.Authenticate("rot-2")
	if !ok {
		t.Fatal("rejection removed the second rotation token")
	}
	if strings.Join(composeDecisionMatrix(before1), "\n") != strings.Join(composeDecisionMatrix(after1), "\n") ||
		strings.Join(composeDecisionMatrix(before2), "\n") != strings.Join(composeDecisionMatrix(after2), "\n") {
		t.Fatal("a rejected add changed the rotation pair's decisions")
	}

	// The same conflict written into a token FILE is refused by the startup
	// load path, and the failed load leaves the live store untouched.
	dir := t.TempDir()
	path := filepath.Join(dir, "conflict.json")
	m := map[string]Principal{
		TokenDigest("rot-1"): composeRotationCanonical(),
		TokenDigest("weak"):  weaker,
	}
	b, merr := json.Marshal(m)
	if merr != nil {
		t.Fatal(merr)
	}
	if werr := os.WriteFile(path, b, 0o600); werr != nil {
		t.Fatal(werr)
	}
	if lerr := s.Load(path); lerr == nil {
		t.Fatal("a conflicting token file loaded over a live rotation pair")
	} else if !errors.Is(lerr, ErrSubjectConflict) {
		t.Fatalf("load rejection %v does not wrap ErrSubjectConflict", lerr)
	}
	if _, ok := s.Authenticate("rot-1"); !ok {
		t.Fatal("failed load clobbered the live store")
	}
	if got, ok := s.PrincipalBySubject("svc-rotation"); !ok || !effectivePrincipalEqual(got, composeRotationCanonical()) {
		t.Fatalf("subject after failed load = (%+v, %v)", got, ok)
	}
}
