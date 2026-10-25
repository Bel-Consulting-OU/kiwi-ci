package executor

import (
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/secrets"
)

// withEnvKeyFold forces the Windows case-folding env contract so the
// collision semantics are exercised on ANY build host (envKeyFold is the
// package seam for runtime.GOOS == "windows").
func withEnvKeyFold(t *testing.T) {
	t.Helper()
	old := envKeyFold
	envKeyFold = true
	t.Cleanup(func() { envKeyFold = old })
}

// TestEnvKeyCanonWindowsCollisions pins the Windows env contract: Path,
// PATH and path are ONE variable at every merge/delete/write site, so a
// secret or pipeline value declared "Path" can never ride alongside an
// inherited PATH into the child (where last-sorting would silently pick
// the winner).
func TestEnvKeyCanonWindowsCollisions(t *testing.T) {
	withEnvKeyFold(t)

	if got := envKeyCanon("Path"); got != "PATH" {
		t.Fatalf("envKeyCanon(Path) = %q", got)
	}
	// Later map wins across a case difference.
	merged := mergeEnvMap(map[string]string{"Path": "from-base"}, map[string]string{"PATH": "from-pipeline"})
	if len(merged) != 1 {
		t.Fatalf("merged keys = %v, want exactly one PATH entry", merged)
	}
	if merged["PATH"] != "from-pipeline" {
		t.Fatalf("merged PATH = %q, want the later map's value", merged["PATH"])
	}
	// ONE map with both spellings (a pathological pipeline env block) must
	// resolve DETERMINISTICALLY — never Go's randomized map iteration.
	want := ""
	for i := 0; i < 200; i++ {
		one := mergeEnvMap(nil, map[string]string{"Path": "a", "PATH": "b"})
		if len(one) != 1 {
			t.Fatalf("single-map merge keys = %v", one)
		}
		if want == "" {
			want = one["PATH"]
		} else if one["PATH"] != want {
			t.Fatalf("intra-map collision resolved nondeterministically: %q vs %q", one["PATH"], want)
		}
	}
	// Sorted-visit contract: the lexicographically-greatest spelling wins
	// ("Path" > "PATH"), so the outcome is documented, not incidental.
	if want != "a" {
		t.Fatalf("intra-map winner = %q, want the lexicographically-greatest spelling's value", want)
	}
}

// TestSecretEnvKeysCanonicalOnWindows: a secret declared with a
// mixed-case name is delivered under its CANONICAL key only, so
// envSlice emits one PATH entry — never PATH=... plus Path=secret
// (which would clobber the executable search path on Windows).
func TestSecretEnvKeysCanonicalOnWindows(t *testing.T) {
	withEnvKeyFold(t)

	e := &Executor{Opt: Options{SecretProvider: secrets.MapProvider{"Path": "C:\\evil"}}, Masker: &secrets.Masker{}}
	out, err := e.resolveSecrets(t.Context(), []string{"Path"}, map[string]string{})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := out["PATH"]; !ok {
		t.Fatalf("resolved secret keys = %v, want canonical PATH", keysOf(out))
	}
	if _, ok := out["Path"]; ok {
		t.Fatalf("raw-case key survived resolution: %v", keysOf(out))
	}
	if _, ok := out["KIWI_SECRET_PATH"]; !ok {
		t.Fatalf("KIWI_SECRET_PATH missing: %v", keysOf(out))
	}
	// Exactly one PATH=... entry in the child environment slice.
	pathEntries := 0
	for _, kv := range envSlice(out) {
		if strings.HasPrefix(kv, "PATH=") {
			pathEntries++
		}
	}
	if pathEntries != 1 {
		t.Fatalf("PATH entries in child env = %d, want 1 (%v)", pathEntries, envSlice(out))
	}
}

// TestServiceEnvStripsSecretsCanonically: serviceEnvFor must DELETE the
// secret from the job env by its canonical key — a raw-spelling delete
// misses after folding and would hand a job secret to a repository-
// controlled sidecar.
func TestServiceEnvStripsSecretsCanonically(t *testing.T) {
	withEnvKeyFold(t)

	jobEnv := map[string]string{"PATH": "C:\\Windows", "PATH_": "kept"}
	// jobSecrets as produced post-resolution (canonical keys).
	jobSecrets := map[string]string{"PATH": "C:\\evil", "KIWI_SECRET_PATH": "C:\\evil"}
	out := serviceEnvFor(jobEnv, jobSecrets)
	if _, ok := out["PATH"]; ok {
		// PATH came only from the secret here — it must be gone.
		t.Fatalf("secret PATH survived into the service env: %v", out)
	}
	if out["PATH_"] != "kept" {
		t.Fatalf("unrelated key lost: %v", out)
	}
	// The same delete with RAW spelling must also work (defense in depth:
	// callers may still pass unresolved declared names).
	out2 := serviceEnvFor(map[string]string{"PATH": "x"}, map[string]string{"Path": "y"})
	if _, ok := out2["PATH"]; ok {
		t.Fatalf("raw-spelling delete missed the folded key: %v", out2)
	}
}

func keysOf(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
