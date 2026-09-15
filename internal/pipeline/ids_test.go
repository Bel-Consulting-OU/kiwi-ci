package pipeline

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestMatrixSuffixCanonicalForSafeValues(t *testing.T) {
	cases := []struct {
		m    map[string]string
		want string
	}{
		{nil, ""},
		{map[string]string{}, ""},
		{map[string]string{"test_shard": "0"}, "[test_shard=0]"},
		{map[string]string{"GO": "1.23", "test_shard": "1"}, "[GO=1.23,test_shard=1]"},
		{map[string]string{"A": "1.2.3_4-5"}, "[A=1.2.3_4-5]"},
	}
	for _, tc := range cases {
		if got := matrixSuffix(tc.m); got != tc.want {
			t.Errorf("matrixSuffix(%v) = %q, want %q", tc.m, got, tc.want)
		}
	}
}

func TestMatrixSuffixEncodesUnsafeValues(t *testing.T) {
	got := matrixSuffix(map[string]string{"P": "../../evil"})
	want := "[P=~" + base64.RawURLEncoding.EncodeToString([]byte("../../evil")) + "]"
	if got != want {
		t.Fatalf("matrixSuffix = %q, want %q", got, want)
	}
	if !compiledIDRegexp.MatchString("job" + got) {
		t.Fatalf("compiled id %q does not match the validation regex", "job"+got)
	}
}

func TestMatrixSuffixUnsafeValuesCannotCollide(t *testing.T) {
	// A literal safe value that equals the base64 form of an unsafe value
	// must not collide: the "~" marker can never occur in a literal value,
	// a matrix name or a job id.
	a := matrixSuffix(map[string]string{"k": "a b"})
	b := matrixSuffix(map[string]string{"k": base64.RawURLEncoding.EncodeToString([]byte("a b"))})
	c := matrixSuffix(map[string]string{"k": "~YWJj"})
	if a == b {
		t.Fatalf("encoded %q collides with literal %q", a, b)
	}
	if a == c || b == c {
		t.Fatalf("marker-prefixed literal collides: %q vs %q vs %q", a, b, c)
	}
	// Two different unsafe values must never render identically.
	d := matrixSuffix(map[string]string{"k": "a c"})
	if a == d {
		t.Fatalf("distinct unsafe values collide: %q", a)
	}
}

func TestMatrixSuffixLongValuesHash(t *testing.T) {
	long := strings.Repeat("x", 200)
	got := matrixSuffix(map[string]string{"k": long})
	if !strings.HasPrefix(got, "[~") || len(got) != 2+32+1 {
		t.Fatalf("long suffix = %q, want the [~<64 hex>] hash fallback", got)
	}
	if !compiledIDRegexp.MatchString("job" + got) {
		t.Fatalf("hashed suffix %q does not match the compiled id regex", got)
	}
	// Deterministic.
	if again := matrixSuffix(map[string]string{"k": long}); again != got {
		t.Fatalf("hash fallback not deterministic: %q vs %q", got, again)
	}
	// Distinct long values hash to distinct suffixes.
	other := matrixSuffix(map[string]string{"k": strings.Repeat("y", 200)})
	if other == got {
		t.Fatal("distinct long values produced the same hash suffix")
	}
}

func TestCompileUnsafeMatrixValueProducesDeterministicSafeID(t *testing.T) {
	doc := `version: 1
jobs:
  x:
    matrix:
      V: ["a b", "ok"]
    steps:
      - run: echo ${{ matrix.V }}
`
	s, err := Parse([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	g1, err := Compile(s)
	if err != nil {
		t.Fatal(err)
	}
	s2, err := Parse([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	g2, err := Compile(s2)
	if err != nil {
		t.Fatal(err)
	}
	if !reflectDeepEqual(jobIDs(g1), jobIDs(g2)) {
		t.Fatalf("compiled ids not deterministic: %v vs %v", jobIDs(g1), jobIDs(g2))
	}
	want := "x[V=~" + base64.RawURLEncoding.EncodeToString([]byte("a b")) + "]"
	if _, ok := g1.Jobs[want]; !ok {
		t.Fatalf("missing encoded variant %q (have %v)", want, jobIDs(g1))
	}
	if _, ok := g1.Jobs["x[V=ok]"]; !ok {
		t.Fatalf("safe value must keep the historical id format (have %v)", jobIDs(g1))
	}
	for id := range g1.Jobs {
		if !compiledIDRegexp.MatchString(id) {
			t.Fatalf("compiled id %q fails the validation regex", id)
		}
	}
}

func TestValidateRejectsMatrixProjectionCollisions(t *testing.T) {
	for _, dims := range [][2]string{{"foo-bar", "foo_bar"}, {"Foo", "foo"}, {"A-B", "a_b"}} {
		s := &Spec{Version: 1, Jobs: map[string]Job{"x": {Steps: []Step{{Run: "true"}},
			Matrix: map[string][]any{dims[0]: {"a"}, dims[1]: {"b"}}}}}
		err := Validate(s)
		if err == nil || !strings.Contains(err.Error(), "both project") || !strings.Contains(err.Error(), "KIWI_MATRIX_") {
			t.Errorf("matrix dims %v error = %v, want KIWI_MATRIX projection collision", dims, err)
		}
	}
}

func TestValidateRejectsInvalidMatrixNames(t *testing.T) {
	for _, name := range []string{"1bad", "-lead", "has space", "dot.ted", "tilde~name", strings.Repeat("a", 65)} {
		s := &Spec{Version: 1, Jobs: map[string]Job{"x": {Steps: []Step{{Run: "true"}},
			Matrix: map[string][]any{name: {"a"}}}}}
		if err := Validate(s); err == nil || !strings.Contains(err.Error(), "invalid") {
			t.Errorf("matrix name %q error = %v, want invalid-name error", name, err)
		}
	}
	for _, name := range []string{"ok", "_under", "with-hyphen", "with9", "GO_VERSION", strings.Repeat("a", 64)} {
		s := &Spec{Version: 1, Jobs: map[string]Job{"x": {Steps: []Step{{Run: "true"}},
			Matrix: map[string][]any{name: {"a"}}}}}
		if err := Validate(s); err != nil {
			t.Errorf("matrix name %q rejected: %v", name, err)
		}
	}
}

func TestMatrixEnvProjectsCanonically(t *testing.T) {
	got := matrixEnv(map[string]string{"foo-bar": "v1", "Version": "2"})
	if got["KIWI_MATRIX_FOO_BAR"] != "v1" {
		t.Errorf("KIWI_MATRIX_FOO_BAR = %q, want v1", got["KIWI_MATRIX_FOO_BAR"])
	}
	if got["KIWI_MATRIX_VERSION"] != "2" {
		t.Errorf("KIWI_MATRIX_VERSION = %q, want 2", got["KIWI_MATRIX_VERSION"])
	}
	if _, ok := got["KIWI_MATRIX_foo-bar"]; ok {
		t.Error("raw matrix name leaked into env as a non-canonical key")
	}
}

func reflectDeepEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
