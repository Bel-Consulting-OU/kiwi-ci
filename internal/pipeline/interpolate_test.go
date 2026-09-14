package pipeline

import "testing"

// TestInterpolateMatrixParity locks the compile-time matrix substitution to
// the exact legacy behavior: matrix holes (spaced and tight) resolve,
// everything else stays literal.
func TestInterpolateMatrixParity(t *testing.T) {
	m := map[string]string{"GO": "1.23", "DB": "postgres"}
	cases := []struct {
		src  string
		want string
	}{
		{"deps-${{ matrix.GO }}", "deps-1.23"},
		{"deps-${{matrix.GO}}", "deps-1.23"},
		{"${{ matrix.GO }} ${{ matrix.DB }}", "1.23 postgres"},
		{"${{matrix.GO}}-${{matrix.DB}}", "1.23-postgres"},
		{"no holes", "no holes"},
		{"${{ matrix.MISSING }}", "${{ matrix.MISSING }}"},
		{"${{matrix.MISSING}}", "${{matrix.MISSING}}"},
		{"${{ needs.build.outputs.bin }}", "${{ needs.build.outputs.bin }}"},
		{"${{ env.VAR }}", "${{ env.VAR }}"},
		{"${{ branch }}", "${{ branch }}"},
		{"${{ github.sha }}", "${{ github.sha }}"},
		{"${{ 'literal' }}", "${{ 'literal' }}"},
		{"${{ hashFiles('go.sum') }}", "${{ hashFiles('go.sum') }}"},
		{"pre ${{ matrix.GO }} post", "pre 1.23 post"},
		{"", ""},
	}
	for _, tc := range cases {
		if got := Interpolate(tc.src, m); got != tc.want {
			t.Errorf("Interpolate(%q) = %q, want %q", tc.src, got, tc.want)
		}
	}
}

func TestInterpolateEmptyAndNilMatrix(t *testing.T) {
	if got := Interpolate("${{ matrix.GO }}", map[string]string{}); got != "${{ matrix.GO }}" {
		t.Fatalf("empty matrix must leave the hole literal, got %q", got)
	}
	if got := Interpolate("plain", nil); got != "plain" {
		t.Fatalf("nil matrix must be a no-op, got %q", got)
	}
}

// TestInterpolateOutputsParity locks the runtime needs/steps substitution to
// the legacy ReplaceAll behavior: known outputs resolve (including empty
// values), unknown outputs and other contexts stay literal.
func TestInterpolateOutputsParity(t *testing.T) {
	needs := map[string]map[string]string{"build": {"bin": "/out/bin", "empty": ""}}
	steps := map[string]map[string]string{"build": {"x": "42"}}
	cases := []struct {
		src  string
		want string
	}{
		{"${{ needs.build.outputs.bin }}", "/out/bin"},
		{"${{needs.build.outputs.bin}}", "/out/bin"},
		{"${{ steps.build.outputs.x }}", "42"},
		{"${{steps.build.outputs.x}}", "42"},
		{"${{ needs.build.outputs.empty }}", ""},
		{"${{ needs.build.outputs.missing }}", "${{ needs.build.outputs.missing }}"},
		{"${{ needs.nope.outputs.x }}", "${{ needs.nope.outputs.x }}"},
		{"${{ steps.nope.outputs.x }}", "${{ steps.nope.outputs.x }}"},
		{"${{ env.VAR }}", "${{ env.VAR }}"},
		{"${{ matrix.GO }}", "${{ matrix.GO }}"},
		{"run ${{ needs.build.outputs.bin }}!", "run /out/bin!"},
		{"", ""},
	}
	for _, tc := range cases {
		if got := InterpolateOutputs(tc.src, needs, steps); got != tc.want {
			t.Errorf("InterpolateOutputs(%q) = %q, want %q", tc.src, got, tc.want)
		}
	}
}

func TestInterpolateOutputsNilMaps(t *testing.T) {
	if got := InterpolateOutputs("${{ needs.build.outputs.bin }}", nil, nil); got != "${{ needs.build.outputs.bin }}" {
		t.Fatalf("nil needs/steps must leave the hole literal, got %q", got)
	}
	if got := InterpolateOutputs("plain", nil, nil); got != "plain" {
		t.Fatalf("no holes must be unchanged, got %q", got)
	}
}

func TestInterpolateOutputMap(t *testing.T) {
	needs := map[string]map[string]string{"build": {"bin": "/out/bin"}}
	in := map[string]string{"a": "${{ needs.build.outputs.bin }}", "b": "static"}
	out := InterpolateOutputMap(in, needs, nil)
	if out["a"] != "/out/bin" || out["b"] != "static" {
		t.Fatalf("InterpolateOutputMap = %v", out)
	}
	if len(out) != 2 {
		t.Fatalf("expected 2 keys, got %d", len(out))
	}
}

// TestParseDefaultsShellUnset locks the shell-default removal: parsing must
// no longer inject shell: bash into defaults; the executor resolves the
// fallback per runtime kind.
func TestParseDefaultsShellUnset(t *testing.T) {
	s, err := Parse([]byte(`version: 1
jobs:
  x:
    steps:
      - run: echo hi
`))
	if err != nil {
		t.Fatal(err)
	}
	if s.Defaults.Shell != "" {
		t.Fatalf("defaults.shell must stay unset after parse, got %q", s.Defaults.Shell)
	}
}

func TestParseExplicitShellPreserved(t *testing.T) {
	s, err := Parse([]byte(`version: 1
defaults:
  shell: zsh
jobs:
  x:
    steps:
      - run: echo hi
`))
	if err != nil {
		t.Fatal(err)
	}
	if s.Defaults.Shell != "zsh" {
		t.Fatalf("explicit defaults.shell must be preserved, got %q", s.Defaults.Shell)
	}
}
