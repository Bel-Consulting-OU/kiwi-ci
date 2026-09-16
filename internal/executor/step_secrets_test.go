package executor

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/logging"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/secrets"
)

func stepSecretGraph(t *testing.T, yaml string) *pipeline.Graph {
	t.Helper()
	s, err := pipeline.Parse([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	g, err := pipeline.Compile(s)
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func TestStepSecretsDoNotReachOtherSteps(t *testing.T) {
	ws := t.TempDir()
	provider := secrets.MapProvider{
		"global_secret": "globalvalue",
		"step_a":        "avalue",
		"step_b":        "bvalue",
	}
	// Each step writes the secret env name into its file when the secret
	// is visible to it. The syntax is per-host: POSIX test on Unix,
	// PowerShell on Windows (the native default shell).
	probe := func(name, file string) string {
		return nativeScript(
			`          [ -n "$KIWI_SECRET_`+name+`" ] && echo KIWI_SECRET_`+name+` > `+file+` || true
`,
			`          if ($env:KIWI_SECRET_`+name+`) { "KIWI_SECRET_`+name+`" | Out-File -Encoding utf8 `+file+` }
`)
	}
	stepOne := probe("STEP_A", "step1_a.txt") + probe("STEP_B", "step1_b.txt") + probe("GLOBAL_SECRET", "step1_g.txt")
	stepTwo := probe("STEP_A", "step2_a.txt") + probe("STEP_B", "step2_b.txt") + probe("GLOBAL_SECRET", "step2_g.txt")
	g := stepSecretGraph(t, `version: 1
secrets: [global_secret]
jobs:
  probe:
    steps:
      - id: one
        secrets: [step_a]
        run: |
`+stepOne+`      - id: two
        secrets: [step_b]
        run: |
`+stepTwo)
	ex := Executor{Opt: Options{Workspace: ws, SecretProvider: provider}}
	res, err := ex.Run(context.Background(), g)
	if err != nil {
		t.Fatal(err)
	}
	if r := res["probe"]; r.Status != model.StatusSuccess {
		t.Fatalf("job failed: %v", r.Error)
	}
	read := func(name string) string {
		t.Helper()
		b, err := os.ReadFile(filepath.Join(ws, name))
		if os.IsNotExist(err) {
			// A secret invisible to the step leaves no file at all.
			return ""
		}
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		return strings.TrimSpace(string(b))
	}
	if got := read("step1_a.txt"); !strings.Contains(got, "KIWI_SECRET_STEP_A") {
		t.Fatalf("step one missing its declared secret: %q", got)
	}
	if got := read("step1_b.txt"); got != "" {
		t.Fatalf("step_b secret leaked into step one: %q", got)
	}
	if got := read("step2_b.txt"); !strings.Contains(got, "KIWI_SECRET_STEP_B") {
		t.Fatalf("step two missing its declared secret: %q", got)
	}
	if got := read("step2_a.txt"); got != "" {
		t.Fatalf("step_a secret leaked into step two: %q", got)
	}
	for _, f := range []string{"step1_g.txt", "step2_g.txt"} {
		if got := read(f); !strings.Contains(got, "KIWI_SECRET_GLOBAL_SECRET") {
			t.Fatalf("global secret missing in %s: %q", f, got)
		}
	}
}

func TestStepSecretMaskedInLogs(t *testing.T) {
	const value = "topsecret-token-9f8a"
	ws := t.TempDir()
	provider := secrets.MapProvider{"step_a": value}
	var mu sync.Mutex
	var lines []string
	sink := logging.Func(func(job, step, line string) {
		mu.Lock()
		lines = append(lines, line)
		mu.Unlock()
	})
	// The echo uses the native shell's env syntax: $VAR on Unix,
	// $env:VAR on Windows PowerShell.
	echoScript := nativeScript(
		`echo "token is $KIWI_SECRET_STEP_A"`,
		`echo "token is $env:KIWI_SECRET_STEP_A"`,
	)
	g := stepSecretGraph(t, `version: 1
jobs:
  probe:
    steps:
      - secrets: [step_a]
        run: `+echoScript+`
`)
	ex := Executor{Opt: Options{Workspace: ws, SecretProvider: provider, Logs: sink}}
	res, err := ex.Run(context.Background(), g)
	if err != nil {
		t.Fatal(err)
	}
	if r := res["probe"]; r.Status != model.StatusSuccess {
		t.Fatalf("job failed: %v", r.Error)
	}
	mu.Lock()
	defer mu.Unlock()
	joined := strings.Join(lines, "\n")
	if strings.Contains(joined, value) {
		t.Fatalf("secret value leaked into emitted logs: %q", joined)
	}
	if !strings.Contains(joined, "***") {
		t.Fatalf("expected masked output in logs, got: %q", joined)
	}
}
