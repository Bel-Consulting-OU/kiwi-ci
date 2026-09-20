package executor

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/artifact"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/cache"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/secrets"
)

// covSink records every emitted line.
type covSink struct {
	lines []string
}

func (s *covSink) WriteLine(job, step, line string) {
	s.lines = append(s.lines, step+": "+line)
}

func (s *covSink) has(sub string) bool {
	for _, l := range s.lines {
		if strings.Contains(l, sub) {
			return true
		}
	}
	return false
}

func TestBackendForVariants(t *testing.T) {
	for _, kind := range []string{"", "native"} {
		b, err := BackendFor(kind, "", "")
		if err != nil {
			t.Fatalf("BackendFor(%q): %v", kind, err)
		}
		if _, ok := b.(*NativeBackend); !ok {
			t.Fatalf("BackendFor(%q) = %T", kind, b)
		}
	}
	cb, err := BackendFor("container", "alpine", "")
	if err != nil {
		t.Fatal(err)
	}
	if cb.(*ContainerBackend).Image != "alpine" {
		t.Fatal("container image not carried")
	}
	tb, err := BackendFor("tart", "", "vm1")
	if runtime.GOOS == "darwin" {
		if err != nil {
			t.Fatal(err)
		}
		if tb.(*TartBackend).VM != "vm1" {
			t.Fatal("tart VM not carried")
		}
	} else if err == nil || !strings.Contains(err.Error(), "requires macOS") {
		t.Fatalf("BackendFor(tart) on %s = (%T, %v), want a requires-macOS error", runtime.GOOS, tb, err)
	}
	if _, err := BackendFor("bogus", "", ""); err == nil {
		t.Fatal("unknown backend accepted")
	}
}

func TestBackendForNetworkCarriesNetwork(t *testing.T) {
	cb, err := BackendForNetwork("container", "alpine", "", "kiwi-net")
	if err != nil {
		t.Fatal(err)
	}
	if cb.(*ContainerBackend).Network != "kiwi-net" {
		t.Fatal("container network not carried")
	}
	tb, err := BackendForNetwork("tart", "", "vm", "none")
	if runtime.GOOS == "darwin" {
		if err != nil {
			t.Fatal(err)
		}
		if tb.(*TartBackend).Network != "none" {
			t.Fatal("tart network not carried")
		}
	} else if err == nil || !strings.Contains(err.Error(), "requires macOS") {
		t.Fatalf("BackendForNetwork(tart) on %s = (%T, %v), want a requires-macOS error", runtime.GOOS, tb, err)
	}
	if _, err := BackendForNetwork("bogus", "", "", ""); err == nil {
		t.Fatal("unknown backend accepted")
	}
}

type errReader struct{ err error }

func (r errReader) Read([]byte) (int, error) { return 0, r.err }

func TestReadCapped(t *testing.T) {
	if _, err := readCapped(strings.NewReader("x"), 0); err == nil {
		t.Fatal("zero limit accepted")
	}
	if _, err := readCapped(errReader{err: errors.New("boom")}, 8); err == nil {
		t.Fatal("read error not surfaced")
	}
	if _, err := readCapped(strings.NewReader("toolong"), 3); err == nil {
		t.Fatal("oversized input accepted")
	}
	got, err := readCapped(strings.NewReader("ok"), 8)
	if err != nil || string(got) != "ok" {
		t.Fatalf("readCapped = %q, %v", got, err)
	}
}

func TestRunErrorHelpers(t *testing.T) {
	base := errors.New("root cause")
	re := &RunError{Kind: ErrorInfra, Err: base}
	if re.Error() != "infra: root cause" {
		t.Fatalf("Error() = %q", re.Error())
	}
	if !errors.Is(re, base) {
		t.Fatal("Unwrap not wired")
	}
	if re.Class() != InfrastructureFailure {
		t.Fatalf("Class = %v", re.Class())
	}
	cases := map[string]FailureClass{
		"":               CommandFailure,
		ErrorFailure:     CommandFailure,
		ErrorInfra:       InfrastructureFailure,
		ErrorTimeout:     TimeoutFailure,
		ErrorLostRunner:  LostRunnerFailure,
		ErrorCancelled:   CancelledFailure,
		ErrorConfig:      ConfigurationFailure,
		ErrorPolicy:      PolicyFailure,
		ErrorCache:       CacheFailure,
		ErrorArtifact:    ArtifactFailure,
		"something-else": CommandFailure,
	}
	for kind, want := range cases {
		if got := (&RunError{Kind: kind}).Class(); got != want {
			t.Fatalf("Class(%q) = %v, want %v", kind, got, want)
		}
		if got := errorKind(&RunError{Kind: kind}); got != kind {
			t.Fatalf("errorKind(%q) = %q", kind, got)
		}
	}
	if errorKind(base) != ErrorFailure {
		t.Fatal("plain error must classify as failure")
	}
	if failureClass(base) != CommandFailure {
		t.Fatal("plain error must map to command failure")
	}
}

func TestCovBackoffForBounds(t *testing.T) {
	d := backoffFor(-1, 0, 0, 1)
	if d <= 0 {
		t.Fatalf("backoff = %v", d)
	}
	d = backoffFor(100, time.Second, maxRetryBackoff, 42)
	if d > maxRetryBackoff {
		t.Fatalf("backoff over cap: %v", d)
	}
	first := backoffFor(1, time.Second, maxRetryBackoff, 42)
	second := backoffFor(1, time.Second, maxRetryBackoff, 42)
	if first != second {
		t.Fatal("backoff is not deterministic")
	}
	if retryableClass(ConfigurationFailure) || retryableClass(PolicyFailure) || retryableClass(CancelledFailure) || retryableClass(LostRunnerFailure) {
		t.Fatal("non-transient classes must not retry")
	}
	if !retryableClass(CommandFailure) || !retryableClass(InfrastructureFailure) || !retryableClass(TimeoutFailure) || !retryableClass(CacheFailure) || !retryableClass(ArtifactFailure) {
		t.Fatal("transient classes must retry")
	}
}

func TestRetryAllowsMatrix(t *testing.T) {
	if retryAllows(pipeline.Retry{}, errors.New("x")) {
		t.Fatal("zero retry must not allow")
	}
	if retryAllows(pipeline.Retry{Max: 1}, &RunError{Kind: ErrorConfig, Err: errors.New("x")}) {
		t.Fatal("config failures must not retry by default")
	}
	if retryAllows(pipeline.Retry{Max: 1}, &RunError{Kind: ErrorCancelled, Err: errors.New("x")}) {
		t.Fatal("cancelled failures must never retry")
	}
	if !retryAllows(pipeline.Retry{Max: 1}, &RunError{Kind: ErrorInfra, Err: errors.New("x")}) {
		t.Fatal("transient failures should retry by default")
	}
	if !retryAllows(pipeline.Retry{Max: 1, On: []string{"any"}}, &RunError{Kind: ErrorPolicy, Err: errors.New("x")}) {
		t.Fatal("explicit any must retry")
	}
	if !retryAllows(pipeline.Retry{Max: 1, On: []string{"command"}}, &RunError{Kind: ErrorFailure, Err: errors.New("x")}) {
		t.Fatal("command selector must retry command failures")
	}
	if !retryAllows(pipeline.Retry{Max: 1, On: []string{"failure"}}, &RunError{Kind: ErrorFailure, Err: errors.New("x")}) {
		t.Fatal("kind selector must retry")
	}
	if retryAllows(pipeline.Retry{Max: 1, On: []string{"timeout"}}, &RunError{Kind: ErrorFailure, Err: errors.New("x")}) {
		t.Fatal("unlisted kind must not retry")
	}
}

func TestSecureWorkingDir(t *testing.T) {
	ws := t.TempDir()
	if err := os.Mkdir(filepath.Join(ws, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	got, err := secureWorkingDir(ws, "sub")
	if err != nil || filepath.Base(got) != "sub" {
		t.Fatalf("secureWorkingDir = %q, %v", got, err)
	}
	if _, err := secureWorkingDir(ws, "/abs"); err == nil {
		t.Fatal("absolute path accepted")
	}
	if _, err := secureWorkingDir(ws, "../escape"); err == nil {
		t.Fatal("escaping path accepted")
	}
	if _, err := secureWorkingDir(ws, "missing-dir"); err == nil {
		t.Fatal("missing directory accepted")
	}
	// A symlink inside the workspace pointing outside is rejected.
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(ws, "link")); err != nil {
		t.Fatal(err)
	}
	if _, err := secureWorkingDir(ws, "link"); err == nil {
		t.Fatal("symlink escape accepted")
	}
	// A missing workspace root fails resolution.
	if _, err := secureWorkingDir(filepath.Join(ws, "no-root"), ""); err == nil {
		t.Fatal("missing workspace accepted")
	}
}

func TestDepsOutcome(t *testing.T) {
	ready, st := depsOutcome(nil, nil)
	if !ready || st != model.StatusSuccess {
		t.Fatalf("empty needs = %v %v", ready, st)
	}
	ready, _ = depsOutcome([]string{"a"}, map[string]model.Status{"a": model.StatusRunning})
	if ready {
		t.Fatal("non-terminal dependency must not be ready")
	}
	ready, _ = depsOutcome([]string{"missing"}, map[string]model.Status{})
	if ready {
		t.Fatal("unknown dependency must not be ready")
	}
	_, st = depsOutcome([]string{"a"}, map[string]model.Status{"a": model.StatusFailure})
	if st != model.StatusFailure {
		t.Fatalf("failure outcome = %v", st)
	}
	_, st = depsOutcome([]string{"a", "b"}, map[string]model.Status{"a": model.StatusCancelled, "b": model.StatusSuccess})
	if st != model.StatusCancelled {
		t.Fatalf("cancelled outcome = %v", st)
	}
	_, st = depsOutcome([]string{"a", "b"}, map[string]model.Status{"a": model.StatusCancelled, "b": model.StatusFailure})
	if st != model.StatusFailure {
		t.Fatalf("failure beats cancelled: %v", st)
	}
	_, st = depsOutcome([]string{"a", "b"}, map[string]model.Status{"a": model.StatusSuccess, "b": model.StatusBlocked})
	if st != model.StatusFailure {
		t.Fatalf("blocked outcome = %v", st)
	}
}

func TestCollectNeedsOutputsAndClone(t *testing.T) {
	jobs := map[string]pipeline.CompiledJob{
		"build (go=1.22)": {ID: "build (go=1.22)", BaseID: "build"},
		"build (go=1.23)": {ID: "build (go=1.23)", BaseID: "build"},
		"single":          {ID: "single", BaseID: "single"},
	}
	results := map[string]model.JobResult{
		"build (go=1.22)": {Outputs: map[string]string{"a": "1"}},
		"build (go=1.23)": {Outputs: map[string]string{"a": "2"}},
		"single":          {Outputs: map[string]string{"b": "x"}},
	}
	out := collectNeedsOutputs([]string{"build (go=1.22)", "build (go=1.23)", "single", "missing"}, jobs, results)
	if len(out) != 3 {
		t.Fatalf("outputs = %v", out)
	}
	if out["single"]["b"] != "x" {
		t.Fatal("single job base id not aliased")
	}
	// Multi-variant base ids are not aliased (ambiguous).
	if _, ok := out["build"]; ok {
		t.Fatal("ambiguous base id must not be aliased")
	}
	clone := cloneOutputs(map[string]string{"k": "v"})
	clone["k"] = "changed"
	if out["single"]["b"] != "x" {
		t.Fatal("cloneOutputs aliases the source")
	}
}

func TestCacheBaseAndName(t *testing.T) {
	ex := Executor{}
	if got := ex.cacheBase("k"); got != "local|k" {
		t.Fatalf("cacheBase = %q", got)
	}
	ex.Opt.CacheNamespace = " ns "
	if got := ex.cacheBase("k"); got != "ns|k" {
		t.Fatalf("namespaced cacheBase = %q", got)
	}
	if cacheName(pipeline.Cache{Name: "n"}) != "n" {
		t.Fatal("name not preferred")
	}
	if cacheName(pipeline.Cache{Key: "k"}) != "k" {
		t.Fatal("key fallback")
	}
	if cacheName(pipeline.Cache{}) != "cache" {
		t.Fatal("default cache name")
	}
}

func TestDefaultShellAndMax(t *testing.T) {
	if defaultShell("container") != "sh" || defaultShell("tart") != "bash" {
		t.Fatal("runtime shells wrong")
	}
	if runtime.GOOS != "windows" && defaultShell("native") != "bash" {
		t.Fatal("native shell must be bash on unix")
	}
	if max(1, 2) != 2 || max(3, 2) != 3 {
		t.Fatal("max broken")
	}
	firstSeed := retrySeed("a", "b")
	secondSeed := retrySeed("a", "b")
	if firstSeed != secondSeed || retrySeed("a", "c") == retrySeed("b", "c") {
		t.Fatal("retrySeed not deterministic/distinct")
	}
}

func TestResolveSecrets(t *testing.T) {
	ex := &Executor{Masker: &secrets.Masker{}}
	// A nil provider skips the secret entirely.
	got, err := ex.resolveSecrets(context.Background(), []string{"TOKEN"}, map[string]string{})
	if err != nil || len(got) != 0 {
		t.Fatalf("nil provider = %v, %v", got, err)
	}
	ex.Opt.SecretProvider = secrets.EnvProvider{Prefix: "KIWI_COV_SECRET_"}
	t.Setenv("KIWI_COV_SECRET_API.TOKEN", "s3cret-value")
	cache := map[string]string{}
	got, err = ex.resolveSecrets(context.Background(), []string{"api.token"}, cache)
	if err != nil {
		t.Fatal(err)
	}
	if got["KIWI_SECRET_API_TOKEN"] != "s3cret-value" {
		t.Fatalf("secret env name = %v", got)
	}
	// The cache short-circuits a second lookup.
	if _, err := ex.resolveSecrets(context.Background(), []string{"api.token"}, cache); err != nil {
		t.Fatal(err)
	}
	if _, err := ex.resolveSecrets(context.Background(), []string{"missing"}, map[string]string{}); err == nil {
		t.Fatal("missing secret did not error")
	}
}

func TestSecretEnvNameAndLimitedSink(t *testing.T) {
	if secretEnvName("a-b.c") != "KIWI_SECRET_A_B_C" {
		t.Fatalf("secretEnvName = %q", secretEnvName("a-b.c"))
	}
	if limitedSink(nil, 5) != nil {
		t.Fatal("nil sink must stay nil")
	}
	sink := &covSink{}
	if limitedSink(sink, 0) != sink {
		t.Fatal("zero quota must pass the sink through")
	}
	l := limitedSink(sink, 3)
	l.WriteLine("j", "s", "abcdef")
	l.WriteLine("j", "s", "more")
	if !sink.has("log quota exceeded") {
		t.Fatal("quota marker missing")
	}
	// A sink with no inner sink drops silently.
	q := &quotaSink{max: 1}
	q.WriteLine("j", "s", "x")
}

func TestStreamLinesEdgeCases(t *testing.T) {
	var got []string
	streamLines(strings.NewReader("a\nb\r\n\nc"), 0, func(s string) { got = append(got, s) })
	if len(got) != 3 || got[0] != "a" || got[1] != "b" || got[2] != "c" {
		t.Fatalf("streamLines = %q", got)
	}
	got = nil
	long := strings.Repeat("x", 10)
	streamLines(strings.NewReader(long+"\n"), 4, func(s string) { got = append(got, s) })
	if len(got) != 1 || !strings.HasPrefix(got[0], "xxxx") || !strings.Contains(got[0], "line truncated") {
		t.Fatalf("truncation = %q", got)
	}
	// A single line larger than the read buffer keeps draining.
	got = nil
	huge := strings.Repeat("y", 200_000) + "\n"
	streamLines(strings.NewReader(huge), 8, func(s string) { got = append(got, s) })
	if len(got) != 1 || !strings.Contains(got[0], "line truncated") {
		t.Fatalf("huge line = %d lines", len(got))
	}
	// A read error flushes accumulated data and stops.
	got = nil
	streamLines(errReader{err: errors.New("boom")}, 8, func(s string) { got = append(got, s) })
	if len(got) != 0 {
		t.Fatalf("error reader = %q", got)
	}
}

func TestReadOutputFile(t *testing.T) {
	vals, err := readOutputFile([]byte("A=1\nB=two=three\n\n"))
	if err != nil || vals["A"] != "1" || vals["B"] != "two=three" {
		t.Fatalf("readOutputFile = %v, %v", vals, err)
	}
	if _, err := readOutputFile([]byte("NOEQUALS\n")); err == nil {
		t.Fatal("line without = accepted")
	}
	if _, err := readOutputFile([]byte("BAD KEY=1\n")); err == nil {
		t.Fatal("invalid key accepted")
	}
}

func TestGCParsers(t *testing.T) {
	cutoff := time.Now()
	out := []byte("abc123 2020-01-01 00:00:00 +0000 UTC\n" +
		"def456 not-a-time\n" +
		"nofields\n" +
		"\n" +
		"ghi789 2999-01-01T00:00:00Z\n" +
		"jkl012 2020-01-01T00:00:00Z\n")
	stale := parseDockerContainers(out, cutoff)
	if len(stale) != 2 || stale[0] != "abc123" || stale[1] != "jkl012" {
		t.Fatalf("stale containers = %v", stale)
	}
	if _, err := parseDockerTime("nonsense"); err == nil {
		t.Fatal("nonsense time accepted")
	}
	if _, err := parseDockerTime("2026-09-14 13:22:32 +0000 UTC"); err != nil {
		t.Fatalf("docker layout rejected: %v", err)
	}
	nanos := time.Now().Add(-time.Hour).UnixNano()
	vmOut := []byte(fmt.Sprintf("kiwi-%d running\nkiwi-badname running\nother-vm running\n\n", nanos))
	vms := parseTartVMs(vmOut, cutoff)
	if len(vms) != 1 || !strings.HasPrefix(vms[0], "kiwi-") {
		t.Fatalf("stale VMs = %v", vms)
	}
	if len(parseTartVMs([]byte(fmt.Sprintf("kiwi-%d\n", time.Now().Add(time.Hour).UnixNano())), cutoff)) != 0 {
		t.Fatal("fresh VM considered stale")
	}
	if got := containerLabels("", "j"); got != nil {
		t.Fatalf("empty runID labels = %v", got)
	}
	if got := containerLabels("r", "j"); len(got) != 4 {
		t.Fatalf("labels = %v", got)
	}
}

func TestTartPureHelpers(t *testing.T) {
	if got := tartGetArgs("vm"); len(got) != 4 || got[0] != "get" {
		t.Fatalf("tartGetArgs = %v", got)
	}
	meta, err := parseTartGetJSON([]byte(`{"name":"vm","labels":{"kiwi.ssh.bootstrap":"yes"}}`))
	if err != nil || meta.Name != "vm" {
		t.Fatalf("parse = %+v, %v", meta, err)
	}
	if _, err := parseTartGetJSON([]byte("{")); err == nil {
		t.Fatal("bad JSON accepted")
	}
	for _, v := range []string{"", "true", "1", "yes", "ENABLED", " true "} {
		if !bootstrapContractDeclared(map[string]string{tartBootstrapLabel: v}) {
			t.Fatalf("label %q must declare the contract", v)
		}
	}
	for _, v := range []string{"no", "false", "0", "disabled"} {
		if bootstrapContractDeclared(map[string]string{tartBootstrapLabel: v}) {
			t.Fatalf("label %q must not declare the contract", v)
		}
	}
	if bootstrapContractDeclared(nil) {
		t.Fatal("missing label must not declare the contract")
	}
	if err := tartBootstrapConfigError(); err == nil {
		t.Fatal("config error is nil")
	}
	flags, advisory := tartResourceFlags(pipeline.Resources{CPU: 2.7, Memory: 1 << 30, Disk: 1 << 30}, "--cpu --memory")
	if len(flags) != 4 || flags[0] != "--cpu" || flags[1] != "2" {
		t.Fatalf("flags = %v", flags)
	}
	if len(advisory) != 1 {
		t.Fatalf("advisory = %v", advisory)
	}
	flags, advisory = tartResourceFlags(pipeline.Resources{CPU: 1, Memory: 1 << 20}, "no flags here")
	if len(flags) != 0 || len(advisory) != 2 {
		t.Fatalf("unsupported flags = %v / %v", flags, advisory)
	}
}

func TestWrapBase64AndGoGeneratedKey(t *testing.T) {
	if wrapBase64([]byte("short")) != "c2hvcnQ=" {
		t.Fatalf("wrapBase64 short = %q", wrapBase64([]byte("short")))
	}
	long := make([]byte, 100)
	wrapped := wrapBase64(long)
	if !strings.Contains(wrapped, "\n") {
		t.Fatal("long base64 must be wrapped")
	}
	path := filepath.Join(t.TempDir(), "key")
	if err := writeGoGeneratedKey(path); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path + ".pub"); err != nil {
		t.Fatalf("public key missing: %v", err)
	}
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("private key mode = %v, %v", info, err)
	}
	// A missing directory surfaces a write error.
	if err := writeGoGeneratedKey(filepath.Join(t.TempDir(), "missing", "key")); err == nil {
		t.Fatal("missing parent directory accepted")
	}
}

func TestShellCommandAndNativeAdvisory(t *testing.T) {
	if got := shellCommand("pwsh", "x"); got[1] != "-NoProfile" {
		t.Fatalf("pwsh args = %v", got)
	}
	if got := shellCommand("bash", "x"); got[1] != "-lc" {
		t.Fatalf("bash args = %v", got)
	}
	lines := nativeResourceAdvisory(pipeline.Resources{CPU: 1, Memory: 1 << 20, Disk: 1 << 20, PIDs: 4})
	if len(lines) != 4 {
		t.Fatalf("advisory lines = %v", lines)
	}
	if len(nativeResourceAdvisory(pipeline.Resources{})) != 0 {
		t.Fatal("empty resources must not advise")
	}
}

func TestNativeBackendReadFileErrors(t *testing.T) {
	nb := &NativeBackend{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := nb.ReadFile(ctx, "/tmp/x", 10); err == nil {
		t.Fatal("cancelled context accepted")
	}
	if _, err := nb.ReadFile(context.Background(), filepath.Join(t.TempDir(), "missing"), 10); err == nil {
		t.Fatal("missing file accepted")
	}
	if nb.Name() != "native" {
		t.Fatal("native name")
	}
}

func TestWriteOwnerOnly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key")
	if _, err := WriteOwnerOnly(path, []byte("data")); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil || string(b) != "data" {
		t.Fatalf("file = %q, %v", b, err)
	}
	// An existing regular file is replaced.
	if err := os.WriteFile(path, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := WriteOwnerOnly(path, []byte("new")); err != nil {
		t.Fatal(err)
	}
	// A non-empty directory cannot be removed: the replace fails.
	blocked := filepath.Join(t.TempDir(), "dir")
	if err := os.Mkdir(blocked, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(blocked, "child"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := WriteOwnerOnly(blocked, []byte("x")); err == nil {
		t.Fatal("non-empty directory accepted")
	}
	// A missing parent directory is a hard error.
	if _, err := WriteOwnerOnly(filepath.Join(t.TempDir(), "missing", "key"), []byte("x")); err == nil {
		t.Fatal("missing parent accepted")
	}
}

func TestReadFileNoFollowRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readFileNoFollow(link, 100); err == nil {
		t.Fatal("symlink followed")
	}
	b, err := readFileNoFollow(target, 100)
	if err != nil || string(b) != "secret" {
		t.Fatalf("direct read = %q, %v", b, err)
	}
}

func TestReadFileWithinRootMatrix(t *testing.T) {
	root := t.TempDir()
	sub := filepath.Join(root, "sub")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sub, "f"), []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	if b, err := readFileWithinRoot(root, filepath.Join(sub, "f"), 100); err != nil || string(b) != "hello" {
		t.Fatalf("read = %q, %v", b, err)
	}
	// Missing file inside the root.
	if _, err := readFileWithinRoot(root, filepath.Join(sub, "missing"), 100); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing file = %v", err)
	}
	// A path outside the root that exists on disk.
	outside := filepath.Join(t.TempDir(), "out")
	if err := os.WriteFile(outside, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readFileWithinRoot(root, outside, 100); err == nil {
		t.Fatal("outside path accepted")
	}
	// A path outside the root that does not exist maps to ErrNotExist.
	if _, err := readFileWithinRoot(root, filepath.Join(t.TempDir(), "nope"), 100); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing outside path = %v", err)
	}
	// A symlinked intermediate directory cannot redirect the read.
	linkDir := filepath.Join(root, "link")
	if err := os.Symlink(t.TempDir(), linkDir); err != nil {
		t.Fatal(err)
	}
	if _, err := readFileWithinRoot(root, filepath.Join(linkDir, "f"), 100); err == nil {
		t.Fatal("symlinked directory followed")
	}
	// Oversized file.
	big := filepath.Join(root, "big")
	if err := os.WriteFile(big, []byte("0123456789"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readFileWithinRoot(root, big, 3); err == nil {
		t.Fatal("oversized file accepted")
	}
	// A broken root fails to open.
	if _, err := readFileWithinRoot(filepath.Join(root, "no-root"), filepath.Join(root, "no-root", "x"), 10); err == nil {
		t.Fatal("missing root accepted")
	}
}

func TestProcessHelpersNilProcess(t *testing.T) {
	cmd := execCmdStub()
	if err := terminateProcess(&cmd); err != nil {
		t.Fatalf("terminateProcess(nil) = %v", err)
	}
	if err := killProcess(&cmd); err != nil {
		t.Fatalf("killProcess(nil) = %v", err)
	}
	if fn, err := superviseChildNow(&cmd, nil); err != nil || fn == nil {
		t.Fatalf("superviseChildNow error = %v", err)
	}
	fn, err := superviseChildNow(&cmd, nil)
	if err == nil {
		fn()
	}
}

func execCmdStub() exec.Cmd { return exec.Cmd{} }

// canonicalTempDir returns a temp dir with symlinks resolved: cache
// restore rejects destinations reached through a symlinked component.
func canonicalTempDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if resolved, err := filepath.EvalSymlinks(dir); err == nil {
		return resolved
	}
	return dir
}

func cacheStoreAt(t *testing.T) *cache.Store {
	t.Helper()
	return &cache.Store{Root: filepath.Join(t.TempDir(), "cache")}
}

func artifactStoreAt(t *testing.T, dir string) *artifact.Store {
	t.Helper()
	return &artifact.Store{Root: dir}
}

func TestRunSchedulerBranches(t *testing.T) {
	ws := t.TempDir()
	// OnlyJob skips everything else.
	g := mustCompileFailureSpec(t, `version: 1
jobs:
  a:
    steps:
      - run: echo a
  b:
    steps:
      - run: echo b
`)
	ex := Executor{Opt: Options{Workspace: ws, OnlyJob: "a", MaxParallel: 1}}
	res, _ := ex.Run(context.Background(), g)
	if len(res) != 1 || res["a"].Status != model.StatusSuccess {
		t.Fatalf("OnlyJob results = %+v", res)
	}
	// Dependency failure blocks a downstream job without an admitting if.
	g2 := mustCompileFailureSpec(t, `version: 1
jobs:
  a:
    steps:
      - run: exit 1
  b:
    needs: [a]
    steps:
      - run: echo b
`)
	ex = Executor{Opt: Options{Workspace: ws, MaxParallel: 1}}
	res, err := ex.Run(context.Background(), g2)
	if err == nil {
		t.Fatal("failing graph must return an error")
	}
	if res["a"].Status != model.StatusFailure || res["b"].Status != model.StatusBlocked {
		t.Fatalf("blocked results = %+v", res)
	}
	// A cycle cannot come from Compile, so hand-build the deadlock: a
	// pending job whose need is absent from the graph never becomes ready.
	g3 := &pipeline.Graph{Spec: &pipeline.Spec{Version: 1}, Jobs: map[string]pipeline.CompiledJob{
		"x": {ID: "x", BaseID: "x", Needs: []string{"ghost"}, Job: pipeline.Job{Steps: []pipeline.Step{{Run: "true"}}}},
	}}
	ex = Executor{Opt: Options{Workspace: ws, MaxParallel: 1}}
	if _, err := ex.Run(context.Background(), g3); err == nil || !strings.Contains(err.Error(), "deadlock") {
		t.Fatalf("deadlock = %v", err)
	}
	// An empty graph completes without error.
	if res, err := (&Executor{Opt: Options{Workspace: ws}}).Run(context.Background(), &pipeline.Graph{Spec: &pipeline.Spec{Version: 1}, Jobs: map[string]pipeline.CompiledJob{}}); err != nil || len(res) != 0 {
		t.Fatalf("empty graph = %v, %v", res, err)
	}
}

func TestRunJobConditionAndPathBranches(t *testing.T) {
	ws := t.TempDir()
	sink := &covSink{}
	ex := &Executor{Opt: Options{Workspace: ws, Logs: sink, RunID: "r"}, Masker: &secrets.Masker{}}
	// Invalid job condition fails the job.
	res := ex.runJob(context.Background(), &pipeline.Spec{}, pipeline.CompiledJob{
		ID: "j", Job: pipeline.Job{If: "not a condition ((", Steps: []pipeline.Step{{Run: "true"}}},
	}, model.StatusSuccess, nil)
	if res.Status != model.StatusFailure {
		t.Fatalf("invalid condition = %+v", res)
	}
	// False condition skips the job.
	res = ex.runJob(context.Background(), &pipeline.Spec{}, pipeline.CompiledJob{
		ID: "j", Job: pipeline.Job{If: "false", Steps: []pipeline.Step{{Run: "true"}}},
	}, model.StatusSuccess, nil)
	if res.Status != model.StatusSkipped {
		t.Fatalf("false condition = %+v", res)
	}
	// Path filters skip the job and log the reason.
	res = ex.runJob(context.Background(), &pipeline.Spec{}, pipeline.CompiledJob{
		ID: "j", Job: pipeline.Job{Paths: []string{"src/**"}, Steps: []pipeline.Step{{Run: "true"}}},
	}, model.StatusSuccess, nil)
	if res.Status != model.StatusSkipped || !sink.has("changed paths") {
		t.Fatalf("path filter = %+v", res)
	}
	// A job timeout bounds execution.
	res = ex.runJob(context.Background(), &pipeline.Spec{}, pipeline.CompiledJob{
		ID: "j", Job: pipeline.Job{Timeout: pipeline.Duration{Duration: time.Second}, Steps: []pipeline.Step{{Run: "true"}}},
	}, model.StatusSuccess, nil)
	if res.Status != model.StatusSuccess {
		t.Fatalf("job timeout = %+v", res)
	}
	// WorkspaceFor failure fails the job before running anything.
	ex2 := &Executor{Opt: Options{Workspace: ws, WorkspaceFor: func(string) (string, func(), error) {
		return "", nil, errors.New("workspace unavailable")
	}}, Masker: &secrets.Masker{}}
	res = ex2.runJob(context.Background(), &pipeline.Spec{}, pipeline.CompiledJob{ID: "j", Job: pipeline.Job{Steps: []pipeline.Step{{Run: "true"}}}}, model.StatusSuccess, nil)
	if res.Status != model.StatusFailure || !strings.Contains(res.Error, "workspace unavailable") {
		t.Fatalf("WorkspaceFor error = %+v", res)
	}
	// WorkspaceFor success provides the job workspace.
	called := false
	ex3 := &Executor{Opt: Options{Workspace: ws, WorkspaceFor: func(id string) (string, func(), error) {
		called = true
		return ws, func() {}, nil
	}}, Masker: &secrets.Masker{}}
	res = ex3.runJob(context.Background(), &pipeline.Spec{}, pipeline.CompiledJob{ID: "j", Job: pipeline.Job{Steps: []pipeline.Step{{Run: "true"}}}}, model.StatusSuccess, nil)
	if res.Status != model.StatusSuccess || !called {
		t.Fatalf("WorkspaceFor success = %+v", res)
	}
}

func TestRunJobStepBranches(t *testing.T) {
	ws := t.TempDir()
	sink := &covSink{}
	ex := &Executor{Opt: Options{Workspace: ws, Logs: sink, RunID: "r"}, Masker: &secrets.Masker{}}
	// An invalid step condition fails the job and records the condition error.
	res := ex.runJob(context.Background(), &pipeline.Spec{}, pipeline.CompiledJob{
		ID: "j", Job: pipeline.Job{Steps: []pipeline.Step{{If: "(((bad", Run: "true"}}},
	}, model.StatusSuccess, nil)
	if res.Status != model.StatusFailure || !strings.Contains(res.Error, "condition") {
		t.Fatalf("invalid step condition = %+v", res)
	}
	// An escaping working directory fails the job.
	res = ex.runJob(context.Background(), &pipeline.Spec{}, pipeline.CompiledJob{
		ID: "j", Job: pipeline.Job{Steps: []pipeline.Step{{WorkingDirectory: "../escape", Run: "true"}}},
	}, model.StatusSuccess, nil)
	if res.Status != model.StatusFailure || !strings.Contains(res.Error, "working_directory") {
		t.Fatalf("bad working dir = %+v", res)
	}
	// continue_on_error keeps the job green.
	sink.lines = nil
	res = ex.runJob(context.Background(), &pipeline.Spec{}, pipeline.CompiledJob{
		ID: "j", Job: pipeline.Job{Steps: []pipeline.Step{
			{Name: "first", Run: "exit 5", ContinueOnError: true},
			{Name: "second", Run: "true"},
		}},
	}, model.StatusSuccess, nil)
	if res.Status != model.StatusSuccess || !sink.has("continue_on_error") || res.Attempts != 2 {
		t.Fatalf("continue_on_error = %+v", res)
	}
	// A negative retry max clamps attempts to one.
	res = ex.runJob(context.Background(), &pipeline.Spec{}, pipeline.CompiledJob{
		ID: "j", Job: pipeline.Job{Retry: pipeline.Retry{Max: -5}, Steps: []pipeline.Step{{Run: "true"}}},
	}, model.StatusSuccess, nil)
	if res.Status != model.StatusSuccess || res.Attempts != 1 {
		t.Fatalf("negative retry = %+v", res)
	}
	// An output file with an invalid key fails the step.
	res = ex.runJob(context.Background(), &pipeline.Spec{}, pipeline.CompiledJob{
		ID: "j", Job: pipeline.Job{Steps: []pipeline.Step{{
			ID:  "gen",
			Run: "printf 'BAD KEY=1\\n' > \"$KIWI_OUTPUT\"",
		}}},
	}, model.StatusSuccess, nil)
	if res.Status != model.StatusFailure || !strings.Contains(res.Error, "step outputs") {
		t.Fatalf("bad output key = %+v", res)
	}
	// A step with an ID and no output file records empty outputs.
	res = ex.runJob(context.Background(), &pipeline.Spec{}, pipeline.CompiledJob{
		ID: "j", Job: pipeline.Job{Steps: []pipeline.Step{{ID: "noout", Run: "true"}}},
	}, model.StatusSuccess, nil)
	if res.Status != model.StatusSuccess {
		t.Fatalf("no output step = %+v", res)
	}
	// OnlyStep with no match fails the job after the loop.
	res = ex.runJob(context.Background(), &pipeline.Spec{}, pipeline.CompiledJob{
		ID: "j", Job: pipeline.Job{Steps: []pipeline.Step{{Name: "one", Run: "true"}}},
	}, model.StatusSuccess, nil)
	_ = res
	exOpt := &Executor{Opt: Options{Workspace: ws, Logs: sink, RunID: "r", OnlyStep: "nope"}, Masker: &secrets.Masker{}}
	res = exOpt.runJob(context.Background(), &pipeline.Spec{}, pipeline.CompiledJob{
		ID: "j", Job: pipeline.Job{Steps: []pipeline.Step{{Name: "one", Run: "true"}}},
	}, model.StatusSuccess, nil)
	if res.Status != model.StatusFailure || !strings.Contains(res.Error, "not found") {
		t.Fatalf("OnlyStep no match = %+v", res)
	}
}

func TestRunJobJobTimeoutCancelsStep(t *testing.T) {
	ws := t.TempDir()
	ex := &Executor{Opt: Options{Workspace: ws, RunID: "r"}, Masker: &secrets.Masker{}}
	res := ex.runJob(context.Background(), &pipeline.Spec{}, pipeline.CompiledJob{
		ID: "j", Job: pipeline.Job{Timeout: pipeline.Duration{Duration: 150 * time.Millisecond}, Steps: []pipeline.Step{{Run: "sleep 10"}}},
	}, model.StatusSuccess, nil)
	if res.Status != model.StatusCancelled {
		t.Fatalf("timeout status = %+v", res)
	}
}

func TestRunJobGenerateBranches(t *testing.T) {
	ws := t.TempDir()
	// generate.path escaping the workspace fails the job.
	ex := &Executor{Opt: Options{Workspace: ws, RunID: "r", GenerateUpload: func(string, string, []byte) error { return nil }}, Masker: &secrets.Masker{}}
	res := ex.runJob(context.Background(), &pipeline.Spec{}, pipeline.CompiledJob{
		ID: "j", Job: pipeline.Job{Generate: pipeline.GenerateSpec{Path: "../escape.yaml"}, Steps: []pipeline.Step{{Run: "true"}}},
	}, model.StatusSuccess, nil)
	if res.Status != model.StatusFailure || !strings.Contains(res.Error, "escapes the workspace") {
		t.Fatalf("generate escape = %+v", res)
	}
	// A missing fragment fails the job.
	res = ex.runJob(context.Background(), &pipeline.Spec{}, pipeline.CompiledJob{
		ID: "j", Job: pipeline.Job{Generate: pipeline.GenerateSpec{Path: "frag.yaml"}, Steps: []pipeline.Step{{Run: "true"}}},
	}, model.StatusSuccess, nil)
	if res.Status != model.StatusFailure || !strings.Contains(res.Error, "frag.yaml") {
		t.Fatalf("missing fragment = %+v", res)
	}
	// An uploaded fragment succeeds.
	res = ex.runJob(context.Background(), &pipeline.Spec{}, pipeline.CompiledJob{
		ID: "j", Job: pipeline.Job{Generate: pipeline.GenerateSpec{Path: "frag.yaml"}, Steps: []pipeline.Step{{Run: "echo ok > frag.yaml"}}},
	}, model.StatusSuccess, nil)
	if res.Status != model.StatusSuccess {
		t.Fatalf("uploaded fragment = %+v", res)
	}
}

func TestRunJobCacheBranches(t *testing.T) {
	ws := canonicalTempDir(t)
	sink := &covSink{}
	store := cacheStoreAt(t)
	// A restore miss logs the miss, then the save runs.
	ex := &Executor{Opt: Options{Workspace: ws, Logs: sink, RunID: "r", Cache: store}, Masker: &secrets.Masker{}}
	res := ex.runJob(context.Background(), &pipeline.Spec{}, pipeline.CompiledJob{
		ID: "j", Job: pipeline.Job{
			Cache: []pipeline.Cache{{Name: "c", Key: "k", Paths: []string{"data"}}},
			Steps: []pipeline.Step{{Run: "mkdir -p data && echo x > data/f"}},
		},
	}, model.StatusSuccess, nil)
	if res.Status != model.StatusSuccess || !sink.has("miss c") || !sink.has("saved c") {
		t.Fatalf("cache miss/save = %+v", res)
	}
	// A second run in a fresh workspace restores the cache (primary hit).
	sink.lines = nil
	ex2 := &Executor{Opt: Options{Workspace: canonicalTempDir(t), Logs: sink, RunID: "r", Cache: store}, Masker: &secrets.Masker{}}
	res = ex2.runJob(context.Background(), &pipeline.Spec{}, pipeline.CompiledJob{
		ID: "j2", Job: pipeline.Job{
			Cache: []pipeline.Cache{{Name: "c", Key: "k", Paths: []string{"data"}}},
			Steps: []pipeline.Step{{Run: "test -f data/f"}},
		},
	}, model.StatusSuccess, nil)
	if res.Status != model.StatusSuccess || !sink.has("restored c") {
		t.Fatalf("cache restore = %+v", res)
	}
	// A hash_files entry that cannot be hashed (a symlink) logs a key warning.
	if err := os.Symlink(filepath.Join(ws, "elsewhere"), filepath.Join(ws, "hashed.lock")); err != nil {
		t.Fatal(err)
	}
	res = ex.runJob(context.Background(), &pipeline.Spec{}, pipeline.CompiledJob{
		ID: "j3", Job: pipeline.Job{
			Cache: []pipeline.Cache{{Name: "bad", Key: "k", HashFiles: []string{"hashed.lock"}, Paths: []string{"data"}}},
			Steps: []pipeline.Step{{Run: "true"}},
		},
	}, model.StatusSuccess, nil)
	if res.Status != model.StatusSuccess || !sink.has("key warning") {
		t.Fatalf("cache key warning = %+v", res)
	}
}

func TestRunJobWorkspaceQuota(t *testing.T) {
	ws := t.TempDir()
	ex := &Executor{Opt: Options{Workspace: ws, RunID: "r", WorkspaceMaxBytes: 1 << 62}, Masker: &secrets.Masker{}}
	res := ex.runJob(context.Background(), &pipeline.Spec{}, pipeline.CompiledJob{
		ID: "j", Job: pipeline.Job{Steps: []pipeline.Step{{Run: "true"}}},
	}, model.StatusSuccess, nil)
	if res.Status != model.StatusFailure || !strings.Contains(res.Error, "workspace quota") {
		t.Fatalf("workspace quota = %+v", res)
	}
}

func TestRunJobArtifactsAndSnapshot(t *testing.T) {
	ws := t.TempDir()
	sink := &covSink{}
	artDir := t.TempDir()
	store := artifactStoreAt(t, artDir)
	ex := &Executor{Opt: Options{
		Workspace: ws, Logs: sink, RunID: "run-art", Artifacts: store,
		ArtifactReporter: func(jobID, name, path string) error { return errors.New("upload refused") },
	}, Masker: &secrets.Masker{}}
	res := ex.runJob(context.Background(), &pipeline.Spec{}, pipeline.CompiledJob{
		ID: "j", Job: pipeline.Job{
			Artifacts: []pipeline.Artifact{
				{Name: "skipme", If: "false", Paths: []string{"out.txt"}},
				{Name: "bad", Paths: []string{"missing/**"}},
				{Name: "good", Paths: []string{"out.txt"}},
			},
			Steps: []pipeline.Step{{Run: "echo artifact > out.txt"}},
		},
	}, model.StatusSuccess, nil)
	if res.Status != model.StatusSuccess {
		t.Fatalf("artifact job = %+v", res)
	}
	if !sink.has("upload warning") {
		t.Fatalf("reporter error not surfaced: %v", sink.lines)
	}
	// A successful reporter logs the upload.
	ex.Opt.ArtifactReporter = func(string, string, string) error { return nil }
	sink.lines = nil
	res = ex.runJob(context.Background(), &pipeline.Spec{}, pipeline.CompiledJob{
		ID: "j2", Job: pipeline.Job{
			Artifacts: []pipeline.Artifact{{Name: "good", Paths: []string{"out.txt"}}},
			Steps:     []pipeline.Step{{Run: "echo artifact > out.txt"}},
		},
	}, model.StatusSuccess, nil)
	if res.Status != model.StatusSuccess || !sink.has("uploaded good") {
		t.Fatalf("artifact upload = %+v", res)
	}
	// Snapshot capture runs on success; an unwritable temp dir yields a
	// warning without changing status.
	ex.Opt.CaptureSnapshot = true
	t.Setenv("TMPDIR", filepath.Join(t.TempDir(), "missing-root"))
	sink.lines = nil
	res = ex.runJob(context.Background(), &pipeline.Spec{}, pipeline.CompiledJob{
		ID: "j3", Job: pipeline.Job{Steps: []pipeline.Step{{Run: "true"}}},
	}, model.StatusSuccess, nil)
	if res.Status != model.StatusSuccess || !sink.has("snapshot") {
		t.Fatalf("snapshot warning = %+v", res)
	}
}

func TestRunJobTaintCheckFailsJob(t *testing.T) {
	ws := t.TempDir()
	masker := &secrets.Masker{}
	masker.Add("tainted")
	ex := &Executor{Opt: Options{Workspace: ws, RunID: "r"}, Masker: masker}
	res := ex.runJob(context.Background(), &pipeline.Spec{}, pipeline.CompiledJob{
		ID: "j", Job: pipeline.Job{
			Outputs: map[string]string{"leak": "tainted"},
			Steps:   []pipeline.Step{{Run: "true"}},
		},
	}, model.StatusSuccess, nil)
	if res.Status != model.StatusFailure || res.Outputs != nil {
		t.Fatalf("taint check = %+v", res)
	}
}

func TestPrepareDefaults(t *testing.T) {
	ex := &Executor{}
	ex.prepare()
	if ex.Opt.MaxParallel <= 0 || ex.Opt.RunID == "" || ex.Opt.Cache == nil || ex.Opt.Artifacts == nil || ex.Masker == nil || ex.sessions == nil {
		t.Fatalf("prepare did not fill defaults: %+v", ex)
	}
}

func TestSessionRegistryNilAndLifecycle(t *testing.T) {
	var r *sessionRegistry
	r.put("j", &NativeBackend{})
	if _, ok := r.get("j"); ok {
		t.Fatal("nil registry returned a session")
	}
	r.delete("j")
	reg := &sessionRegistry{}
	if _, ok := reg.get("j"); ok {
		t.Fatal("empty registry returned a session")
	}
	reg.put("j", &NativeBackend{})
	if _, ok := reg.get("j"); !ok {
		t.Fatal("registered session not found")
	}
	reg.delete("j")
	if _, ok := reg.get("j"); ok {
		t.Fatal("deleted session still found")
	}
}

func TestReadJobFileNoSession(t *testing.T) {
	ex := &Executor{}
	if _, err := ex.ReadJobFile(context.Background(), "j", "p", 10); err == nil {
		t.Fatal("read without a session succeeded")
	}
}

func TestQuotaSinkLimitedSinkPassThrough(t *testing.T) {
	sink := &covSink{}
	l := limitedSink(sink, -1)
	if l != sink {
		t.Fatal("negative quota must pass the sink through")
	}
	l.WriteLine("j", "s", "kept")
	if !sink.has("kept") {
		t.Fatal("passthrough line missing")
	}
}

func TestGCNoBinaries(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	if rep := GC(context.Background(), t.TempDir(), time.Hour); rep != (GCReport{}) {
		t.Fatalf("report with no binaries = %+v", rep)
	}
	if rep := GC(context.TODO(), t.TempDir(), time.Hour); rep != (GCReport{}) {
		t.Fatalf("TODO context report = %+v", rep)
	}
	if rep := GC(context.Background(), t.TempDir(), 0); rep != (GCReport{}) {
		t.Fatalf("zero age report = %+v", rep)
	}
}
