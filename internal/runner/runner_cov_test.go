package runner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	testutil "github.com/Bel-Consulting-OU/kiwi-ci/internal/testutil"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/executor"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

func TestMetricsExposeAndServeHTTP(t *testing.T) {
	m := NewMetrics()
	m.Counter("b_total", 2)
	m.Observe("a_seconds", 0.5)
	var buf bytes.Buffer
	if err := m.Expose(&buf); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "a_seconds 0.5") || !strings.Contains(out, "b_total 2") {
		t.Fatalf("exposition = %q", out)
	}
	if strings.Index(out, "a_seconds") > strings.Index(out, "b_total") {
		t.Fatal("exposition is not sorted")
	}
	rec := httptest.NewRecorder()
	m.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Header().Get("Content-Type"), "text/plain") {
		t.Fatalf("ServeHTTP = %d %q", rec.Code, rec.Header().Get("Content-Type"))
	}
	// A write failure surfaces through Expose.
	if err := m.Expose(failingWriter{}); err == nil {
		t.Fatal("write failure not surfaced")
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, fmt.Errorf("write refused") }

func TestMetricsServeHTTPErrorStatus(t *testing.T) {
	m := NewMetrics()
	m.Counter("x", 1)
	rec := httptest.NewRecorder()
	m.ServeHTTP(&failThenRecorder{ResponseRecorder: rec}, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("ServeHTTP after an exposition write failure = %d, want 500", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "flush refused") {
		t.Fatalf("ServeHTTP error body = %q, want the exposition error surfaced", rec.Body.String())
	}
}

type failThenRecorder struct {
	*httptest.ResponseRecorder
	failed bool
}

func (f *failThenRecorder) Write(b []byte) (int, error) {
	if !f.failed {
		f.failed = true
		return 0, fmt.Errorf("flush refused")
	}
	return f.ResponseRecorder.Write(b)
}

func TestNewMetricsServerServes(t *testing.T) {
	addr := freeRunnerAddr(t)
	srv := newMetricsServer(addr, NewMetrics())
	errCh := make(chan error, 1)
	go func() { errCh <- srv.ListenAndServe() }()
	waitRunnerTCP(t, addr)
	resp, err := http.Get("http://" + addr + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if err := srv.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-errCh; err != nil && err != http.ErrServerClosed {
		t.Fatalf("metrics server: %v", err)
	}
}

func TestIdentityStoreLifecycle(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "identity")
	store := IdentityStore{Dir: dir}
	if id, ok := store.LoadID(); ok || id != "" {
		t.Fatalf("empty store LoadID = %q, %v", id, ok)
	}
	if _, ok := store.Load(); ok {
		t.Fatal("empty store Load reported complete")
	}
	// Incomplete identities are refused.
	if err := store.Save(Identity{ID: "r1"}); err == nil {
		t.Fatal("incomplete identity saved")
	}
	// A blank runner-id file is not an ID.
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, identityIDFile), []byte("  \n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if id, ok := store.LoadID(); ok || id != "" {
		t.Fatalf("blank ID = %q, %v", id, ok)
	}
	// A partial store still exposes the ID for re-enrollment.
	if err := os.WriteFile(filepath.Join(dir, identityIDFile), []byte("runner-9\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	id, ok := store.Load()
	if ok || id.ID != "runner-9" {
		t.Fatalf("partial Load = %+v, %v", id, ok)
	}
	full := Identity{ID: "runner-9", KeyPEM: []byte("key"), CertPEM: []byte("cert"), CACertPEM: []byte("ca")}
	if err := store.Save(full); err != nil {
		t.Fatal(err)
	}
	loaded, ok := store.Load()
	if !ok || loaded.ID != "runner-9" || string(loaded.KeyPEM) != "key" {
		t.Fatalf("Load = %+v, %v", loaded, ok)
	}
	if got, ok := store.LoadID(); !ok || got != "runner-9" {
		t.Fatalf("LoadID = %q, %v", got, ok)
	}
	// The key is owner-only.
	info, err := os.Stat(filepath.Join(dir, identityKeyFile))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("key mode = %v", info.Mode().Perm())
	}
	// ClearCert is idempotent and keeps the ID.
	if err := store.ClearCert(); err != nil {
		t.Fatal(err)
	}
	if err := store.ClearCert(); err != nil {
		t.Fatalf("second ClearCert: %v", err)
	}
	if got, ok := store.LoadID(); !ok || got != "runner-9" {
		t.Fatal("ClearCert dropped the runner ID")
	}
	// A file where the store directory belongs fails Save.
	blocked := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(blocked, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := (IdentityStore{Dir: blocked}).Save(full); err == nil {
		t.Fatal("Save under a file succeeded")
	}
}

func TestCovMaintenanceScheduleDue(t *testing.T) {
	now := time.Now()
	m := maintenanceSchedule{GCInterval: time.Minute, PrewarmInterval: 0}
	gc, pw := m.due(now, time.Time{}, time.Time{})
	if !gc || pw {
		t.Fatalf("due = %v, %v", gc, pw)
	}
	gc, _ = m.due(now, now.Add(-30*time.Second), time.Time{})
	if gc {
		t.Fatal("recent GC reported due")
	}
	m = maintenanceSchedule{GCInterval: time.Minute, PrewarmInterval: time.Minute}
	_, pw = m.due(now, now, now.Add(-2*time.Minute))
	if !pw {
		t.Fatal("prewarm not due")
	}
}

func TestPrewarmRefParsing(t *testing.T) {
	pr, err := parsePrewarmRef("alpine@sha256:" + strings.Repeat("a", 64))
	if err != nil || pr.Kind != "docker" || pr.Ref == "" {
		t.Fatalf("docker ref = %+v, %v", pr, err)
	}
	digest := strings.Repeat("B", 64)
	pr, err = parsePrewarmRef("tart://ghcr.io/x/macos@" + "sha256:" + digest)
	if err != nil || pr.Kind != "tart" || pr.VMName != "kiwi-prewarm-ghcr-io-x-macos" || pr.Digest != "sha256:"+digest {
		t.Fatalf("tart ref = %+v, %v", pr, err)
	}
	for _, bad := range []string{"", "  ", "tart://x", "tart://@sha256:" + digest, "tart://x@sha256:short", "tart://x@sha256:" + strings.Repeat("z", 64)} {
		if _, err := parsePrewarmRef(bad); err == nil {
			t.Fatalf("bad ref %q accepted", bad)
		}
	}
	if !isSHA256Hex(strings.Repeat("F", 64)) || isSHA256Hex(strings.Repeat("g", 64)) || isSHA256Hex("abc") {
		t.Fatal("isSHA256Hex misbehaves")
	}
	if got := prewarmVMName("Ubuntu/24.04!!"); got != "kiwi-prewarm-ubuntu-24-04" {
		t.Fatalf("prewarmVMName = %q", got)
	}
	if got := prewarmVMName("---"); got != "kiwi-prewarm-" {
		t.Fatalf("prewarmVMName dashes = %q", got)
	}
}

func TestCovValidatePrewarmRefs(t *testing.T) {
	if err := validatePrewarmRefs([]string{"alpine@sha256:" + strings.Repeat("a", 64)}); err != nil {
		t.Fatal(err)
	}
	if err := validatePrewarmRefs([]string{"tart://img@sha256:" + strings.Repeat("a", 64)}); err != nil {
		t.Fatal(err)
	}
	for _, bad := range [][]string{{""}, {" "}, {"alpine:latest"}, {"tart://bad"}} {
		if err := validatePrewarmRefs(bad); err == nil {
			t.Fatalf("refs %v accepted", bad)
		}
	}
}

func TestCovPrewarmHelpers(t *testing.T) {
	testutil.UnixShell(t)
	remove, keep := prewarmRemovals(prewarmState{Items: []prewarmItem{
		{Ref: "gone", Kind: "docker"},
		{Ref: "kept", Kind: "tart"},
	}}, []string{"kept"})
	if len(remove) != 1 || remove[0].Ref != "gone" || len(keep) != 1 || keep[0].Ref != "kept" {
		t.Fatalf("removals = %v / %v", remove, keep)
	}
	items := []prewarmItem{{Ref: "b", Kind: "tart"}, {Ref: "a", Kind: "tart"}, {Ref: "a", Kind: "docker"}}
	capped := capPrewarmItems(items, 2)
	if len(capped) != 2 || capped[0].Ref != "a" || capped[0].Kind != "docker" {
		t.Fatalf("capped = %v", capped)
	}
	if len(capPrewarmItems(items, 5)) != 3 {
		t.Fatal("cap above length must pass through")
	}
	vms, err := parseTartList([]byte(`[{"name":"vm1","source":"img@sha256:abc"}]`))
	if err != nil || len(vms) != 1 || vms[0].Name != "vm1" {
		t.Fatalf("parseTartList = %+v, %v", vms, err)
	}
	if _, err := parseTartList([]byte("{")); err == nil {
		t.Fatal("malformed tart list accepted")
	}
	if tartSourceDigest("plain") != "" || tartSourceDigest("img@sha256:abc") != "sha256:abc" {
		t.Fatal("tartSourceDigest")
	}
	stale := tartStaleVMs([]tartVM{
		{Name: "other-vm", Source: "x@sha256:aaa"},
		{Name: "kiwi-prewarm-a", Source: "x@sha256:aaa"},
		{Name: "kiwi-prewarm-b", Source: "x@sha256:bbb"},
		{Name: "kiwi-prewarm-c", Source: "no-digest"},
	}, map[string]bool{"sha256:bbb": true})
	if len(stale) != 2 || stale[0] != "kiwi-prewarm-a" || stale[1] != "kiwi-prewarm-c" {
		t.Fatalf("stale VMs = %v", stale)
	}
}

func TestPrewarmRunFullCycle(t *testing.T) {
	bin := installRunnerFakes(t)
	stateFile := filepath.Join(t.TempDir(), "state", "prewarm.json")
	prev := prewarmState{Version: 1, Items: []prewarmItem{
		{Ref: "old-docker@sha256:" + strings.Repeat("1", 64), Kind: "docker"},
		{Ref: "tart://old@" + "sha256:" + strings.Repeat("2", 64), Kind: "tart"},
		{Ref: "keep-docker@sha256:" + strings.Repeat("3", 64), Kind: "docker"},
	}}
	body, _ := json.Marshal(prev)
	if err := os.MkdirAll(filepath.Dir(stateFile), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(stateFile, body, 0o600); err != nil {
		t.Fatal(err)
	}
	good := "keep-docker@sha256:" + strings.Repeat("3", 64)
	tartImage := "ghcr.io/acme/macos"
	tartDigest := strings.Repeat("4", 64)
	tartRef := "tart://" + tartImage + "@sha256:" + tartDigest
	t.Setenv("FAKE_TART_LIST_JSON", fmt.Sprintf(`[{"name":"kiwi-prewarm-stale","source":"old@sha256:%s"},{"name":"kiwi-prewarm-%s","source":"%s@sha256:%s"}]`,
		strings.Repeat("9", 64), "ghcr-io-acme-macos", tartImage, tartDigest))
	logger := &covLogger{}
	p := &prewarmer{refs: []string{good, tartRef, "tart://bad", "not-pinned:latest"}, stateFile: stateFile,
		maxTracked: 10, dockerPath: filepath.Join(bin, "docker"), tartPath: filepath.Join(bin, "tart"),
		logf: logger.logf}
	if err := p.run(context.Background()); err != nil {
		t.Fatalf("prewarm run: %v", err)
	}
	joined := logger.joined()
	if !strings.Contains(joined, "removed stale tart VM kiwi-prewarm-stale") {
		t.Fatalf("stale VM sweep missing: %s", joined)
	}
	if !strings.Contains(joined, "invalid tart reference") {
		t.Fatalf("bad tart ref not logged: %s", joined)
	}
	// The state tracks the successfully prewarmed refs (kept entries plus
	// this pass's pulls) and never the removed ones.
	st := p.loadState()
	if len(st.Items) == 0 {
		t.Fatal("no items persisted")
	}
	sawTart := false
	for _, item := range st.Items {
		if item.Ref == "old-docker@sha256:"+strings.Repeat("1", 64) || strings.HasPrefix(item.Ref, "tart://old@") {
			t.Fatalf("removed item persisted: %+v", st.Items)
		}
		if item.Kind == "tart" && strings.Contains(item.Ref, "ghcr.io/acme/macos") {
			sawTart = true
		}
	}
	if !sawTart {
		t.Fatalf("tart prewarm not persisted: %+v", st.Items)
	}
	// No refs: the pass is a no-op.
	if err := (&prewarmer{}).run(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestPrewarmRunFailuresAreLogged(t *testing.T) {
	bin := installRunnerFakes(t)
	t.Setenv("FAKE_DOCKER_PULL_FAIL", "1")
	t.Setenv("FAKE_TART_LIST_FAIL", "1")
	t.Setenv("FAKE_TART_PULL_FAIL", "1")
	logger := &covLogger{}
	p := &prewarmer{
		refs:       []string{"img@sha256:" + strings.Repeat("a", 64), "tart://vm@sha256:" + strings.Repeat("b", 64)},
		dockerPath: filepath.Join(bin, "docker"), tartPath: filepath.Join(bin, "tart"),
		logf: logger.logf,
	}
	if err := p.run(context.Background()); err != nil {
		t.Fatalf("failed pulls must not be fatal: %v", err)
	}
	joined := logger.joined()
	if !strings.Contains(joined, "docker pull") || !strings.Contains(joined, "tart list") {
		t.Fatalf("failures not logged: %s", joined)
	}
}

func TestPrewarmTartVerification(t *testing.T) {
	bin := installRunnerFakes(t)
	image := "ghcr.io/acme/macos"
	digest := strings.Repeat("c", 64)
	pr := prewarmRef{Kind: "tart", Ref: "tart://" + image + "@sha256:" + digest, Image: image,
		Digest: "sha256:" + digest, VMName: prewarmVMName(image)}
	p := &prewarmer{tartPath: filepath.Join(bin, "tart"), logf: func(string, ...any) {}}
	t.Setenv("FAKE_TART_LIST_JSON", fmt.Sprintf(`[{"name":%q,"source":%q}]`, pr.VMName, image+"@sha256:"+digest))
	if err := p.prewarmTart(context.Background(), pr); err != nil {
		t.Fatalf("prewarmTart: %v", err)
	}
	// Digest mismatch.
	t.Setenv("FAKE_TART_LIST_JSON", fmt.Sprintf(`[{"name":%q,"source":"other@sha256:%s"}]`, pr.VMName, strings.Repeat("d", 64)))
	err := p.prewarmTart(context.Background(), pr)
	if err == nil || !strings.Contains(err.Error(), "digest mismatch") {
		t.Fatalf("mismatch = %v", err)
	}
	// Missing VM.
	t.Setenv("FAKE_TART_LIST_JSON", `[]`)
	if err := p.prewarmTart(context.Background(), pr); err == nil {
		t.Fatal("missing VM accepted")
	}
	// Listing fails after a successful clone.
	t.Setenv("FAKE_TART_LIST_FAIL", "1")
	if err := p.prewarmTart(context.Background(), pr); err == nil {
		t.Fatal("failing list accepted")
	}
	// Clone fails.
	t.Setenv("FAKE_TART_LIST_FAIL", "")
	t.Setenv("FAKE_TART_CLONE_FAIL", "1")
	if err := p.prewarmTart(context.Background(), pr); err == nil {
		t.Fatal("failing clone accepted")
	}
	// Pull fails.
	t.Setenv("FAKE_TART_CLONE_FAIL", "")
	t.Setenv("FAKE_TART_PULL_FAIL", "1")
	if err := p.prewarmTart(context.Background(), pr); err == nil {
		t.Fatal("failing pull accepted")
	}
}

func TestPrewarmListTartVMsErrors(t *testing.T) {
	bin := installRunnerFakes(t)
	p := &prewarmer{tartPath: filepath.Join(bin, "tart"), logf: func(string, ...any) {}}
	if _, err := p.listTartVMs(context.Background()); err != nil {
		t.Fatalf("listTartVMs: %v", err)
	}
	t.Setenv("FAKE_TART_LIST_FAIL", "1")
	if _, err := p.listTartVMs(context.Background()); err == nil {
		t.Fatal("failing list accepted")
	}
	t.Setenv("FAKE_TART_LIST_FAIL", "")
	t.Setenv("FAKE_TART_LIST_JSON", "{")
	if _, err := p.listTartVMs(context.Background()); err == nil {
		t.Fatal("malformed list accepted")
	}
}

func TestPrewarmPullError(t *testing.T) {
	bin := installRunnerFakes(t)
	if err := prewarmPull(context.Background(), filepath.Join(bin, "docker"), "img@sha256:"+strings.Repeat("a", 64)); err != nil {
		t.Fatalf("pull: %v", err)
	}
	t.Setenv("FAKE_DOCKER_PULL_FAIL", "1")
	if err := prewarmPull(context.Background(), filepath.Join(bin, "docker"), "img"); err == nil {
		t.Fatal("failing pull accepted")
	}
}

func TestPrewarmRemoveItem(t *testing.T) {
	bin := installRunnerFakes(t)
	logger := &covLogger{}
	p := &prewarmer{dockerPath: filepath.Join(bin, "docker"), tartPath: filepath.Join(bin, "tart"),
		logf: logger.logf}
	p.removeItem(context.Background(), prewarmItem{Kind: "docker", Ref: "img@sha256:" + strings.Repeat("a", 64)})
	p.removeItem(context.Background(), prewarmItem{Kind: "tart", Ref: "tart://vm@sha256:" + strings.Repeat("b", 64)})
	// A malformed tart ref falls back to the raw ref as the VM name.
	p.removeItem(context.Background(), prewarmItem{Kind: "tart", Ref: "not-a-ref"})
	// Unknown kinds are ignored.
	p.removeItem(context.Background(), prewarmItem{Kind: "mystery", Ref: "x"})
	// Removal failures are logged, not fatal.
	t.Setenv("FAKE_DOCKER_IMAGE_RM_FAIL", "1")
	t.Setenv("FAKE_TART_DELETE_FAIL", "1")
	p.removeItem(context.Background(), prewarmItem{Kind: "docker", Ref: "img"})
	p.removeItem(context.Background(), prewarmItem{Kind: "tart", Ref: "tart://vm@sha256:" + strings.Repeat("b", 64)})
	if !strings.Contains(logger.joined(), "remove docker image") {
		t.Fatalf("removal failures not logged: %s", logger.joined())
	}
}

func TestPrewarmStateRoundTrip(t *testing.T) {
	// No state file: empty state, no-op save.
	p := &prewarmer{}
	if st := p.loadState(); st.Version != 0 || len(st.Items) != 0 {
		t.Fatalf("empty state = %+v", st)
	}
	if err := p.saveState(prewarmState{Version: 1}); err != nil {
		t.Fatal(err)
	}
	// Corrupt state is ignored.
	dir := t.TempDir()
	p = &prewarmer{stateFile: filepath.Join(dir, "state.json")}
	if st := p.loadState(); len(st.Items) != 0 {
		t.Fatalf("missing file state = %+v", st)
	}
	if err := os.WriteFile(p.stateFile, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if st := p.loadState(); len(st.Items) != 0 {
		t.Fatalf("corrupt state = %+v", st)
	}
	// Round trip.
	if err := p.saveState(prewarmState{Version: 1, Items: []prewarmItem{{Ref: "r", Kind: "docker"}}}); err != nil {
		t.Fatal(err)
	}
	if st := p.loadState(); len(st.Items) != 1 || st.Items[0].Ref != "r" {
		t.Fatalf("round trip = %+v", st)
	}
	// The state directory cannot be created under a file.
	blocked := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(blocked, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	p = &prewarmer{stateFile: filepath.Join(blocked, "state.json")}
	if err := p.saveState(prewarmState{}); err == nil {
		t.Fatal("save under a file succeeded")
	}
	// The rename target being a directory fails the save.
	dirState := filepath.Join(t.TempDir(), "state.json")
	if err := os.Mkdir(dirState, 0o755); err != nil {
		t.Fatal(err)
	}
	p = &prewarmer{stateFile: dirState}
	if err := p.saveState(prewarmState{}); err == nil {
		t.Fatal("save onto a directory succeeded")
	}
}

func TestNewPrewarmerDefaults(t *testing.T) {
	bin := installRunnerFakes(t)
	p := newPrewarmer(Config{Prewarm: []string{"a"}, PrewarmStateFile: "state"})
	if p.dockerPath == "" || p.tartPath == "" || p.maxTracked != prewarmMaxTracked {
		t.Fatalf("prewarmer = %+v", p)
	}
	if len(p.refs) != 1 {
		t.Fatal("refs not copied")
	}
	// Without the binaries on PATH the paths stay empty.
	t.Setenv("PATH", t.TempDir())
	_ = bin
	p = newPrewarmer(Config{})
	if p.dockerPath != "" || p.tartPath != "" {
		t.Fatalf("paths without binaries = %+v", p)
	}
}

func TestCovStatusForErr(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got := statusForErr(ctx, nil); got != model.StatusCancelled {
		t.Fatalf("cancelled = %v", got)
	}
	if got := statusForErr(context.Background(), &executor.RunError{Kind: executor.ErrorTimeout, Err: fmt.Errorf("slow")}); got != model.StatusFailure {
		t.Fatalf("timeout = %v", got)
	}
	if got := statusForErr(context.Background(), fmt.Errorf("boom")); got != model.StatusFailure {
		t.Fatalf("plain error = %v", got)
	}
}

// covLogger collects log lines from concurrent prewarm workers.
type covLogger struct {
	mu    sync.Mutex
	lines []string
}

func (l *covLogger) logf(format string, args ...any) {
	l.mu.Lock()
	l.lines = append(l.lines, fmt.Sprintf(format, args...))
	l.mu.Unlock()
}

func (l *covLogger) joined() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return strings.Join(l.lines, "\n")
}

// installRunnerFakes writes docker/tart fake binaries and prepends them to
// PATH.
func installRunnerFakes(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	docker := `#!/bin/sh
echo "$@" >> "${FAKE_RUNNER_LOG:-/dev/null}"
case "$1" in
  pull) if [ -n "$FAKE_DOCKER_PULL_FAIL" ]; then echo "pull failed"; exit 1; fi;;
  image) if [ -n "$FAKE_DOCKER_IMAGE_RM_FAIL" ]; then echo "rm failed" >&2; exit 1; fi;;
esac
exit 0
`
	tart := `#!/bin/sh
echo "$@" >> "${FAKE_RUNNER_LOG:-/dev/null}"
case "$1" in
  list)
    if [ -n "$FAKE_TART_LIST_FAIL" ]; then echo "list failed"; exit 1; fi
    printf '%s\n' "${FAKE_TART_LIST_JSON:-[]}";;
  pull) if [ -n "$FAKE_TART_PULL_FAIL" ]; then echo "pull failed"; exit 1; fi;;
  clone) if [ -n "$FAKE_TART_CLONE_FAIL" ]; then echo "clone failed"; exit 1; fi;;
  delete) if [ -n "$FAKE_TART_DELETE_FAIL" ]; then echo "delete failed" >&2; exit 1; fi;;
esac
exit 0
`
	for name, body := range map[string]string{"docker": docker, "tart": tart} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
	return dir
}

func freeRunnerAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

func waitRunnerTCP(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			_ = c.Close()
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("no listener on %s", addr)
}
