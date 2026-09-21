package components

import (
	"context"
	"encoding/json"
	"errors"
	testutil "github.com/Bel-Consulting-OU/kiwi-ci/internal/testutil"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
)

func TestNewRemoteRegistryRejectsInvalidURLs(t *testing.T) {
	if _, err := NewRemoteRegistry("https://exa mple.com", ""); err == nil || !strings.Contains(err.Error(), "parse remote registry URL") {
		t.Fatalf("invalid URL = %v", err)
	}
	if _, err := NewRemoteRegistry("https://", ""); err == nil || !strings.Contains(err.Error(), "no host") {
		t.Fatalf("host-less URL = %v", err)
	}
	if _, err := NewRemoteRegistry("ftp://registry.example.com", ""); err == nil || !strings.Contains(err.Error(), "must use https") {
		t.Fatalf("non-https URL = %v", err)
	}
	reg, err := NewRemoteRegistry("https://registry.example.com/", "tok")
	if err != nil {
		t.Fatal(err)
	}
	if reg.BaseURL != "https://registry.example.com" || reg.Token != "tok" {
		t.Fatalf("registry = %+v", reg)
	}
}

func TestRemoteRegistryDefaultClient(t *testing.T) {
	reg := &RemoteRegistry{BaseURL: "https://registry.example.com"}
	cl := reg.client()
	if cl == nil || cl.Timeout == 0 {
		t.Fatalf("default client = %+v", cl)
	}
	if err := cl.CheckRedirect(nil, nil); !errors.Is(err, http.ErrUseLastResponse) {
		t.Fatalf("CheckRedirect = %v, want ErrUseLastResponse", err)
	}
	// A caller-supplied client is copied and hardened, never used as-is and
	// never mutated: the copy gets the policy fields, the original keeps its
	// own (zero) timeout and redirect handler.
	custom := &http.Client{}
	reg.Client = custom
	got := reg.client()
	if got == custom {
		t.Fatal("client() must return a hardened copy, not the injected client")
	}
	if got.Timeout != defaultRegistryTimeout {
		t.Fatalf("hardened Timeout = %v, want %v", got.Timeout, defaultRegistryTimeout)
	}
	if err := got.CheckRedirect(nil, nil); !errors.Is(err, http.ErrUseLastResponse) {
		t.Fatalf("hardened CheckRedirect = %v, want ErrUseLastResponse", err)
	}
	if custom.Timeout != 0 || custom.CheckRedirect != nil {
		t.Fatalf("hardening mutated the caller's client: %+v", custom)
	}
	// An explicit caller timeout below the class default is preserved.
	reg.Client = &http.Client{Timeout: time.Second}
	if got := reg.client().Timeout; got != time.Second {
		t.Fatalf("caller Timeout = %v, want 1s", got)
	}
}

func TestRemoteRegistryResolveValidationAndTransport(t *testing.T) {
	testutil.UnixChmod(t)
	reg, err := NewRemoteRegistry("https://registry.example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := reg.Resolve(context.Background(), "not a ref"); err == nil {
		t.Fatal("invalid ref must fail before any request")
	}
	if _, _, err := reg.Resolve(context.Background(), "build.yaml"); err == nil || !strings.Contains(err.Error(), "digest-pinned") {
		t.Fatalf("unpinned ref = %v", err)
	}
	if _, _, err := reg.Resolve(context.Background(), "build@sha256:"+strings.Repeat("ab", 32)); err == nil {
		t.Fatal("unreachable registry must fail (default client, no network)")
	}

	// A control character in the base URL makes http.NewRequest fail.
	bad := &RemoteRegistry{BaseURL: "https://registry.example.com/\x7f"}
	if _, _, err := bad.Resolve(context.Background(), "build@sha256:"+strings.Repeat("ab", 32)); err == nil {
		t.Fatal("unbuildable request URL must fail")
	}

	// Status errors surface the body.
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "missing", http.StatusNotFound)
	}))
	defer ts.Close()
	reg.Client = ts.Client()
	if _, _, err := reg.Resolve(context.Background(), "build@sha256:"+strings.Repeat("ab", 32)); err == nil || !strings.Contains(err.Error(), "404") {
		t.Fatalf("status error = %v", err)
	}

	// Malformed JSON is rejected.
	badJSON := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("{nope"))
	}))
	defer badJSON.Close()
	reg.Client = badJSON.Client()
	if _, _, err := reg.Resolve(context.Background(), "build@sha256:"+strings.Repeat("ab", 32)); err == nil || !strings.Contains(err.Error(), "decode") {
		t.Fatalf("decode error = %v", err)
	}
}

func TestChainRegistry(t *testing.T) {
	var spec Spec
	if err := json.Unmarshal([]byte(`{"name":"build","steps":[{"run":"echo hi"}]}`), &spec); err != nil {
		t.Fatal(err)
	}
	digest, err := Digest(spec)
	if err != nil {
		t.Fatal(err)
	}
	ref := "build@sha256:" + digest

	notFound := &LocalRegistry{}
	found := NewLocalRegistry()
	found.Register(spec)

	got, gotDigest, err := ChainRegistry{nil, notFound, found}.Resolve(context.Background(), ref)
	if err != nil || gotDigest != digest {
		t.Fatalf("chain resolve = %+v %q (err %v)", got, gotDigest, err)
	}

	_, _, err = ChainRegistry{nil, notFound, NewLocalRegistry()}.Resolve(context.Background(), ref)
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("failing chain = %v", err)
	}

	if _, _, err := (ChainRegistry{}).Resolve(context.Background(), ref); err == nil || !strings.Contains(err.Error(), "empty registry chain") {
		t.Fatalf("empty chain = %v", err)
	}
	if _, _, err := (ChainRegistry{nil, nil}).Resolve(context.Background(), ref); err == nil || !strings.Contains(err.Error(), "empty registry chain") {
		t.Fatalf("nil-only chain = %v", err)
	}
}

func TestLocalRegistryResolveUnknownPinnedName(t *testing.T) {
	reg := NewLocalRegistry()
	if _, _, err := reg.Resolve(context.Background(), "ghost@sha256:"+strings.Repeat("ab", 32)); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("unknown pinned name = %v", err)
	}
}

func TestNewLocalRegistryFromDirErrors(t *testing.T) {
	if _, err := NewLocalRegistryFromDir(filepath.Join(t.TempDir(), "missing")); err == nil || !strings.Contains(err.Error(), "load registry dir") {
		t.Fatalf("missing dir = %v", err)
	}

	dir := t.TempDir()
	// Unreadable spec file: the walk reports the read error. The denial only
	// exists for a non-root euid, so this assertion is its own subtest and
	// the malformed-spec assertions below still run as root.
	t.Run("unreadable spec", func(t *testing.T) {
		testutil.UnixChmod(t)
		testutil.RequireNonRoot(t)
		lockedDir := t.TempDir()
		unreadable := filepath.Join(lockedDir, "locked.yaml")
		if err := os.WriteFile(unreadable, []byte("name: locked\n"), 0o000); err != nil {
			t.Fatal(err)
		}
		if _, err := NewLocalRegistryFromDir(lockedDir); err == nil {
			t.Fatalf("unreadable spec must fail the load")
		}
		if err := os.Chmod(unreadable, 0o600); err != nil {
			t.Fatal(err)
		}
	})

	// Malformed spec file.
	if err := os.WriteFile(filepath.Join(dir, "broken.yaml"), []byte("name: [\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewLocalRegistryFromDir(dir); err == nil || !strings.Contains(err.Error(), "parse") {
		t.Fatalf("malformed spec = %v", err)
	}
	if err := os.Remove(filepath.Join(dir, "broken.yaml")); err != nil {
		t.Fatal(err)
	}

	// Non-spec files and directories are ignored; both path spellings and
	// case-insensitive extensions resolve.
	if err := os.MkdirAll(filepath.Join(dir, "nested"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "nested", "tool.YML"), []byte("name: tool\nsteps:\n  - run: echo t\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("ignore me"), 0o600); err != nil {
		t.Fatal(err)
	}
	reg, err := NewLocalRegistryFromDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, ref := range []string{"nested/tool.YML", "components/nested/tool.YML"} {
		if _, _, err := reg.Resolve(context.Background(), ref); err != nil {
			t.Fatalf("resolve %s: %v", ref, err)
		}
	}
}

func TestValidateInvocationInputDeclarationErrors(t *testing.T) {
	cases := []struct {
		name string
		spec Spec
		want string
	}{
		{"empty name", Spec{Name: "c", Inputs: []Input{{Name: "  "}}}, "empty name"},
		{"unknown type", Spec{Name: "c", Inputs: []Input{{Name: "x", Type: "float"}}}, "unknown type"},
		{"enum without options", Spec{Name: "c", Inputs: []Input{{Name: "x", Type: "enum"}}}, "declares no options"},
		{"duplicate", Spec{Name: "c", Inputs: []Input{{Name: "x"}, {Name: "x"}}}, "duplicate input"},
	}
	for _, tc := range cases {
		err := ValidateInvocation(tc.spec, nil)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: error = %v, want %q", tc.name, err, tc.want)
		}
	}

	spec := Spec{Name: "c", Inputs: []Input{{Name: "known"}}}
	if err := ValidateInvocation(spec, map[string]string{"other": "x"}); err == nil || !strings.Contains(err.Error(), "unknown input") {
		t.Fatalf("unknown input = %v", err)
	}
	if err := ValidateInvocation(spec, map[string]string{"known": "x"}); err != nil {
		t.Fatalf("declared string input = %v", err)
	}
	if err := ValidateInvocation(spec, map[string]string{"steps": "boom"}); err == nil || !strings.Contains(err.Error(), "privileged") {
		t.Fatalf("privileged field = %v", err)
	}
}

func TestValidateInvocationTypes(t *testing.T) {
	spec := Spec{Name: "c", Inputs: []Input{
		{Name: "s"},
		{Name: "b", Type: "boolean"},
		{Name: "i", Type: "integer"},
		{Name: "e", Type: "enum", Options: []string{"a", "b"}},
		{Name: "req", Required: true, Default: "d"},
	}}
	if err := ValidateInvocation(spec, map[string]string{"b": "true", "i": "-12", "e": "b"}); err != nil {
		t.Fatalf("valid invocation = %v", err)
	}
	for name, with := range map[string]map[string]string{
		"bad boolean": {"b": "yes"},
		"bad integer": {"i": "1.5"},
		"bad enum":    {"e": "c"},
	} {
		if err := ValidateInvocation(spec, with); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
	required := Spec{Name: "c", Inputs: []Input{{Name: "must", Required: true}}}
	if err := ValidateInvocation(required, nil); err == nil || !strings.Contains(err.Error(), "required input") {
		t.Fatalf("missing required input = %v", err)
	}
}

func TestApplyEdges(t *testing.T) {
	if err := Apply(Spec{Name: "c"}, nil, nil); err == nil || !strings.Contains(err.Error(), "nil job") {
		t.Fatalf("nil job = %v", err)
	}
	job := &pipeline.Job{}
	spec := Spec{
		Name:    "c",
		Steps:   []pipeline.Step{{Run: "echo component"}},
		Env:     map[string]string{"LAYER": "component"},
		Secrets: []string{"token"},
		Cache:   []pipeline.Cache{{Key: "component-cache"}},
		Sandbox: &pipeline.Sandbox{Network: pipeline.NetworkPolicyNone},
		Inputs:  []Input{{Name: "mode", Default: "fast"}},
	}
	if err := Apply(spec, job, nil); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if len(job.Steps) != 1 || len(job.Steps[0].Secrets) != 1 || job.Steps[0].Secrets[0] != "token" {
		t.Fatalf("steps = %+v", job.Steps)
	}
	if job.Env["LAYER"] != "component" || job.Env["mode"] != "fast" {
		t.Fatalf("env = %v", job.Env)
	}
	if len(job.Cache) != 1 || job.Sandbox.Network != pipeline.NetworkPolicyNone {
		t.Fatalf("cache/sandbox = %+v %+v", job.Cache, job.Sandbox)
	}

	// The job keeps its own sandbox and its env wins over component env; the
	// invocation wins over both.
	job2 := &pipeline.Job{
		Steps:   []pipeline.Step{{Run: "echo job"}},
		Env:     map[string]string{"LAYER": "job", "mode": "slow"},
		Sandbox: pipeline.Sandbox{Network: pipeline.NetworkPolicyInternet},
	}
	if err := Apply(spec, job2, map[string]string{"mode": "invoked"}); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if job2.Env["LAYER"] != "job" || job2.Env["mode"] != "invoked" {
		t.Fatalf("env precedence = %v", job2.Env)
	}
	if job2.Sandbox.Network != pipeline.NetworkPolicyInternet {
		t.Fatalf("job sandbox overwritten: %+v", job2.Sandbox)
	}
	if len(job2.Steps) != 2 || job2.Steps[0].Run != "echo component" || job2.Steps[1].Run != "echo job" {
		t.Fatalf("step order = %+v", job2.Steps)
	}
}

func TestInputNamesSorted(t *testing.T) {
	spec := Spec{Inputs: []Input{{Name: "zulu"}, {Name: "alpha"}, {Name: "mike"}}}
	got := InputNames(spec)
	want := []string{"alpha", "mike", "zulu"}
	if len(got) != len(want) {
		t.Fatalf("InputNames = %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("InputNames = %v, want %v", got, want)
		}
	}
	if names := InputNames(Spec{}); len(names) != 0 {
		t.Fatalf("InputNames(empty) = %v", names)
	}
}

func TestResolveComponentRefMatrix(t *testing.T) {
	valid := []string{
		"build.yaml",
		"components/build.yaml",
		"a_b/c.d-e",
		"name@sha256:" + strings.Repeat("ab", 32),
	}
	for _, ref := range valid {
		if err := ResolveComponentRef(ref); err != nil {
			t.Errorf("ResolveComponentRef(%q) = %v, want nil", ref, err)
		}
	}
	invalid := []string{
		"",
		"   ",
		"bad@ref",
		"name@sha256:short",
		"name@sha256:" + strings.Repeat("ZZ", 32),
		`win\path`,
		"/absolute/path",
		"../escape",
		"a..b",
		"has space",
	}
	for _, ref := range invalid {
		if err := ResolveComponentRef(ref); err == nil {
			t.Errorf("ResolveComponentRef(%q) = nil, want an error", ref)
		}
	}
	if name, digest := splitRemoteRef("no-at-sign"); name != "no-at-sign" || digest != "" {
		t.Fatalf("splitRemoteRef(no-at-sign) = %q,%q", name, digest)
	}
	if name, digest := splitRemoteRef("build@sha256:abcd"); name != "build" || digest != "abcd" {
		t.Fatalf("splitRemoteRef = %q,%q", name, digest)
	}
}
