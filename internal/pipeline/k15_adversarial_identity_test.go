package pipeline

import (
	"encoding/json"
	"strings"
	"testing"
)

// Adversarial: pipelines that differ ONLY in toolchain pins must not share
// a canonical digest (pipeline identity / attestation binding).
func TestCanonicalDigestIncludesToolchains(t *testing.T) {
	base := `version: 1
toolchains:
  rust:
    version: "1.83.0"
    command: ["rustc", "--version"]
jobs:
  b:
    toolchains: [rust]
    steps: [{run: "true"}]
`
	bumped := `version: 1
toolchains:
  rust:
    version: "1.84.0"
    command: ["rustc", "--version"]
jobs:
  b:
    toolchains: [rust]
    steps: [{run: "true"}]
`
	noPin := `version: 1
toolchains:
  rust:
    command: ["rustc", "--version"]
jobs:
  b:
    toolchains: [rust]
    steps: [{run: "true"}]
`
	s1, err := Parse([]byte(base))
	if err != nil {
		t.Fatal(err)
	}
	s2, err := Parse([]byte(bumped))
	if err != nil {
		t.Fatal(err)
	}
	s3, err := Parse([]byte(noPin))
	if err != nil {
		t.Fatal(err)
	}
	j1, _ := CanonicalJSON(s1)
	j2, _ := CanonicalJSON(s2)
	j3, _ := CanonicalJSON(s3)
	if string(j1) == string(j2) {
		t.Fatalf("toolchain version bump did not change digest:\n%s", j1)
	}
	if string(j1) == string(j3) {
		t.Fatal("adding/removing version pin did not change digest")
	}
	// Job-level toolchain names are identity too.
	withTool, _ := CanonicalJSON(s1)
	s4, err := Parse([]byte(`version: 1
toolchains:
  rust:
    version: "1.83.0"
    command: ["rustc", "--version"]
jobs:
  b:
    steps: [{run: "true"}]
`))
	if err != nil {
		t.Fatal(err)
	}
	without, _ := CanonicalJSON(s4)
	if string(withTool) == string(without) {
		t.Fatal("job toolchains: reference missing from digest")
	}
}

// Adversarial: flipping a service to native:true is a different pipeline.
func TestCanonicalDigestIncludesServiceNative(t *testing.T) {
	containerish := `version: 1
jobs:
  x:
    runtime: container
    image: alpine:3.20
    services:
      - name: redis
        image: redis:7-alpine
        ready: "tcp:6379"
    steps: [{run: "true"}]
`
	nativeish := `version: 1
jobs:
  x:
    runtime: native
    services:
      - name: redis
        native: true
        command: ["redis-server"]
        ready: "tcp:6379"
    steps: [{run: "true"}]
`
	// Same-name native vs non-native on native runtime:
	mixedA := `version: 1
jobs:
  x:
    runtime: native
    services:
      - name: redis
        native: true
        command: ["true"]
    steps: [{run: "true"}]
`
	mixedB := `version: 1
jobs:
  x:
    runtime: native
    services:
      - name: redis
        native: true
        command: ["true"]
        env:
          A: "1"
    steps: [{run: "true"}]
`
	a, err := Parse([]byte(mixedA))
	if err != nil {
		t.Fatal(err)
	}
	b, err := Parse([]byte(mixedB))
	if err != nil {
		t.Fatal(err)
	}
	ja, _ := CanonicalJSON(a)
	jb, _ := CanonicalJSON(b)
	if string(ja) == string(jb) {
		t.Fatal("service env change missing from digest")
	}
	// native flag participates: flip image path vs native path
	c, err := Parse([]byte(nativeish))
	if err != nil {
		t.Fatal(err)
	}
	d, err := Parse([]byte(containerish))
	if err != nil {
		t.Fatal(err)
	}
	jc, _ := CanonicalJSON(c)
	jd, _ := CanonicalJSON(d)
	if string(jc) == string(jd) {
		t.Fatal("native vs container service pipeline shared a digest")
	}
	// Same name, one native one not — on a pipeline that validates:
	e, err := Parse([]byte(`version: 1
toolchains: {}
jobs:
  a:
    runtime: native
    services:
      - name: db
        native: true
        command: ["true"]
    steps: [{run: "true"}]
`))
	if err != nil {
		t.Fatal(err)
	}
	f, err := Parse([]byte(`version: 1
toolchains: {}
jobs:
  a:
    runtime: native
    services:
      - name: db
        native: true
        command: ["false"]
    steps: [{run: "true"}]
`))
	if err != nil {
		t.Fatal(err)
	}
	je, _ := CanonicalJSON(e)
	jf, _ := CanonicalJSON(f)
	if string(je) == string(jf) {
		t.Fatal("native service command identity missing from digest")
	}
}

// Adversarial: toolchains install format/url/sha must be required together.
func TestToolchainInstallValidation(t *testing.T) {
	_, err := Parse([]byte(`version: 1
toolchains:
  zola:
    install:
      url: "https://example.com/zola"
jobs:
  a:
    steps: [{run: "true"}]
`))
	if err == nil || !strings.Contains(err.Error(), "sha256") {
		t.Fatalf("install without sha256 = %v", err)
	}
	_, err = Parse([]byte(`version: 1
toolchains:
  zola:
    install:
      url: "https://example.com/zola"
      sha256: "00"
      bin: "zola"
      format: "dmg"
jobs:
  a:
    steps: [{run: "true"}]
`))
	if err == nil || !strings.Contains(err.Error(), "format") {
		t.Fatalf("bad install format = %v", err)
	}
}

// Adversarial: unknown toolchains.* field is still rejected.
func TestToolchainsUnknownFieldRejected(t *testing.T) {
	_, err := Parse([]byte(`version: 1
toolchains:
  rust:
    version: "1"
    version_cmd: ["rustc"]
jobs:
  a:
    steps: [{run: "true"}]
`))
	if err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("unknown toolchain field = %v", err)
	}
}

// Adversarial: download.if is accepted and lands on the compiled job.
func TestDownloadIfCompiled(t *testing.T) {
	s, err := Parse([]byte(`version: 1
jobs:
  producer:
    steps: [{run: "true"}]
    artifacts:
      - name: log
        paths: ["out.txt"]
  consumer:
    needs: [producer]
    downloads:
      - from: producer
        name: log
        path: diag
        if: failure()
    steps: [{run: "true"}]
`))
	if err != nil {
		t.Fatal(err)
	}
	g, err := Compile(s)
	if err != nil {
		t.Fatal(err)
	}
	c := g.Jobs["consumer"]
	if len(c.Job.Downloads) != 1 || c.Job.Downloads[0].If != "failure()" {
		t.Fatalf("downloads = %+v", c.Job.Downloads)
	}
	j, err := json.Marshal(c.Job.Downloads[0])
	if err != nil || !strings.Contains(string(j), "failure()") {
		t.Fatalf("json = %s err=%v", j, err)
	}
}

// Adversarial: matrix variants each bind toolchains.
func TestMatrixToolchainsBoundOnAllVariants(t *testing.T) {
	s, err := Parse([]byte(`version: 1
toolchains:
  go:
    version: "go1."
    command: ["go", "version"]
jobs:
  m:
    matrix:
      os: [linux, darwin]
    toolchains: [go]
    steps: [{run: "true"}]
`))
	if err != nil {
		t.Fatal(err)
	}
	g, err := Compile(s)
	if err != nil {
		t.Fatal(err)
	}
	if len(g.Jobs) != 2 {
		t.Fatalf("jobs = %d", len(g.Jobs))
	}
	for id, cj := range g.Jobs {
		if len(cj.Job.BoundToolchains) != 1 {
			t.Fatalf("%s BoundToolchains = %+v", id, cj.Job.BoundToolchains)
		}
		if cj.Job.BoundToolchains[0].Version != "go1." {
			t.Fatalf("%s version = %q", id, cj.Job.BoundToolchains[0].Version)
		}
	}
}
