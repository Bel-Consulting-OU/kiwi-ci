package pipeline

import (
	"strings"
	"testing"
)

func TestToolchainsBindAndUnknown(t *testing.T) {
	s, err := Parse([]byte(`version: 1
toolchains:
  rust:
    version: "1.83"
    command: ["rustc", "--version"]
jobs:
  build:
    toolchains: [rust]
    steps:
      - run: cargo test
`))
	if err != nil {
		t.Fatal(err)
	}
	if err := Validate(s); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	g2, err := Compile(s)
	if err != nil {
		t.Fatal(err)
	}
	cj, ok := g2.Jobs["build"]
	if !ok {
		t.Fatal("build job missing")
	}
	if len(cj.Job.BoundToolchains) != 1 || cj.Job.BoundToolchains[0].Version != "1.83" {
		t.Fatalf("BoundToolchains = %+v", cj.Job.BoundToolchains)
	}

	_, err = Parse([]byte(`version: 1
toolchains:
  rust:
    version: "1"
jobs:
  build:
    toolchains: [nope]
    steps:
      - run: "true"
`))
	if err == nil || !strings.Contains(err.Error(), "unknown toolchain") {
		t.Fatalf("Parse(bad toolchain) = %v, want unknown toolchain", err)
	}
}

func TestNativeServiceValidation(t *testing.T) {
	ok, err := Parse([]byte(`version: 1
jobs:
  live:
    runtime: native
    services:
      - name: redis
        native: true
        command: ["redis-server", "--port", "6379"]
        ready: "tcp:6379"
    steps:
      - run: "true"
`))
	if err != nil {
		t.Fatal(err)
	}
	if err := Validate(ok); err != nil {
		t.Fatalf("Validate native service: %v", err)
	}

	// native service on container runtime is refused
	_, err = Parse([]byte(`version: 1
jobs:
  live:
    runtime: container
    image: alpine:3.20
    services:
      - name: redis
        native: true
        command: ["redis-server"]
    steps:
      - run: "true"
`))
	if err == nil || !strings.Contains(err.Error(), "native") {
		t.Fatalf("Parse(container+native svc) = %v, want native error", err)
	}
}
