package pipeline

import (
	"bytes"
	"testing"
)

func TestCanonicalJSONDeterministic(t *testing.T) {
	docA := `version: 1
env:
  B: "2"
  A: "1"
jobs:
  x:
    env:
      D: "4"
      C: "3"
    steps:
      - run: echo hi
`
	docB := `version: 1
jobs:
  x:
    steps:
      - run: echo hi
    env:
      C: "3"
      D: "4"
env:
  A: "1"
  B: "2"
`
	sa, err := Parse([]byte(docA))
	if err != nil {
		t.Fatal(err)
	}
	sb, err := Parse([]byte(docB))
	if err != nil {
		t.Fatal(err)
	}
	ca, err := CanonicalJSON(sa)
	if err != nil {
		t.Fatal(err)
	}
	cb, err := CanonicalJSON(sb)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ca, cb) {
		t.Fatalf("canonical JSON differs:\n%s\n---\n%s", ca, cb)
	}
	da, err := PipelineDigest(sa)
	if err != nil {
		t.Fatal(err)
	}
	db, err := PipelineDigest(sb)
	if err != nil {
		t.Fatal(err)
	}
	if da != db {
		t.Fatalf("digests differ: %s vs %s", da, db)
	}
}

func TestPipelineDigestChangesWithStepCommand(t *testing.T) {
	docOne := `version: 1
jobs:
  x:
    steps:
      - run: echo one
`
	docTwo := `version: 1
jobs:
  x:
    steps:
      - run: echo two
`
	s1, err := Parse([]byte(docOne))
	if err != nil {
		t.Fatal(err)
	}
	s2, err := Parse([]byte(docTwo))
	if err != nil {
		t.Fatal(err)
	}
	d1, err := PipelineDigest(s1)
	if err != nil {
		t.Fatal(err)
	}
	d2, err := PipelineDigest(s2)
	if err != nil {
		t.Fatal(err)
	}
	if d1 == d2 {
		t.Fatal("digest must change when a step command changes")
	}
}

// TestPipelineDigestChangesWithCheckoutAndMounts: Clone, Workspace and
// Volumes are execution identity. A digest that ignores them would let two
// different checkouts/mounts collide as one pipeline definition.
func TestPipelineDigestChangesWithCheckoutAndMounts(t *testing.T) {
	base := `version: 1
jobs:
  x:
    steps:
      - run: echo hi
`
	cases := map[string]string{
		"clone.skip": `version: 1
jobs:
  x:
    clone:
      skip: true
    steps:
      - run: echo hi
`,
		"clone.depth": `version: 1
jobs:
  x:
    clone:
      depth: 1
    steps:
      - run: echo hi
`,
		"clone.lfs": `version: 1
jobs:
  x:
    clone:
      lfs: true
    steps:
      - run: echo hi
`,
		"workspace.base": `version: 1
jobs:
  x:
    workspace:
      base: repo
    steps:
      - run: echo hi
`,
		"workspace.path": `version: 1
jobs:
  x:
    workspace:
      path: src
    steps:
      - run: echo hi
`,
		"volumes": `version: 1
jobs:
  x:
    volumes:
      - name: data
        path: /data
    steps:
      - run: echo hi
`,
		"volume.host_path": `version: 1
jobs:
  x:
    volumes:
      - name: data
        path: /data
        host_path: /var/data
    steps:
      - run: echo hi
`,
		"sandbox.privileged": `version: 1
jobs:
  x:
    runtime: container
    image: alpine:3.20
    sandbox:
      privileged: true
    steps:
      - run: echo hi
`,
	}
	s0, err := Parse([]byte(base))
	if err != nil {
		t.Fatal(err)
	}
	d0, err := PipelineDigest(s0)
	if err != nil {
		t.Fatal(err)
	}
	for name, doc := range cases {
		s, err := Parse([]byte(doc))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		d, err := PipelineDigest(s)
		if err != nil {
			t.Fatal(err)
		}
		if d == d0 {
			t.Fatalf("%s must change the pipeline digest", name)
		}
	}
}

func TestPipelineDigestIgnoresSecretOrderAndDuplicates(t *testing.T) {
	docA := `version: 1
secrets: [a, b, a]
jobs:
  x:
    steps:
      - run: echo hi
`
	docB := `version: 1
secrets: [b, a]
jobs:
  x:
    steps:
      - run: echo hi
`
	sa, err := Parse([]byte(docA))
	if err != nil {
		t.Fatal(err)
	}
	sb, err := Parse([]byte(docB))
	if err != nil {
		t.Fatal(err)
	}
	da, err := PipelineDigest(sa)
	if err != nil {
		t.Fatal(err)
	}
	db, err := PipelineDigest(sb)
	if err != nil {
		t.Fatal(err)
	}
	if da != db {
		t.Fatalf("secret declaration order/repetition must not change the digest: %s vs %s", da, db)
	}
}

func TestCanonicalJSONNilSpec(t *testing.T) {
	if _, err := CanonicalJSON(nil); err == nil {
		t.Fatal("nil spec must error")
	}
	if _, err := PipelineDigest(nil); err == nil {
		t.Fatal("nil spec must error")
	}
}
