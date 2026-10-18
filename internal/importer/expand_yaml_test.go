package importer

import (
	"testing"

	"gopkg.in/yaml.v3"
)

func TestExpandYAMLResolvesAnchorsAndMerges(t *testing.T) {
	src := `
base: &base
  image: php:8.3
  commands: [composer install]
matrix: &mat
  PHP: ["8.2", "8.3"]
steps:
  a:
    <<: *base
    matrix: *mat
  b:
    <<: *base
    commands: [phpunit]
`
	var root yaml.Node
	if err := yaml.Unmarshal([]byte(src), &root); err != nil {
		t.Fatal(err)
	}
	ExpandYAML(&root)
	doc := Document(&root)
	steps := Key(doc, "steps")
	a := Key(steps, "a")
	if img := StrScalar(Key(a, "image")); img != "php:8.3" {
		t.Fatalf("a.image = %q, want php:8.3 (alias/merge)", img)
	}
	if got := SeqScalars(Key(a, "commands")); len(got) != 1 || got[0] != "composer install" {
		t.Fatalf("a.commands = %v", got)
	}
	if got := SeqScalars(Key(a, "matrix") /* wrong shape */); got != nil {
		_ = got
	}
	mat := Key(a, "matrix")
	if mat == nil || mat.Kind != yaml.MappingNode {
		t.Fatalf("a.matrix not a mapping: %#v", mat)
	}
	php := SeqScalars(Key(mat, "PHP"))
	if len(php) != 2 {
		t.Fatalf("a.matrix.PHP = %v, want 2 values", php)
	}
	b := Key(steps, "b")
	if got := SeqScalars(Key(b, "commands")); len(got) != 1 || got[0] != "phpunit" {
		t.Fatalf("b.commands = %v (explicit must override merge)", got)
	}
	if img := StrScalar(Key(b, "image")); img != "php:8.3" {
		t.Fatalf("b.image = %q", img)
	}
}
