package migrations

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"
)

var updateDigests = flag.Bool("update-migration-digests", false, "rewrite digests.golden from the current migration files")

// TestMigrationDigests is the release-integrity gate: every migration that
// has ever shipped is pinned by its SHA-256. Editing an already-applied
// migration (instead of adding a new one) produces schema-history divergence
// between fresh installs and upgraded databases, so it must fail CI here —
// and at runtime, where Migrate verifies the recorded digest.
func TestMigrationDigests(t *testing.T) {
	all, err := All()
	if err != nil {
		t.Fatal(err)
	}
	current := map[int]string{}
	names := map[int]string{}
	floors := map[int]int{}
	for _, m := range all {
		current[m.Version] = m.Digest
		names[m.Version] = m.Name
		floors[m.Version] = m.CompatibleFrom
	}

	const goldenPath = "digests.golden"
	if *updateDigests {
		versions := make([]int, 0, len(current))
		for v := range current {
			versions = append(versions, v)
		}
		sort.Ints(versions)
		var b strings.Builder
		for _, v := range versions {
			fmt.Fprintf(&b, "%d %s %s %d\n", v, names[v], current[v], floors[v])
		}
		if err := os.WriteFile(goldenPath, []byte(b.String()), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}

	f, err := os.Open(goldenPath)
	if err != nil {
		t.Fatalf("open %s: %v (run: go test ./internal/storage/migrations -run TestMigrationDigests -update-migration-digests)", goldenPath, err)
	}
	defer f.Close()
	type pinned struct {
		name, digest string
		floor        int
	}
	golden := map[int]pinned{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var v, floor int
		var name, digest string
		if _, err := fmt.Sscanf(line, "%d %s %s %d", &v, &name, &digest, &floor); err != nil {
			t.Fatalf("bad golden line %q: %v", line, err)
		}
		golden[v] = pinned{name: name, digest: digest, floor: floor}
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}

	for v, dig := range current {
		p, ok := golden[v]
		if !ok {
			t.Fatalf("migration %d (%s) is not recorded in %s; a new migration must be committed together with its digest (run: go test ./internal/storage/migrations -run TestMigrationDigests -update-migration-digests)", v, names[v], goldenPath)
		}
		if p.digest != dig || p.name != names[v] {
			t.Fatalf("migration %d was EDITED after ship (golden %s/%s, current %s/%s); never edit an applied migration — add a new one", v, p.name, p.digest, names[v], dig)
		}
		if p.floor != floors[v] {
			t.Fatalf("migration %d compatible-from changed (%d -> %d)", v, p.floor, floors[v])
		}
	}
}
