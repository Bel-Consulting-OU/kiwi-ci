package storage

// Source-level contract for last_seen authority: runner health/liveness code
// must read the relational last_seen column (which runnerScanner overlays onto
// the decoded payload) and never the stale payload JSON. TouchRunnerLastSeen
// deliberately updates only the column, so a future query that reads
// payload->>'last_seen' would silently see the registration-time value and
// could make liveness decisions on non-monotonic data.

import (
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestRunnerLastSeenAuthorityIsRelationalColumn(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	root := filepath.Join(filepath.Dir(thisFile), "..", "..")

	var offenders []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", "vendor", "dist":
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, needle := range []string{"payload->>'last_seen'", "payload->> 'last_seen'", "payload ->> 'last_seen'"} {
			if strings.Contains(string(src), needle) {
				offenders = append(offenders, path+" contains "+needle)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk source tree: %v", err)
	}
	if len(offenders) > 0 {
		t.Fatalf("runner liveness must read the relational last_seen column (TouchRunnerLastSeen owns it), not the stale payload JSON:\n%s", strings.Join(offenders, "\n"))
	}

	// The authority itself must stay the narrow clock write and the scanner
	// must keep overlaying the column on the payload.
	code, err := os.ReadFile(filepath.Join(root, "internal", "storage", "postgres.go"))
	if err != nil {
		t.Fatal(err)
	}
	src := string(code)
	if !strings.Contains(src, "UPDATE runners SET last_seen=clock_timestamp() WHERE id=$1") {
		t.Fatal("PostgresStore.TouchRunnerLastSeen is no longer the narrow database-clock write")
	}
	if !strings.Contains(src, "r.LastSeen = *rs.lastSeen") {
		t.Fatal("runnerScanner no longer overlays the relational last_seen column on the payload")
	}
}
