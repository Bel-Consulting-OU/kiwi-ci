package server

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// TestCheckRunIDsSetEviction covers the lazy map init and the order-empty
// eviction fallback.
func TestCheckRunIDsSetEviction(t *testing.T) {
	var c checkRunIDs
	c.set("k", "v")
	if c.m["k"] != "v" || len(c.order) != 1 {
		t.Fatalf("lazy set = %+v", c)
	}

	full := checkRunIDs{m: map[string]string{}}
	for i := 0; i < maxCheckRunIDs; i++ {
		full.m[string(rune('a'+i%26))+string(rune('a'+(i/26)%26))+string(rune('0'+i%10))] = "x"
	}
	// Over the cap with an empty order (disk-loaded state) still evicts.
	full.m["overflow-key"] = "y"
	full.set("new-key", "z")
	if len(full.m) > maxCheckRunIDs {
		t.Fatalf("order-empty eviction left %d entries, want <= %d", len(full.m), maxCheckRunIDs)
	}
}

// TestPutCheckRunIDFsArms covers the input guard and the fs persistence
// failure/rollback arms.
func TestPutCheckRunIDFsArms(t *testing.T) {
	ctx := context.Background()
	if err := (&Server{}).putCheckRunID(ctx, "", "id"); err == nil {
		t.Fatal("empty key was accepted")
	}
	if err := (&Server{}).putCheckRunID(ctx, "key", ""); err == nil {
		t.Fatal("empty id was accepted")
	}
	// No data dir: memory-only success.
	mem := &Server{}
	if err := mem.putCheckRunID(ctx, "key", "id1"); err != nil {
		t.Fatalf("memory put = %v", err)
	}
	if got, err := mem.getCheckRunID(ctx, "key"); err != nil || got != "id1" {
		t.Fatalf("memory get = (%q,%v)", got, err)
	}

	// MkdirAll failure: the data dir path is a file.
	blocker := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	badMkdir := &Server{dataDir: blocker}
	if err := badMkdir.putCheckRunID(ctx, "key", "id"); err == nil {
		t.Fatal("mkdir failure was ignored")
	}
	if _, ok := badMkdir.checkRuns.m["key"]; ok {
		t.Fatal("staged mapping survived a pre-rename mkdir failure")
	}

	// Pre-rename write failure (the mirror path is a directory) rolls back.
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "check-runs.json"), 0o700); err != nil {
		t.Fatal(err)
	}
	badWrite := &Server{dataDir: dir}
	if err := badWrite.putCheckRunID(ctx, "key", "id"); err == nil {
		t.Fatal("write failure was ignored")
	}
	if _, ok := badWrite.checkRuns.m["key"]; ok {
		t.Fatal("staged mapping survived a pre-rename write failure")
	}

	// Healthy fs persist writes the mirror.
	good := &Server{dataDir: t.TempDir()}
	if err := good.putCheckRunID(ctx, "key", "id2"); err != nil {
		t.Fatalf("fs put = %v", err)
	}
	if _, err := os.Stat(filepath.Join(good.dataDir, "check-runs.json")); err != nil {
		t.Fatalf("mirror not written: %v", err)
	}
}

// TestLoadCheckRunIDsArms covers the empty, unreadable, corrupt and valid
// mirror arms.
func TestLoadCheckRunIDsArms(t *testing.T) {
	if m, err := loadCheckRunIDs(""); err != nil || len(m) != 0 {
		t.Fatalf("empty dataDir = (%v,%v)", m, err)
	}
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "check-runs.json"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := loadCheckRunIDs(dir); err == nil {
		t.Fatal("unreadable mirror was accepted")
	}
	if err := os.RemoveAll(filepath.Join(dir, "check-runs.json")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "check-runs.json"), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadCheckRunIDs(dir); err == nil {
		t.Fatal("corrupt mirror was accepted")
	}
	if err := os.WriteFile(filepath.Join(dir, "check-runs.json"), []byte(`{"k":"v"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	m, err := loadCheckRunIDs(dir)
	if err != nil || m["k"] != "v" {
		t.Fatalf("valid mirror = (%v,%v)", m, err)
	}
}
