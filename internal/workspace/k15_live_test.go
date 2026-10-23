package workspace

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestK15LiveApexMailDeterministic(t *testing.T) {
	if os.Getenv("KIWI_LIVE_APEXMAIL") == "" {
		t.Skip("set KIWI_LIVE_APEXMAIL=1 to stage the ApexMail tree (slow, ~1m)")
	}
	src := "/Users/sabelakhoua/IdeaProjects/ApexMail"
	if _, err := os.Stat(src); err != nil {
		t.Skip("no ApexMail")
	}
	m, err := NewManager(src)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	var prev int
	for i := 0; i < 3; i++ {
		dir, cleanup, err := m.Prepare(context.Background(), "live")
		if err != nil {
			// job id collision after first — use unique
			dir, cleanup, err = m.Prepare(context.Background(), "live-"+string(rune('0'+i)))
		}
		if err != nil {
			t.Fatalf("iter %d: %v", i, err)
		}
		n := 0
		hasEnv, hasServices, hasGit := false, false, false
		_ = filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return nil
			}
			n++
			rel, _ := filepath.Rel(dir, p)
			if rel == ".env" {
				hasEnv = true
			}
			if rel == filepath.Join("services", "mail-server", "migrations") || filepath.HasPrefix(rel, filepath.Join("services", "mail-server", "migrations")+string(filepath.Separator)) {
				hasServices = true
			}
			if rel == ".git" || filepath.HasPrefix(rel, ".git"+string(filepath.Separator)) {
				hasGit = true
			}
			return nil
		})
		// also check dirs
		if _, err := os.Stat(filepath.Join(dir, "services")); err == nil {
			hasServices = true
		}
		t.Logf("iter %d: files=%d env=%v services=%v git=%v", i, n, hasEnv, hasServices, hasGit)
		if !hasEnv {
			t.Fatalf("iter %d: .env missing (ignored files must be staged)", i)
		}
		if !hasServices {
			t.Fatalf("iter %d: services/ missing (top-level dir lost)", i)
		}
		if prev != 0 && n != prev {
			t.Fatalf("iter %d: files=%d != prev %d — non-deterministic", i, n, prev)
		}
		prev = n
		cleanup()
	}
}
