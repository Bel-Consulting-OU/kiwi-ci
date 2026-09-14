package app

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestConfigCheckValid(t *testing.T) {
	p := filepath.Join(t.TempDir(), "kiwi.toml")
	content := "[server]\nmode = \"dev\"\nlisten = \":8123\"\n"
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ConfigCheck(context.Background(), []string{"-config", p}); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
}

func TestConfigCheckInvalid(t *testing.T) {
	p := filepath.Join(t.TempDir(), "kiwi.toml")
	if err := os.WriteFile(p, []byte("[server]\nmode = \"staging\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ConfigCheck(context.Background(), []string{"-config", p}); err == nil {
		t.Fatal("invalid config accepted")
	}
}

func TestConfigCheckMalformed(t *testing.T) {
	p := filepath.Join(t.TempDir(), "kiwi.toml")
	if err := os.WriteFile(p, []byte("[server]\nunknown_key = 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ConfigCheck(context.Background(), []string{"-config", p}); err == nil {
		t.Fatal("config with unknown key accepted")
	}
}

func TestConfigCheckMissingFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "missing.toml")
	if err := ConfigCheck(context.Background(), []string{"-config", p}); err == nil {
		t.Fatal("missing file accepted")
	}
}
