package app

import (
	"context"
	"strings"
	"testing"
)

// Promote and VerifySince are deferred: the local blessing ledger was only
// a recomputable SHA-256, not an authenticated signed chain. Public commands
// must fail closed with that explanation (audit: do not oversell checksums).
func TestPromoteDeferred(t *testing.T) {
	err := Promote(context.Background(), []string{"run-1", "--env", "prod"})
	if err == nil || !strings.Contains(err.Error(), "deferred") {
		t.Fatalf("Promote = %v, want deferred error", err)
	}
}

func TestVerifySinceDeferred(t *testing.T) {
	err := VerifySince([]string{"--ledger", t.TempDir()})
	if err == nil || !strings.Contains(err.Error(), "deferred") {
		t.Fatalf("VerifySince = %v, want deferred error", err)
	}
}
