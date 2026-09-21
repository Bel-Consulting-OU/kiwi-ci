package snapshot

import (
	"bytes"
	"crypto/rand"
	"errors"
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/safefs"
)

// TestSharedArchiveLimitIsTheParserDefault pins the ONE compressed snapshot
// archive budget: the constant documented in manifest.go is what Parse's
// limit default resolves to, and it is the same 4 GiB value the runner's
// capture cap (internal/runner/snapshots.go) and the control plane's upload
// body cap (internal/server/snapshots.go) reference. The cross-package
// references are asserted by construction in the runner/server tests.
func TestSharedArchiveLimitIsTheParserDefault(t *testing.T) {
	if MaxArchiveBytes != 4<<30 {
		t.Fatalf("shared archive budget = %d, want 4 GiB", MaxArchiveBytes)
	}
	if got := parseLimits(safefs.ExtractLimits{}).MaxArchiveBytes; got != MaxArchiveBytes {
		t.Fatalf("Parse default archive limit = %d, want the shared %d", got, MaxArchiveBytes)
	}
}

// TestParseRejectsArchiveOverTheSharedLimitWithClearError exercises the
// boundary with a SMALL explicit budget (never GiBs): the archive is between
// the budget and twice the budget — exactly the region the old runner could
// assemble but the receiver rejected — and ParseWithLimits refuses it with
// an ErrLimits reason that names the compressed limit. The same archive is
// accepted within the default budget.
func TestParseRejectsArchiveOverTheSharedLimitWithClearError(t *testing.T) {
	body := make([]byte, 8<<10)
	if _, err := rand.Read(body); err != nil {
		t.Fatal(err)
	}
	// Two incompressible entries, so the counter is examined again at the
	// second header after the first entry's compressed bytes were counted.
	data := tarGzEntries(t, []struct {
		name string
		data []byte
	}{
		{"a.bin", body},
		{"b.bin", body},
	})
	limit := int64(len(data)/2 + 1)
	if limit <= 0 || int64(len(data)) <= limit || int64(len(data)) > 2*limit {
		t.Fatalf("test premise broken: archive %d bytes, limit %d", len(data), limit)
	}
	_, err := ParseWithLimits(bytes.NewReader(data), safefs.ExtractLimits{MaxArchiveBytes: limit})
	if !errors.Is(err, safefs.ErrLimits) {
		t.Fatalf("err = %v, want ErrLimits", err)
	}
	if !strings.Contains(err.Error(), "compressed limit") {
		t.Fatalf("err = %v, want the compressed-limit reason", err)
	}
	if _, err := Parse(bytes.NewReader(data)); err != nil {
		t.Fatalf("archive within the default budget rejected: %v", err)
	}
}
