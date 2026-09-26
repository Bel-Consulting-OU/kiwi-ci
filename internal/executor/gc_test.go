package executor

import (
	"context"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestContainerLabels(t *testing.T) {
	labels := containerLabels("run-1", "build")
	want := []string{"--label", "kiwi.run=run-1", "--label", "kiwi.job=build"}
	if len(labels) != len(want) {
		t.Fatalf("containerLabels = %v, want %v", labels, want)
	}
	for i := range want {
		if labels[i] != want[i] {
			t.Fatalf("containerLabels = %v, want %v", labels, want)
		}
	}
	if got := containerLabels("", "build"); got != nil {
		t.Fatalf("containerLabels with empty runID = %v, want nil", got)
	}
}

func TestParseDockerContainers(t *testing.T) {
	cutoff := time.Date(2026, 9, 14, 0, 0, 0, 0, time.UTC)
	out := []byte(strings.Join([]string{
		"abc123def456 2026-09-13 10:00:00 +0000 UTC",
		"fed654cba321 2026-09-14 10:00:00 +0000 UTC",
		"aaa111bbb222 2026-09-12 10:00:00 +0000 UTC",
		"bbb222ccc333 not-a-time",
		"",
	}, "\n"))
	stale := parseDockerContainers(out, cutoff)
	want := []string{"abc123def456", "aaa111bbb222"}
	if len(stale) != len(want) {
		t.Fatalf("parseDockerContainers = %v, want %v", stale, want)
	}
	for i := range want {
		if stale[i] != want[i] {
			t.Fatalf("parseDockerContainers = %v, want %v", stale, want)
		}
	}
}

func TestParseDockerContainersRFC3339(t *testing.T) {
	cutoff := time.Date(2026, 9, 14, 0, 0, 0, 0, time.UTC)
	out := []byte("abc123def456 2026-09-13T10:00:00Z\nfresh111 2026-09-15T10:00:00Z\n")
	stale := parseDockerContainers(out, cutoff)
	if len(stale) != 1 || stale[0] != "abc123def456" {
		t.Fatalf("parseDockerContainers = %v, want [abc123def456]", stale)
	}
}

func TestParseTartVMs(t *testing.T) {
	cutoff := time.Date(2026, 9, 14, 0, 0, 0, 0, time.UTC)
	oldNanos := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC).UnixNano()
	newNanos := time.Date(2026, 9, 15, 0, 0, 0, 0, time.UTC).UnixNano()
	out := []byte(strings.Join([]string{
		"NAME",
		"kiwi-" + strconv.FormatInt(oldNanos, 10) + "\tother\tcolumns",
		"kiwi-" + strconv.FormatInt(newNanos, 10) + "\tother\tcolumns",
		"kiwi-not-a-number",
		"my-precious-vm",
		"",
	}, "\n"))
	stale := parseTartVMs(out, cutoff)
	if len(stale) != 1 || stale[0] != "kiwi-"+strconv.FormatInt(oldNanos, 10) {
		t.Fatalf("parseTartVMs = %v, want only the old kiwi clone", stale)
	}
}

// TestParseTartVMsMixedLegacyAndHashedNames proves the GC parser accepts both
// the legacy kiwi-<nano> and the identity-hashed kiwi-<nano>-<hash16> forms in
// one listing, derives staleness from the FIRST numeric field (ignoring the
// hash), and still fails closed for foreign or malformed names.
func TestParseTartVMsMixedLegacyAndHashedNames(t *testing.T) {
	cutoff := time.Date(2026, 9, 14, 0, 0, 0, 0, time.UTC)
	oldNanos := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC).UnixNano()
	freshNanos := time.Date(2026, 9, 15, 0, 0, 0, 0, time.UTC).UnixNano()
	legacyOld := "kiwi-" + strconv.FormatInt(oldNanos, 10)
	hashedOld := legacyOld + "-0123456789abcdef"
	hashedFresh := "kiwi-" + strconv.FormatInt(freshNanos, 10) + "-fedcba9876543210"
	out := []byte(strings.Join([]string{
		"NAME",
		legacyOld + "\tother\tcolumns",
		hashedOld + "\tother\tcolumns",
		hashedFresh + "\tother\tcolumns",
		"kiwi-abc",
		"kiwi-abc-0123456789abcdef",
		"kiwi-",
		"kiwi-not-a-number",
		"my-precious-vm",
		"",
	}, "\n"))
	stale := parseTartVMs(out, cutoff)
	want := []string{legacyOld, hashedOld}
	if len(stale) != len(want) {
		t.Fatalf("parseTartVMs = %v, want %v", stale, want)
	}
	for i := range want {
		if stale[i] != want[i] {
			t.Fatalf("parseTartVMs = %v, want %v", stale, want)
		}
	}
}

// TestTartCloneTimestampFirstNumericField pins the field rule: staleness is
// the first dash-separated numeric field after the prefix, so a hash-like or
// arbitrary trailing field is ignored, while a non-numeric first field and an
// overflowing timestamp are rejected.
func TestTartCloneTimestampFirstNumericField(t *testing.T) {
	cases := []struct {
		name  string
		nanos int64
		ok    bool
	}{
		{"kiwi-42", 42, true},
		{"kiwi-42-deadbeefdeadbeef", 42, true},
		{"kiwi-42-anything-at-all", 42, true},
		{"kiwi-42-", 42, true},
		{"kiwi-abc-42", 0, false},
		{"kiwi-", 0, false},
		{"kiwi--42", 0, false},
		{"kiwi-99999999999999999999-hash", 0, false},
		{"other-42", 0, false},
		{"", 0, false},
	}
	for _, c := range cases {
		nanos, ok := tartCloneTimestamp(c.name)
		if ok != c.ok || (ok && nanos != c.nanos) {
			t.Fatalf("tartCloneTimestamp(%q) = (%d, %v), want (%d, %v)", c.name, nanos, ok, c.nanos, c.ok)
		}
	}
}

func TestGCToolsAbsentReturnsEmptyReport(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	rep := GC(context.Background(), t.TempDir(), time.Hour)
	if rep.Containers != 0 || rep.Networks != 0 || rep.VMs != 0 {
		t.Fatalf("GC with no tools = %+v, want zero report", rep)
	}
	if rep := GC(context.Background(), t.TempDir(), 0); rep != (GCReport{}) {
		t.Fatalf("GC with non-positive olderThan = %+v, want zero report", rep)
	}
}
