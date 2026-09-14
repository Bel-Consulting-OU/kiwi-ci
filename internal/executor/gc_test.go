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
