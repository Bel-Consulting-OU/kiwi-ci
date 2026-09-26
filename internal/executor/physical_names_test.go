package executor

import (
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestServiceNetworkNameLongCommonPrefixDoesNotCollide is the Y2-A core: two
// 200-character IDs that differ only after byte 100 must never share a
// physical docker network. The old `network[:60]` truncation mapped both onto
// the same 60 normalized characters, so one job's cleanup could address (and
// remove) another job's network; the canonical helper hashes the FULL
// identity instead.
func TestServiceNetworkNameLongCommonPrefixDoesNotCollide(t *testing.T) {
	common := strings.Repeat("a", 100)
	runFirst := common + strings.Repeat("b", 100)
	runSecond := common + strings.Repeat("c", 100)
	// Sanity-check the defect scenario: the OLD lossy truncation mapped both
	// identities onto one 60-character physical network name.
	lossy := func(runID string) string {
		full := strings.ToLower(dockerNameClean.ReplaceAllString("kiwi-net-"+runID+"-job-1", "-"))
		return full[:60]
	}
	if lossy(runFirst) != lossy(runSecond) {
		t.Fatal("test identities were not colliding under the old truncation")
	}
	first := serviceNetworkName(runFirst, "job-1")
	second := serviceNetworkName(runSecond, "job-1")
	if first == second {
		t.Fatalf("distinct 200-char run IDs sharing their first 100 bytes collided on %q", first)
	}
	if len(first) != maxServiceNetworkNameLen || len(second) != maxServiceNetworkNameLen {
		t.Fatalf("bounded names = %d/%d chars, want exactly %d", len(first), len(second), maxServiceNetworkNameLen)
	}
	// The same property must hold on the job-ID axis.
	jobFirst := serviceNetworkName("run-1", common+strings.Repeat("b", 100))
	jobSecond := serviceNetworkName("run-1", common+strings.Repeat("c", 100))
	if jobFirst == jobSecond {
		t.Fatalf("distinct 200-char job IDs sharing their first 100 bytes collided on %q", jobFirst)
	}
}

func TestServiceNetworkNameDeterministic(t *testing.T) {
	runID := strings.Repeat("x", 300)
	jobID := strings.Repeat("y", 300)
	want := serviceNetworkName(runID, jobID)
	for i := 0; i < 8; i++ {
		if got := serviceNetworkName(runID, jobID); got != want {
			t.Fatalf("call %d = %q, want the deterministic %q", i, got, want)
		}
	}
}

func TestServiceNetworkNameWithinDockerLimit(t *testing.T) {
	cases := [][2]string{
		{"", ""},
		{"r", "j"},
		{strings.Repeat("a", 60), ""},
		{strings.Repeat("a", 61), ""},
		{strings.Repeat("a", 200), strings.Repeat("b", 200)},
		{"run with spaces/and:chars", "job.with.dots"},
	}
	for _, c := range cases {
		got := serviceNetworkName(c[0], c[1])
		if len(got) > maxServiceNetworkNameLen {
			t.Fatalf("serviceNetworkName(%q, %q) = %q is %d chars, exceeds %d", c[0], c[1], got, len(got), maxServiceNetworkNameLen)
		}
	}
}

func TestServiceNetworkNameNormalShortIdentityUnchanged(t *testing.T) {
	if got := serviceNetworkName("run-1", "job-1"); got != "kiwi-net-run-1-job-1" {
		t.Fatalf("short identity changed: %q", got)
	}
	if got := serviceNetworkName("Run 1", "Job/1"); got != "kiwi-net-run-1-job-1" {
		t.Fatalf("sanitization changed for short identities: %q", got)
	}
}

// TestBoundedNormalizedNameHashesFullIdentity pins the canonical helper's
// contract: unchanged when it fits, exactly limit characters when bounded,
// and the 16-hex suffix derived from the full identity, never the truncated
// prefix.
func TestBoundedNormalizedNameHashesFullIdentity(t *testing.T) {
	if got := boundedNormalizedName("Short.Name", 60); got != "short.name" {
		t.Fatalf("short name = %q", got)
	}
	long := strings.Repeat("p", 100) + strings.Repeat("q", 100)
	got := boundedNormalizedName(long, 60)
	if len(got) != 60 {
		t.Fatalf("bounded name = %d chars, want exactly 60", len(got))
	}
	if got[:43] != long[:43] {
		t.Fatalf("bounded name prefix = %q, want the first 43 identity chars", got[:43])
	}
	other := boundedNormalizedName(strings.Repeat("p", 100)+strings.Repeat("r", 100), 60)
	if got == other {
		t.Fatalf("full-identity hash collided: %q", got)
	}
	// A pathological limit can never panic and is still bounded.
	if tiny := boundedNormalizedName(long, 8); len(tiny) != 8 {
		t.Fatalf("tiny limit name = %q (%d chars)", tiny, len(tiny))
	}
}

// TestJobContainerNameBoundedAndDistinct covers the second physical docker
// name the audit repaired: the job container carries the run/job identity, a
// monotonic timestamp, and full-identity hashing when bounded.
func TestJobContainerNameBoundedAndDistinct(t *testing.T) {
	if got := jobContainerName("run-1", "job-1"); !strings.HasPrefix(got, "kiwi-job-run-1-job-1-") {
		t.Fatalf("short name %q does not carry the run/job identity", got)
	}
	long := strings.Repeat("a", 300)
	first := jobContainerName(long, long)
	if len(first) > maxJobContainerNameLen {
		t.Fatalf("long name = %d chars, exceeds %d", len(first), maxJobContainerNameLen)
	}
	if other := jobContainerName(long+"b", long); other == first {
		t.Fatalf("distinct long run IDs collided on %q", first)
	}
	if other := jobContainerName(long, long+"c"); other == first {
		t.Fatalf("distinct long job IDs collided on %q", first)
	}
	// The monotonic timestamp guarantees no collision even for identical
	// identities generated concurrently in one process.
	const n = 64
	names := make([]string, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			names[i] = jobContainerName("run-1", "job-1")
		}(i)
	}
	wg.Wait()
	seen := map[string]bool{}
	for _, name := range names {
		if seen[name] {
			t.Fatalf("duplicate job container name %q", name)
		}
		seen[name] = true
	}
}

// TestTartCloneNameUniqueParseableAndGCCompatible proves the tart VM/session
// name stays within the GC parser's kiwi-<unix-nano> grammar (so leak cleanup
// still works) while the monotonic timestamp makes same-process collisions
// impossible.
func TestTartCloneNameUniqueParseableAndGCCompatible(t *testing.T) {
	const n = 32
	names := make([]string, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			names[i] = tartCloneName()
		}(i)
	}
	wg.Wait()
	seen := map[string]bool{}
	for _, name := range names {
		if !strings.HasPrefix(name, "kiwi-") {
			t.Fatalf("clone name %q missing the kiwi- prefix", name)
		}
		if _, err := strconv.ParseInt(strings.TrimPrefix(name, "kiwi-"), 10, 64); err != nil {
			t.Fatalf("clone name %q is not parseable by the GC contract: %v", name, err)
		}
		if seen[name] {
			t.Fatalf("duplicate tart clone name %q", name)
		}
		seen[name] = true
	}
	future := time.Now().Add(time.Hour)
	if got := parseTartVMs([]byte(names[0]+"\tother\tcolumns\n"), future); len(got) != 1 || got[0] != names[0] {
		t.Fatalf("parseTartVMs rejected a generated clone name: %v", got)
	}
}
