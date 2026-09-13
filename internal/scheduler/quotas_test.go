package scheduler

import (
	"math"
	"testing"
)

func TestWithinQuota(t *testing.T) {
	cases := []struct {
		name        string
		limit, used float64
		delta       float64
		want        bool
		wantErr     bool
	}{
		{"within", 100, 50, 10, true, false},
		{"at limit", 100, 90, 10, true, false},
		{"over", 100, 90, 11, false, false},
		{"zero limit zero delta", 0, 0, 0, true, false},
		{"negative limit", -1, 0, 0, false, true},
		{"negative used", 10, -1, 0, false, true},
		{"negative delta", 10, 0, -1, false, true},
		{"NaN limit", math.NaN(), 0, 0, false, true},
		{"NaN used", 10, math.NaN(), 0, false, true},
		{"Inf limit", math.Inf(1), 0, 0, false, true},
		{"Inf used", 10, math.Inf(1), 0, false, true},
		{"overflow saturates to MaxInt64", math.MaxInt64, math.MaxInt64, 1, true, false},
		{"saturated total beyond limit", math.MaxInt64, math.MaxInt64 - 1, 10, true, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := WithinQuota(c.limit, c.used, c.delta)
			if c.wantErr && err == nil {
				t.Fatalf("WithinQuota(%v, %v, %v) = %v, want error", c.limit, c.used, c.delta, got)
			}
			if !c.wantErr && err != nil {
				t.Fatalf("WithinQuota: unexpected error %v", err)
			}
			if got != c.want {
				t.Errorf("WithinQuota(%v, %v, %v) = %v, want %v", c.limit, c.used, c.delta, got, c.want)
			}
		})
	}
}

func TestSaturatingAdd(t *testing.T) {
	if got := SaturatingAdd(math.MaxInt64, 1); got != math.MaxInt64 {
		t.Errorf("SaturatingAdd(MaxInt64, 1) = %d, want MaxInt64 (no wrap)", got)
	}
	if got := SaturatingAdd(math.MaxInt64, math.MaxInt64); got != math.MaxInt64 {
		t.Errorf("SaturatingAdd(MaxInt64, MaxInt64) = %d, want MaxInt64", got)
	}
	if got := SaturatingAdd(1, 2); got != 3 {
		t.Errorf("SaturatingAdd(1, 2) = %d, want 3", got)
	}
	if got := SaturatingAdd(-5, 3); got != 3 {
		t.Errorf("SaturatingAdd(-5, 3) = %d, want 3 (negatives clamp to zero)", got)
	}
}

func TestQuotaStructs(t *testing.T) {
	rq := RepoQuota{Repo: "repo", Limit: 100, Used: 40}
	tq := TeamQuota{Team: "team", Limit: 100, Used: 40}
	for _, q := range []struct{ limit, used float64 }{{rq.Limit, rq.Used}, {tq.Limit, tq.Used}} {
		ok, err := WithinQuota(q.limit, q.used, 60)
		if err != nil || !ok {
			t.Errorf("quota {limit=%v, used=%v} + 60 = (%v, %v), want (true, nil)", q.limit, q.used, ok, err)
		}
	}
}
