package verifyapi

import "testing"

// TestEpistemicLadderOrder pins the rung order and the FactSource mapping:
// requested < configured < observed < attested < derived, and every existing
// FactSource lands on a valid rung.
func TestEpistemicLadderOrder(t *testing.T) {
	ladder := []EpistemicLevel{
		EpistemicRequested, EpistemicConfigured, EpistemicObserved,
		EpistemicAttested, EpistemicDerived,
	}
	for i, l := range ladder {
		if !l.Valid() {
			t.Fatalf("rung %d (%s) is not valid", i, l)
		}
		if got, want := l.String(), []string{"requested", "configured", "observed", "attested", "derived"}[i]; got != want {
			t.Fatalf("rung %d String() = %q, want %q", i, got, want)
		}
		if i > 0 && !l.AtLeast(ladder[i-1]) {
			t.Fatalf("%s must be at least %s", l, ladder[i-1])
		}
		if i > 0 && ladder[i-1].AtLeast(l) {
			t.Fatalf("%s must not be at least %s", ladder[i-1], l)
		}
	}
	if EpistemicLevel(99).Valid() {
		t.Fatal("out-of-range level must not be valid")
	}
	if EpistemicLevel(99).String() != "unknown" {
		t.Fatalf("out-of-range String() = %q", EpistemicLevel(99).String())
	}
}

func TestEpistemicLevelOfFactSource(t *testing.T) {
	cases := map[FactSource]EpistemicLevel{
		FactSourceReported: EpistemicObserved,
		FactSourceAttested: EpistemicAttested,
		FactSourceDerived:  EpistemicDerived,
		FactSource("nope"): EpistemicRequested,
	}
	for src, want := range cases {
		if got := EpistemicLevelOf(src); got != want {
			t.Fatalf("EpistemicLevelOf(%q) = %s, want %s", src, got, want)
		}
	}
	// Every documented resource-fact name maps onto a defined level.
	for _, name := range []string{
		"measured.duration_ns", "measured.wall_time_ns",
		"cpu_time_ns", "wall_time_ns", "peak_memory_bytes",
	} {
		if src := FactSourceOf(name); src == "" {
			t.Fatalf("FactSourceOf(%q) is empty", name)
		}
		if !EpistemicLevelOf(FactSourceOf(name)).Valid() {
			t.Fatalf("fact %q maps to an invalid level", name)
		}
	}
}

func TestEpistemicTaggedValues(t *testing.T) {
	req := Requested(3)
	cfg := Configured("pinned")
	obs := Observed(int64(7))
	att := AttestedE(true)
	der := DerivedE(1.5)
	if req.Level != EpistemicRequested || req.Value != 3 {
		t.Fatalf("Requested = %+v", req)
	}
	if cfg.Level != EpistemicConfigured || cfg.Value != "pinned" {
		t.Fatalf("Configured = %+v", cfg)
	}
	if obs.Level != EpistemicObserved || obs.Value != 7 {
		t.Fatalf("Observed = %+v", obs)
	}
	if att.Level != EpistemicAttested || att.Value != true {
		t.Fatalf("AttestedE = %+v", att)
	}
	if der.Level != EpistemicDerived || der.Value != 1.5 {
		t.Fatalf("DerivedE = %+v", der)
	}
	if !att.Known(EpistemicObserved) || att.Known(EpistemicDerived) {
		t.Fatal("Known() must respect the ladder")
	}
}
