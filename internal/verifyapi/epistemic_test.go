package verifyapi

import (
	"encoding/json"
	"errors"
	"testing"
)

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

// TestEpistemicUnknownIsValidP3f: EpistemicUnknown is the zero value and is
// invalid — it is never treated as EpistemicRequested, and AtLeast is fail
// closed on it from either side.
func TestEpistemicUnknownIsValidP3f(t *testing.T) {
	if EpistemicUnknown.Valid() {
		t.Fatal("EpistemicUnknown must be invalid")
	}
	if EpistemicUnknown.String() != "unknown" {
		t.Fatalf("EpistemicUnknown.String() = %q, want unknown", EpistemicUnknown.String())
	}
	var zero EpistemicLevel
	if zero != EpistemicUnknown {
		t.Fatalf("zero value = %s, want EpistemicUnknown", zero)
	}
	if EpistemicUnknown.AtLeast(EpistemicRequested) || EpistemicRequested.AtLeast(EpistemicUnknown) {
		t.Fatal("AtLeast must be fail-closed across the unknown boundary")
	}
	if (&Epistemic[int]{Value: 1, Level: EpistemicUnknown}).Known(EpistemicRequested) {
		t.Fatal("an unknown-level value is never Known at any rung")
	}
}

func TestEpistemicLevelOfFactSource(t *testing.T) {
	cases := map[FactSource]struct {
		level EpistemicLevel
		ok    bool
	}{
		FactSourceReported: {EpistemicObserved, true},
		FactSourceAttested: {EpistemicAttested, true},
		FactSourceDerived:  {EpistemicDerived, true},
		FactSource("nope"): {EpistemicUnknown, false},
		FactSource(""):     {EpistemicUnknown, false},
	}
	for src, want := range cases {
		got, ok := EpistemicLevelOf(src)
		if got != want.level || ok != want.ok {
			t.Fatalf("EpistemicLevelOf(%q) = (%s, %v), want (%s, %v)", src, got, ok, want.level, want.ok)
		}
	}
	// Every documented resource-fact name maps onto a defined, valid level.
	for _, name := range []string{
		"measured.duration_ns", "measured.wall_time_ns",
		"cpu_time_ns", "wall_time_ns", "peak_memory_bytes",
	} {
		if src := FactSourceOf(name); src == "" {
			t.Fatalf("FactSourceOf(%q) is empty", name)
		}
		lvl, ok := EpistemicLevelOf(FactSourceOf(name))
		if !ok || !lvl.Valid() {
			t.Fatalf("fact %q maps to an invalid level (%s, ok=%v)", name, lvl, ok)
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

// TestEpistemicLevelJSONRoundTrip: the level serializes as its wire
// spelling so a consumer reads "observed", not an opaque ordinal, and an
// unknown spelling is refused rather than coerced onto a real rung.
func TestEpistemicLevelJSONRoundTrip(t *testing.T) {
	for _, lvl := range []EpistemicLevel{
		EpistemicUnknown, EpistemicRequested, EpistemicConfigured,
		EpistemicObserved, EpistemicAttested, EpistemicDerived,
	} {
		b, err := json.Marshal(lvl)
		if err != nil {
			t.Fatalf("Marshal(%s) = %v", lvl, err)
		}
		var back EpistemicLevel
		if err := json.Unmarshal(b, &back); err != nil {
			t.Fatalf("Unmarshal(%s) = %v", b, err)
		}
		if back != lvl {
			t.Fatalf("round-trip %s -> %s", lvl, back)
		}
	}
	b, err := json.Marshal(Observed(int64(7)))
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != `{"value":7,"level":"observed"}` {
		t.Fatalf("Epistemic wire = %s", b)
	}
	var bad EpistemicLevel
	if err := json.Unmarshal([]byte(`"nope"`), &bad); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unknown level = %v, want ErrInvalid", err)
	}
}
