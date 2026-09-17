package secrets

import (
	"encoding/base64"
	"encoding/hex"
	"net/url"
	"strings"
	"testing"
	"time"
)

// TestMaskerValueBoundaries pins the masking window: 3-byte and 8192-byte
// values are masked, 2-byte and 8193-byte values are rejected by AddStrict.
func TestMaskerValueBoundaries(t *testing.T) {
	min := "abc"
	max := strings.Repeat("Z", 8192)
	m := &Masker{}
	if err := m.AddStrict(min); err != nil {
		t.Fatalf("3-byte secret rejected: %v", err)
	}
	if err := m.AddStrict(max); err != nil {
		t.Fatalf("8192-byte secret rejected: %v", err)
	}
	if got := m.MaskMulti("x" + min + "y"); strings.Contains(got, min) {
		t.Fatalf("3-byte secret not masked: %q", got)
	}
	if got := m.MaskMulti(max); strings.Contains(got, max) {
		t.Fatal("8192-byte secret not masked")
	}
	if err := m.AddStrict("ab"); err != ErrMaskValueInvalid {
		t.Fatalf("2-byte secret: want ErrMaskValueInvalid, got %v", err)
	}
	if err := m.AddStrict(strings.Repeat("Z", 8193)); err != ErrMaskValueInvalid {
		t.Fatalf("8193-byte secret: want ErrMaskValueInvalid, got %v", err)
	}
	if m.Len() != 2 {
		t.Fatalf("Len = %d, want 2", m.Len())
	}
}

// TestMaskerCapacityAllValuesMasked verifies that a full masker (exactly the
// shared capacity) masks every registered value, including the last one
// added, and rejects the next one.
func TestMaskerCapacityAllValuesMasked(t *testing.T) {
	m := &Masker{}
	var all []string
	for i := 0; i < MaxSecretNames; i++ {
		v := "value-" + strings.Repeat("x", i%7) + "-" + string(rune('a'+i%26)) + "-" + strings.Repeat("0", i/26)
		if err := m.AddStrict(v); err != nil {
			t.Fatalf("AddStrict %d: %v", i, err)
		}
		all = append(all, v)
	}
	if err := m.AddStrict("overflow-secret-129"); err != ErrMaskerCapacity {
		t.Fatalf("129th secret: want ErrMaskerCapacity, got %v", err)
	}
	for i, v := range all {
		if m.ContainsSecret("prefix "+v+" suffix") != true {
			t.Fatalf("secret %d not detected", i)
		}
		if got := m.MaskMulti("prefix " + v + " suffix"); strings.Contains(got, v) {
			t.Fatalf("secret %d not masked: %q", i, got)
		}
	}
}

// TestMaskMultiLargeLineTimeBound verifies a 10 MiB line is masked well under
// a generous bound with a full secret set.
func TestMaskMultiLargeLineTimeBound(t *testing.T) {
	m := &Masker{}
	for i := 0; i < MaxSecretNames; i++ {
		if err := m.AddStrict("secret-" + strings.Repeat("q", 4) + "-" + string(rune('a'+i%26)) + strings.Repeat("0", i/26)); err != nil {
			t.Fatal(err)
		}
	}
	line := strings.Repeat("lorem ipsum dolor sit amet ", 400000) // ~10.8 MiB
	start := time.Now()
	out := m.MaskMulti(line)
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("MaskMulti of 10 MiB took %v", elapsed)
	}
	if out != line {
		t.Fatal("line without secrets must pass through unchanged")
	}
}

// TestTaintCheckDetectsEncodedForms verifies the taint predicate covers the
// derived encodings, not only the raw value.
func TestTaintCheckDetectsEncodedForms(t *testing.T) {
	secret := "s3cr3t/p@th:v1"
	m := &Masker{}
	if err := m.AddStrict(secret); err != nil {
		t.Fatal(err)
	}
	forms := map[string]string{
		"raw":         "out=" + secret,
		"query":       "out=" + url.QueryEscape(secret),
		"path":        "out=" + url.PathEscape(secret),
		"base64":      "out=" + base64.StdEncoding.EncodeToString([]byte(secret)),
		"base64raw":   "out=" + base64.RawURLEncoding.EncodeToString([]byte(secret)),
		"hex":         "out=" + hex.EncodeToString([]byte(secret)),
		"json quoted": "out=" + `"` + secret + `"`,
	}
	for label, value := range forms {
		if !m.ContainsSecret(value) {
			t.Errorf("%s form not detected: %q", label, value)
		}
		if err := m.TaintCheck(map[string]string{"out": value}, nil); err == nil {
			t.Errorf("%s form passed TaintCheck", label)
		}
	}
	// Per-step outputs are checked too.
	if err := m.TaintCheck(nil, map[string]map[string]string{"step": {"out": secret}}); err == nil {
		t.Fatal("step output containing a secret passed TaintCheck")
	}
	if err := m.TaintCheck(map[string]string{"clean": "nothing here"}, nil); err != nil {
		t.Fatalf("clean output flagged: %v", err)
	}
}
