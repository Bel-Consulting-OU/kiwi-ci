package secrets

import (
	"encoding/base32"
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

// TestTaintCheckUppercaseHex pins F5-A: upper-case hex is a trivial
// re-encoding and must be detected and masked, not only lower-case hex.
func TestTaintCheckUppercaseHex(t *testing.T) {
	const secret = "s3cr3t-Value-0123456789abcdef"
	m := &Masker{}
	if err := m.AddStrict(secret); err != nil {
		t.Fatal(err)
	}
	upper := strings.ToUpper(hex.EncodeToString([]byte(secret)))
	if !m.ContainsSecret(upper) {
		t.Fatal("upper-case hex secret not detected")
	}
	if got := m.MaskMulti(upper); got != maskReplacement {
		t.Fatalf("MaskMulti(upper hex) = %q, want %q", got, maskReplacement)
	}
	if err := m.TaintCheck(map[string]string{"out": upper}, nil); err == nil {
		t.Fatal("upper-case hex secret passed TaintCheck and would be persisted")
	}
}

// TestTaintCheckBase32Forms pins base32 as a covered derived encoding in both
// the padded/unpadded standard and extended-hex alphabets.
func TestTaintCheckBase32Forms(t *testing.T) {
	const secret = "s3cr3t-Value-0123456789abcdef"
	m := &Masker{}
	if err := m.AddStrict(secret); err != nil {
		t.Fatal(err)
	}
	b := []byte(secret)
	forms := map[string]string{
		"base32":           base32.StdEncoding.EncodeToString(b),
		"base32 nopad":     base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b),
		"base32 hex":       base32.HexEncoding.EncodeToString(b),
		"base32 lower":     strings.ToLower(base32.StdEncoding.EncodeToString(b)),
		"base32 hex lower": strings.ToLower(base32.HexEncoding.EncodeToString(b)),
	}
	for label, f := range forms {
		if !m.ContainsSecret("out=" + f) {
			t.Errorf("%s form not detected: %q", label, f)
		}
		if got := m.MaskMulti("out=" + f); strings.Contains(got, f) {
			t.Errorf("%s form left unmasked: %q", label, got)
		}
		if err := m.TaintCheck(map[string]string{"out": f}, nil); err == nil {
			t.Errorf("%s form passed TaintCheck", label)
		}
	}
}

// TestTaintCheckAndMaskWrappedBase64 pins F5-A: base64(1)/MIME output wraps
// long values at 76 columns. Whitespace must not split the form past
// detection or masking.
func TestTaintCheckAndMaskWrappedBase64(t *testing.T) {
	secret := strings.Repeat("A1b2C3d4E5f6G7h8", 8) // 128 bytes
	m := &Masker{}
	if err := m.AddStrict(secret); err != nil {
		t.Fatal(err)
	}
	oneLine := base64.StdEncoding.EncodeToString([]byte(secret))
	wrapped := wrap76(oneLine)

	if !m.ContainsSecret(oneLine) {
		t.Fatal("single-line base64 not detected")
	}
	if !m.ContainsSecret(wrapped) {
		t.Fatal("76-column-wrapped base64 not detected")
	}
	masked := m.MaskMulti(wrapped)
	if strings.Contains(masked, oneLine[0:76]) {
		t.Fatalf("wrapped base64 left unmasked: %q", masked)
	}
	if !strings.Contains(masked, maskReplacement) {
		t.Fatalf("wrapped base64 produced no mask replacement: %q", masked)
	}
	if err := m.TaintCheck(map[string]string{"out": wrapped}, nil); err == nil {
		t.Fatal("76-column-wrapped base64 secret passed TaintCheck and would be persisted")
	}

	// An indented form (leading whitespace on the wrap) must also be caught.
	indented := "  " + strings.ReplaceAll(wrapped, "\n", "\n  ")
	if !m.ContainsSecret(indented) {
		t.Fatal("indented wrapped base64 not detected")
	}
	if got := m.MaskMulti(indented); strings.Contains(got, oneLine[0:32]) {
		t.Fatalf("indented wrapped base64 left unmasked: %q", got)
	}
}

// wrap76 emulates the base64(1) command: 76-character lines, each terminated
// by a newline.
func wrap76(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i += 76 {
		end := i + 76
		if end > len(s) {
			end = len(s)
		}
		b.WriteString(s[i:end])
		b.WriteByte('\n')
	}
	return b.String()
}
