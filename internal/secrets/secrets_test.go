package secrets

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"testing"
)

func TestMaskerLongestFirst(t *testing.T) {
	m := &Masker{}
	m.Add("abcdef")
	m.Add("abc")
	if got := m.Mask("token=abcdef and abc"); got != "token=*** and ***" {
		t.Fatalf("got %q", got)
	}
}

func TestMaskerMaskMultiEncodedForms(t *testing.T) {
	raw := "tok:en abc/123"
	m := &Masker{}
	m.Add(raw)

	forms := []string{
		raw,
		url.QueryEscape(raw),
		url.PathEscape(raw),
		base64.StdEncoding.EncodeToString([]byte(raw)),
		base64.RawURLEncoding.EncodeToString([]byte(raw)),
		hex.EncodeToString([]byte(raw)),
		strconv.Quote(raw),
		"'" + raw + "'",
	}
	input := strings.Join(forms, " | ")
	got := m.MaskMulti(input)
	if strings.Contains(got, "tok:en") {
		t.Fatalf("derived form left unmasked: %q", got)
	}
	want := strings.Repeat("*** | ", len(forms)-1) + "***"
	if got != want {
		t.Fatalf("MaskMulti got %q want %q", got, want)
	}
}

func TestMaskerMaskKeepsDerivedForms(t *testing.T) {
	raw := "tok:en abc/123"
	m := &Masker{}
	m.Add(raw)

	escaped := url.QueryEscape(raw)
	got := m.Mask("raw=" + raw + " escaped=" + escaped)
	if got != "raw=*** escaped="+escaped {
		t.Fatalf("Mask should only replace raw values, got %q", got)
	}
}

func TestMaskerMaskMultiMultiline(t *testing.T) {
	secret := "line-one\nline-two\nline-three"
	m := &Masker{}
	m.Add(secret)

	in := "prefix line-one middle line-three suffix\ninner line: line-two"
	got := m.MaskMulti(in)
	for _, frag := range []string{"line-one", "line-two", "line-three"} {
		if strings.Contains(got, frag) {
			t.Fatalf("multiline fragment %q left unmasked in %q", frag, got)
		}
	}

	whole := m.MaskMulti("block:" + secret + ":end")
	if strings.Contains(whole, "line-one") || strings.Contains(whole, "line-two") {
		t.Fatalf("whole multiline value left unmasked in %q", whole)
	}
}

func TestMaskerMaskMultiCRLFLines(t *testing.T) {
	secret := "first\r\nsecond\r\nthird"
	m := &Masker{}
	m.Add(secret)

	got := m.MaskMulti("see first and second and third")
	for _, frag := range []string{"first", "second", "third"} {
		if strings.Contains(got, frag) {
			t.Fatalf("CRLF line %q left unmasked in %q", frag, got)
		}
	}
}

func TestMaskerOverLimitSecretsIgnored(t *testing.T) {
	m := &Masker{}
	for i := 0; i < 64; i++ {
		m.Add(fmt.Sprintf("secret-%03d-value", i))
	}
	m.Add("extra-secret-999")
	if got := m.MaskMulti("extra-secret-999"); got != "extra-secret-999" {
		t.Fatalf("secret beyond the 64 limit should be ignored, got %q", got)
	}
}

func TestMaskerOversizedSecretIgnored(t *testing.T) {
	m := &Masker{}
	big := strings.Repeat("x", 8193)
	m.Add(big)
	if got := m.MaskMulti(big); strings.Contains(got, maskReplacement) {
		t.Fatalf("oversized secret should be ignored")
	}
}

func TestMaskerShortSecretIgnored(t *testing.T) {
	m := &Masker{}
	m.Add("ab")
	if got := m.MaskMulti("ab"); got != "ab" {
		t.Fatalf("short secret should be ignored, got %q", got)
	}
}

func TestMaskerBoundaryLengthsAccepted(t *testing.T) {
	m := &Masker{}
	m.Add("abc")
	if got := m.MaskMulti("xabcx"); got != "x***x" {
		t.Fatalf("min-length secret should mask, got %q", got)
	}
	m2 := &Masker{}
	max := strings.Repeat("y", 8192)
	m2.Add(max)
	if got := m2.MaskMulti("z" + max + "z"); got != "z***z" {
		t.Fatalf("max-length secret should mask")
	}
}

func TestMaskerEmptyNoCrash(t *testing.T) {
	m := &Masker{}
	if got := m.Mask("plain"); got != "plain" {
		t.Fatalf("got %q", got)
	}
	if got := m.MaskMulti("plain"); got != "plain" {
		t.Fatalf("got %q", got)
	}
}
