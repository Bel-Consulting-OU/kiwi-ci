package testutil

import (
	"strings"
	"testing"
)

// TestDSNWithDatabaseRewrites covers the URL and keyword=value DSN forms,
// including a value that needs quoting in both.
func TestDSNWithDatabaseRewrites(t *testing.T) {
	got, err := dsnWithDatabase("postgres://user:pass@host:5432/old?sslmode=disable", "newdb")
	if err != nil {
		t.Fatal(err)
	}
	if got != "postgres://user:pass@host:5432/newdb?sslmode=disable" {
		t.Fatalf("url rewrite = %q", got)
	}
	got, err = dsnWithDatabase("postgresql://host/old", "newdb")
	if err != nil || got != "postgresql://host/newdb" {
		t.Fatalf("postgresql rewrite = %q/%v", got, err)
	}
	if _, err := dsnWithDatabase("postgres://%zz", "newdb"); err == nil {
		t.Fatal("unparsable DSN URL accepted")
	}

	got, err = dsnWithDatabase("host=localhost port=5432 dbname=old user=u", "new db")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, "dbname='new db'") || strings.Contains(got, "dbname=old") {
		t.Fatalf("keyword replace = %q", got)
	}
	got, err = dsnWithDatabase("host=localhost", "newdb")
	if err != nil || !strings.HasSuffix(got, " dbname=newdb") {
		t.Fatalf("keyword append = %q/%v", got, err)
	}
	got, err = dsnWithDatabase("HOST=h DATABASE=old", "x")
	if err != nil || !strings.Contains(got, "dbname=x") || !strings.Contains(got, "HOST=h") {
		t.Fatalf("case-insensitive replace = %q/%v", got, err)
	}
}

// TestQuoteDSNValue pins the quoting rules: empty, space, quote and backslash
// values become single-quoted with escapes; plain values stay bare.
func TestQuoteDSNValue(t *testing.T) {
	cases := map[string]string{
		"":      "''",
		"plain": "plain",
		"a b":   "'a b'",
		"a'b":   `'a\'b'`,
		`a\b`:   `'a\\b'`,
		"a ' b": `'a \' b'`,
	}
	for in, want := range cases {
		if got := quoteDSNValue(in); got != want {
			t.Errorf("quoteDSNValue(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestRandomHexShape proves the clone-name suffix is exactly n lowercase hex
// characters and varies between calls.
func TestRandomHexShape(t *testing.T) {
	first := randomHex(t, 12)
	second := randomHex(t, 12)
	if len(first) != 12 || len(second) != 12 {
		t.Fatalf("lengths = %d/%d, want 12", len(first), len(second))
	}
	for _, s := range []string{first, second} {
		for _, r := range s {
			if !strings.ContainsRune("0123456789abcdef", r) {
				t.Fatalf("non-lowercase-hex character %q in %q", r, s)
			}
		}
	}
	if first == second {
		t.Fatalf("randomHex repeated %q", first)
	}
}
