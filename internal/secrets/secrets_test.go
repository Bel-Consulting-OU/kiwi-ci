package secrets

import "testing"

func TestMaskerLongestFirst(t *testing.T) {
	m := &Masker{}
	m.Add("abcdef")
	m.Add("abc")
	if got := m.Mask("token=abcdef and abc"); got != "token=*** and ***" {
		t.Fatalf("got %q", got)
	}
}
