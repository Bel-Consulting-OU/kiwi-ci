package version

import "testing"

func TestString(t *testing.T) {
	cases := []struct {
		version, commit, want string
	}{
		{"0.1.0-dev", "", "0.1.0-dev"},
		{"1.2.3", "", "1.2.3"},
		{"1.2.3", "a1b2c3d", "1.2.3 (a1b2c3d)"},
	}
	for _, c := range cases {
		Version, Commit = c.version, c.commit
		if got := String(); got != c.want {
			t.Errorf("String() with version=%q commit=%q = %q, want %q", c.version, c.commit, got, c.want)
		}
	}
}

func TestFull(t *testing.T) {
	Version, Commit, BuildDate, Dirty = "2.0.0", "deadbeef", "2026-09-14T00:00:00Z", "true"
	full := Full()
	want := map[string]string{
		"version":                 "2.0.0",
		"commit":                  "deadbeef",
		"build_date":              "2026-09-14T00:00:00Z",
		"dirty":                   "true",
		"protocol_version":        "3",
		"pipeline_schema_version": "1",
		"storage_schema_version":  "1",
	}
	for k, v := range want {
		if full[k] != v {
			t.Errorf("Full()[%q] = %q, want %q", k, full[k], v)
		}
	}
	if full["go_version"] == "" {
		t.Error("Full() go_version is empty")
	}
}
