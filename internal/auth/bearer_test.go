package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestParseBearerGrammar pins the ONE bearer grammar every parsing site now
// shares: exact scheme, trimmed non-empty token, no whitespace/comma inside.
// A header that IS the raw credential is rejected — the pre-fix
// strings.TrimPrefix behavior accepted it.
func TestParseBearerGrammar(t *testing.T) {
	cases := []struct {
		name   string
		header string
		want   string
		ok     bool
	}{
		{"canonical", "Bearer tok", "tok", true},
		{"surrounding whitespace trimmed", "Bearer \ttok \t", "tok", true},
		{"single space token with padding", "Bearer  tok", "tok", true},
		{"scheme and opaque token", "Bearer abc.def-123_456", "abc.def-123_456", true},
		// The regression this grammar exists for: a bare credential with no
		// scheme is not a bearer presentation.
		{"raw token without scheme", "tok", "", false},
		{"raw token that looks like a scheme", "Basic dXNlcjpwYXNz", "", false},
		{"lowercase scheme", "bearer tok", "", false},
		{"uppercase scheme", "BEARER tok", "", false},
		{"no space after scheme", "Bearertok", "", false},
		{"scheme only", "Bearer", "", false},
		{"empty token", "Bearer ", "", false},
		{"whitespace-only token", "Bearer \t \r\n", "", false},
		{"whitespace inside token", "Bearer to k", "", false},
		{"tab inside token", "Bearer to\tk", "", false},
		{"newline inside token", "Bearer to\nk", "", false},
		{"comma inside token", "Bearer tok,other", "", false},
		{"comma list", "Bearer a,b", "", false},
		{"empty header", "", "", false},
		{"scheme with different separator", "Bearer:tok", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := ParseBearer(tc.header)
			if ok != tc.ok || got != tc.want {
				t.Fatalf("ParseBearer(%q) = (%q, %v), want (%q, %v)", tc.header, got, ok, tc.want, tc.ok)
			}
		})
	}
}

// TestMiddlewareRejectsSchemeLessRawToken proves the middleware no longer
// accepts a header that is the raw store token: the pre-fix TrimPrefix
// parsing authenticated it.
func TestMiddlewareRejectsSchemeLessRawToken(t *testing.T) {
	store := NewTokenStore()
	if err := store.AddToken("store-token", Principal{Subject: "bot", Roles: []Role{RoleRead}}); err != nil {
		t.Fatal(err)
	}
	reached := false
	h := Middleware(store, "", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
	}), nil)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/runs", nil)
	req.Header.Set("Authorization", "store-token")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized || reached {
		t.Fatalf("scheme-less raw token: status=%d reached=%v, want 401 and no principal", w.Code, reached)
	}
	// The canonical presentation still authenticates.
	req = httptest.NewRequest(http.MethodGet, "/api/v1/runs", nil)
	req.Header.Set("Authorization", "Bearer store-token")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK || !reached {
		t.Fatalf("canonical bearer: status=%d reached=%v, want 200", w.Code, reached)
	}
}
