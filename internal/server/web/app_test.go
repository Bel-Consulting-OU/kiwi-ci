package web

import (
	"strings"
	"testing"
)

// TestDashboardRunsPaginationControl pins the client half of the runs
// collection contract at the asset level (this package has no JS test
// harness): the dashboard follows X-Kiwi-Next-Cursor through the explicit
// "Load older runs" control — one page per click, never an automatic walk —
// and keeps the CSP-safe createElement/textContent rendering path (no
// innerHTML, no inline handlers).
func TestDashboardRunsPaginationControl(t *testing.T) {
	raw, err := Assets.ReadFile("app.js")
	if err != nil {
		t.Fatalf("read embedded app.js: %v", err)
	}
	js := string(raw)
	for _, want := range []string{
		"X-Kiwi-Next-Cursor",
		"Load older runs",
		"loadOlderBtn.addEventListener(\"click\", loadOlderRuns);",
		`"/api/v1/runs?cursor=" + encodeURIComponent(cursor)`,
		"createElement",
		"textContent",
	} {
		if !strings.Contains(js, want) {
			t.Errorf("app.js does not reference %q", want)
		}
	}
	if strings.Contains(js, ".innerHTML") || strings.Contains(js, "outerHTML") {
		t.Error("app.js assigns innerHTML/outerHTML; the dashboard renders via textContent/createElement")
	}
	// The control appends the next page once per click and hides when the
	// previous response reported no continuation, so the cursor walk is
	// user-driven rather than automatic.
	if !strings.Contains(js, "loadOlderBtn.classList.toggle(\"hidden\", !state.nextCursor);") {
		t.Error("app.js does not hide the control on the last page")
	}
}
