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

// TestDashboardPausedHistoryMode pins the finding-13 client contract at the
// asset level: paging into history shows a visible "live updates paused"
// indicator (toggled by setPaged), the 4s interval still refreshes the
// SELECTED run's jobs through the quiet path without replacing the paged
// table, the stats label the paged population as "loaded runs", and the
// dashboard keeps the CSP-safe createElement/textContent rendering path.
func TestDashboardPausedHistoryMode(t *testing.T) {
	read := func(name string) string {
		t.Helper()
		raw, err := Assets.ReadFile(name)
		if err != nil {
			t.Fatalf("read embedded %s: %v", name, err)
		}
		return string(raw)
	}
	js := read("app.js")
	html := read("index.html")
	css := read("app.css")

	// The indicator lives in the runs toolbar and starts hidden.
	for _, want := range []string{
		`id="paused"`,
		"live updates paused (viewing history)",
	} {
		if !strings.Contains(html, want) {
			t.Errorf("index.html does not contain %q", want)
		}
	}
	if !strings.Contains(css, "#paused") {
		t.Error("app.css does not style the paused indicator")
	}
	// The indicator toggles on every paged transition: sign-out, load-older
	// and refresh all go through setPaged.
	for _, want := range []string{
		`const pausedEl = $("#paused");`,
		`pausedEl.classList.toggle("hidden", !state.paged);`,
		"setPaged(true)",
		"setPaged(false)",
	} {
		if !strings.Contains(js, want) {
			t.Errorf("app.js does not contain %q", want)
		}
	}
	// Stats label the paged population explicitly.
	if !strings.Contains(js, `state.paged ? "loaded runs" : "runs"`) {
		t.Error("app.js does not label the paged stats population as \"loaded runs\"")
	}
	// While paged the interval must run the quiet selected-run refresh, not
	// the table-replacing refresh; a vanished selected run surfaces as a
	// note instead of clearing the pane.
	for _, want := range []string{
		"refreshSelectedQuiet",
		"run unavailable",
	} {
		if !strings.Contains(js, want) {
			t.Errorf("app.js does not contain %q", want)
		}
	}
	intervalAt := strings.Index(js, "setInterval(")
	if intervalAt < 0 {
		t.Fatal("app.js has no polling interval")
	}
	interval := js[intervalAt:]
	pagedBranchAt := strings.Index(interval, "if (state.paged) {")
	if pagedBranchAt < 0 {
		t.Fatal("the interval has no paged branch")
	}
	quietAt := strings.Index(interval[pagedBranchAt:], "refreshSelectedQuiet();")
	liveAt := strings.Index(interval[pagedBranchAt:], "refresh();")
	if quietAt < 0 || liveAt < 0 || quietAt > liveAt {
		t.Error("the interval's paged branch must reach refreshSelectedQuiet before the live refresh")
	}
	if strings.Contains(js, ".innerHTML") || strings.Contains(js, "outerHTML") {
		t.Error("app.js assigns innerHTML/outerHTML; the dashboard renders via textContent/createElement")
	}
}
