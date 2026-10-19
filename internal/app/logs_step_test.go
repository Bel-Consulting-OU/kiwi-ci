package app

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// TestLogsStepFilter: kiwi logs --step security prints only that step's
// lines (including backlog and follow).
func TestLogsStepFilter(t *testing.T) {
	entries := []model.LogEntry{
		{Seq: 1, JobKey: "toolchain", Step: "toolchain", Line: "assert"},
		{Seq: 2, JobKey: "toolchain", Step: "security", Line: "gitleaks clean"},
		{Seq: 3, JobKey: "toolchain", Step: "validate", Line: "compose ok"},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/runs/r1/logs" {
			_ = json.NewEncoder(w).Encode(entries)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	got := captureStdout(t, func() {
		if err := opsLogs(context.Background(), []string{"--server", srv.URL, "--token", "t", "--step", "security", "r1"}); err != nil {
			t.Errorf("opsLogs: %v", err)
		}
	})
	if strings.Contains(got, "assert") || strings.Contains(got, "compose ok") {
		t.Fatalf("step filter leaked other steps:\n%s", got)
	}
	if !strings.Contains(got, "gitleaks clean") {
		t.Fatalf("security line missing:\n%s", got)
	}
}
