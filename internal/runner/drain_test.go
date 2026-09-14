package runner

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/server"
)

// TestDrainRunnerExitsIdle verifies kiwi runner --drain semantics: the
// runner registers with Draining=true, takes no work, and exits cleanly
// instead of polling forever.
func TestDrainRunnerExitsIdle(t *testing.T) {
	srv := server.New("runner-tok")
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	r := &Runner{Cfg: Config{Server: ts.URL, Token: "runner-tok", Poll: 10 * time.Millisecond, Drain: true}}
	done := make(chan error, 1)
	go func() { done <- r.Run(ctx) }()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("drain runner exited with error: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("drain runner did not exit")
	}

	// The server recorded the runner as draining.
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, ts.URL+"/api/v1/runners", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer runner-tok")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var runners []model.Runner
	if err := json.NewDecoder(resp.Body).Decode(&runners); err != nil {
		t.Fatal(err)
	}
	if len(runners) != 1 || !runners[0].Draining {
		t.Fatalf("server runners = %+v, want exactly one draining runner", runners)
	}
}
