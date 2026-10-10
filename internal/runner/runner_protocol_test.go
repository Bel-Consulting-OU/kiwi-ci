package runner

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/server"
)

// TestCheckServerProtocol pins the runner-side compatibility rule: the
// runner supports server protocol versions up to its own, and refuses to
// start when either the server's current protocol or its required minimum is
// newer than what this runner implements.
func TestCheckServerProtocol(t *testing.T) {
	compatible := []struct {
		name           string
		serverProtocol int
		minProtocol    int
	}{
		{"legacy server omits both", 0, 0},
		{"same protocol", model.RunnerProtocolVersion, model.RunnerProtocolVersion},
		{"older server minimum", model.RunnerProtocolVersion, 1},
	}
	for _, tc := range compatible {
		t.Run(tc.name, func(t *testing.T) {
			if err := checkServerProtocol(tc.serverProtocol, tc.minProtocol); err != nil {
				t.Fatalf("compatible server refused: %v", err)
			}
		})
	}
	incompatible := []struct {
		name           string
		serverProtocol int
		minProtocol    int
	}{
		{"minimum above runner", model.RunnerProtocolVersion, model.RunnerProtocolVersion + 1},
		{"server protocol above runner", model.RunnerProtocolVersion + 1, model.RunnerProtocolVersion},
	}
	for _, tc := range incompatible {
		t.Run(tc.name, func(t *testing.T) {
			err := checkServerProtocol(tc.serverProtocol, tc.minProtocol)
			if err == nil || !strings.Contains(err.Error(), "upgrade the runner") {
				t.Fatalf("incompatible server = %v, want an upgrade-the-runner error", err)
			}
		})
	}
}

// TestCheckTaskProtocol pins the runner-side lease refusal: a task whose
// required protocol exceeds what this runner implements is refused before
// execution; absent and equal versions pass.
func TestCheckTaskProtocol(t *testing.T) {
	if err := checkTaskProtocol(0); err != nil {
		t.Fatalf("task without protocol_version refused: %v", err)
	}
	if err := checkTaskProtocol(model.RunnerProtocolVersion); err != nil {
		t.Fatalf("same-version task refused: %v", err)
	}
	err := checkTaskProtocol(model.RunnerProtocolVersion + 1)
	if err == nil || !strings.Contains(err.Error(), "upgrade the runner") {
		t.Fatalf("newer task = %v, want an upgrade-the-runner error", err)
	}
}

// TestRegisterRefusesIncompatibleServerResponse drives the registration
// response parsing end to end against a fake control plane: a response whose
// min_runner_protocol or protocol_version is newer than this runner fails
// registration instead of running with degraded semantics.
func TestRegisterRefusesIncompatibleServerResponse(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
	}{
		{"minimum above runner", fmt.Sprintf(`{"id":"r1","min_runner_protocol":%d}`, model.RunnerProtocolVersion+1)},
		{"server protocol above runner", fmt.Sprintf(`{"id":"r1","protocol_version":%d}`, model.RunnerProtocolVersion+1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(w, tc.body)
			}))
			defer ts.Close()
			r := &Runner{Cfg: Config{Server: ts.URL, Token: "t"}, ID: "r1", Client: ts.Client()}
			err := r.register(context.Background())
			if err == nil || !strings.Contains(err.Error(), "upgrade the runner") {
				t.Fatalf("register against incompatible server = %v, want an upgrade-the-runner error", err)
			}
		})
	}
}

// TestNextRefusesTaskRequiringNewerProtocol drives the /next response parsing:
// a task advertising newer semantics is refused; a task with this runner's
// protocol (or none) is adopted.
func TestNextRefusesTaskRequiringNewerProtocol(t *testing.T) {
	serve := func(task server.Task) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(task)
		}))
	}
	ts := serve(server.Task{ProtocolVersion: model.RunnerProtocolVersion + 1})
	r := &Runner{Cfg: Config{Server: ts.URL, Token: "t"}, ID: "r1", Client: ts.Client()}
	_, _, err := r.next(context.Background())
	ts.Close()
	if err == nil || !strings.Contains(err.Error(), "upgrade the runner") {
		t.Fatalf("newer task next = %v, want an upgrade-the-runner error", err)
	}

	ts = serve(server.Task{ProtocolVersion: model.JobRequiresProtocol})
	r = &Runner{Cfg: Config{Server: ts.URL, Token: "t"}, ID: "r1", Client: ts.Client()}
	task, drain, err := r.next(context.Background())
	ts.Close()
	if err != nil || drain || task == nil {
		t.Fatalf("compatible task = task=%v drain=%v err=%v", task, drain, err)
	}
}
