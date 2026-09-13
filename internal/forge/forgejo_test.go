package forge

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestForgejoVerifyWebhook(t *testing.T) {
	f := &Forgejo{Secret: "It's a Secret to Everybody"}
	payload := []byte("Hello, World!")
	h := http.Header{}
	h.Set("X-Hub-Signature-256", "sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17")
	if err := f.VerifyWebhook(payload, "It's a Secret to Everybody", h); err != nil {
		t.Fatalf("valid signature rejected: %v", err)
	}
	if err := f.VerifyWebhook([]byte("tampered"), "It's a Secret to Everybody", h); err == nil {
		t.Fatal("tampered payload accepted")
	}
}

func TestParseForgejoEvents(t *testing.T) {
	f := &Forgejo{}
	ec, err := f.ParseEvent([]byte(testPushPayload))
	if err != nil {
		t.Fatal(err)
	}
	if ec.Event != "push" || !ec.Trusted || ec.Forge != "forgejo" || ec.Repository.FullName != "octocat/hello-world" {
		t.Fatalf("bad push parse: %+v", ec)
	}
	pec, err := f.ParseEvent([]byte(testPRPayload))
	if err != nil {
		t.Fatal(err)
	}
	if pec.Event != "pull_request" || !pec.Trusted || pec.Forge != "forgejo" {
		t.Fatalf("bad PR parse: %+v", pec)
	}
	fec, err := f.ParseEvent([]byte(testForkPRPayload))
	if err != nil {
		t.Fatal(err)
	}
	if fec.Trusted {
		t.Fatal("fork PR must be untrusted")
	}
	// Unrelated events parse to an empty event.
	if ec, err = f.ParseEvent([]byte(`{"action":"created","issue":{"number":1}}`)); err != nil || ec.Event != "" {
		t.Fatalf("issue event handling: %+v %v", ec, err)
	}
}

func TestForgejoFetchFile(t *testing.T) {
	content := "version: 1\njobs:\n  build:\n    steps: [{run: echo hi}]\n"
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/api/v1/repos/octocat/hello-world/contents/") {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("Authorization") != "token fjtok" {
			http.Error(w, "missing token", http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(`{"content":"dmVyc2lvbjogMQpqb2JzOgogIGJ1aWxkOgogICAgc3RlcHM6IFt7cnVuOiBlY2hvIGhpfV0K","encoding":"base64"}`))
	}))
	defer ts.Close()
	f := &Forgejo{BaseURL: ts.URL, Token: "fjtok"}
	got, err := f.FetchFile(context.Background(), "octocat/hello-world", ".kiwi/pipeline.yaml", "main")
	if err != nil {
		t.Fatal(err)
	}
	if got != content {
		t.Fatalf("content mismatch: %q", got)
	}
}

func TestForgejoChangedFilesAndStatus(t *testing.T) {
	var statusBody map[string]any
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/compare/"):
			_, _ = w.Write([]byte(`{"files":[{"filename":"go.mod"},{"filename":"README.md"}]}`))
		case strings.Contains(r.URL.Path, "/statuses/"):
			_ = decodeJSONBody(r, &statusBody)
			w.WriteHeader(http.StatusCreated)
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()
	f := &Forgejo{BaseURL: ts.URL}
	files, err := f.ChangedFiles(context.Background(), EventContext{Repository: Repository{FullName: "octocat/hello-world"}, BaseSHA: "a", HeadSHA: "b"})
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 2 || files[0] != "go.mod" {
		t.Fatalf("unexpected files: %v", files)
	}
	if err := f.PublishCheck(context.Background(), "octocat/hello-world", "sha", "build", "completed", "cancelled", "", "cancelled", nil); err != nil {
		t.Fatal(err)
	}
	if statusBody["state"] != "error" || statusBody["context"] != "Kiwi / build" {
		t.Fatalf("bad status body: %v", statusBody)
	}
}

func decodeJSONBody(r *http.Request, v any) error {
	dec := json.NewDecoder(r.Body)
	return dec.Decode(v)
}
