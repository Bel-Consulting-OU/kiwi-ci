package executor

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestTartGetArgs(t *testing.T) {
	args := tartGetArgs("kiwi-123")
	want := []string{"get", "--format", "json", "kiwi-123"}
	if len(args) != len(want) {
		t.Fatalf("args = %v, want %v", args, want)
	}
	for i := range want {
		if args[i] != want[i] {
			t.Fatalf("args = %v, want %v", args, want)
		}
	}
}

func TestParseTartGetJSONAndContract(t *testing.T) {
	out, err := parseTartGetJSON([]byte(`{"name": "kiwi-1", "labels": {"kiwi.ssh.bootstrap": "true", "other": "x"}}`))
	if err != nil {
		t.Fatal(err)
	}
	if out.Name != "kiwi-1" {
		t.Fatalf("name = %q", out.Name)
	}
	if !bootstrapContractDeclared(out.Labels) {
		t.Fatal("declared contract not detected")
	}
	if _, err := parseTartGetJSON([]byte(`not json`)); err == nil {
		t.Fatal("malformed tart get output accepted")
	}
}

func TestBootstrapContractLabelSemantics(t *testing.T) {
	for _, v := range []string{"true", "TRUE", "1", "yes", "enabled", ""} {
		if !bootstrapContractDeclared(map[string]string{"kiwi.ssh.bootstrap": v}) {
			t.Errorf("value %q must declare the contract", v)
		}
	}
	for _, v := range []string{"false", "no", "0", "garbage"} {
		if bootstrapContractDeclared(map[string]string{"kiwi.ssh.bootstrap": v}) {
			t.Errorf("value %q must not declare the contract", v)
		}
	}
	if bootstrapContractDeclared(map[string]string{}) {
		t.Fatal("missing label must not declare the contract")
	}
}

// TestMissingBootstrapMarkerFailsConfig asserts a missing marker produces
// the clear configuration error (not retried) the contract demands.
func TestMissingBootstrapMarkerFailsConfig(t *testing.T) {
	meta, err := parseTartGetJSON([]byte(`{"name": "kiwi-1", "labels": {}}`))
	if err != nil {
		t.Fatal(err)
	}
	if bootstrapContractDeclared(meta.Labels) {
		t.Fatal("label-less image must not declare the contract")
	}
	cfgErr := tartBootstrapConfigError()
	if !strings.Contains(cfgErr.Error(), "kiwi ssh bootstrap contract") {
		t.Fatalf("error = %q, want the bootstrap contract message", cfgErr)
	}
	re, ok := cfgErr.(*RunError)
	if !ok || re.Kind != ErrorConfig {
		t.Fatalf("missing marker is not a config error: %T %v", cfgErr, cfgErr)
	}
}

// TestPostAuthorizedKeyDeliversPubKey drives the real bootstrap client call
// against a fake kiwi-agent and asserts the ephemeral public key line
// reaches the endpoint.
func TestPostAuthorizedKeyDeliversPubKey(t *testing.T) {
	var gotBody string
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.WriteHeader(http.StatusOK)
	}))
	defer agent.Close()

	pub := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGKi/job kiwi-job"
	if err := postAuthorizedKey(context.Background(), agent.URL+"/kiwi/v1/bootstrap/authorized-key", pub, tartBootstrapHTTPClient()); err != nil {
		t.Fatalf("injection failed: %v", err)
	}
	if !strings.Contains(gotBody, "ssh-ed25519 ") || !strings.Contains(gotBody, "kiwi-job") {
		t.Fatalf("agent received %q, want the public key line", gotBody)
	}
}

func TestPostAuthorizedKeyRefusesNon2xx(t *testing.T) {
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not authorized", http.StatusForbidden)
	}))
	defer agent.Close()
	err := postAuthorizedKey(context.Background(), agent.URL+"/kiwi/v1/bootstrap/authorized-key", "ssh-ed25519 AAA kiwi-job", tartBootstrapHTTPClient())
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("non-2xx agent response not refused: %v", err)
	}
}

func TestPostAuthorizedKeyNeverFollowsRedirects(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("redirect was followed")
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	defer redirector.Close()
	if err := postAuthorizedKey(context.Background(), redirector.URL, "ssh-ed25519 AAA kiwi-job", tartBootstrapHTTPClient()); err == nil || !strings.Contains(err.Error(), "302") {
		t.Fatalf("redirect not refused: %v", err)
	}
}
