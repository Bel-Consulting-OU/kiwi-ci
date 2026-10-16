package fleet

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// cloudStub is a minimal fake cloud API: it records the calls and serves
// canned JSON so each provider's wire shape is exercised without a real
// cloud account.
type cloudStub struct {
	mu       sync.Mutex
	calls    []string
	response map[string]string // path prefix -> JSON body
	status   map[string]int    // path prefix -> HTTP status
}

func (c *cloudStub) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.mu.Lock()
		// Record the RAW QUERY too: AWS uses ?Action=… on the root path,
		// so path-only recording cannot see the action name.
		c.calls = append(c.calls, r.Method+" "+r.URL.Path+"?"+r.URL.RawQuery)
		resp := ""
		status := 200
		for prefix, body := range c.response {
			if strings.Contains(r.URL.Path, prefix) || strings.Contains(r.URL.RawQuery, prefix) {
				resp = body
				break
			}
		}
		for prefix, s := range c.status {
			if strings.Contains(r.URL.Path, prefix) || strings.Contains(r.URL.RawQuery, prefix) {
				status = s
				break
			}
		}
		c.mu.Unlock()
		if status < 200 || status > 299 {
			w.WriteHeader(status)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(resp))
	})
}

func (c *cloudStub) saw(substr string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, call := range c.calls {
		if strings.Contains(call, substr) {
			return true
		}
	}
	return false
}

func newStub(t *testing.T, responses map[string]string) (*cloudStub, *httptest.Server) {
	t.Helper()
	c := &cloudStub{response: responses, status: map[string]int{}}
	srv := httptest.NewServer(c.handler())
	t.Cleanup(srv.Close)
	return c, srv
}

// Every cloud provider fails closed on a non-2xx: an unreachable cloud is
// NOT the same as an empty pool, and Reconcile must see the error.
func TestCloudProvidersFailClosedOnHTTPError(t *testing.T) {
	cases := []struct {
		name string
		mk   func(base string) Provisioner
	}{
		{"kubernetes", func(b string) Provisioner {
			return NewKubernetesProvider("k8s", b, "tok", "default", "runner:latest")
		}},
		{"aws", func(b string) Provisioner {
			return NewAWSProvider("aws", b, "tok", "us-east-1", "ami-1", "")
		}},
		{"gcp", func(b string) Provisioner {
			return NewGCPProvider("gcp", b, "tok", "us-central1", "us-central1-a", "img", "")
		}},
		{"azure", func(b string) Provisioner {
			return NewAzureProvider("az", b, "tok", "sub", "rg", "eastus", "img", "")
		}},
		{"hetzner", func(b string) Provisioner {
			return NewHetznerProvider("hz", b, "tok", "fsn1", "", "")
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, srv := newStub(t, nil)
			srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			})
			p := tc.mk(srv.URL)
			if _, err := p.Capacity(context.Background()); err == nil {
				t.Fatal("Capacity must fail closed on HTTP 500")
			}
			if _, err := p.Provision(context.Background(), Profile{Name: "pool"}, 1); err == nil {
				t.Fatal("Provision must fail closed on HTTP 500")
			}
		})
	}
}

// Kubernetes: Provision posts a Pod, Capacity reads the pod list, and the
// pool records the created instance.
func TestKubernetesProvisionAndCapacity(t *testing.T) {
	c, srv := newStub(t, map[string]string{
		"/pods": `{"items":[{"metadata":{"name":"p1","labels":{"kiwi.fleet.profile":"pool"}},"status":{"phase":"Running"}}]}`,
	})
	k := NewKubernetesProvider("k8s", srv.URL, "tok", "default", "runner:latest")
	got, err := k.Provision(context.Background(), Profile{Name: "pool", Labels: []string{"os:linux"}}, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("provisioned %d, want 2", len(got))
	}
	if !c.saw("POST") || !c.saw("/pods") {
		t.Fatalf("calls = %v", c.calls)
	}
	caps, err := k.Capacity(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if caps["pool"].Ready != 1 {
		t.Fatalf("capacity = %+v, want 1 running pod", caps)
	}
	// Drain and Terminate hit DELETE.
	if err := k.Drain(context.Background(), []string{"p1"}); err != nil {
		t.Fatal(err)
	}
	if err := k.Terminate(context.Background(), []string{"p1"}); err != nil {
		t.Fatal(err)
	}
	if !c.saw("DELETE") {
		t.Fatalf("calls = %v", c.calls)
	}
}

// AWS: Provision posts RunInstances, Drain posts StopInstances, Terminate
// posts TerminateInstances.
func TestAWSProvisionDrainTerminate(t *testing.T) {
	c, srv := newStub(t, map[string]string{
		"RunInstances":      `{"Instances":[{"InstanceId":"i-1"}]}`,
		"DescribeInstances": `{"Reservations":[{"Instances":[{"InstanceId":"i-1","State":{"Name":"Running"}}]}]}`,
	})
	a := NewAWSProvider("aws", srv.URL, "tok", "us-east-1", "ami-1", "")
	got, err := a.Provision(context.Background(), Profile{Name: "pool"}, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("provisioned %d", len(got))
	}
	// Capacity is checked BEFORE drain/terminate: after Terminate the
	// instance is gone from the pool and the cloud listing has no profile
	// label to recover it from.
	caps, err := a.Capacity(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if caps["pool"].Max != 1 {
		t.Fatalf("capacity = %+v", caps)
	}
	if err := a.Drain(context.Background(), []string{"i-1"}); err != nil {
		t.Fatal(err)
	}
	if err := a.Terminate(context.Background(), []string{"i-1"}); err != nil {
		t.Fatal(err)
	}
	if !c.saw("RunInstances") || !c.saw("StopInstances") || !c.saw("TerminateInstances") {
		t.Fatalf("calls = %v", c.calls)
	}
}

// GCP / Azure / Hetzner: the same create/drain/terminate contract.
func TestGCPCloudContract(t *testing.T) {
	c, srv := newStub(t, map[string]string{
		"/instances": `{"items":[{"name":"g1","status":"RUNNING"}]}`,
	})
	g := NewGCPProvider("gcp", srv.URL, "tok", "us-central1", "us-central1-a", "img", "")
	got, err := g.Provision(context.Background(), Profile{Name: "pool"}, 1)
	if err != nil || len(got) != 1 {
		t.Fatalf("provision = %v err=%v", got, err)
	}
	if err := g.Drain(context.Background(), []string{"g1"}); err != nil {
		t.Fatal(err)
	}
	if err := g.Terminate(context.Background(), []string{"g1"}); err != nil {
		t.Fatal(err)
	}
	if !c.saw("/instances") {
		t.Fatalf("calls = %v", c.calls)
	}
}

func TestAzureCloudContract(t *testing.T) {
	c, srv := newStub(t, map[string]string{
		"virtualMachines": `{"value":[{"name":"a1","properties":{"provisioningState":"Succeeded"}}]}`,
	})
	a := NewAzureProvider("az", srv.URL, "tok", "sub", "rg", "eastus", "img", "")
	got, err := a.Provision(context.Background(), Profile{Name: "pool"}, 1)
	if err != nil || len(got) != 1 {
		t.Fatalf("provision = %v err=%v", got, err)
	}
	if err := a.Drain(context.Background(), []string{"a1"}); err != nil {
		t.Fatal(err)
	}
	if err := a.Terminate(context.Background(), []string{"a1"}); err != nil {
		t.Fatal(err)
	}
	if !c.saw("virtualMachines") {
		t.Fatalf("calls = %v", c.calls)
	}
}

func TestHetznerCloudContract(t *testing.T) {
	c, srv := newStub(t, map[string]string{
		"/servers": `{"servers":[{"id":1,"name":"h1","status":"running"}]}`,
	})
	h := NewHetznerProvider("hz", srv.URL, "tok", "fsn1", "", "")
	got, err := h.Provision(context.Background(), Profile{Name: "pool"}, 1)
	if err != nil || len(got) != 1 {
		t.Fatalf("provision = %v err=%v", got, err)
	}
	if err := h.Drain(context.Background(), []string{"h1"}); err != nil {
		t.Fatal(err)
	}
	if err := h.Terminate(context.Background(), []string{"h1"}); err != nil {
		t.Fatal(err)
	}
	if !c.saw("/servers") {
		t.Fatalf("calls = %v", c.calls)
	}
}

// All five satisfy the full SPI surface.
func TestCloudProvidersConformance(t *testing.T) {
	provs := map[string]Provisioner{
		"k8s":     NewKubernetesProvider("k8s", "http://x", "t", "ns", "img"),
		"aws":     NewAWSProvider("aws", "http://x", "t", "r", "ami", ""),
		"gcp":     NewGCPProvider("gcp", "http://x", "t", "r", "z", "img", ""),
		"azure":   NewAzureProvider("az", "http://x", "t", "s", "rg", "loc", "img", ""),
		"hetzner": NewHetznerProvider("hz", "http://x", "t", "fsn1", "", ""),
	}
	for name, p := range provs {
		var _ Provisioner = p
		var _ CountDrainer = p.(CountDrainer)
		var _ HealthScanner = p.(HealthScanner)
		if p.Name() == "" {
			t.Fatalf("%s has empty name", name)
		}
	}
}

// A cloud provider plugged into Reconcile converges without fabricating
// capacity when the API is down.
func TestCloudProviderWithReconcileFailsClosed(t *testing.T) {
	_, srv := newStub(t, nil)
	srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	})
	k := NewKubernetesProvider("k8s", srv.URL, "tok", "default", "img")
	m := NewManager()
	if err := m.Register(k); err != nil {
		t.Fatal(err)
	}
	rep := m.Reconcile(context.Background(), []Target{{
		Provider: "k8s",
		Profile:  Profile{Name: "pool", Min: 0, Max: 5},
		Want:     3,
	}})
	if rep.Errors == 0 {
		t.Fatal("Reconcile must record the capacity failure")
	}
	for _, ch := range rep.Changes {
		if ch.Action == "provision" {
			t.Fatal("must not provision on unknown capacity")
		}
	}
}

// JSON round-trip of the pool's instance view keeps labels and profile.
func TestCloudPoolKeepsProfileAndLabels(t *testing.T) {
	p := newCloudPool()
	p.put(cloudInstance{ID: "x", Profile: "pool", Labels: []string{"a", "b"}, State: StateReady})
	inst, ok := p.get("x")
	if !ok || inst.Profile != "pool" || len(inst.Labels) != 2 {
		t.Fatalf("pool = %+v ok=%v", inst, ok)
	}
	raw, _ := json.Marshal(inst.toInstance())
	var back Instance
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	if back.Profile != "pool" {
		t.Fatalf("roundtrip = %+v", back)
	}
}
