package fleet

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// apiClient is the shared HTTP seam every cloud provider uses. It is
// deliberately small: JSON in, JSON out, a bearer/basic/token header, and
// fail-closed on any non-2xx. Providers never swallow a 4xx/5xx as "empty
// capacity" — an unreachable cloud is NOT the same as an empty pool.
type apiClient struct {
	base   string
	token  string
	client *http.Client
	// header is the authorization scheme (Bearer, Basic, token).
	header string
}

func newAPIClient(base, scheme, token string) *apiClient {
	return &apiClient{
		base:   strings.TrimRight(base, "/"),
		token:  token,
		header: scheme,
		client: &http.Client{Timeout: 30 * time.Second},
	}
}

func (c *apiClient) do(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		raw, err := json.Marshal(in)
		if err != nil {
			return fmt.Errorf("cloud api: marshal: %w", err)
		}
		body = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, body)
	if err != nil {
		return err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.token != "" {
		if c.header == "Basic" {
			req.Header.Set("Authorization", "Basic "+c.token)
		} else if c.header == "token" {
			req.Header.Set("Authorization", "token "+c.token)
		} else {
			req.Header.Set("Authorization", "Bearer "+c.token)
		}
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("cloud api: %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return fmt.Errorf("cloud api: %s %s: read: %w", method, path, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		// Opaque to callers about the body (it may echo tokens); the status
		// and path are the diagnostic.
		return fmt.Errorf("cloud api: %s %s: HTTP %d", method, path, resp.StatusCode)
	}
	if out != nil && len(raw) > 0 {
		if err := json.Unmarshal(raw, out); err != nil {
			return fmt.Errorf("cloud api: %s %s: decode: %w", method, path, err)
		}
	}
	return nil
}

// cloudInstance is the shared internal view of one provisioned instance
// across providers. Each provider maps its native shape onto this so the
// pool logic stays identical.
type cloudInstance struct {
	ID       string
	Profile  string
	Labels   []string
	Region   string
	Arch     string
	State    InstanceState
	Started  time.Time
	Cost     float64
	Provider string
}

func (c cloudInstance) toInstance() Instance {
	return Instance{
		ID:          c.ID,
		Profile:     c.Profile,
		Labels:      append([]string(nil), c.Labels...),
		Region:      c.Region,
		Arch:        c.Arch,
		State:       c.State,
		StartedAt:   c.Started,
		CostPerHour: c.Cost,
	}
}

// cloudPool is the shared bookkeeping every cloud provider keeps: the
// instances it has created, keyed by id. It is the provider-local view; the
// cloud itself is always the source of truth for liveness.
type cloudPool struct {
	mu        sync.Mutex
	instances map[string]cloudInstance
}

func newCloudPool() *cloudPool {
	return &cloudPool{instances: map[string]cloudInstance{}}
}

func (p *cloudPool) put(inst cloudInstance) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.instances[inst.ID] = inst
}

func (p *cloudPool) get(id string) (cloudInstance, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	inst, ok := p.instances[id]
	return inst, ok
}

func (p *cloudPool) remove(ids ...string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, id := range ids {
		delete(p.instances, id)
	}
}

func (p *cloudPool) setState(id string, st InstanceState) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if inst, ok := p.instances[id]; ok {
		inst.State = st
		p.instances[id] = inst
	}
}

func (p *cloudPool) capacityFor(profile string) Capacity {
	p.mu.Lock()
	defer p.mu.Unlock()
	c := Capacity{}
	for _, inst := range p.instances {
		if inst.Profile != profile {
			continue
		}
		c.Max++
		switch inst.State {
		case StateReady:
			c.Ready++
		case StatePending:
			c.Pending++
		case StateDraining, StateQuarantined:
			c.Draining++
		}
	}
	return c
}

func (p *cloudPool) idsIn(profile string, states ...InstanceState) []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	want := map[InstanceState]bool{}
	for _, s := range states {
		want[s] = true
	}
	var out []string
	for id, inst := range p.instances {
		if inst.Profile == profile && want[inst.State] {
			out = append(out, id)
		}
	}
	return out
}

// cloudProvisionLoop is the shared Provision shape: ask the provider to
// start `want` instances, record them as PENDING, and return the created
// set. The provider's create call is the only native part.
type cloudCreator interface {
	createInstance(ctx context.Context, p Profile, n int) ([]cloudInstance, error)
}

func cloudProvision(ctx context.Context, pool *cloudPool, c cloudCreator, p Profile, want int) ([]Instance, error) {
	created, err := c.createInstance(ctx, p, want)
	if err != nil {
		return nil, err
	}
	out := make([]Instance, 0, len(created))
	for _, inst := range created {
		if inst.State == "" {
			inst.State = StatePending
		}
		pool.put(inst)
		out = append(out, inst.toInstance())
	}
	return out, nil
}
