package fleet

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// HetznerProvider runs fleet capacity as Hetzner Cloud servers.
// EXPERIMENTAL — not production cloud support. The provider speaks the
// real API shape but has not been certified against live disposable
// resources. Frozen scope: cloud/fleet autoscaling is optional and does
// not block a core release. Do not advertise this as production-ready.
type HetznerProvider struct {
	name   string
	region string
	typ    string
	image  string
	client *apiClient
	pool   *cloudPool
}

// NewHetznerProvider builds a Hetzner-Cloud-backed provider. The token is
// the Hetzner API token; baseURL is https://api.hetzner.cloud/v1.
func NewHetznerProvider(name, baseURL, token, region, serverType, image string) *HetznerProvider {
	if serverType == "" {
		serverType = "cx22"
	}
	if image == "" {
		image = "ubuntu-24.04"
	}
	return &HetznerProvider{
		name: name, region: region, typ: serverType, image: image,
		client: newAPIClient(baseURL, "Bearer", token),
		pool:   newCloudPool(),
	}
}

func (h *HetznerProvider) Name() string { return h.name }

type hetznerServerList struct {
	Servers []struct {
		ID         int64  `json:"id"`
		Name       string `json:"name"`
		Status     string `json:"status"`
		ServerType struct {
			Name string `json:"name"`
		} `json:"server_type"`
		Datacenter struct {
			Name string `json:"name"`
		} `json:"datacenter"`
		Created string `json:"created"`
	} `json:"servers"`
}

func hetznerStateToInstance(s string) InstanceState {
	switch strings.ToLower(s) {
	case "running":
		return StateReady
	case "initializing", "starting":
		return StatePending
	case "stopping":
		return StateDraining
	case "off", "deleting":
		return StateTerminated
	default:
		return StatePending
	}
}

func (h *HetznerProvider) Capacity(ctx context.Context) (map[string]Capacity, error) {
	var list hetznerServerList
	if err := h.client.do(ctx, "GET", "/servers", nil, &list); err != nil {
		return nil, err
	}
	out := map[string]Capacity{}
	for _, srv := range list.Servers {
		profile := "default"
		if p, ok := h.pool.get(srv.Name); ok {
			profile = p.Profile
		}
		c := out[profile]
		c.Max++
		switch hetznerStateToInstance(srv.Status) {
		case StateReady:
			c.Ready++
		case StatePending:
			c.Pending++
		default:
			c.Draining++
		}
		out[profile] = c
	}
	return out, nil
}

func (h *HetznerProvider) createInstance(ctx context.Context, p Profile, n int) ([]cloudInstance, error) {
	var out []cloudInstance
	typ := h.typ
	if p.GPU {
		typ = "ccx33"
	}
	for i := 0; i < n; i++ {
		name := fmt.Sprintf("kiwi-%s-%s-%d", h.name, p.Name, time.Now().UnixNano()%1e6)
		body := map[string]any{
			"name":        name,
			"server_type": typ,
			"image":       h.image,
			"location":    h.region,
			"labels": map[string]string{
				"kiwi-fleet-provider": h.name,
				"kiwi-fleet-profile":  p.Name,
			},
		}
		if err := h.client.do(ctx, "POST", "/servers", body, nil); err != nil {
			return out, err
		}
		out = append(out, cloudInstance{
			ID: name, Profile: p.Name, Labels: p.Labels,
			Region: p.Region, Arch: p.Architecture,
			State: StatePending, Started: time.Now().UTC(),
			Provider: "hetzner",
		})
	}
	return out, nil
}

func (h *HetznerProvider) Provision(ctx context.Context, p Profile, want int) ([]Instance, error) {
	return cloudProvision(ctx, h.pool, h, p, want)
}

func (h *HetznerProvider) Drain(ctx context.Context, ids []string) error {
	for _, id := range ids {
		if err := h.client.do(ctx, "POST", "/servers/"+id+"/actions/poweroff", nil, nil); err != nil {
			return err
		}
		h.pool.setState(id, StateDraining)
	}
	return nil
}

func (h *HetznerProvider) Terminate(ctx context.Context, ids []string) error {
	for _, id := range ids {
		if err := h.client.do(ctx, "DELETE", "/servers/"+id, nil, nil); err != nil {
			return err
		}
		h.pool.remove(id)
	}
	return nil
}

func (h *HetznerProvider) Cost(ctx context.Context, id string) (float64, error) {
	inst, ok := h.pool.get(id)
	if !ok {
		return 0, fmt.Errorf("fleet/hetzner: unknown instance %q", id)
	}
	return inst.Cost, nil
}

func (h *HetznerProvider) Capabilities(ctx context.Context, id string) ([]string, error) {
	inst, ok := h.pool.get(id)
	if !ok {
		return nil, fmt.Errorf("fleet/hetzner: unknown instance %q", id)
	}
	return append([]string(nil), inst.Labels...), nil
}

func (h *HetznerProvider) Attestation(ctx context.Context, id string) ([]byte, error) {
	if _, ok := h.pool.get(id); !ok {
		return nil, fmt.Errorf("fleet/hetzner: unknown instance %q", id)
	}
	return []byte(id), nil
}

var (
	_ Provisioner   = (*HetznerProvider)(nil)
	_ CountDrainer  = (*HetznerProvider)(nil)
	_ HealthScanner = (*HetznerProvider)(nil)
	_ cloudCreator  = (*HetznerProvider)(nil)
)

func (h *HetznerProvider) DrainN(ctx context.Context, profile string, n int) error {
	ids := h.pool.idsIn(profile, StateReady, StatePending)
	if len(ids) > n {
		ids = ids[:n]
	}
	return h.Drain(ctx, ids)
}

func (h *HetznerProvider) Unhealthy(ctx context.Context, profile string) ([]string, error) {
	var list hetznerServerList
	if err := h.client.do(ctx, "GET", "/servers", nil, &list); err != nil {
		return nil, err
	}
	var bad []string
	for _, srv := range list.Servers {
		if strings.EqualFold(srv.Status, "off") {
			bad = append(bad, srv.Name)
		}
	}
	return bad, nil
}
