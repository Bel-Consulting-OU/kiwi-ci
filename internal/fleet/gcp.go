package fleet

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// GCPProvider runs fleet capacity as Compute Engine instances.
type GCPProvider struct {
	name       string
	region     string
	zone       string
	image      string
	machineTyp string
	client     *apiClient
	pool       *cloudPool
}

// NewGCPProvider builds a Compute-Engine-backed provider.
func NewGCPProvider(name, baseURL, token, region, zone, image, machineType string) *GCPProvider {
	if machineType == "" {
		machineType = "e2-medium"
	}
	return &GCPProvider{
		name: name, region: region, zone: zone, image: image,
		machineTyp: machineType,
		client:     newAPIClient(baseURL, "Bearer", token),
		pool:       newCloudPool(),
	}
}

func (g *GCPProvider) Name() string { return g.name }

type gcpInstanceList struct {
	Items []struct {
		Name              string `json:"name"`
		Status            string `json:"status"`
		CreationTimestamp string `json:"creationTimestamp"`
		MachineType       string `json:"machineType"`
		Zone              string `json:"zone"`
	} `json:"items"`
}

func gcpStateToInstance(status string) InstanceState {
	switch strings.ToLower(status) {
	case "running":
		return StateReady
	case "staging", "provisioning", "creating":
		return StatePending
	case "stopping", "suspending":
		return StateDraining
	case "terminated", "stopped":
		return StateTerminated
	default:
		return StatePending
	}
}

func (g *GCPProvider) Capacity(ctx context.Context) (map[string]Capacity, error) {
	var list gcpInstanceList
	path := "/compute/v1/projects/kiwi/zones/" + g.zone + "/instances?filter=labels.kiwi-fleet-provider%3D" + g.name
	if err := g.client.do(ctx, "GET", path, nil, &list); err != nil {
		return nil, err
	}
	out := map[string]Capacity{}
	for _, item := range list.Items {
		profile := "default"
		if p, ok := g.pool.get(item.Name); ok {
			profile = p.Profile
		}
		c := out[profile]
		c.Max++
		switch gcpStateToInstance(item.Status) {
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

func (g *GCPProvider) createInstance(ctx context.Context, p Profile, n int) ([]cloudInstance, error) {
	var out []cloudInstance
	shape := g.machineTyp
	if p.GPU {
		shape = "n1-standard-4"
	}
	for i := 0; i < n; i++ {
		name := fmt.Sprintf("kiwi-%s-%s-%d", g.name, p.Name, time.Now().UnixNano()%1e6)
		body := map[string]any{
			"name":        name,
			"machineType": "zones/" + g.zone + "/machineTypes/" + shape,
			"disks": []map[string]any{{
				"boot":             true,
				"autoDelete":       true,
				"initializeParams": map[string]any{"sourceImage": g.image},
			}},
			"labels": map[string]string{
				"kiwi-fleet-provider": g.name,
				"kiwi-fleet-profile":  p.Name,
			},
		}
		if err := g.client.do(ctx, "POST", "/compute/v1/projects/kiwi/zones/"+g.zone+"/instances", body, nil); err != nil {
			return out, err
		}
		out = append(out, cloudInstance{
			ID: name, Profile: p.Name, Labels: p.Labels,
			Region: p.Region, Arch: p.Architecture,
			State: StatePending, Started: time.Now().UTC(),
			Provider: "gcp",
		})
	}
	return out, nil
}

func (g *GCPProvider) Provision(ctx context.Context, p Profile, want int) ([]Instance, error) {
	return cloudProvision(ctx, g.pool, g, p, want)
}

func (g *GCPProvider) Drain(ctx context.Context, ids []string) error {
	for _, id := range ids {
		if err := g.client.do(ctx, "POST", "/compute/v1/projects/kiwi/zones/"+g.zone+"/instances/"+id+"/stop", nil, nil); err != nil {
			return err
		}
		g.pool.setState(id, StateDraining)
	}
	return nil
}

func (g *GCPProvider) Terminate(ctx context.Context, ids []string) error {
	for _, id := range ids {
		if err := g.client.do(ctx, "DELETE", "/compute/v1/projects/kiwi/zones/"+g.zone+"/instances/"+id, nil, nil); err != nil {
			return err
		}
		g.pool.remove(id)
	}
	return nil
}

func (g *GCPProvider) Cost(ctx context.Context, id string) (float64, error) {
	inst, ok := g.pool.get(id)
	if !ok {
		return 0, fmt.Errorf("fleet/gcp: unknown instance %q", id)
	}
	return inst.Cost, nil
}

func (g *GCPProvider) Capabilities(ctx context.Context, id string) ([]string, error) {
	inst, ok := g.pool.get(id)
	if !ok {
		return nil, fmt.Errorf("fleet/gcp: unknown instance %q", id)
	}
	return append([]string(nil), inst.Labels...), nil
}

func (g *GCPProvider) Attestation(ctx context.Context, id string) ([]byte, error) {
	if _, ok := g.pool.get(id); !ok {
		return nil, fmt.Errorf("fleet/gcp: unknown instance %q", id)
	}
	return []byte(id), nil
}

var (
	_ Provisioner   = (*GCPProvider)(nil)
	_ CountDrainer  = (*GCPProvider)(nil)
	_ HealthScanner = (*GCPProvider)(nil)
	_ cloudCreator  = (*GCPProvider)(nil)
)

func (g *GCPProvider) DrainN(ctx context.Context, profile string, n int) error {
	ids := g.pool.idsIn(profile, StateReady, StatePending)
	if len(ids) > n {
		ids = ids[:n]
	}
	return g.Drain(ctx, ids)
}

func (g *GCPProvider) Unhealthy(ctx context.Context, profile string) ([]string, error) {
	var list gcpInstanceList
	if err := g.client.do(ctx, "GET", "/compute/v1/projects/kiwi/zones/"+g.zone+"/instances", nil, &list); err != nil {
		return nil, err
	}
	var bad []string
	for _, item := range list.Items {
		if strings.EqualFold(item.Status, "terminated") || strings.EqualFold(item.Status, "stopped") {
			bad = append(bad, item.Name)
		}
	}
	return bad, nil
}
