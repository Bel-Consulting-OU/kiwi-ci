package fleet

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// AzureProvider runs fleet capacity as Azure VMs.
// EXPERIMENTAL — not production cloud support. The provider speaks the
// real API shape but has not been certified against live disposable
// resources. Frozen scope: cloud/fleet autoscaling is optional and does
// not block a core release. Do not advertise this as production-ready.
type AzureProvider struct {
	name     string
	subID    string
	rg       string
	location string
	image    string
	vmSize   string
	client   *apiClient
	pool     *cloudPool
}

// NewAzureProvider builds an Azure-VM-backed provider.
func NewAzureProvider(name, baseURL, token, subscription, resourceGroup, location, image, vmSize string) *AzureProvider {
	if vmSize == "" {
		vmSize = "Standard_B2s"
	}
	return &AzureProvider{
		name: name, subID: subscription, rg: resourceGroup,
		location: location, image: image, vmSize: vmSize,
		client: newAPIClient(baseURL, "Bearer", token),
		pool:   newCloudPool(),
	}
}

func (a *AzureProvider) Name() string { return a.name }

type azureVMList struct {
	Value []struct {
		Name       string `json:"name"`
		Location   string `json:"location"`
		Properties struct {
			ProvisioningState string `json:"provisioningState"`
		} `json:"properties"`
	} `json:"value"`
}

func azureStateToInstance(s string) InstanceState {
	switch strings.ToLower(s) {
	case "succeeded":
		return StateReady
	case "creating", "updating":
		return StatePending
	case "deleting":
		return StateDraining
	default:
		return StatePending
	}
}

func (a *AzureProvider) Capacity(ctx context.Context) (map[string]Capacity, error) {
	var list azureVMList
	path := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Compute/virtualMachines?api-version=2023-09-01", a.subID, a.rg)
	if err := a.client.do(ctx, "GET", path, nil, &list); err != nil {
		return nil, err
	}
	out := map[string]Capacity{}
	for _, vm := range list.Value {
		profile := "default"
		if p, ok := a.pool.get(vm.Name); ok {
			profile = p.Profile
		}
		c := out[profile]
		c.Max++
		switch azureStateToInstance(vm.Properties.ProvisioningState) {
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

func (a *AzureProvider) createInstance(ctx context.Context, p Profile, n int) ([]cloudInstance, error) {
	var out []cloudInstance
	size := a.vmSize
	if p.GPU {
		size = "Standard_NC6s_v3"
	}
	for i := 0; i < n; i++ {
		name := fmt.Sprintf("kiwi-%s-%s-%d", a.name, p.Name, time.Now().UnixNano()%1e6)
		body := map[string]any{
			"location": a.location,
			"properties": map[string]any{
				"hardwareProfile": map[string]any{"vmSize": size},
				"storageProfile": map[string]any{
					"imageReference": map[string]any{"id": a.image},
				},
			},
			"tags": map[string]string{
				"kiwi.fleet.provider": a.name,
				"kiwi.fleet.profile":  p.Name,
			},
		}
		path := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Compute/virtualMachines/%s?api-version=2023-09-01", a.subID, a.rg, name)
		if err := a.client.do(ctx, "PUT", path, body, nil); err != nil {
			return out, err
		}
		out = append(out, cloudInstance{
			ID: name, Profile: p.Name, Labels: p.Labels,
			Region: p.Region, Arch: p.Architecture,
			State: StatePending, Started: time.Now().UTC(),
			Provider: "azure",
		})
	}
	return out, nil
}

func (a *AzureProvider) Provision(ctx context.Context, p Profile, want int) ([]Instance, error) {
	return cloudProvision(ctx, a.pool, a, p, want)
}

func (a *AzureProvider) Drain(ctx context.Context, ids []string) error {
	for _, id := range ids {
		path := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Compute/virtualMachines/%s/deallocate?api-version=2023-09-01", a.subID, a.rg, id)
		if err := a.client.do(ctx, "POST", path, nil, nil); err != nil {
			return err
		}
		a.pool.setState(id, StateDraining)
	}
	return nil
}

func (a *AzureProvider) Terminate(ctx context.Context, ids []string) error {
	for _, id := range ids {
		path := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Compute/virtualMachines/%s?api-version=2023-09-01", a.subID, a.rg, id)
		if err := a.client.do(ctx, "DELETE", path, nil, nil); err != nil {
			return err
		}
		a.pool.remove(id)
	}
	return nil
}

func (a *AzureProvider) Cost(ctx context.Context, id string) (float64, error) {
	inst, ok := a.pool.get(id)
	if !ok {
		return 0, fmt.Errorf("fleet/azure: unknown instance %q", id)
	}
	return inst.Cost, nil
}

func (a *AzureProvider) Capabilities(ctx context.Context, id string) ([]string, error) {
	inst, ok := a.pool.get(id)
	if !ok {
		return nil, fmt.Errorf("fleet/azure: unknown instance %q", id)
	}
	return append([]string(nil), inst.Labels...), nil
}

func (a *AzureProvider) Attestation(ctx context.Context, id string) ([]byte, error) {
	if _, ok := a.pool.get(id); !ok {
		return nil, fmt.Errorf("fleet/azure: unknown instance %q", id)
	}
	return []byte(id), nil
}

var (
	_ Provisioner   = (*AzureProvider)(nil)
	_ CountDrainer  = (*AzureProvider)(nil)
	_ HealthScanner = (*AzureProvider)(nil)
	_ cloudCreator  = (*AzureProvider)(nil)
)

func (a *AzureProvider) DrainN(ctx context.Context, profile string, n int) error {
	ids := a.pool.idsIn(profile, StateReady, StatePending)
	if len(ids) > n {
		ids = ids[:n]
	}
	return a.Drain(ctx, ids)
}

func (a *AzureProvider) Unhealthy(ctx context.Context, profile string) ([]string, error) {
	var list azureVMList
	path := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Compute/virtualMachines?api-version=2023-09-01", a.subID, a.rg)
	if err := a.client.do(ctx, "GET", path, nil, &list); err != nil {
		return nil, err
	}
	var bad []string
	for _, vm := range list.Value {
		if strings.EqualFold(vm.Properties.ProvisioningState, "failed") {
			bad = append(bad, vm.Name)
		}
	}
	return bad, nil
}
