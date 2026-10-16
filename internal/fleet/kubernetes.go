package fleet

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// KubernetesProvider runs fleet capacity as ephemeral runner pods. It talks
// to the API server over HTTPS with a bearer token (a service account or an
// operator token); no client-go dependency — the shapes it needs are small
// and the cloud.go seam covers the transport.
type KubernetesProvider struct {
	name   string
	ns     string
	image  string
	client *apiClient
	pool   *cloudPool
}

// NewKubernetesProvider builds a pod-backed provider.
func NewKubernetesProvider(name, baseURL, token, namespace, image string) *KubernetesProvider {
	return &KubernetesProvider{
		name:   name,
		ns:     namespace,
		image:  image,
		client: newAPIClient(baseURL, "Bearer", token),
		pool:   newCloudPool(),
	}
}

func (k *KubernetesProvider) Name() string { return k.name }

// podList is the subset of a PodList the provider reads.
type podList struct {
	Items []podItem `json:"items"`
}

type podItem struct {
	Metadata struct {
		Name   string            `json:"name"`
		Labels map[string]string `json:"labels"`
	} `json:"metadata"`
	Status struct {
		Phase             string `json:"phase"`
		StartTime         string `json:"startTime"`
		ContainerStatuses []struct {
			State map[string]struct {
				StartedAt string `json:"startedAt"`
			} `json:"state"`
		} `json:"containerStatuses"`
	} `json:"status"`
}

func podStateToInstance(phase string) InstanceState {
	switch strings.ToLower(phase) {
	case "running":
		return StateReady
	case "pending":
		return StatePending
	case "succeeded", "failed":
		return StateTerminated
	default:
		return StatePending
	}
}

// Capacity lists pods labeled kiwi.fleet.provider=<name>.
func (k *KubernetesProvider) Capacity(ctx context.Context) (map[string]Capacity, error) {
	var list podList
	path := fmt.Sprintf("/api/v1/namespaces/%s/pods?labelSelector=kiwi.fleet.provider%%3D%s", k.ns, k.name)
	if err := k.client.do(ctx, "GET", path, nil, &list); err != nil {
		return nil, err
	}
	out := map[string]Capacity{}
	for _, item := range list.Items {
		profile := item.Metadata.Labels["kiwi.fleet.profile"]
		if profile == "" {
			continue
		}
		c := out[profile]
		c.Max++
		switch podStateToInstance(item.Status.Phase) {
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

// createInstance starts n pods for the profile (cloudProvision's creator).
func (k *KubernetesProvider) createInstance(ctx context.Context, p Profile, n int) ([]cloudInstance, error) {
	var out []cloudInstance
	for i := 0; i < n; i++ {
		name := fmt.Sprintf("kiwi-%s-%s-%d", k.name, p.Name, time.Now().UnixNano()%1e6)
		body := map[string]any{
			"apiVersion": "v1",
			"kind":       "Pod",
			"metadata": map[string]any{
				"name":      name,
				"namespace": k.ns,
				"labels": map[string]string{
					"kiwi.fleet.provider": k.name,
					"kiwi.fleet.profile":  p.Name,
				},
			},
			"spec": map[string]any{
				"restartPolicy": "Never",
				"containers": []map[string]any{{
					"name":  "runner",
					"image": k.image,
					"args":  []string{"sleep", "infinity"},
				}},
			},
		}
		if err := k.client.do(ctx, "POST", "/api/v1/namespaces/"+k.ns+"/pods", body, nil); err != nil {
			return out, err
		}
		out = append(out, cloudInstance{
			ID: name, Profile: p.Name, Labels: p.Labels,
			Region: p.Region, Arch: p.Architecture,
			State: StatePending, Started: time.Now().UTC(),
			Provider: "kubernetes",
		})
	}
	return out, nil
}

// Provision starts pods.
func (k *KubernetesProvider) Provision(ctx context.Context, p Profile, want int) ([]Instance, error) {
	return cloudProvision(ctx, k.pool, k, p, want)
}

// Drain deletes pods gracefully (DELETE with grace period).
func (k *KubernetesProvider) Drain(ctx context.Context, ids []string) error {
	for _, id := range ids {
		path := fmt.Sprintf("/api/v1/namespaces/%s/pods/%s?gracePeriodSeconds=30", k.ns, id)
		if err := k.client.do(ctx, "DELETE", path, nil, nil); err != nil {
			return err
		}
		k.pool.setState(id, StateDraining)
	}
	return nil
}

// Terminate force-deletes pods.
func (k *KubernetesProvider) Terminate(ctx context.Context, ids []string) error {
	for _, id := range ids {
		path := fmt.Sprintf("/api/v1/namespaces/%s/pods/%s?gracePeriodSeconds=0", k.ns, id)
		if err := k.client.do(ctx, "DELETE", path, nil, nil); err != nil {
			return err
		}
		k.pool.remove(id)
	}
	return nil
}

// Cost is not reported by Kubernetes; returns 0.
func (k *KubernetesProvider) Cost(context.Context, string) (float64, error) { return 0, nil }

// Capabilities returns the profile labels recorded at provision time.
func (k *KubernetesProvider) Capabilities(_ context.Context, id string) ([]string, error) {
	inst, ok := k.pool.get(id)
	if !ok {
		return nil, fmt.Errorf("fleet/kubernetes: unknown instance %q", id)
	}
	return append([]string(nil), inst.Labels...), nil
}

// Attestation returns the pod UID as weak identity evidence.
func (k *KubernetesProvider) Attestation(ctx context.Context, id string) ([]byte, error) {
	var item podItem
	path := fmt.Sprintf("/api/v1/namespaces/%s/pods/%s", k.ns, id)
	if err := k.client.do(ctx, "GET", path, nil, &item); err != nil {
		return nil, err
	}
	return []byte(item.Metadata.Name), nil
}

var (
	_ Provisioner   = (*KubernetesProvider)(nil)
	_ CountDrainer  = (*KubernetesProvider)(nil)
	_ HealthScanner = (*KubernetesProvider)(nil)
	_ cloudCreator  = (*KubernetesProvider)(nil)
)

// DrainN deletes n pods of the named profile.
func (k *KubernetesProvider) DrainN(ctx context.Context, profile string, n int) error {
	ids := k.pool.idsIn(profile, StateReady, StatePending)
	if len(ids) > n {
		ids = ids[:n]
	}
	return k.Drain(ctx, ids)
}

// Unhealthy reports pods that are Failed or stuck Pending.
func (k *KubernetesProvider) Unhealthy(ctx context.Context, profile string) ([]string, error) {
	var list podList
	path := fmt.Sprintf("/api/v1/namespaces/%s/pods?labelSelector=kiwi.fleet.provider%%3D%s,kiwi.fleet.profile%%3D%s", k.ns, k.name, profile)
	if err := k.client.do(ctx, "GET", path, nil, &list); err != nil {
		return nil, err
	}
	var bad []string
	for _, item := range list.Items {
		phase := strings.ToLower(item.Status.Phase)
		if phase == "failed" {
			bad = append(bad, item.Metadata.Name)
		}
	}
	return bad, nil
}
