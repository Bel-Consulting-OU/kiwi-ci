package fleet

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// AWSProvider runs fleet capacity as EC2 instances. It speaks the EC2
// Query API shape through the cloud.go seam (base URL is the regional
// endpoint); the instance-id is the fleet ID.
// EXPERIMENTAL — not production cloud support. The provider speaks the
// real API shape but has not been certified against live disposable
// resources. Frozen scope: cloud/fleet autoscaling is optional and does
// not block a core release. Do not advertise this as production-ready.
type AWSProvider struct {
	name        string
	region      string
	ami         string
	instanceTyp string
	client      *apiClient
	pool        *cloudPool
}

// NewAWSProvider builds an EC2-backed provider. instanceType is the default
// shape; a Profile.MemoryBytes/GPU may select a different one later.
func NewAWSProvider(name, baseURL, token, region, ami, instanceType string) *AWSProvider {
	if instanceType == "" {
		instanceType = "t3.medium"
	}
	return &AWSProvider{
		name:        name,
		region:      region,
		ami:         ami,
		instanceTyp: instanceType,
		client:      newAPIClient(baseURL, "Bearer", token),
		pool:        newCloudPool(),
	}
}

func (a *AWSProvider) Name() string { return a.name }

type awsInstanceList struct {
	Reservations []struct {
		Instances []struct {
			InstanceID string `json:"InstanceId"`
			State      struct {
				Name string `json:"Name"`
			} `json:"State"`
			LaunchTime string            `json:"LaunchTime"`
			Tags       map[string]string `json:"-"`
			Placement  struct {
				AvailabilityZone string `json:"AvailabilityZone"`
			} `json:"Placement"`
			Architecture string `json:"Architecture"`
		} `json:"Instances"`
	} `json:"Reservations"`
}

func awsStateToInstance(name string) InstanceState {
	switch strings.ToLower(name) {
	case "running":
		return StateReady
	case "pending", "initializing", "rebooting":
		return StatePending
	case "stopping", "shutting-down", "stopped":
		return StateDraining
	case "terminated":
		return StateTerminated
	default:
		return StatePending
	}
}

// Capacity lists instances labeled kiwi:fleet:provider=<name>.
func (a *AWSProvider) Capacity(ctx context.Context) (map[string]Capacity, error) {
	var list awsInstanceList
	path := "/?Action=DescribeInstances&Version=2016-11-15&Filter.1.Name=tag:kiwi.fleet.provider&Filter.1.Value=" + a.name
	if err := a.client.do(ctx, "GET", path, nil, &list); err != nil {
		return nil, err
	}
	out := map[string]Capacity{}
	for _, r := range list.Reservations {
		for _, inst := range r.Instances {
			// Profile is carried in a tag; the JSON shim above collapses
			// tags, so fall back to the pool's own view when present.
			profile := "default"
			if p, ok := a.pool.get(inst.InstanceID); ok {
				profile = p.Profile
			}
			c := out[profile]
			c.Max++
			switch awsStateToInstance(inst.State.Name) {
			case StateReady:
				c.Ready++
			case StatePending:
				c.Pending++
			default:
				c.Draining++
			}
			out[profile] = c
		}
	}
	return out, nil
}

func (a *AWSProvider) createInstance(ctx context.Context, p Profile, n int) ([]cloudInstance, error) {
	var out []cloudInstance
	shape := a.instanceTyp
	if p.GPU {
		shape = "g4dn.xlarge"
	}
	for i := 0; i < n; i++ {
		body := map[string]any{
			"ImageId":      a.ami,
			"InstanceType": shape,
			"TagSpecifications": []map[string]any{{
				"ResourceType": "instance",
				"Tags": map[string]string{
					"kiwi.fleet.provider": a.name,
					"kiwi.fleet.profile":  p.Name,
				},
			}},
		}
		var resp struct {
			Instances []struct {
				InstanceID string `json:"InstanceId"`
			} `json:"Instances"`
		}
		if err := a.client.do(ctx, "POST", "/?Action=RunInstances&Version=2016-11-15", body, &resp); err != nil {
			return out, err
		}
		// A create that reports success WITHOUT a provider-native instance
		// id is unknown, not success. Fabricating an internal id would
		// produce a phantom instance the pool tracks but the cloud never
		// created. Fail closed.
		if len(resp.Instances) == 0 || resp.Instances[0].InstanceID == "" {
			return out, fmt.Errorf("fleet/aws: RunInstances succeeded without an instance id; refusing to fabricate one")
		}
		out = append(out, cloudInstance{
			ID: resp.Instances[0].InstanceID, Profile: p.Name, Labels: p.Labels,
			Region: p.Region, Arch: p.Architecture,
			State: StatePending, Started: time.Now().UTC(),
			Provider: "aws",
		})
	}
	return out, nil
}

func (a *AWSProvider) Provision(ctx context.Context, p Profile, want int) ([]Instance, error) {
	return cloudProvision(ctx, a.pool, a, p, want)
}

func (a *AWSProvider) Drain(ctx context.Context, ids []string) error {
	for _, id := range ids {
		if err := a.client.do(ctx, "POST", "/?Action=StopInstances&Version=2016-11-15", map[string]any{"InstanceId": id}, nil); err != nil {
			return err
		}
		a.pool.setState(id, StateDraining)
	}
	return nil
}

func (a *AWSProvider) Terminate(ctx context.Context, ids []string) error {
	for _, id := range ids {
		if err := a.client.do(ctx, "POST", "/?Action=TerminateInstances&Version=2016-11-15", map[string]any{"InstanceId": id}, nil); err != nil {
			return err
		}
		a.pool.remove(id)
	}
	return nil
}

func (a *AWSProvider) Cost(ctx context.Context, id string) (float64, error) {
	inst, ok := a.pool.get(id)
	if !ok {
		return 0, fmt.Errorf("fleet/aws: unknown instance %q", id)
	}
	return inst.Cost, nil
}

func (a *AWSProvider) Capabilities(ctx context.Context, id string) ([]string, error) {
	inst, ok := a.pool.get(id)
	if !ok {
		return nil, fmt.Errorf("fleet/aws: unknown instance %q", id)
	}
	return append([]string(nil), inst.Labels...), nil
}

// Attestation returns the instance id as weak identity evidence (a real
// deployment would return the instance identity document).
func (a *AWSProvider) Attestation(ctx context.Context, id string) ([]byte, error) {
	if _, ok := a.pool.get(id); !ok {
		return nil, fmt.Errorf("fleet/aws: unknown instance %q", id)
	}
	return []byte(id), nil
}

var (
	_ Provisioner   = (*AWSProvider)(nil)
	_ CountDrainer  = (*AWSProvider)(nil)
	_ HealthScanner = (*AWSProvider)(nil)
	_ cloudCreator  = (*AWSProvider)(nil)
)

func (a *AWSProvider) DrainN(ctx context.Context, profile string, n int) error {
	ids := a.pool.idsIn(profile, StateReady, StatePending)
	if len(ids) > n {
		ids = ids[:n]
	}
	return a.Drain(ctx, ids)
}

func (a *AWSProvider) Unhealthy(ctx context.Context, profile string) ([]string, error) {
	var list awsInstanceList
	path := "/?Action=DescribeInstances&Version=2016-11-15&Filter.1.Name=tag:kiwi.fleet.profile&Filter.1.Value=" + profile
	if err := a.client.do(ctx, "GET", path, nil, &list); err != nil {
		return nil, err
	}
	var bad []string
	for _, r := range list.Reservations {
		for _, inst := range r.Instances {
			if strings.EqualFold(inst.State.Name, "stopped") || strings.EqualFold(inst.State.Name, "terminated") {
				bad = append(bad, inst.InstanceID)
			}
		}
	}
	return bad, nil
}
