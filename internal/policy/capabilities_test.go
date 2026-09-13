package policy

import (
	"reflect"
	"testing"

	"github.com/kiwici/kiwi/internal/pipeline"
)

func TestDefaultTrustedCapabilities(t *testing.T) {
	c := DefaultTrustedCapabilities()
	if !c.NativeExecution || !c.Container || !c.Tart {
		t.Fatalf("trusted defaults must allow native/container/tart execution: %+v", c)
	}
	if c.Network != pipeline.NetworkPolicyInternet {
		t.Fatalf("trusted default network = %v, want internet", c.Network)
	}
	if c.Secrets != nil {
		t.Fatalf("trusted default secrets must be nil (unrestricted), got %v", c.Secrets)
	}
	if c.OIDC != nil {
		t.Fatalf("trusted default OIDC must be nil (any audience), got %v", c.OIDC)
	}
	if c.Deployments || c.GenerateChildGraph || c.CrossRepoTrigger {
		t.Fatalf("trusted defaults must deny deployments/child-graph/cross-repo: %+v", c)
	}
	if !c.CacheRead || !c.CacheWrite {
		t.Fatalf("trusted defaults must allow cache read/write: %+v", c)
	}
}

func TestDefaultUntrustedCapabilities(t *testing.T) {
	c := DefaultUntrustedCapabilities()
	if c.NativeExecution {
		t.Fatal("untrusted defaults must deny native execution")
	}
	if !c.Container || !c.Tart {
		t.Fatal("untrusted defaults must allow container/tart execution")
	}
	if c.Network != pipeline.NetworkPolicyNone {
		t.Fatalf("untrusted default network = %v, want none", c.Network)
	}
	if c.Secrets == nil || len(c.Secrets) != 0 {
		t.Fatalf("untrusted default secrets must be empty non-nil (deny all), got %v", c.Secrets)
	}
	if c.OIDC == nil || len(c.OIDC) != 0 {
		t.Fatalf("untrusted default OIDC must be empty non-nil (deny all), got %v", c.OIDC)
	}
	if c.Deployments || c.GenerateChildGraph || c.CrossRepoTrigger {
		t.Fatalf("untrusted defaults must deny deployments/child-graph/cross-repo: %+v", c)
	}
	if !c.CacheRead || !c.CacheWrite {
		t.Fatalf("untrusted defaults must allow cache read/write (server scopes namespace): %+v", c)
	}
}

func TestIntersectNetwork(t *testing.T) {
	cases := []struct {
		name string
		a, b pipeline.NetworkPolicy
		want pipeline.NetworkPolicy
	}{
		{"default treated as internet vs services-only", pipeline.NetworkPolicyDefault, pipeline.NetworkPolicyServicesOnly, pipeline.NetworkPolicyServicesOnly},
		{"internet vs none", pipeline.NetworkPolicyInternet, pipeline.NetworkPolicyNone, pipeline.NetworkPolicyNone},
		{"none vs internet", pipeline.NetworkPolicyNone, pipeline.NetworkPolicyInternet, pipeline.NetworkPolicyNone},
		{"internet vs services-only", pipeline.NetworkPolicyInternet, pipeline.NetworkPolicyServicesOnly, pipeline.NetworkPolicyServicesOnly},
		{"services-only vs services-only", pipeline.NetworkPolicyServicesOnly, pipeline.NetworkPolicyServicesOnly, pipeline.NetworkPolicyServicesOnly},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Intersect(Capabilities{Network: tc.a}, Capabilities{Network: tc.b}).Network; got != tc.want {
				t.Fatalf("Intersect(%v, %v).Network = %v, want %v", tc.a, tc.b, got, tc.want)
			}
		})
	}
}

func TestIntersectSets(t *testing.T) {
	base := Capabilities{
		Secrets:      map[string]bool{"a": true, "b": true},
		OIDC:         []string{"x", "y"},
		RunnerLabels: []string{"l1", "l2"},
	}
	restriction := Capabilities{
		Secrets:      map[string]bool{"b": true, "c": true},
		OIDC:         []string{"y", "z"},
		RunnerLabels: []string{"l2", "l3"},
	}
	got := Intersect(base, restriction)
	if want := map[string]bool{"b": true}; !reflect.DeepEqual(got.Secrets, want) {
		t.Fatalf("secrets intersection = %v, want %v", got.Secrets, want)
	}
	if want := []string{"y"}; !reflect.DeepEqual(got.OIDC, want) {
		t.Fatalf("oidc intersection = %v, want %v", got.OIDC, want)
	}
	if want := []string{"l2"}; !reflect.DeepEqual(got.RunnerLabels, want) {
		t.Fatalf("label intersection = %v, want %v", got.RunnerLabels, want)
	}

	nilBase := Intersect(Capabilities{Secrets: nil, OIDC: nil, RunnerLabels: nil}, restriction)
	if !reflect.DeepEqual(nilBase.Secrets, restriction.Secrets) || !reflect.DeepEqual(nilBase.OIDC, restriction.OIDC) || !reflect.DeepEqual(nilBase.RunnerLabels, restriction.RunnerLabels) {
		t.Fatalf("nil base must defer to restriction: %+v", nilBase)
	}
	nilRestriction := Intersect(base, Capabilities{})
	if !reflect.DeepEqual(nilRestriction.Secrets, base.Secrets) || !reflect.DeepEqual(nilRestriction.OIDC, base.OIDC) || !reflect.DeepEqual(nilRestriction.RunnerLabels, base.RunnerLabels) {
		t.Fatalf("nil restriction must defer to base: %+v", nilRestriction)
	}

	empty := Intersect(Capabilities{Secrets: map[string]bool{}, OIDC: []string{}, RunnerLabels: []string{}}, base)
	if empty.Secrets == nil || len(empty.Secrets) != 0 {
		t.Fatalf("empty ∩ base secrets must stay empty non-nil (deny), got %v", empty.Secrets)
	}
	if empty.OIDC == nil || len(empty.OIDC) != 0 {
		t.Fatalf("empty ∩ base oidc must stay empty non-nil (deny), got %v", empty.OIDC)
	}
	if empty.RunnerLabels == nil || len(empty.RunnerLabels) != 0 {
		t.Fatalf("empty ∩ base labels must stay empty non-nil (deny), got %v", empty.RunnerLabels)
	}
}

func TestIntersectCommutativeAndIdempotent(t *testing.T) {
	a := Capabilities{
		NativeExecution: true,
		Container:       true,
		Tart:            false,
		Network:         pipeline.NetworkPolicyServicesOnly,
		Secrets:         map[string]bool{"a": true, "b": true},
		OIDC:            []string{"x", "y"},
		RunnerLabels:    []string{"l1", "l2"},
		Deployments:     true,
		CacheRead:       false,
		CacheWrite:      true,
	}
	b := Capabilities{
		NativeExecution: false,
		Container:       true,
		Tart:            true,
		Network:         pipeline.NetworkPolicyInternet,
		Secrets:         map[string]bool{"b": true, "c": true},
		OIDC:            []string{"y", "z"},
		RunnerLabels:    []string{"l2", "l3"},
		Deployments:     false,
		CacheRead:       true,
		CacheWrite:      true,
	}
	ab := Intersect(a, b)
	ba := Intersect(b, a)
	if !reflect.DeepEqual(ab, ba) {
		t.Fatalf("Intersect not commutative:\n%+v\n%+v", ab, ba)
	}
	if again := Intersect(ab, b); !reflect.DeepEqual(ab, again) {
		t.Fatalf("Intersect not idempotent:\n%+v\n%+v", ab, again)
	}
	if again := Intersect(ab, a); !reflect.DeepEqual(ab, again) {
		t.Fatalf("Intersect not idempotent vs base:\n%+v\n%+v", ab, again)
	}
}

func TestEffectiveTrustedUnchanged(t *testing.T) {
	c := Capabilities{
		NativeExecution: true,
		Container:       false,
		Tart:            true,
		Network:         pipeline.NetworkPolicyNone,
		Secrets:         map[string]bool{"a": true},
		OIDC:            []string{"aud"},
		Deployments:     true,
	}
	if got := c.Effective(true); !reflect.DeepEqual(got, c) {
		t.Fatalf("Effective(true) changed capabilities: %+v", got)
	}
}

func TestEffectiveUntrustedFloor(t *testing.T) {
	c := Capabilities{
		NativeExecution:    true,
		Container:          true,
		Tart:               true,
		Network:            pipeline.NetworkPolicyInternet,
		Secrets:            map[string]bool{"a": true},
		OIDC:               []string{"aud1", "aud2"},
		Deployments:        true,
		CacheRead:          true,
		CacheWrite:         true,
		RunnerLabels:       []string{"linux", "gpu"},
		GenerateChildGraph: true,
		CrossRepoTrigger:   true,
	}
	got := c.Effective(false)
	want := DefaultUntrustedCapabilities()
	want.RunnerLabels = []string{"linux", "gpu"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Effective(false) = %+v, want untrusted floor %+v", got, want)
	}
}

func TestUntrustedFloorCannotBeLifted(t *testing.T) {
	maxed := Capabilities{
		NativeExecution:    true,
		Container:          true,
		Tart:               true,
		Network:            pipeline.NetworkPolicyInternet,
		Secrets:            map[string]bool{"a": true},
		OIDC:               []string{"aud"},
		Deployments:        true,
		GenerateChildGraph: true,
		CrossRepoTrigger:   true,
	}
	floored := maxed.Effective(false)
	if floored.NativeExecution || floored.Network != pipeline.NetworkPolicyNone || floored.Deployments || floored.GenerateChildGraph || floored.CrossRepoTrigger {
		t.Fatalf("untrusted floor lifted by intersection: %+v", floored)
	}
	if floored.Secrets == nil || len(floored.Secrets) != 0 {
		t.Fatalf("untrusted secrets floor lifted: %v", floored.Secrets)
	}
	if floored.OIDC == nil || len(floored.OIDC) != 0 {
		t.Fatalf("untrusted OIDC floor lifted: %v", floored.OIDC)
	}
}

func TestOIDCAllowsSemantics(t *testing.T) {
	trusted := DefaultTrustedCapabilities()
	if !trusted.OIDCAllows("any-audience-at-all") {
		t.Fatal("nil OIDC must allow any audience")
	}
	untrusted := DefaultUntrustedCapabilities()
	if untrusted.OIDCAllows("anything") {
		t.Fatal("empty non-nil OIDC must deny every audience")
	}
	restricted := Capabilities{OIDC: []string{"ci.example.com"}}
	if !restricted.OIDCAllows("ci.example.com") {
		t.Fatal("allowlisted audience must be allowed")
	}
	if restricted.OIDCAllows("evil.example.com") {
		t.Fatal("non-allowlisted audience must be denied")
	}
}
