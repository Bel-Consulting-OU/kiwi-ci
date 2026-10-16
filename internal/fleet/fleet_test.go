package fleet

import (
	"context"
	"testing"
)

type fakeProvider struct {
	name string
	inst map[string]Instance
}

func (f *fakeProvider) Name() string { return f.name }
func (f *fakeProvider) Capacity(context.Context) (map[string]Capacity, error) {
	return map[string]Capacity{"pool": {Ready: len(f.inst), Max: 10}}, nil
}
func (f *fakeProvider) Provision(_ context.Context, p Profile, want int) ([]Instance, error) {
	var out []Instance
	for i := 0; i < want; i++ {
		in := Instance{ID: f.name + "-1", Profile: p.Name, State: StateReady, Labels: p.Labels, Region: p.Region, Arch: p.Architecture}
		f.inst[in.ID] = in
		out = append(out, in)
	}
	return out, nil
}
func (f *fakeProvider) Drain(_ context.Context, ids []string) error {
	for _, id := range ids {
		if in, ok := f.inst[id]; ok {
			in.State = StateDraining
			f.inst[id] = in
		}
	}
	return nil
}
func (f *fakeProvider) Terminate(_ context.Context, ids []string) error {
	for _, id := range ids {
		delete(f.inst, id)
	}
	return nil
}
func (f *fakeProvider) Cost(context.Context, string) (float64, error) { return 0.05, nil }
func (f *fakeProvider) Capabilities(context.Context, string) ([]string, error) {
	return []string{"os:linux"}, nil
}
func (f *fakeProvider) Attestation(context.Context, string) ([]byte, error) {
	return []byte("att"), nil
}

// The fleet SPI is the dynamic-capacity seam: providers fulfil profiles and
// the manager never executes work. This pins the interface and the register
// / lookup surface.
func TestManagerRegistersProvisioner(t *testing.T) {
	m := NewManager()
	p := &fakeProvider{name: "fake", inst: map[string]Instance{}}
	_ = m.Register(p)
	got, ok := m.Provider("fake")
	if !ok || got.Name() != "fake" {
		t.Fatal("provider not registered")
	}
	inst, err := got.Provision(context.Background(), Profile{Name: "pool", Labels: []string{"os:linux"}}, 2)
	if err != nil || len(inst) != 2 {
		t.Fatalf("provision = %v %v", inst, err)
	}
	if err := got.Drain(context.Background(), []string{inst[0].ID}); err != nil {
		t.Fatal(err)
	}
	if err := got.Terminate(context.Background(), []string{inst[0].ID, inst[1].ID}); err != nil {
		t.Fatal(err)
	}
	cap, err := got.Capacity(context.Background())
	if err != nil || cap["pool"].Ready != 0 {
		t.Fatalf("capacity after terminate = %v %v", cap, err)
	}
	if _, err := got.Attestation(context.Background(), "x"); err != nil {
		t.Fatal(err)
	}
}
