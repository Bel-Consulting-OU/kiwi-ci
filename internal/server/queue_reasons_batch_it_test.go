package server

// K4-A: the DB fleet-global queue-reason view must resolve every runner's
// live profile binding and reservation sum in TWO set-based queries (one
// binding query, one GROUP BY reservation query) per pass, never with a
// per-runner sequence of link/profile/SUM round trips. This test counts the
// SQL round trips the pass issues and pins the precedence the batched view
// shares with ResolveLiveProfileBinding (cert binding > runner-ID binding >
// registration snapshot, dangling bindings deny).

import (
	"context"
	"sync/atomic"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// fleetQueryCounter counts the SQL round trips a store issues (test tracer).
type fleetQueryCounter struct{ queries atomic.Int64 }

func (q *fleetQueryCounter) TraceQueryStart(ctx context.Context, _ *pgx.Conn, _ pgx.TraceQueryStartData) context.Context {
	q.queries.Add(1)
	return ctx
}

func (q *fleetQueryCounter) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}

var _ pgx.QueryTracer = (*fleetQueryCounter)(nil)

func TestIntegrationQueueReasonFleetBatchedViewPostgres(t *testing.T) {
	env := pgITServerSetup(t)
	ctx := context.Background()
	tracer := &fleetQueryCounter{}
	st, err := storage.NewPostgresOpt(ctx, env.base, func(c *pgxpool.Config) {
		if c.ConnConfig.RuntimeParams == nil {
			c.ConnConfig.RuntimeParams = map[string]string{}
		}
		c.ConnConfig.RuntimeParams["search_path"] = env.schema
		c.ConnConfig.Tracer = tracer
	})
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatalf("NewPersistent: %v", err)
	}
	if err := s.SwitchToDB(st); err != nil {
		t.Fatalf("SwitchToDB: %v", err)
	}
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	newID := func() string { return pgITServerRandomHex(t, 32) }
	profCert, profLink := newID(), newID()

	must(st.UpsertProfile(ctx, model.RunnerProfile{ID: profCert, Labels: []string{"cert"}, Region: "eu", MaxCapacity: 3}))
	must(st.BindCertProfile(ctx, "serial-cert", profCert))
	must(st.UpsertProfile(ctx, model.RunnerProfile{ID: profLink, Labels: []string{"link"}, Region: "us", MaxCapacity: 4}))

	certRunner, linkRunner, dangleCertRunner, dangleLinkRunner, plainRunner := newID(), newID(), newID(), newID(), newID()
	must(st.LinkRunnerProfile(ctx, linkRunner, profLink))
	// Dangling bindings: the bound profile row is gone. Both sources must
	// deny the lease (zero capacity), never resurrect the snapshot.
	must(st.BindCertProfile(ctx, "serial-dangle", "prof-gone"))
	must(st.LinkRunnerProfile(ctx, dangleLinkRunner, "prof-gone"))

	runners := []model.Runner{
		{ID: certRunner, Name: "cert", Capacity: 1, Labels: []string{"snapshot-cert"}, CertSerial: "serial-cert"},
		{ID: linkRunner, Name: "link", Capacity: 1, Labels: []string{"snapshot-link"}},
		{ID: dangleCertRunner, Name: "dangle-cert", Capacity: 1, Labels: []string{"snapshot-dangle-cert"}, CertSerial: "serial-dangle"},
		{ID: dangleLinkRunner, Name: "dangle-link", Capacity: 1, Labels: []string{"snapshot-dangle-link"}},
		{ID: plainRunner, Name: "plain", Capacity: 2, Labels: []string{"plain"}},
	}
	for _, r := range runners {
		must(st.UpsertRunner(ctx, r))
	}

	tracer.queries.Store(0)
	fleet, complete := s.fleetQueueRunnerViewsDB(ctx, runners[4])
	got := tracer.queries.Load()
	t.Logf("fleetQueueRunnerViewsDB issued %d SQL round trips for %d runners", got, len(runners))
	if !complete {
		t.Fatal("fleet view reported incomplete, want complete")
	}
	// ListRunners + the binding batch + the reservation-sum batch. A per-runner
	// resolution (the K4-A defect) issued 15 here.
	if got != 3 {
		t.Fatalf("fleet view issued %d SQL round trips for %d runners, want 3 (list + batched bindings + batched reservation sums)", got, len(runners))
	}
	if len(fleet) != len(runners) {
		t.Fatalf("fleet views = %d, want %d", len(fleet), len(runners))
	}

	// PARITY: every batched view must equal the per-runner live resolution
	// (the same ResolveLiveProfileBinding precedence and the same SUM).
	expected := map[string]queueRunnerView{}
	for _, r := range runners {
		eff := s.Sched.EffectiveRunner(ctx, r)
		res := s.Sched.ReservedResources(ctx, eff.ID)
		key := ""
		if len(eff.Labels) > 0 {
			key = eff.Labels[0]
		}
		expected[key] = queueRunnerView{
			labels:   eff.Labels,
			region:   eff.Region,
			slots:    eff.Capacity,
			active:   len(eff.ActiveJobs),
			capacity: eff.ResourceCapacity,
			reserved: res,
		}
	}
	for _, v := range fleet {
		key := ""
		if len(v.labels) > 0 {
			key = v.labels[0]
		}
		want, ok := expected[key]
		if !ok {
			t.Fatalf("unexpected fleet view %+v", v)
		}
		if len(v.labels) != len(want.labels) || v.region != want.region || v.slots != want.slots || v.active != want.active || v.capacity != want.capacity || v.reserved != want.reserved {
			t.Fatalf("view %q = %+v, want %+v (batched view diverged from the per-runner resolver)", key, v, want)
		}
	}
	// Precedence pins: cert binding beats the snapshot, runner-ID binding
	// applies for bearer runners, both dangling sources deny with zero slots.
	byKey := map[string]queueRunnerView{}
	for _, v := range fleet {
		byKey[v.labels[0]] = v
	}
	if v := byKey["cert"]; v.region != "eu" || v.slots != 3 {
		t.Fatalf("cert-bound view = %+v, want profile labels/region/capacity", v)
	}
	if v := byKey["link"]; v.region != "us" || v.slots != 4 {
		t.Fatalf("runner-ID-bound view = %+v, want profile labels/region/capacity", v)
	}
	if v := byKey["snapshot-dangle-cert"]; v.slots != 0 {
		t.Fatalf("dangling cert view = %+v, want zero slots (deny)", v)
	}
	if v := byKey["snapshot-dangle-link"]; v.slots != 0 {
		t.Fatalf("dangling runner-ID view = %+v, want zero slots (deny)", v)
	}
	if v := byKey["plain"]; v.slots != 2 || v.region != "" {
		t.Fatalf("unbound view = %+v, want registration snapshot", v)
	}
}
