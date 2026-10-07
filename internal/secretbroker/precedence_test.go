package secretbroker

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// TestClassPrecedenceLattice pins the declared lattice ranks: forbidden and
// unauthorized share the top rank, then malformed, unavailable, not_found.
// Unknown, empty and unrecognized names rank 0 and never participate.
func TestClassPrecedenceLattice(t *testing.T) {
	cases := []struct {
		class string
		want  int
	}{
		{ClassForbidden, 4},
		{ClassUnauthorized, 4},
		{ClassMalformed, 3},
		{FallbackClassUnavailable, 2},
		{FallbackClassNotFound, 1},
		{ClassUnknown, 0},
		{"", 0},
		{"bogus", 0},
	}
	if ClassPrecedence(ClassForbidden) != ClassPrecedence(ClassUnauthorized) {
		t.Fatal("forbidden and unauthorized must share the same top rank")
	}
	for _, tc := range cases {
		if got := ClassPrecedence(tc.class); got != tc.want {
			t.Fatalf("ClassPrecedence(%q) = %d, want %d", tc.class, got, tc.want)
		}
	}

	// Every ranked class maps to a sentinel; unknown/empty names map to nil.
	for _, entry := range classPrecedenceTable {
		if classSentinel(entry.name) != entry.sentinel {
			t.Fatalf("classSentinel(%q) != %v", entry.name, entry.sentinel)
		}
		if entry.rank <= 0 {
			t.Fatalf("ranked entry %q has non-positive rank %d", entry.name, entry.rank)
		}
	}
	if classSentinel(ClassUnknown) != nil || classSentinel("") != nil || classSentinel("bogus") != nil {
		t.Fatal("unrecognized class names must not map to a sentinel")
	}
}

// TestTerminalClassTable pins the pure precedence function: highest class
// wins, order-independent, top-rank ties resolve to forbidden, unclassified
// errors contribute nothing.
func TestTerminalClassTable(t *testing.T) {
	nf := func() error { return classError("a", ErrSecretNotFound, "missing", nil) }
	un := func(cause error) error { return classError("b", ErrUnavailable, "outage", cause) }
	mal := func() error { return classError("c", ErrMalformedResponse, "bad body", nil) }
	forb := func() error { return classError("d", ErrForbidden, "denied", nil) }
	unauth := func() error { return classError("e", ErrUnauthorized, "expired", nil) }
	plain := errors.New("boom")

	cases := []struct {
		label string
		errs  []error
		want  error
		class string
	}{
		{"no errors", nil, nil, ""},
		{"unclassified only", []error{plain}, nil, ""},
		{"not_found only", []error{nf()}, ErrSecretNotFound, FallbackClassNotFound},
		{"unavailable only", []error{un(nil)}, ErrUnavailable, FallbackClassUnavailable},
		{"not_found + unavailable", []error{nf(), un(nil)}, ErrUnavailable, FallbackClassUnavailable},
		{"unavailable + not_found (order independent)", []error{un(nil), nf()}, ErrUnavailable, FallbackClassUnavailable},
		{"not_found + not_found", []error{nf(), nf()}, ErrSecretNotFound, FallbackClassNotFound},
		{"not_found + unavailable + malformed", []error{nf(), un(nil), mal()}, ErrMalformedResponse, ClassMalformed},
		{"malformed + not_found", []error{mal(), nf()}, ErrMalformedResponse, ClassMalformed},
		{"unavailable + malformed", []error{un(nil), mal()}, ErrMalformedResponse, ClassMalformed},
		{"forbidden + malformed", []error{forb(), mal()}, ErrForbidden, ClassForbidden},
		{"unauthorized + not_found", []error{unauth(), nf()}, ErrUnauthorized, ClassUnauthorized},
		{"forbidden + unauthorized (tie resolves to forbidden)", []error{unauth(), forb()}, ErrForbidden, ClassForbidden},
		{"unclassified + not_found", []error{plain, nf()}, ErrSecretNotFound, FallbackClassNotFound},
	}
	for _, tc := range cases {
		t.Run(tc.label, func(t *testing.T) {
			got := terminalClass(tc.errs)
			if got != tc.want {
				t.Fatalf("terminalClass = %v, want %v", got, tc.want)
			}
			if tc.class != "" && ErrorClass(got) != tc.class {
				t.Fatalf("ErrorClass(terminalClass) = %q, want %q", ErrorClass(got), tc.class)
			}
			// The winner must carry the maximum member rank.
			wantRank := 0
			for _, e := range tc.errs {
				if rank := ClassPrecedence(ErrorClass(e)); rank > wantRank {
					wantRank = rank
				}
			}
			gotRank := 0
			if got != nil {
				gotRank = ClassPrecedence(ErrorClass(got))
			}
			if gotRank != wantRank {
				t.Fatalf("winner rank = %d, want the maximum member rank %d", gotRank, wantRank)
			}
		})
	}
}

// TestErrorClassOnExhaustionAggregate pins telemetry on a real aggregate:
// ErrorClass reports the highest-precedence class even though errors.Is
// matches every member class and cause.
func TestErrorClassOnExhaustionAggregate(t *testing.T) {
	nf := classError("vault", ErrSecretNotFound, "absent", nil)
	un := classError("aws", ErrUnavailable, "outage", context.DeadlineExceeded)
	mal := classError("gcp", ErrMalformedResponse, "bad body", nil)
	forbidden := classError("azure", ErrForbidden, "denied", nil)

	cases := []struct {
		label       string
		errs        []error
		want        string
		hasDeadline bool
	}{
		{"all not_found", []error{nf, nf}, FallbackClassNotFound, false},
		{"not_found + unavailable", []error{nf, un}, FallbackClassUnavailable, true},
		{"unavailable + not_found", []error{un, nf}, FallbackClassUnavailable, true},
		{"not_found + unavailable + malformed", []error{nf, un, mal}, ClassMalformed, true},
		{"forbidden outranks everything", []error{nf, un, mal, forbidden}, ClassForbidden, true},
	}
	for _, tc := range cases {
		t.Run(tc.label, func(t *testing.T) {
			aggregate := classError("chain", terminalClass(tc.errs), "exhausted",
				errors.Join(tc.errs...))
			if got := ErrorClass(aggregate); got != tc.want {
				t.Fatalf("ErrorClass = %q, want %q", got, tc.want)
			}
			for _, member := range tc.errs {
				if !errors.Is(aggregate, member) {
					t.Fatalf("aggregate no longer matches member cause %v", member)
				}
				if !errors.Is(aggregate, classSentinel(ErrorClass(member))) {
					t.Fatalf("aggregate no longer matches class %s", ErrorClass(member))
				}
			}
			if tc.hasDeadline && !errors.Is(aggregate, context.DeadlineExceeded) {
				t.Fatal("aggregate lost the underlying deadline cause")
			}
		})
	}
}

// TestChainExhaustionPrecedence pins the exhausted-chain semantics: when
// every broker fails with a fallback-allowed class, the aggregate takes the
// highest-precedence encountered class while still matching each member.
func TestChainExhaustionPrecedence(t *testing.T) {
	policy := []string{FallbackClassNotFound, FallbackClassUnavailable}
	nf := func() Broker {
		return &callCountBroker{err: classError("gone", ErrSecretNotFound, "secret absent", nil)}
	}
	un := func(cause error) Broker {
		return &callCountBroker{err: classError("outage", ErrUnavailable, "provider unavailable", cause)}
	}

	cases := []struct {
		label     string
		brokers   []Broker
		fallback  []string
		want      error
		wantClass string
		wantIs    []error
		wantNotIs []error
	}{
		{
			label:     "not_found then unavailable",
			brokers:   []Broker{nf(), un(nil)},
			fallback:  policy,
			want:      ErrUnavailable,
			wantClass: FallbackClassUnavailable,
			wantIs:    []error{ErrSecretNotFound, ErrUnavailable},
		},
		{
			label:     "unavailable then not_found",
			brokers:   []Broker{un(nil), nf()},
			fallback:  policy,
			want:      ErrUnavailable,
			wantClass: FallbackClassUnavailable,
			wantIs:    []error{ErrSecretNotFound, ErrUnavailable},
		},
		{
			label:     "all not_found keeps not_found",
			brokers:   []Broker{nf(), nf()},
			fallback:  nil,
			want:      ErrSecretNotFound,
			wantClass: FallbackClassNotFound,
			wantIs:    []error{ErrSecretNotFound},
			wantNotIs: []error{ErrUnavailable},
		},
		{
			label:     "three unavailable",
			brokers:   []Broker{un(nil), un(nil), un(nil)},
			fallback:  policy,
			want:      ErrUnavailable,
			wantClass: FallbackClassUnavailable,
			wantIs:    []error{ErrUnavailable},
			wantNotIs: []error{ErrSecretNotFound},
		},
	}
	for _, tc := range cases {
		t.Run(tc.label, func(t *testing.T) {
			v, err := (&ChainBroker{Brokers: tc.brokers, FallbackOn: tc.fallback}).
				Resolve(context.Background(), "K", SecretScope{})
			if v != "" {
				t.Fatalf("exhausted chain delivered %q", v)
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			if got := ErrorClass(err); got != tc.wantClass {
				t.Fatalf("ErrorClass = %q, want %q", got, tc.wantClass)
			}
			for _, want := range tc.wantIs {
				if !errors.Is(err, want) {
					t.Fatalf("exhausted aggregate lost class %v", want)
				}
			}
			for _, notWant := range tc.wantNotIs {
				if errors.Is(err, notWant) {
					t.Fatalf("exhausted aggregate falsely matched %v", notWant)
				}
			}
			if !strings.Contains(err.Error(), "chain exhausted") {
				t.Fatalf("error does not name the exhaustion: %v", err)
			}
		})
	}

	t.Run("underlying cause survives exhaustion", func(t *testing.T) {
		deadline := classError("outage", ErrUnavailable, "request failed", context.DeadlineExceeded)
		chain := ChainBroker{
			Brokers:    []Broker{nf(), &callCountBroker{err: deadline}},
			FallbackOn: policy,
		}
		_, err := chain.Resolve(context.Background(), "K", SecretScope{})
		if !errors.Is(err, ErrUnavailable) || !errors.Is(err, ErrSecretNotFound) || !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("err = %v, want ErrUnavailable + ErrSecretNotFound + DeadlineExceeded", err)
		}
		if got := ErrorClass(err); got != FallbackClassUnavailable {
			t.Fatalf("ErrorClass = %q, want %q", got, FallbackClassUnavailable)
		}
	})

	t.Run("empty chain still yields not_found", func(t *testing.T) {
		_, err := ChainBroker{Brokers: []Broker{nil}}.Resolve(context.Background(), "K", SecretScope{})
		if !errors.Is(err, ErrSecretNotFound) {
			t.Fatalf("empty chain err = %v, want ErrSecretNotFound", err)
		}
		if got := ErrorClass(err); got != FallbackClassNotFound {
			t.Fatalf("ErrorClass = %q, want %q", got, FallbackClassNotFound)
		}
	})
}

// TestChainEarlyStopBeatsPrecedence pins that a non-fallback class stops the
// chain and keeps its own class, so precedence never rewrites an early stop.
func TestChainEarlyStopBeatsPrecedence(t *testing.T) {
	policy := []string{FallbackClassNotFound, FallbackClassUnavailable}

	t.Run("malformed after fallbacks", func(t *testing.T) {
		nf := &callCountBroker{err: classError("gone", ErrSecretNotFound, "absent", nil)}
		un := &callCountBroker{err: classError("outage", ErrUnavailable, "outage", nil)}
		mal := &callCountBroker{err: classError("bad", ErrMalformedResponse, "bad body", nil)}
		later := &callCountBroker{value: "later"}
		chain := ChainBroker{Brokers: []Broker{nf, un, mal, later}, FallbackOn: policy}
		v, err := chain.Resolve(context.Background(), "K", SecretScope{})
		if !errors.Is(err, ErrMalformedResponse) {
			t.Fatalf("err = %v, want ErrMalformedResponse", err)
		}
		if errors.Is(err, ErrUnavailable) || errors.Is(err, ErrSecretNotFound) {
			t.Fatalf("early stop leaked a lower-precedence class: %v", err)
		}
		if got := ErrorClass(err); got != ClassMalformed {
			t.Fatalf("ErrorClass = %q, want %q", got, ClassMalformed)
		}
		if v != "" || later.calls.Load() != 0 {
			t.Fatalf("chain continued past malformed: value=%q later calls=%d", v, later.calls.Load())
		}
		if !strings.Contains(err.Error(), "chain stopped") {
			t.Fatalf("early-stop annotation lost: %v", err)
		}
	})

	t.Run("unclassified stops as-is", func(t *testing.T) {
		boom := errors.New("boom")
		first := &callCountBroker{err: boom}
		later := &callCountBroker{value: "later"}
		chain := ChainBroker{Brokers: []Broker{first, later}, FallbackOn: policy}
		v, err := chain.Resolve(context.Background(), "K", SecretScope{})
		if !errors.Is(err, boom) {
			t.Fatalf("err = %v, want the unclassified cause preserved", err)
		}
		if errors.Is(err, ErrSecretNotFound) || errors.Is(err, ErrUnavailable) {
			t.Fatalf("unclassified error was masked by a class: %v", err)
		}
		if got := ErrorClass(err); got != ClassUnknown {
			t.Fatalf("ErrorClass = %q, want %q", got, ClassUnknown)
		}
		if v != "" || later.calls.Load() != 0 {
			t.Fatalf("chain continued past an unclassified failure: value=%q later calls=%d", v, later.calls.Load())
		}
		if !strings.Contains(err.Error(), "chain stopped") {
			t.Fatalf("early-stop annotation lost: %v", err)
		}
	})

	t.Run("nested chain preserves outage over absence", func(t *testing.T) {
		inner := ChainBroker{
			Brokers: []Broker{
				&callCountBroker{err: classError("gone", ErrSecretNotFound, "absent", nil)},
				&callCountBroker{err: classError("outage", ErrUnavailable, "outage", nil)},
			},
			FallbackOn: policy,
		}
		later := &callCountBroker{value: "later"}
		outer := ChainBroker{Brokers: []Broker{inner, later}} // default [not_found]
		v, err := outer.Resolve(context.Background(), "K", SecretScope{})
		if !errors.Is(err, ErrUnavailable) {
			t.Fatalf("outer err = %v, want the nested ErrUnavailable to fail closed", err)
		}
		if got := ErrorClass(err); got != FallbackClassUnavailable {
			t.Fatalf("ErrorClass = %q, want %q", got, FallbackClassUnavailable)
		}
		if v != "" || later.calls.Load() != 0 {
			t.Fatalf("outer chain fell back across an outage: value=%q later calls=%d", v, later.calls.Load())
		}
	})
}
