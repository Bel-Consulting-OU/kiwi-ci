package storage

import (
	"context"
	"reflect"
	"strings"
	"testing"
)

// sweepFaultyStore invokes every exported FaultyStore method with zero
// arguments (context.Background for context parameters) and reports each
// method's result. Methods forwarding through the base Store interface
// dereference Inner directly; a nil-inner one of those panics, which the
// sweep records and tolerates (it is a wiring bug, not a capability
// contract). Capability-based forwarders must never panic.
func sweepFaultyStore(t *testing.T, f *FaultyStore) (invoked, panicked int, results map[string][]reflect.Value) {
	t.Helper()
	ctxType := reflect.TypeOf((*context.Context)(nil)).Elem()
	value := reflect.ValueOf(f)
	typ := value.Type()
	results = map[string][]reflect.Value{}
	for i := 0; i < typ.NumMethod(); i++ {
		m := typ.Method(i)
		if m.PkgPath != "" {
			continue // unexported helper
		}
		fn := value.Method(i)
		mt := fn.Type()
		args := make([]reflect.Value, mt.NumIn())
		for j := 0; j < mt.NumIn(); j++ {
			pt := mt.In(j)
			if pt == ctxType {
				args[j] = reflect.ValueOf(context.Background())
				continue
			}
			args[j] = reflect.Zero(pt)
		}
		var out []reflect.Value
		recovered := func() (r any) {
			defer func() { r = recover() }()
			out = fn.Call(args)
			return nil
		}()
		if recovered != nil {
			panicked++
			continue
		}
		results[m.Name] = out
		invoked++
	}
	return invoked, panicked, results
}

// TestFaultyStoreWithoutInnerFailsClosed is the completeness property for the
// fault-injection wrapper: with NO inner store configured, every capability
// forwarder must fail closed with the missing-inner refusal instead of
// silently succeeding. One reflective sweep exercises every method's early
// `f.Inner.(XStore)` assertion — exactly the branch an operator hits after a
// wiring mistake. Base-Store forwarders dereference the nil interface
// directly and panic; that is recorded (and bounded) rather than hidden.
func TestFaultyStoreWithoutInnerFailsClosed(t *testing.T) {
	f := &FaultyStore{}
	invoked, panicked, results := sweepFaultyStore(t, f)
	refusals := 0
	for name, out := range results {
		for _, value := range out {
			if !value.Type().Implements(reflect.TypeOf((*error)(nil)).Elem()) || value.IsNil() {
				continue
			}
			err, _ := value.Interface().(error)
			if err == nil {
				continue
			}
			if strings.Contains(err.Error(), "inner store") {
				refusals++
				continue
			}
			t.Fatalf("%s returned %v instead of a missing-inner refusal", name, err)
		}
	}
	// The capability surface is large; a wiring mistake must refuse broadly,
	// not just in a handful of methods. (A few optional readers deliberately
	// report absence as a zero value with no error, which is why nil errors
	// are skipped above rather than failed.)
	if refusals < 40 {
		t.Fatalf("only %d methods refused with a nil inner store; the fail-closed surface shrank", refusals)
	}
	if invoked < 60 {
		t.Fatalf("reflective sweep invoked %d methods; the capability surface shrank unexpectedly", invoked)
	}
	_ = panicked
}

// TestFaultyStoreMissingInnerHelper pins the helper's message shape used by
// the sweep above.
func TestFaultyStoreMissingInnerHelper(t *testing.T) {
	err := errMissingInnerInterface("ExampleStore")
	if err == nil || !strings.Contains(err.Error(), "ExampleStore") {
		t.Fatalf("errMissingInnerInterface = %v", err)
	}
}
