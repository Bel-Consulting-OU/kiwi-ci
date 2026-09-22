package storage

// Unit coverage for the shared resource-admission predicate and the
// reservation observation API's pure-Go guards. The predicate is the ONE
// place every lease path decides whether a request fits, so each dimension
// is pinned at its boundary, including the CPU dimension and the
// unconstrained (zero capacity) case.

import (
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// TestResourceAdmissionEveryDimensionAndBoundary pins ExceedsRemaining /
// Allows / EverSatisfiable per dimension: exactly-at-capacity fits, one unit
// over does not, a zero capacity dimension is unconstrained, and a request
// larger than the CONFIGURED capacity is permanently unsatisfiable.
func TestResourceAdmissionEveryDimensionAndBoundary(t *testing.T) {
	cases := []struct {
		name      string
		capacity  model.ResourceCapacity
		reserved  model.ResourceCapacity
		requested model.ResourceCapacity
		exceeds   bool
		everFit   bool
	}{
		{"cpu fits exactly", model.ResourceCapacity{CPU: 4}, model.ResourceCapacity{CPU: 3}, model.ResourceCapacity{CPU: 1}, false, true},
		{"cpu over by one", model.ResourceCapacity{CPU: 4}, model.ResourceCapacity{CPU: 3}, model.ResourceCapacity{CPU: 1.5}, true, true},
		{"cpu alone over capacity", model.ResourceCapacity{CPU: 2}, model.ResourceCapacity{}, model.ResourceCapacity{CPU: 3}, true, false},
		{"cpu unconstrained", model.ResourceCapacity{}, model.ResourceCapacity{CPU: 99}, model.ResourceCapacity{CPU: 99}, false, true},
		{"memory fits exactly", model.ResourceCapacity{Memory: 1 << 30}, model.ResourceCapacity{Memory: 1 << 29}, model.ResourceCapacity{Memory: 1 << 29}, false, true},
		{"memory over by one byte", model.ResourceCapacity{Memory: 1 << 30}, model.ResourceCapacity{Memory: 1 << 29}, model.ResourceCapacity{Memory: 1<<29 + 1}, true, true},
		{"memory alone over capacity", model.ResourceCapacity{Memory: 1024}, model.ResourceCapacity{}, model.ResourceCapacity{Memory: 2048}, true, false},
		{"memory unconstrained", model.ResourceCapacity{}, model.ResourceCapacity{Memory: 1 << 40}, model.ResourceCapacity{Memory: 1 << 40}, false, true},
		{"disk fits exactly", model.ResourceCapacity{Disk: 4096}, model.ResourceCapacity{Disk: 1024}, model.ResourceCapacity{Disk: 3072}, false, true},
		{"disk over by one byte", model.ResourceCapacity{Disk: 4096}, model.ResourceCapacity{Disk: 1024}, model.ResourceCapacity{Disk: 3073}, true, true},
		{"disk alone over capacity", model.ResourceCapacity{Disk: 10}, model.ResourceCapacity{}, model.ResourceCapacity{Disk: 11}, true, false},
		{"disk unconstrained", model.ResourceCapacity{}, model.ResourceCapacity{Disk: 1 << 30}, model.ResourceCapacity{Disk: 1 << 30}, false, true},
		{"pids fit exactly", model.ResourceCapacity{PIDs: 256}, model.ResourceCapacity{PIDs: 200}, model.ResourceCapacity{PIDs: 56}, false, true},
		{"pids over by one", model.ResourceCapacity{PIDs: 256}, model.ResourceCapacity{PIDs: 200}, model.ResourceCapacity{PIDs: 57}, true, true},
		{"pids alone over capacity", model.ResourceCapacity{PIDs: 8}, model.ResourceCapacity{}, model.ResourceCapacity{PIDs: 9}, true, false},
		{"pids unconstrained", model.ResourceCapacity{}, model.ResourceCapacity{PIDs: 100000}, model.ResourceCapacity{PIDs: 100000}, false, true},
		{"no capacity at all admits everything", model.ResourceCapacity{}, model.ResourceCapacity{CPU: 100, Memory: 1 << 40, Disk: 1 << 40, PIDs: 1 << 20}, model.ResourceCapacity{CPU: 100, Memory: 1 << 40, Disk: 1 << 40, PIDs: 1 << 20}, false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := ResourceAdmission{Capacity: tc.capacity, Reserved: tc.reserved, Requested: tc.requested}
			if got := a.ExceedsRemaining(); got != tc.exceeds {
				t.Fatalf("ExceedsRemaining = %v, want %v", got, tc.exceeds)
			}
			if got := a.Allows(); got == tc.exceeds {
				t.Fatalf("Allows = %v, want the inverse of ExceedsRemaining %v", got, tc.exceeds)
			}
			if got := a.EverSatisfiable(); got != tc.everFit {
				t.Fatalf("EverSatisfiable = %v, want %v", got, tc.everFit)
			}
		})
	}
}

// TestListResourceReservationsRejectsInvalidRunnerID: the observation API
// validates the runner ID before any query, so a malformed ID can never be
// interpolated or scanned into a query.
func TestListResourceReservationsRejectsInvalidRunnerID(t *testing.T) {
	st := &PostgresStore{}
	if _, err := st.ListResourceReservations(ctx(), "not a valid runner id!"); err == nil {
		t.Fatal("invalid runner id accepted")
	}
	if _, err := st.ListResourceReservations(ctx(), ""); err == nil {
		t.Fatal("empty runner id accepted")
	}
}
