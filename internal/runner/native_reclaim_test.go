package runner

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/executor"
)

func TestReclaimNativeServicesSkipsMissingPID(t *testing.T) {
	// Nonexistent PID: must not be treated as unresolved debt.
	if err := reclaimNativeServices([]NativeServiceLedger{{
		Name: "ghost", Port: 1, PID: 1 << 22, PGID: 1 << 22, Start: "x",
	}}); err != nil {
		t.Fatalf("reclaim missing pid = %v, want nil", err)
	}
}

func TestLedgerSetNativeServicesRoundtrip(t *testing.T) {
	r := &Runner{ID: "test-runner-native", Cfg: Config{}}
	id, err := r.ledgerAdd(runtimeLedgerEntry{Instance: "i1", JobID: "j1"})
	if err != nil {
		t.Fatal(err)
	}
	defer r.ledgerRemove(id)
	if err := r.ledgerSetNativeServices(id, []executor.NativeServiceInfo{
		{Name: "pg", Port: 5432, PID: 12345, PGID: 12345, Start: "t:100"},
	}); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(r.runtimeLedgerDir(), id+".json"))
	if err != nil {
		t.Fatal(err)
	}
	var e runtimeLedgerEntry
	if err := json.Unmarshal(b, &e); err != nil {
		t.Fatal(err)
	}
	if len(e.NativeServices) != 1 || e.NativeServices[0].Port != 5432 || e.NativeServices[0].Start != "t:100" {
		t.Fatalf("NativeServices = %+v", e.NativeServices)
	}
}

func TestReclaimNativeRefusesUnverifiedLivePID(t *testing.T) {
	// Our own PID is live; without a matching start stamp reclaim must
	// refuse to kill rather than signal an arbitrary live process.
	self := os.Getpid()
	err := reclaimNativeServices([]NativeServiceLedger{{
		Name: "self", PID: self, PGID: self, Start: "",
	}})
	if err == nil {
		t.Fatal("empty start stamp on a live PID must be recovery debt, not a silent skip/kill")
	}
	// Mismatched stamp on a live PID: recycled — skip, no error.
	err = reclaimNativeServices([]NativeServiceLedger{{
		Name: "recycled", PID: self, PGID: self, Start: "t:1",
	}})
	if err != nil {
		t.Fatalf("stamped mismatch on live pid should skip without error, got %v", err)
	}
}
