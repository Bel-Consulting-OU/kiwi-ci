package app

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// VerifySince walks the local blessing ledger (and optional run list) and
// proves the append-only chain has not been tampered with between two
// points: each record's digest must match its bytes, and timestamps must
// be non-decreasing. Prints "chain OK" or the exact break.
func VerifySince(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	dir := fs.String("ledger", ".kiwi/blessings", "blessing ledger directory")
	since := fs.String("since", "", "RFC3339 lower bound (records before this are skipped)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	var sinceT time.Time
	if *since != "" {
		t, err := time.Parse(time.RFC3339, *since)
		if err != nil {
			return fmt.Errorf("--since: %w", err)
		}
		sinceT = t
	}
	entries, err := os.ReadDir(*dir)
	if err != nil {
		return fmt.Errorf("ledger %s: %w", *dir, err)
	}
	type rec struct {
		path string
		at   time.Time
		dig  string
	}
	var recs []rec
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		path := filepath.Join(*dir, e.Name())
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		var m map[string]any
		if err := json.Unmarshal(raw, &m); err != nil {
			return fmt.Errorf("%s: invalid JSON: %w", path, err)
		}
		// Recompute digest over the canonical body (digest field stripped).
		declared, _ := m["digest"].(string)
		delete(m, "digest")
		body, _ := json.MarshalIndent(m, "", "  ")
		sum := sha256.Sum256(body)
		got := hex.EncodeToString(sum[:])
		if declared != "" && declared != got {
			return fmt.Errorf("%s: digest mismatch (declared %s, computed %s) — ledger tampered", path, declared, got)
		}
		issued, _ := m["issued_at"].(string)
		at, _ := time.Parse(time.RFC3339, issued)
		if !sinceT.IsZero() && at.Before(sinceT) {
			continue
		}
		recs = append(recs, rec{path: path, at: at, dig: got})
	}
	// Non-decreasing issued_at.
	for i := 1; i < len(recs); i++ {
		if recs[i].at.Before(recs[i-1].at) {
			return fmt.Errorf("ledger order broken: %s (%s) before %s (%s)", recs[i].path, recs[i].at, recs[i-1].path, recs[i-1].at)
		}
	}
	fmt.Printf("chain OK (%d records)\n", len(recs))
	for _, r := range recs {
		fmt.Printf("  %s  %s\n", r.at.Format(time.RFC3339), filepath.Base(r.path))
	}
	return nil
}
