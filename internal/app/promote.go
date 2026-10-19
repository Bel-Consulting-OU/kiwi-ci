package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// Promote issues a signed, append-only blessing record: "artifact at SHA
// may be promoted to ENV because run X verified it". It refuses unless the
// run is green AND its execution attestation verifies for that exact sha.
// This is the native form of the .gate-blessing.json mechanism (audit fix).
func Promote(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("promote", flag.ContinueOnError)
	srv := fs.String("server", "", "Kiwi server URL")
	tok := fs.String("token", os.Getenv("KIWI_ADMIN_TOKEN"), "admin token")
	env := fs.String("env", "", "target environment (prod, staging, ...)")
	sha := fs.String("sha", "", "exact commit SHA being promoted")
	out := fs.String("out", "", "blessing output path (default .kiwi/blessings/<env>.json)")
	rest, err := parseFlagsAndPositionals(fs, args)
	if err != nil {
		return err
	}
	if len(rest) != 1 {
		return fmt.Errorf("kiwi promote requires a run ID")
	}
	if *env == "" {
		return fmt.Errorf("kiwi promote: --env is required")
	}
	runID := rest[0]
	ep, err := ResolveEndpoint(*srv, *tok)
	if err != nil {
		return err
	}
	c := newOpsClient(ep.Server, ep.Token)

	var run model.Run
	if err := c.do(ctx, http.MethodGet, "/api/v1/runs/"+runID, nil, &run); err != nil {
		return fmt.Errorf("load run: %w", err)
	}
	if run.Status != model.StatusSuccess {
		return fmt.Errorf("refuse promotion: run %s status is %s, not success", runID, run.Status)
	}
	if *sha != "" && !strings.EqualFold(run.SHA, *sha) {
		return fmt.Errorf("refuse promotion: run SHA %s does not match --sha %s", run.SHA, *sha)
	}
	// Require a verified execution attestation for at least one job.
	var jobs []model.Job
	if err := c.do(ctx, http.MethodGet, "/api/v1/runs/"+runID+"/jobs", nil, &jobs); err != nil {
		return fmt.Errorf("load jobs: %w", err)
	}
	attested := 0
	for _, j := range jobs {
		var envelope map[string]any
		if err := c.do(ctx, http.MethodGet, "/api/v1/jobs/"+j.ID+"/attestation", nil, &envelope); err == nil && envelope != nil {
			attested++
		}
	}
	if attested == 0 {
		return fmt.Errorf("refuse promotion: run %s has no execution attestation (nothing to bless)", runID)
	}

	blessing := map[string]any{
		"version":      1,
		"environment":  *env,
		"run_id":       runID,
		"sha":          run.SHA,
		"repo":         run.RepoFullName,
		"attested_jobs": attested,
		"issued_at":    time.Now().UTC().Format(time.RFC3339),
		"statement":    fmt.Sprintf("artifact %s may be promoted to %s because run %s verified it", run.SHA, *env, runID),
	}
	body, _ := json.MarshalIndent(blessing, "", "  ")
	digest := sha256.Sum256(body)
	blessing["digest"] = hex.EncodeToString(digest[:])
	body, _ = json.MarshalIndent(blessing, "", "  ")

	path := *out
	if path == "" {
		path = filepath.Join(".kiwi", "blessings", *env+".json")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(path, body, 0o644); err != nil {
		return err
	}
	fmt.Printf("blessed %s → %s (run %s, %d attested jobs)\n", run.SHA, *env, runID, attested)
	fmt.Println("statement:", blessing["statement"])
	return nil
}
