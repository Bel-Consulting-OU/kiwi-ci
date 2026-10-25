package system_test

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/dogfood/system"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// forgeCanarySecret is the webhook HMAC secret this canary signs with. It is
// a test-owned value; the canary never contacts an external provider.
const forgeCanarySecret = "forge-canary-webhook-secret"

// realisticGitHubPush builds a full GitHub `push` webhook envelope — the
// shape github.com actually delivers (ref/before/after, compare URL, the
// commits array with author/committer and file lists, head_commit, the full
// repository object with node_id/owner/urls, pusher and sender). The
// product's parsePush only reads the subset it needs, but the canary's job
// is to prove the REAL wire document is accepted, not a minimized stand-in.
// Repository identity is the trusted-ingress default so the forge stand-in
// serves its pipeline and validateWebhookRepoBinding accepts the clone URL.
func realisticGitHubPush(deliveryID, headSHA, pipelinePath string) []byte {
	beforeSHA := strings.Repeat("0", 40)
	if len(headSHA) != 40 {
		headSHA = fmt.Sprintf("%040x", sha256.Sum256([]byte(deliveryID)))
	}
	commit := map[string]any{
		"id":        headSHA,
		"distinct":  true,
		"message":   "ci: dogfood forge canary pipeline\n\nSigned push envelope protocol canary.",
		"timestamp": "2026-01-01T00:00:00Z",
		"url":       "https://github.com/" + system.DefaultTrustedRepo + "/commit/" + headSHA,
		"author": map[string]any{
			"name":     "Kiwi Dogfood",
			"email":    "dogfood@example.com",
			"username": "kiwi-dogfood",
		},
		"committer": map[string]any{
			"name":     "Kiwi Dogfood",
			"email":    "dogfood@example.com",
			"username": "kiwi-dogfood",
		},
		"added":    []any{},
		"removed":  []any{},
		"modified": []any{pipelinePath},
	}
	payload := map[string]any{
		"ref":         "refs/heads/main",
		"before":      beforeSHA,
		"after":       headSHA,
		"created":     false,
		"deleted":     false,
		"forced":      false,
		"compare":     "https://github.com/" + system.DefaultTrustedRepo + "/compare/" + beforeSHA + "..." + headSHA,
		"commits":     []any{commit},
		"head_commit": commit,
		"repository": map[string]any{
			"id":        1296269,
			"node_id":   "MDEwOlJlcG9zaXRvcnkxMjk2MjY5",
			"name":      "system",
			"full_name": system.DefaultTrustedRepo,
			"private":   false,
			"owner": map[string]any{
				"name":       "Kiwi Dogfood",
				"email":      "dogfood@example.com",
				"login":      "kiwi-dogfood",
				"id":         1,
				"node_id":    "MDQ6VXNlcjE=",
				"type":       "Organization",
				"site_admin": false,
			},
			"html_url":                "https://github.com/" + system.DefaultTrustedRepo,
			"description":             "Kiwi CI dogfood system repository",
			"fork":                    false,
			"url":                     "https://api.github.com/repos/" + system.DefaultTrustedRepo,
			"clone_url":               system.DefaultTrustedRepoURL,
			"git_url":                 "git://github.com/" + system.DefaultTrustedRepo + ".git",
			"ssh_url":                 "git@github.com:" + system.DefaultTrustedRepo + ".git",
			"svn_url":                 "https://github.com/" + system.DefaultTrustedRepo,
			"homepage":                "",
			"archived":                false,
			"disabled":                false,
			"default_branch":          "main",
			"master_branch":           "main",
			"created_at":              1700000000,
			"updated_at":              "2026-01-01T00:00:00Z",
			"pushed_at":               1767225600,
			"size":                    1,
			"stargazers_count":        0,
			"watchers_count":          0,
			"language":                "Go",
			"has_issues":              true,
			"has_projects":            true,
			"has_downloads":           true,
			"has_wiki":                true,
			"has_pages":               false,
			"open_issues_count":       0,
			"license":                 nil,
			"topics":                  []any{"ci"},
			"visibility":              "public",
			"forks":                   0,
			"open_issues":             0,
			"watchers":                0,
			"default_branch_language": "Go",
		},
		"pusher": map[string]any{
			"name":  "kiwi-dogfood",
			"email": "dogfood@example.com",
		},
		"sender": map[string]any{
			"login":       "kiwi-dogfood",
			"id":          1,
			"node_id":     "MDQ6VXNlcjE=",
			"avatar_url":  "https://avatars.githubusercontent.com/u/1",
			"gravatar_id": "",
			"url":         "https://api.github.com/users/kiwi-dogfood",
			"html_url":    "https://github.com/kiwi-dogfood",
			"type":        "Organization",
			"site_admin":  false,
		},
		"organization": map[string]any{
			"login":              "kiwi-dogfood",
			"id":                 1,
			"node_id":            "MDEyOk9yZ2FuaXphdGlvbjE=",
			"url":                "https://api.github.com/orgs/kiwi-dogfood",
			"repos_url":          "https://api.github.com/orgs/kiwi-dogfood/repos",
			"events_url":         "https://api.github.com/orgs/kiwi-dogfood/events",
			"hooks_url":          "https://api.github.com/orgs/kiwi-dogfood/hooks",
			"issues_url":         "https://api.github.com/orgs/kiwi-dogfood/issues",
			"members_url":        "https://api.github.com/orgs/kiwi-dogfood/members{/member}",
			"public_members_url": "https://api.github.com/orgs/kiwi-dogfood/public_members{/member}",
			"avatar_url":         "https://avatars.githubusercontent.com/u/1",
			"description":        "Kiwi CI dogfood",
		},
		"installation": map[string]any{
			"id":      1,
			"node_id": "MDIzOkluc3RhbGxhdGlvbjE=",
		},
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		// Static maps above always marshal; a failure here is a test bug.
		panic(err)
	}
	return raw
}

// signGitHubCanary computes the X-Hub-Signature-256 value github.com sends:
// "sha256=" + hex(HMAC-SHA256(secret, body)).
func signGitHubCanary(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

// postForgeCanary delivers one signed push envelope to the product webhook
// handler and returns the HTTP status and response body.
func postForgeCanary(ctx context.Context, baseURL, secret, deliveryID string, body []byte, mutate func(*http.Request)) (int, []byte) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+"/hooks/github", bytes.NewReader(body))
	if err != nil {
		return 0, nil
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-GitHub-Event", "push")
	req.Header.Set("X-GitHub-Delivery", deliveryID)
	req.Header.Set("X-Hub-Signature-256", signGitHubCanary(secret, body))
	req.Header.Set("User-Agent", "GitHub-Hookshot/forge-canary")
	if mutate != nil {
		mutate(req)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, nil
	}
	defer resp.Body.Close()
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(resp.Body)
	return resp.StatusCode, buf.Bytes()
}

// TestSysDFForgeCanary001 is the PROTOCOL-LEVEL forge canary. It is NOT a
// live github.com delivery: the forge API side is the harness stand-in and
// the "provider" is a locally signed envelope. What it proves is the
// product's GitHub webhook wire contract end to end:
//
//   - a realistic github.com `push` document (full repository object,
//     commits array, head_commit, pusher/sender/organization/installation)
//     is accepted by the real POST /hooks/github handler;
//   - X-Hub-Signature-256 HMAC verification is part of that contract
//     (a wrong secret is refused with 401 before anything is enqueued);
//   - the forge-derived Trusted bit lands on the job, a native host step
//     runs to success, and the produced evidence verifies under JWKS.
//
// A drift in the product's webhook signature/payload contract fails this
// canary even when no live provider credentials are configured. The live
// provider (real github.com) canary remains a separate, planned proof.
func TestSysDFForgeCanary001(t *testing.T) {
	// Hermetic: the webhook-ingress canary runs a native runner against a
	// fresh stack that never creates a container; without the shim a
	// CLI-present/daemon-down host fail-closes crash reconciliation and
	// kills the runner after registration.
	installFakeDockerForSystem(t)
	dataDir := t.TempDir()
	sys, err := system.Launch(system.SystemConfig{
		RunnerToken: "forge-canary-runner",
		AdminToken:  "forge-canary-admin",
		DataDir:     dataDir,
	})
	if err != nil {
		t.Fatalf("launch: %v", err)
	}
	defer func() { _ = sys.Close() }()
	if err := sys.EnableTrustedWebhook(system.TrustedWebhookConfig{
		Secret:       forgeCanarySecret,
		PipelineYAML: nativeEchoPipeline,
	}); err != nil {
		t.Fatalf("enable trusted webhook: %v", err)
	}
	if err := sys.StartRunner("forge-canary-exec", nil); err != nil {
		t.Fatalf("start runner: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	body := realisticGitHubPush("forge-canary-delivery-1", "", ".kiwi/pipeline.yaml")

	// Negative arm: a wrong HMAC secret must be refused before anything is
	// enqueued — the signature check is the ingress gate, not decoration.
	code, respBody := postForgeCanary(ctx, sys.BaseURL, "wrong-secret", "forge-canary-bad-sig", body, nil)
	if code != http.StatusUnauthorized {
		t.Fatalf("wrong-signature push = HTTP %d (%s), want 401", code, strings.TrimSpace(string(respBody)))
	}

	// Positive arm: the realistic envelope, correctly signed.
	code, respBody = postForgeCanary(ctx, sys.BaseURL, forgeCanarySecret, "forge-canary-delivery-1", body, nil)
	if code != http.StatusAccepted {
		t.Fatalf("signed push = HTTP %d (%s), want 202", code, strings.TrimSpace(string(respBody)))
	}
	var accepted struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(respBody, &accepted); err != nil {
		t.Fatalf("decode accept body: %v (%s)", err, respBody)
	}
	if accepted.ID == "" {
		t.Fatalf("empty run id in %s", respBody)
	}
	runID := accepted.ID

	status, err := sys.WaitJobTerminal(ctx, runID, "build")
	if err != nil {
		t.Fatalf("wait job: %v", err)
	}
	if status != model.StatusSuccess {
		j, _ := sys.JobByKey(ctx, runID, "build")
		t.Fatalf("forge canary job status = %s error=%q, want success", status, j.Error)
	}
	job, err := sys.JobByKey(ctx, runID, "build")
	if err != nil {
		t.Fatalf("job: %v", err)
	}
	if !job.Trusted {
		t.Fatal("forge canary job is untrusted; the signed push's forge-derived Trusted bit was lost")
	}
	if job.AttemptRunnerID == "" {
		t.Fatal("forge canary job has no attempt runner id after terminal success")
	}

	// The canary is only green when the ingress produced real evidence.
	evCtx, evCancel := context.WithTimeout(ctx, 25*time.Second)
	defer evCancel()
	envBytes, err := sys.FetchEvidence(evCtx, job.ID, job.LeaseGeneration)
	if err != nil {
		t.Fatalf("fetch evidence: %v", err)
	}
	if len(envBytes) == 0 {
		t.Fatal("empty attestation envelope")
	}
	st, err := sys.VerifyEvidence(ctx, envBytes)
	if err != nil {
		t.Fatalf("verify evidence: %v", err)
	}
	if st.Attestation == nil {
		t.Fatal("verified statement carries no execution attestation")
	}
	if st.Attestation.JobID != job.ID {
		t.Fatalf("attestation job id = %q, want %q", st.Attestation.JobID, job.ID)
	}
}
