package runner

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
)

// testReportMaskServer records every POST to /api/v1/jobs/{id}/tests so a
// test can assert on the exact bytes the runner uploaded.
type testReportMaskServer struct {
	mu    sync.Mutex
	tests int
	body  []byte
}

func (s *testReportMaskServer) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/tests") {
			body, _ := io.ReadAll(r.Body)
			s.mu.Lock()
			s.tests++
			s.body = append([]byte(nil), body...)
			s.mu.Unlock()
		}
		w.WriteHeader(http.StatusOK)
	})
}

func (s *testReportMaskServer) uploaded() (int, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.tests, string(s.body)
}

// testReportLeakXML carries the job's lease token in all four report
// surfaces the collector ingests (failure message, failure body, error body,
// system-err).
const testReportLeakXML = `<testsuite name="s" tests="2" failures="1" errors="1">
  <testcase name="fails"><failure message="boom lease-token">body lease-token</failure></testcase>
  <testcase name="errors"><error message="oops">error lease-token</error><system-err>stderr lease-token</system-err></testcase>
</testsuite>`

// TestExecuteMasksTestReportSecrets exercises the runner's JUnit collection
// end to end: the job holds a resolved secret (basicTask's lease token,
// registered in the masker because the job requests an id_token), the report
// it drops in the workspace embeds that secret, and the uploaded report must
// carry the redaction instead of the secret. With the pre-fix call
// (testintel.Aggregate, a nil mask) this test fails because the raw secret
// reaches the read tier.
func TestExecuteMasksTestReportSecrets(t *testing.T) {
	srv := &testReportMaskServer{}
	ts := httptest.NewServer(srv.handler())
	defer ts.Close()
	text := "version: 1\njobs:\n  build:\n    permissions:\n      id_token: true\n    steps:\n      - run: echo hi\n"
	payload := payloadWithEffectiveJob(t, text, "build", func(cj *pipeline.CompiledJob) {
		cj.Job.TestReports = []string{"report.xml"}
	})
	task := basicTask(text)
	task.Job.CompiledJobPayload = payload
	r := testRunnerFor(t, ts, Config{})
	r.Cfg.CheckoutFn = func(_ context.Context, _ model.Job, dir string) error {
		return os.WriteFile(filepath.Join(dir, "report.xml"), []byte(testReportLeakXML), 0o644)
	}
	r.execute(context.Background(), task)

	uploads, body := srv.uploaded()
	if uploads != 1 {
		t.Fatalf("test report uploads = %d, want 1 (body %q)", uploads, body)
	}
	// The lease token in the request envelope is the endpoint credential and
	// is expected; only the persisted "report" payload must be clean.
	var posted struct {
		Report json.RawMessage `json:"report"`
	}
	if err := json.Unmarshal([]byte(body), &posted); err != nil {
		t.Fatalf("decode uploaded report: %v (body %s)", err, body)
	}
	report := string(posted.Report)
	if report == "" {
		t.Fatalf("uploaded report payload is empty: %s", body)
	}
	if strings.Contains(report, "lease-token") {
		t.Fatalf("uploaded test report leaks the resolved secret: %s", report)
	}
	if !strings.Contains(report, "***") {
		t.Fatalf("uploaded test report was not redacted: %s", report)
	}
	if !strings.Contains(report, "boom") || !strings.Contains(report, "body") {
		t.Fatalf("uploaded test report lost its non-secret content: %s", report)
	}
}
