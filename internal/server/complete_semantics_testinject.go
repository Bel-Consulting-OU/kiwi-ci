package server

import (
	"context"
	"encoding/json"
	"strings"
)

// maybeInjectCompleteSemantics is a TEST-ONLY helper used by the HTTP test
// drivers (doJSON / doJSONHeaders / pgITDo / testClient.do). Production
// requires an explicit execution_semantics on every completion of a stamped
// job (see checkCompletionSemantics). Test fixtures that predate that
// contract omit the key; this fills it from the target job so those fixtures
// keep testing what they mean to test, while omission tests that send an
// explicit `"execution_semantics": ""` are left alone.
//
// It never invents a stamp for an unstamped job and never overwrites an
// explicit value (including "").
func maybeInjectCompleteSemantics(s *Server, reqPath, body string) string {
	if body == "" || !strings.HasSuffix(reqPath, "/complete") {
		return body
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(body), &m); err != nil {
		return body
	}
	if _, present := m["execution_semantics"]; present {
		return body
	}
	// /api/v1/jobs/{id}/complete
	parts := strings.Split(strings.Trim(reqPath, "/"), "/")
	if len(parts) < 4 || parts[0] != "api" || parts[2] != "jobs" || parts[len(parts)-1] != "complete" {
		return body
	}
	jobID := parts[3]
	sem, ok := s.jobExecutionSemanticsForTest(jobID)
	if !ok || sem == "" {
		return body
	}
	m["execution_semantics"] = sem
	out, err := json.Marshal(m)
	if err != nil {
		return body
	}
	return string(out)
}

// jobExecutionSemanticsForTest reads the job stamp from memory or the DB
// without assuming which mode the fixture runs in.
func (s *Server) jobExecutionSemanticsForTest(jobID string) (string, bool) {
	s.mu.Lock()
	j, ok := s.jobs[jobID]
	s.mu.Unlock()
	if ok {
		return j.ExecutionSemantics, true
	}
	if s.DB == nil {
		return "", false
	}
	j2, err := s.DB.GetJob(context.Background(), jobID)
	if err != nil {
		return "", false
	}
	return j2.ExecutionSemantics, true
}
