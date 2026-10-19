package pipeline

import (
	"strings"
	"testing"
)

// TestServiceReadyFieldParses: ready: tcp/http/pg_isready probes parse and
// survive known-field validation.
func TestServiceReadyFieldParses(t *testing.T) {
	const src = `version: 1
jobs:
  t:
    image: alpine
    services:
      - name: db
        image: postgres:16
        ready: "pg_isready:5432"
      - name: ch
        image: clickhouse/clickhouse-server
        ready: "http:8123/ping"
      - name: redis
        image: redis:7
        ready: "tcp:6379"
    steps:
      - run: echo hi
`
	spec, err := Parse([]byte(src))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	j := spec.Jobs["t"]
	if len(j.Services) != 3 {
		t.Fatalf("services = %+v", j.Services)
	}
	for i, want := range []string{"pg_isready:5432", "http:8123/ping", "tcp:6379"} {
		if j.Services[i].Ready != want {
			t.Fatalf("services[%d].Ready = %q, want %q", i, j.Services[i].Ready, want)
		}
	}
	// unknown field still rejected
	bad := strings.Replace(src, `ready: "tcp:6379"`, `readyy: "tcp:6379"`, 1)
	if _, err := Parse([]byte(bad)); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("typo field accepted: %v", err)
	}
}
