package server

import (
	"net/http"
	"reflect"
	"strings"
	"testing"
)

func TestParseScheduleSpecStrictForms(t *testing.T) {
	// Mapping form (cron + branches).
	cron, ref, err := parseScheduleSpec(scheduleSpec)
	if err != nil {
		t.Fatalf("mapping form: %v", err)
	}
	if reflect.DeepEqual(cron, cronSchedule{}) {
		t.Fatal("mapping form cron empty")
	}
	if ref != "refs/heads/main" {
		t.Fatalf("mapping form ref = %q", ref)
	}
	// Bare string form.
	cron, ref, err = parseScheduleSpec(`version: 1
on:
  schedule: "*/5 * * * *"
jobs:
  a:
    steps:
      - run: echo hi
`)
	if err != nil {
		t.Fatalf("string form: %v", err)
	}
	if reflect.DeepEqual(cron, cronSchedule{}) {
		t.Fatal("string form cron empty")
	}
	if ref != "" {
		t.Fatalf("string form ref = %q, want empty", ref)
	}
	// List form.
	cron, ref, err = parseScheduleSpec(`version: 1
on:
  schedule:
    - cron: "0 3 * * *"
      branches: [release]
jobs:
  a:
    steps:
      - run: echo hi
`)
	if err != nil {
		t.Fatalf("list form: %v", err)
	}
	if reflect.DeepEqual(cron, cronSchedule{}) {
		t.Fatal("list form cron empty")
	}
	if ref != "refs/heads/release" {
		t.Fatalf("list form ref = %q", ref)
	}
}

func TestParseScheduleSpecStrictRejections(t *testing.T) {
	cases := []struct {
		name string
		doc  string
		want string
	}{
		{
			name: "unknown field with line number",
			doc:  "version: 1\non:\n  schedule:\n    cron: \"* * * * *\"\n    bogus: true\njobs:\n  a:\n    steps:\n      - run: x\n",
			want: "line 5",
		},
		{
			name: "unknown field",
			doc:  "version: 1\non:\n  schedule:\n    cron: \"* * * * *\"\n    bogus: true\njobs:\n  a:\n    steps:\n      - run: x\n",
			want: "unknown field",
		},
		{
			name: "job without steps",
			doc:  "version: 1\non:\n  schedule: \"* * * * *\"\njobs:\n  a:\n    name: x\n",
			want: "no steps",
		},
		{
			name: "duplicate key",
			doc:  "version: 1\non:\n  schedule:\n    cron: \"* * * * *\"\n    cron: \"1 1 * * *\"\njobs:\n  a:\n    steps:\n      - run: x\n",
			want: "duplicate key",
		},
		{
			name: "invalid cron",
			doc:  "version: 1\non:\n  schedule:\n    cron: \"61 * * * *\"\njobs:\n  a:\n    steps:\n      - run: x\n",
			want: "invalid range",
		},
		{
			name: "missing cron",
			doc:  "version: 1\non:\n  schedule:\n    branches: [main]\njobs:\n  a:\n    steps:\n      - run: x\n",
			want: "on.schedule.cron",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := parseScheduleSpec(tc.doc)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestUpsertScheduleStrictParse(t *testing.T) {
	s := New("token")
	// A schedule spec with an unknown field is rejected with line numbers
	// by the strict parser before the schedule is stored.
	w := doJSON(t, s, http.MethodPut, "/api/v1/schedules", "token",
		`{"repository":"https://example.com/o/r.git","spec":`+jsonString("version: 1\non:\n  schedule:\n    cron: \"* * * * *\"\n    nope: true\njobs:\n  a:\n    steps:\n      - run: x\n")+`}`)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "line") {
		t.Fatalf("invalid schedule = %d %s, want line-numbered rejection", w.Code, w.Body.String())
	}
	s.mu.Lock()
	n := len(s.schedules)
	s.mu.Unlock()
	if n != 0 {
		t.Fatalf("invalid schedule stored: %d schedules", n)
	}
}
