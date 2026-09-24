package logging

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"testing"
)

func TestStructuredJSONLines(t *testing.T) {
	var buf bytes.Buffer
	s := NewStructured(&buf)
	s.Info("job leased", "request_id", "abc123", "job", "build", "attempts", 2)
	s.Warn("lease expiring", "job", "build")
	s.Error("store failure", "error", "connection refused")

	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("got %d lines, want 3:\n%s", len(lines), buf.String())
	}
	var first map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &first); err != nil {
		t.Fatalf("line 0 is not JSON: %v: %q", err, lines[0])
	}
	if first["level"] != "info" || first["msg"] != "job leased" {
		t.Errorf("line 0 level/msg = %v/%v", first["level"], first["msg"])
	}
	if first["request_id"] != "abc123" || first["attempts"] != float64(2) {
		t.Errorf("line 0 fields = %v", first)
	}
	if _, ok := first["time"].(string); !ok {
		t.Errorf("line 0 time missing: %v", first)
	}

	var third map[string]any
	if err := json.Unmarshal([]byte(lines[2]), &third); err != nil {
		t.Fatal(err)
	}
	if third["level"] != "error" {
		t.Errorf("line 2 level = %v", third["level"])
	}
}

func TestStructuredOddKeyRendersAsValue(t *testing.T) {
	var buf bytes.Buffer
	s := NewStructured(&buf)
	s.Info("started", "listener")
	var line map[string]any
	if err := json.Unmarshal(bytes.TrimRight(buf.Bytes(), "\n"), &line); err != nil {
		t.Fatal(err)
	}
	if line["listener"] != "listener" {
		t.Errorf("odd key rendered as %v, want \"listener\"", line["listener"])
	}
}

func TestStructuredLevelFilter(t *testing.T) {
	var buf bytes.Buffer
	s := NewStructured(&buf)
	s.Level = "warn"
	s.Info("dropped")
	s.Warn("kept")
	s.Error("kept too")
	if strings.Contains(buf.String(), "dropped") {
		t.Error("info line emitted at warn level")
	}
	if !strings.Contains(buf.String(), "kept") || !strings.Contains(buf.String(), "kept too") {
		t.Errorf("warn/error lines missing: %s", buf.String())
	}
}

func TestStructuredConcurrentWrites(t *testing.T) {
	var buf bytes.Buffer
	s := NewStructured(&buf)
	done := make(chan struct{})
	for i := 0; i < 16; i++ {
		go func() {
			defer func() { done <- struct{}{} }()
			for j := 0; j < 50; j++ {
				s.Info("tick", "n", j)
			}
		}()
	}
	for i := 0; i < 16; i++ {
		<-done
	}
	for _, line := range strings.Split(strings.TrimRight(buf.String(), "\n"), "\n") {
		if !json.Valid([]byte(line)) {
			t.Fatalf("interleaved write produced invalid JSON line: %q", line)
		}
	}
}

func TestNewStructuredNilWriter(t *testing.T) {
	// A nil writer must be replaced with io.Discard (never left nil, never
	// pointed at stdout), and logging through it must not panic.
	s := NewStructured(nil)
	if s.w != io.Discard {
		t.Fatalf("NewStructured(nil).w = %v, want io.Discard", s.w)
	}
	s.Info("should not panic")
	s.Warn("should not panic")
	s.Error("should not panic")
}
