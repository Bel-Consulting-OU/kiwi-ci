package logging

import (
	"errors"
	"strings"
	"testing"
)

type failingWriter struct{ err error }

func (f failingWriter) Write(p []byte) (int, error) { return 0, f.err }

// TestConsoleWriteErrRecorded: K8 — a closed pipe must be recorded, not
// silently ignored.
func TestConsoleWriteErrRecorded(t *testing.T) {
	c := &Console{Writer: failingWriter{err: errors.New("broken pipe")}}
	c.WriteLine("job", "step", "hello")
	if c.WriteErr() == nil {
		t.Fatal("WriteErr nil after failed write")
	}
	if !strings.Contains(c.WriteErr().Error(), "broken pipe") {
		t.Fatalf("WriteErr = %v", c.WriteErr())
	}
}

// TestConsoleWriteErrNilOnSuccess: clean writes leave WriteErr nil.
func TestConsoleWriteErrNilOnSuccess(t *testing.T) {
	var sb strings.Builder
	c := &Console{Writer: &sb}
	c.WriteLine("job", "step", "ok")
	if c.WriteErr() != nil {
		t.Fatalf("WriteErr = %v", c.WriteErr())
	}
	if !strings.Contains(sb.String(), "ok") {
		t.Fatalf("output = %q", sb.String())
	}
}
