package logging

import (
	"bytes"
	"encoding/json"
	"math"
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/secrets"
)

func TestConsoleWriteLineBranches(t *testing.T) {
	var buf bytes.Buffer
	c := &Console{Writer: &buf}
	c.WriteLine("job", "step", "plain line")
	if !strings.Contains(buf.String(), "plain line") || !strings.Contains(buf.String(), "[job/step]") {
		t.Fatalf("console output = %q", buf.String())
	}

	masker := &secrets.Masker{}
	if err := masker.AddStrict("super-secret-value"); err != nil {
		t.Fatal(err)
	}
	buf.Reset()
	masked := &Console{Writer: &buf, Masker: masker}
	masked.WriteLine("job", "step", "token=super-secret-value")
	if strings.Contains(buf.String(), "super-secret-value") {
		t.Fatalf("masker must redact console output: %q", buf.String())
	}

	quiet := &Console{}
	quiet.WriteLine("job", "step", "dropped")
}

func TestFuncAndMultiSinks(t *testing.T) {
	var got []string
	Func(func(job, step, line string) {
		got = append(got, job+"|"+step+"|"+line)
	}).WriteLine("j", "s", "l")
	if len(got) != 1 || got[0] != "j|s|l" {
		t.Fatalf("Func sink recorded %v", got)
	}

	var second []string
	multi := Multi{
		Func(func(job, step, line string) { got = append(got, "a:"+line) }),
		nil,
		Func(func(job, step, line string) { second = append(second, "b:"+line) }),
	}
	multi.WriteLine("j", "s", "l")
	if len(got) != 2 || got[1] != "a:l" || len(second) != 1 || second[0] != "b:l" {
		t.Fatalf("Multi fan-out = %v %v", got, second)
	}
	if len(Multi(nil)) != 0 {
		t.Fatal("nil Multi must be a no-op")
	}
	Multi(nil).WriteLine("j", "s", "l")
}

func TestStructuredEdgeBranches(t *testing.T) {
	var buf bytes.Buffer
	zero := &Structured{}
	zero.Info("dropped")
	if buf.Len() != 0 {
		t.Fatalf("zero-value logger wrote %q", buf.String())
	}

	s := NewStructured(&buf)
	s.Info("visible")
	if buf.Len() == 0 {
		t.Fatal("info must be emitted at the default level")
	}

	buf.Reset()
	s.Level = "verbose"
	s.Info("fallback")
	if buf.Len() == 0 {
		t.Fatal("unknown level must fall back to info")
	}

	buf.Reset()
	s.Level = "error"
	s.Info("suppressed")
	if buf.Len() != 0 {
		t.Fatalf("info below error level must be suppressed: %q", buf.String())
	}
	s.Error("emitted")
	if buf.Len() == 0 {
		t.Fatal("error must be emitted at error level")
	}

	buf.Reset()
	s.Level = "info"
	s.Info("msg", 42, "key", "value")
	// Structural assertion: a substring search for "42" over the whole
	// record is flaky because the timestamp can contain it (observed on
	// macOS CI). Decode and inspect the fields instead.
	var rec map[string]any
	if err := json.Unmarshal(buf.Bytes(), &rec); err != nil {
		t.Fatalf("record is not valid JSON: %v (%q)", err, buf.String())
	}
	if rec["key"] != "value" {
		t.Fatalf("kv pair missing: %v", rec)
	}
	if _, ok := rec["42"]; ok {
		t.Fatalf("numeric key became a field: %v", rec)
	}

	buf.Reset()
	s.Info("msg", "bad", math.Inf(1))
	var rec2 map[string]any
	if err := json.Unmarshal(buf.Bytes(), &rec2); err != nil {
		t.Fatalf("record is not valid JSON: %v (%q)", err, buf.String())
	}
	if v, ok := rec2["bad"]; !ok || v != nil {
		t.Fatalf("unmarshalable value must render null: %v", rec2)
	}
}
