package logging

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"sync"
	"time"
)

// Structured writes operational logs as JSON lines, one object per line:
//
//	{"time":"2026-09-14T01:02:03.456Z","level":"info","msg":"...","k":"v"}
//
// Key/value pairs after msg are rendered as fields. A key whose value is
// nil (or a trailing odd key without a pair) renders the key itself as the
// value, so Info("started", "listener") yields {"listener":"listener"}.
// Values that fail JSON marshaling are skipped.
type Structured struct {
	mu sync.Mutex
	w  io.Writer
	// Level is the minimum level to emit: "debug", "info", "warn" or
	// "error" (case-insensitive, default "info").
	Level string
}

// NewStructured returns a Structured logger writing to w (io.Discard when
// w is nil).
func NewStructured(w io.Writer) *Structured {
	if w == nil {
		w = io.Discard
	}
	return &Structured{w: w, Level: "info"}
}

var levelRank = map[string]int{"debug": 0, "info": 1, "warn": 2, "error": 3}

// Info logs at info level.
func (s *Structured) Info(msg string, kv ...any) { s.log("info", msg, kv) }

// Warn logs at warn level.
func (s *Structured) Warn(msg string, kv ...any) { s.log("warn", msg, kv) }

// Error logs at error level.
func (s *Structured) Error(msg string, kv ...any) { s.log("error", msg, kv) }

func (s *Structured) log(level, msg string, kv []any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.w == nil {
		return
	}
	min, ok := levelRank[strings.ToLower(s.Level)]
	if !ok {
		min = levelRank["info"]
	}
	if levelRank[level] < min {
		return
	}
	var b bytes.Buffer
	b.WriteString(`{"time":`)
	writeJSON(&b, time.Now().UTC().Format(time.RFC3339Nano))
	b.WriteString(`,"level":`)
	writeJSON(&b, level)
	b.WriteString(`,"msg":`)
	writeJSON(&b, msg)
	for i := 0; i < len(kv); i++ {
		k, isKey := kv[i].(string)
		if !isKey {
			continue
		}
		var v any
		if i+1 < len(kv) {
			v = kv[i+1]
			i++
		}
		b.WriteByte(',')
		writeJSON(&b, k)
		b.WriteByte(':')
		if v == nil {
			// Odd key with no value: the key renders as the value.
			writeJSON(&b, k)
			continue
		}
		encoded, err := json.Marshal(v)
		if err != nil {
			b.WriteString(`null`)
			continue
		}
		b.Write(encoded)
	}
	b.WriteString("}\n")
	_, _ = s.w.Write(b.Bytes())
}

func writeJSON(b *bytes.Buffer, s string) {
	encoded, _ := json.Marshal(s)
	b.Write(encoded)
}
