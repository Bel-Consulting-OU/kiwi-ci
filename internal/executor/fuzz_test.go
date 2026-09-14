package executor

import (
	"strings"
	"testing"
)

// FuzzOutputParser drives the step output file parser. A step writes
// attacker-controlled KIWI_OUTPUT content; the parser must never panic and
// every key it admits must be a non-empty KEY in KEY=VALUE form.
func FuzzOutputParser(f *testing.F) {
	f.Add([]byte("KEY=value\nOTHER=x=y\n"))
	f.Add([]byte("NOVALUE\n"))
	f.Add([]byte("=emptykey\n"))
	f.Add([]byte(""))
	f.Add([]byte("A=\nB==\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		out, err := readOutputFile(data)
		if err != nil {
			return
		}
		for k, v := range out {
			if k == "" {
				t.Fatalf("readOutputFile admitted an empty key from %q", data)
			}
			if strings.ContainsAny(k, "=\n\r") {
				t.Fatalf("readOutputFile admitted key %q containing separators from %q", k, data)
			}
			_ = v
		}
	})
}
