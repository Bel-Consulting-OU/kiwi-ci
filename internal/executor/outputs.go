package executor

import (
	"errors"
	"strings"
)

// readOutputFile parses a step's KIWI_OUTPUT file content. The format is one
// KEY=VALUE pair per line; a value may contain '='. A missing file (the step
// wrote no outputs) is handled by the caller, which yields an empty map rather
// than an error.
func readOutputFile(data []byte) (map[string]string, error) {
	out := map[string]string{}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimRight(line, "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		i := strings.IndexByte(line, '=')
		if i <= 0 {
			return out, errors.New("step output line is not KEY=VALUE")
		}
		out[line[:i]] = line[i+1:]
	}
	return out, nil
}
