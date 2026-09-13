package executor

import (
	"errors"
	"os"
	"strings"
)

// readOutputFile parses a step's KIWI_OUTPUT file. The format is one KEY=VALUE
// pair per line; a value may contain '='. A missing file (the step wrote no
// outputs) yields an empty map rather than an error.
func readOutputFile(path string) (map[string]string, error) {
	out := map[string]string{}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return out, nil
	}
	if err != nil {
		return out, err
	}
	for _, line := range strings.Split(string(b), "\n") {
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
