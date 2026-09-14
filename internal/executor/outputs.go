package executor

import (
	"errors"
	"regexp"
	"strings"
)

// outputKeyRE constrains step output names to safe identifiers. The executor
// exposes outputs as environment variables, so control characters,
// whitespace, and separator characters are never admissible.
var outputKeyRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.-]{0,127}$`)

// readOutputFile parses a step's KIWI_OUTPUT file content. The format is one
// KEY=VALUE pair per line; a value may contain '='. Keys must be safe
// identifiers; anything else is rejected rather than silently exported. A
// missing file (the step wrote no outputs) is handled by the caller, which
// yields an empty map rather than an error.
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
		key := line[:i]
		if !outputKeyRE.MatchString(key) {
			return out, errors.New("step output key is not a valid identifier")
		}
		out[key] = line[i+1:]
	}
	return out, nil
}
