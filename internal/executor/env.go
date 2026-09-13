package executor

import (
	"os"
	"sort"
	"strings"
)

// cleanExecutionEnv returns the minimal environment remote (container/Tart)
// jobs run in. Host credentials, HOME, SSH_AUTH_SOCK and every other ambient
// variable are deliberately excluded; the host environment must never leak
// into a distributed runner job.
func cleanExecutionEnv() map[string]string {
	return map[string]string{
		"PATH":   "/usr/local/bin:/usr/bin:/bin",
		"LANG":   "C.UTF-8",
		"LC_ALL": "C.UTF-8",
		"CI":     "true",
		"KIWI":   "true",
	}
}

// osEnvironMap captures the host environment as a map. It is used only for the
// explicit InheritEnv opt-in (local trusted jobs) and PassEnv allowlisting.
func osEnvironMap() map[string]string {
	m := map[string]string{}
	for _, e := range os.Environ() {
		if i := strings.IndexByte(e, '='); i > 0 {
			m[e[:i]] = e[i+1:]
		}
	}
	return m
}

// mergeEnvMap merges maps left to right; later maps win per key.
func mergeEnvMap(base map[string]string, maps ...map[string]string) map[string]string {
	out := make(map[string]string, len(base))
	for k, v := range base {
		out[k] = v
	}
	for _, x := range maps {
		for k, v := range x {
			out[k] = v
		}
	}
	return out
}

// envSlice converts an env map to a sorted KEY=VALUE slice suitable for
// exec.Cmd.Env.
func envSlice(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, k+"="+m[k])
	}
	return out
}
