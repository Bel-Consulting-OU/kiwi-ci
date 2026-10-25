package executor

import (
	"os"
	"runtime"
	"sort"
	"strings"
)

// cleanExecutionEnv returns the minimal environment remote (container/Tart)
// jobs run in. Host credentials, HOME, SSH_AUTH_SOCK and every other ambient
// variable are deliberately excluded; the host environment must never leak
// into a distributed runner job.
func cleanExecutionEnv() map[string]string {
	m := map[string]string{
		"LANG":   "C.UTF-8",
		"LC_ALL": "C.UTF-8",
		"CI":     "true",
		"KIWI":   "true",
	}
	if runtime.GOOS == "windows" {
		// Windows native steps/services resolve executables with PATH
		// separators ';'. A POSIX PATH would make lookPathWithExt walk
		// one giant directory name.
		m["PATH"] = `C:\Windows\system32;C:\Windows`
		m["PATHEXT"] = ".COM;.EXE;.BAT;.CMD"
	} else {
		m["PATH"] = "/usr/local/bin:/usr/bin:/bin"
	}
	return m
}

// containerSafeEnv drops host-only variables that must never enter a
// container step: they carry host paths and make the toolchain diverge per
// invoking user. PATH is dropped entirely so the IMAGE's PATH stands
// (a digest-pinned image is the toolchain contract).
func containerSafeEnv(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		switch k {
		case "PATH", "HOME", "USER", "LOGNAME", "SHELL", "TMPDIR", "TEMP", "TMP",
			"PWD", "OLDPWD", "SHLVL", "TERM", "LC_CTYPE", "LC_COLLATE",
			"LC_MESSAGES", "LC_MONETARY", "LC_NUMERIC", "LC_TIME":
			continue
		}
		out[k] = v
	}
	return out
}

// osEnvironMap captures the host environment as a map. It is used only for the
// explicit InheritEnv opt-in (local trusted jobs) and PassEnv allowlisting.
// On Windows, keys are stored uppercased so PATH/Path collide to one entry
// (Go's case-insensitive env contract). On Unix keys keep their case.
func osEnvironMap() map[string]string {
	m := map[string]string{}
	for _, e := range os.Environ() {
		if i := strings.IndexByte(e, '='); i > 0 {
			m[envKeyCanon(e[:i])] = e[i+1:]
		}
	}
	return m
}

// envKeyCanon is the canonical map key for an environment variable name.
// Windows environment names are case-insensitive; Go itself implements
// case-insensitive duplicate elimination. One canonical form prevents
// Path= and PATH= from both surviving into the child environment where
// the last-sorting entry would silently win.
func envKeyCanon(key string) string {
	if runtime.GOOS == "windows" {
		return strings.ToUpper(key)
	}
	return key
}

// mergeEnvMap merges maps left to right; later maps win per key. Keys are
// canonicalized first (case-folded on Windows) so a later PATH cannot
// coexist with an earlier Path.
func mergeEnvMap(base map[string]string, maps ...map[string]string) map[string]string {
	out := make(map[string]string, len(base))
	for k, v := range base {
		out[envKeyCanon(k)] = v
	}
	for _, x := range maps {
		for k, v := range x {
			out[envKeyCanon(k)] = v
		}
	}
	return out
}

// serviceEnvFor builds the environment native sidecar processes receive:
// the job env minus every resolved secret key (both KIWI_SECRET_* and the
// bare declared name). Repository-controlled services must not inherit
// job secrets just because they share the job's environment map.
func serviceEnvFor(jobEnv, jobSecrets map[string]string) map[string]string {
	out := make(map[string]string, len(jobEnv))
	for k, v := range jobEnv {
		out[k] = v
	}
	for k := range jobSecrets {
		delete(out, k)
		if secret := secretEnvName(k); secret != k {
			delete(out, secret)
		}
	}
	return out
}

// envSlice converts an env map to a sorted KEY=VALUE slice suitable for
// exec.Cmd.Env. Keys are already canonical (envKeyCanon), so on Windows a
// single PATH entry survives — never both Path= and PATH=.
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
