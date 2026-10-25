package executor

import (
	"path/filepath"
	"runtime"
	"strings"
)

// lookPathWithEnv resolves name against an explicit PATH (and on Windows
// also PATHEXT). It never consults the process ambient environment.
// pathExt is ignored on Unix; on Windows it is the PATHEXT list (e.g.
// ".COM;.EXE;.BAT;.CMD"). Callers must pass empty pathExt to use the
// platform default when the execution env did not define PATHEXT.
func lookPathWithEnv(name, pathEnv, pathExt string) (string, error) {
	return lookPathWithExt(name, pathEnv, pathExt)
}

// resolveExecutable resolves argv0 the way the child process will see it:
// against workDir (Cmd.Dir, the execution directory) and the FULLY merged
// effective environment (base + service/step overlays). A relative path
// with a separator ("./bin/tool") is evaluated relative to workDir, matching
// Go's os/exec contract for a command with Dir set. Bare names search PATH
// (case-insensitively on Windows).
func resolveExecutable(name, workDir string, env map[string]string) (string, error) {
	if name == "" {
		return "", errEmptyExecutable
	}
	pathVal := ""
	pathExt := ""
	if runtime.GOOS == "windows" {
		pathVal = envValueFold(env, "PATH")
		pathExt = envValueFold(env, "PATHEXT")
	} else {
		pathVal = env["PATH"]
	}
	// Relative (or absolute) path containing a separator: resolve against
	// the execution directory the child will use, not the runner CWD.
	if strings.ContainsAny(name, `/\`) || (len(name) > 1 && name[1] == ':') {
		cand := name
		if !filepath.IsAbs(name) {
			base := workDir
			if base == "" {
				base = "."
			}
			cand = filepath.Join(base, name)
		}
		if resolved, err := lookPathWithEnv(cand, pathVal, pathExt); err == nil {
			return resolved, nil
		}
		// Fall through: PATH search is still valid for names that contain a
		// separator only as a drive-relative quirk; re-try bare below when
		// the join missed.
		if filepath.IsAbs(name) {
			return "", errNotFoundOnPath(name, pathVal, pathExt)
		}
	}
	return lookPathWithEnv(name, pathVal, pathExt)
}

// envValueFold is the Windows case-insensitive env lookup (PATH/PATHEXT).
func envValueFold(env map[string]string, key string) string {
	if v, ok := env[key]; ok {
		return v
	}
	want := strings.ToUpper(key)
	for k, v := range env {
		if strings.ToUpper(k) == want {
			return v
		}
	}
	return ""
}

// pathFromEnv extracts a KEY from a KEY=VALUE slice (native step env).
// On Windows the comparison is case-insensitive so PATH= and Path= both
// resolve to the same authority.
func pathFromEnv(kv []string, key string) string {
	prefix := key + "="
	for _, e := range kv {
		if len(e) > len(prefix) && e[:len(prefix)] == prefix {
			return e[len(prefix):]
		}
		if runtime.GOOS == "windows" && len(e) > len(prefix) {
			// Case-insensitive key match on Windows.
			head := e[:len(prefix)]
			if strings.EqualFold(head, prefix) {
				return e[len(prefix):]
			}
		}
	}
	return ""
}

// windowsCandidates expands base with PATHEXT suffixes. Pure helper
// (no build tag) so tests run on every OS.
//
// Windows LookPath semantics: a name without an executable extension is
// tried with each PATHEXT suffix in order; the bare (extensionless) form is
// NOT an executable. A name that already carries a PATHEXT extension is
// tried exactly once.
func windowsCandidates(base, pathExt string) []string {
	ext := strings.ToLower(filepath.Ext(base))
	for _, e := range strings.Split(pathExt, ";") {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		if !strings.HasPrefix(e, ".") {
			e = "." + e
		}
		if strings.EqualFold(ext, e) {
			return []string{base}
		}
	}
	if ext != "" {
		// Has some extension that is not in PATHEXT: still try the exact
		// path first (operator may invoke a non-PATHEXT script by full
		// name), then PATHEXT-suffixed forms.
		out := []string{base}
		for _, e := range strings.Split(pathExt, ";") {
			e = strings.TrimSpace(e)
			if e == "" {
				continue
			}
			if !strings.HasPrefix(e, ".") {
				e = "." + e
			}
			out = append(out, base+e)
		}
		return out
	}
	// No extension: PATHEXT candidates only (never the bare name).
	out := make([]string, 0, 8)
	for _, e := range strings.Split(pathExt, ";") {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		if !strings.HasPrefix(e, ".") {
			e = "." + e
		}
		out = append(out, base+e)
	}
	return out
}
