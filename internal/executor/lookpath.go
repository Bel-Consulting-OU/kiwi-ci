package executor

import (
	"fmt"
	"os/exec"
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
// effective environment (base + service/step overlays).
//
// Authority rule (single semantic resolver, also used for the native step
// shell): a PATH-QUALIFIED name ("./bin/tool", "sub/tool", "C:\x\y.exe")
// has already expressed its resolution domain, so it resolves ONLY against
// workDir and NEVER falls back to a PATH search or — worse — to a bare
// stat of the name relative to the RUNNER PROCESS'S current directory. The
// old fall-through let a job ask for "./tools/compiler", miss it in the
// workspace, and silently execute a same-named file living beside the
// runner daemon. Bare names search PATH (case-insensitively on Windows).
func resolveExecutable(name, workDir string, env map[string]string) (string, error) {
	pathVal, pathExt := "", ""
	if runtime.GOOS == "windows" {
		pathVal = envValueFold(env, "PATH")
		pathExt = envValueFold(env, "PATHEXT")
	} else {
		pathVal = env["PATH"]
	}
	return resolveExecutableIn(name, workDir, pathVal, pathExt)
}

// PathQualified reports whether name already expressed a filesystem domain
// (contains a path separator or a drive prefix). Such names bind to the
// job's workDir and never fall back to PATH or the process CWD.
func PathQualified(name string) bool {
	return strings.ContainsAny(name, `/\`) || (len(name) > 1 && name[1] == ':')
}

// resolveExecutableIn is the shared resolver core: path-qualified names
// bind to workDir, bare names search the supplied PATH/PATHEXT. Callers
// extract the PATH authorities themselves (service env maps, step env
// slices) so every native argv0 — service commands, the step shell, and
// other helpers — goes through identical semantics.
func resolveExecutableIn(name, workDir, pathVal, pathExt string) (string, error) {
	if name == "" {
		return "", errEmptyExecutable
	}
	// Relative (or absolute) path containing a separator or a drive prefix.
	if PathQualified(name) {
		cand := name
		base := workDir
		if base == "" {
			base = "."
		}
		if !filepath.IsAbs(name) {
			cand = filepath.Join(base, name)
		}
		if resolved, err := lookPathWithEnv(cand, pathVal, pathExt); err == nil {
			return resolved, nil
		}
		// No fallback of any kind: the resolution domain was expressed.
		return "", fmt.Errorf("executable %q not found relative to workdir %q (path-qualified names never fall back to PATH or the runner's current directory)", name, base)
	}
	return lookPathWithEnv(name, pathVal, pathExt)
}

// ResolveDeclaredTool resolves a tools:/toolchains: declaration name.
// Path-qualified entries ("./tools/go") bind to the job workspace root —
// the verification probe may never execute a same-named binary beside the
// runner daemon. Bare names keep the documented host-tool contract (the
// ambient PATH): these gates verify runner-provided tooling, while the
// step shell independently resolves job-visible executables against the
// effective environment.
func ResolveDeclaredTool(name, workDir string) (string, error) {
	if PathQualified(name) {
		// Path-qualified candidates ignore PATH/PATHEXT-as-search (unix
		// stats the joined path directly; windows applies PATHEXT suffixes
		// to the joined path), so an empty env map is correct here.
		return resolveExecutableIn(name, workDir, "", "")
	}
	return exec.LookPath(name)
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
