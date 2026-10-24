package executor

import (
	"path/filepath"
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

// pathFromEnv extracts a KEY from a KEY=VALUE slice (native step env).
func pathFromEnv(kv []string, key string) string {
	prefix := key + "="
	for _, e := range kv {
		if len(e) > len(prefix) && e[:len(prefix)] == prefix {
			return e[len(prefix):]
		}
	}
	return ""
}

// windowsCandidates expands base with PATHEXT suffixes. Pure helper
// (no build tag) so tests run on every OS.
func windowsCandidates(base, pathExt string) []string {
	// Already has an executable extension → exact first.
	ext := strings.ToLower(filepath.Ext(base))
	for _, e := range strings.Split(pathExt, ";") {
		e = strings.TrimSpace(e)
		if e != "" && strings.EqualFold(ext, e) {
			return []string{base}
		}
	}
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
