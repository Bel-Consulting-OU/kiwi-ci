package pipeline

import (
	"regexp"
	"strings"
	"sync"
)

func PathsMatch(changed, include, exclude []string) bool {
	if len(changed) == 0 {
		return len(include) == 0
	}
	for _, p := range changed {
		p = strings.TrimPrefix(strings.ReplaceAll(p, "\\", "/"), "./")
		if matchesAny(p, exclude) {
			continue
		}
		if len(include) == 0 || matchesAny(p, include) {
			return true
		}
	}
	return false
}

func matchesAny(path string, patterns []string) bool {
	for _, p := range patterns {
		if globMatch(p, path) {
			return true
		}
	}
	return false
}

// globReCache memoizes compiled glob regexes. PathsMatch runs the same
// pattern against every changed file (and impact analysis repeats that per
// package/job); compiling RE2 on each call is O(patterns × files) regex
// compiles on monorepo pushes. Cache is unbounded in theory but pattern
// strings are short and pipeline-declared; a hostile spec is already capped
// by admission limits.
var globReCache sync.Map // pattern string -> *regexp.Regexp (nil entry = compile failed)

func globMatch(pattern, value string) bool {
	pattern = strings.TrimPrefix(strings.ReplaceAll(pattern, "\\", "/"), "./")
	var re *regexp.Regexp
	if v, ok := globReCache.Load(pattern); ok {
		re, _ = v.(*regexp.Regexp)
	} else {
		re = compileGlob(pattern)
		globReCache.Store(pattern, re) // nil ok: caches the failed compile too
	}
	if re == nil {
		return false
	}
	return re.MatchString(value)
}

func compileGlob(pattern string) *regexp.Regexp {
	var b strings.Builder
	b.WriteByte('^')
	for i := 0; i < len(pattern); i++ {
		c := pattern[i]
		switch c {
		case '*':
			if i+1 < len(pattern) && pattern[i+1] == '*' {
				i++
				if i+1 < len(pattern) && pattern[i+1] == '/' {
					i++
					b.WriteString("(?:.*/)?")
				} else {
					b.WriteString(".*")
				}
			} else {
				b.WriteString("[^/]*")
			}
		case '?':
			b.WriteString("[^/]")
		default:
			b.WriteString(regexp.QuoteMeta(string(c)))
		}
	}
	b.WriteByte('$')
	re, err := regexp.Compile(b.String())
	if err != nil {
		return nil
	}
	return re
}
