package pipeline

import (
	"regexp"
	"strings"
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

func globMatch(pattern, value string) bool {
	pattern = strings.TrimPrefix(strings.ReplaceAll(pattern, "\\", "/"), "./")
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
	return err == nil && re.MatchString(value)
}
