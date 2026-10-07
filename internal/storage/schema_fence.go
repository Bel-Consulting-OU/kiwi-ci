package storage

import "strings"

// classifySQLMutation is the pure SQL-classification half of the schema-fence
// architecture guard (schema_fence_architecture_test.go). It decides whether
// an SQL string reaching a raw pool execution path may modify data.
//
// Exactly one result is true:
//
//   - mutation=true, readOnly=false: the statement may modify data. Leading
//     line (--) and block (/* */) comments and whitespace are stripped first.
//     INSERT/UPDATE/DELETE/MERGE/TRUNCATE and DDL verbs are mutations, a WITH
//     statement whose text contains a data-modifying word (INSERT/UPDATE/
//     DELETE/MERGE, word-bounded, case-insensitive) is a mutation, and
//     anything that is not recognizable as SQL fails CLOSED as a mutation so
//     a variable or malformed statement can never be classified as a safe
//     read.
//   - mutation=false, readOnly=true: a SELECT-only statement, including
//     WITH ... SELECT whose CTE bodies contain no data-modifying word.
//
// It is deliberately conservative, NOT a SQL parser: a mutation hiding behind
// a leading SELECT of a multi-statement string, or one built entirely from
// variables (the empty string fails closed at the call site), is not detected
// here. The AST guard's doc comment states what the overall scan does and
// does not prove.
func classifySQLMutation(sql string) (mutation bool, readOnly bool) {
	rest := stripLeadingSQLComments(sql)
	if rest == "" {
		// Nothing (or only comments): unknown SQL fails closed.
		return true, false
	}
	switch leadingSQLWord(rest) {
	case "SELECT":
		return false, true
	case "INSERT", "UPDATE", "DELETE", "MERGE", "TRUNCATE", "ALTER", "CREATE", "DROP":
		return true, false
	case "WITH":
		if containsSQLWord(rest, "INSERT") || containsSQLWord(rest, "UPDATE") ||
			containsSQLWord(rest, "DELETE") || containsSQLWord(rest, "MERGE") {
			return true, false
		}
		// A WITH statement with no data-modifying CTE body can only be a
		// read when it actually selects; a non-SQL string that merely starts
		// with "with" has no SELECT and fails closed.
		if containsSQLWord(rest, "SELECT") {
			return false, true
		}
		return true, false
	}
	// Unknown leading keyword: fail closed.
	return true, false
}

// stripLeadingSQLComments removes leading whitespace and SQL comments (a
// line comment to end of line, a block comment to its terminator, repeatedly)
// so classification sees the statement's first keyword. An unterminated
// comment leaves nothing and therefore fails closed upstream.
func stripLeadingSQLComments(sql string) string {
	rest := strings.TrimLeft(sql, " \t\r\n\f\v")
	for {
		switch {
		case strings.HasPrefix(rest, "--"):
			i := strings.IndexByte(rest, '\n')
			if i < 0 {
				return ""
			}
			rest = strings.TrimLeft(rest[i+1:], " \t\r\n\f\v")
		case strings.HasPrefix(rest, "/*"):
			i := strings.Index(rest[2:], "*/")
			if i < 0 {
				return ""
			}
			rest = strings.TrimLeft(rest[2+i+2:], " \t\r\n\f\v")
		default:
			return rest
		}
	}
}

// leadingSQLWord returns the first word of a comment-stripped SQL string,
// uppercased, or "" when there is none.
func leadingSQLWord(s string) string {
	i := 0
	for i < len(s) && isSQLWordByte(s[i]) {
		i++
	}
	return strings.ToUpper(s[:i])
}

// sqlLeadingKeyword returns the first keyword of raw SQL after comment
// stripping (used by the AST guard's concatenation fail-closed check).
func sqlLeadingKeyword(sql string) string {
	return leadingSQLWord(stripLeadingSQLComments(sql))
}

// containsSQLWord reports whether word occurs in s as a whole word,
// case-insensitively. Word boundaries are ASCII identifier characters, so
// "insert_log" does not match INSERT while "INSERT INTO" does.
func containsSQLWord(s, word string) bool {
	for i := 0; i+len(word) <= len(s); i++ {
		if !strings.EqualFold(s[i:i+len(word)], word) {
			continue
		}
		if i > 0 && isSQLWordByte(s[i-1]) {
			continue
		}
		if j := i + len(word); j < len(s) && isSQLWordByte(s[j]) {
			continue
		}
		return true
	}
	return false
}

func isSQLWordByte(b byte) bool {
	return b == '_' || (b >= '0' && b <= '9') || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}
