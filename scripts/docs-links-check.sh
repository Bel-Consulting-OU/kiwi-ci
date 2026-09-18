#!/bin/sh
# docs-links-check.sh fails on relative Markdown links in every git-tracked
# Markdown file whose local target does not exist, and on links whose
# #fragment does not match a heading in the target Markdown file.
#
# Usage: scripts/docs-links-check.sh
#
# Inline links of the form ](target) are resolved relative to the file that
# contains them. External links (http://, https://, mailto:, and any other
# scheme) are skipped, as are links to non-Markdown files: only a missing
# local file or directory, or a missing heading anchor, fails the gate.
#
# Anchors use the GitHub slug algorithm: heading text is lowercased,
# surrounding whitespace trimmed, punctuation stripped, internal spaces
# turned into hyphens, underscores kept, and repeated slugs disambiguated
# with -1, -2, ... Percent-encoded fragments are decoded before matching.
# Known limitations: the slug algorithm is ASCII-only (non-ASCII letters are
# dropped), explicit HTML anchors (<a name=...>) are not recognised, and only
# ATX headings outside fenced code blocks are collected.
set -eu
LC_ALL=C
export LC_ALL

ROOT="$(cd "$(dirname "$0")/.." && pwd -P)"
cd "$ROOT"

if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
	echo "docs-links-check: $ROOT is not a git working tree" >&2
	exit 1
fi

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT HUP INT TERM
FILES="$TMP/files"
LINKS="$TMP/links"
MDFILES="$TMP/mdfiles"
SLUGS="$TMP/slugs"
TAB="$(printf '\t')"

SLUG_AWK="$TMP/slug.awk"
cat > "$SLUG_AWK" <<'AWK'
# GitHub-style heading slug.
function slugify(s,   out, i, c) {
	s = tolower(s)
	sub(/^[ \t]+/, "", s)
	sub(/[ \t]+$/, "", s)
	out = ""
	for (i = 1; i <= length(s); i++) {
		c = substr(s, i, 1)
		if ((c >= "a" && c <= "z") || (c >= "0" && c <= "9") || c == "-" || c == "_") {
			out = out c
		} else if (c == " " || c == "\t") {
			out = out "-"
		}
	}
	return out
}

function hexval(c) { return index("0123456789abcdef", c) - 1 }

# Percent-decode a URL fragment.
function urldecode(s,   out, i, c, h) {
	out = ""
	for (i = 1; i <= length(s); i++) {
		c = substr(s, i, 1)
		if (c == "%" && i + 2 <= length(s)) {
			h = tolower(substr(s, i + 1, 2))
			if (h ~ /^[0-9a-f][0-9a-f]$/) {
				out = out sprintf("%c", hexval(substr(h, 1, 1)) * 16 + hexval(substr(h, 2, 1)))
				i += 2
				continue
			}
		}
		out = out c
	}
	return out
}
AWK

COLLECT_AWK="$TMP/collect.awk"
cat > "$COLLECT_AWK" <<'AWK'
FNR == 1 { fence = 0; delete taken; delete count }
{
	line = $0
	if (line ~ /^[ \t]*(```|~~~)/) { fence = !fence; next }
	if (fence) next
	if (line !~ /^#{1,6}[ \t]/) next
	text = line
	sub(/^#{1,6}[ \t]+/, "", text)
	sub(/[ \t]+#+[ \t]*$/, "", text)
	base = slugify(text)
	if (base == "") next
	cand = base
	if (taken[cand]) {
		n = (count[base] > 0 ? count[base] : 1)
		cand = base "-" n
		while (taken[cand]) {
			n++
			cand = base "-" n
		}
		count[base] = n + 1
	} else {
		count[base] = 1
	}
	taken[cand] = 1
	print root "/" FILENAME "\t" cand
}
AWK

FRAG_AWK="$TMP/frag.awk"
cat > "$FRAG_AWK" <<'AWK'
{ print slugify(urldecode($0)) }
AWK

# Every tracked Markdown file is in scope; generated ones (for example
# FILE_MAP.md) are cheap to scan and contain no relative links.
git ls-files '*.md' > "$FILES"
if [ ! -s "$FILES" ]; then
	echo "docs-links-check: no tracked Markdown files under $ROOT" >&2
	exit 1
fi

: > "$MDFILES"
: > "$LINKS"
: > "$SLUGS"
while IFS= read -r f; do
	[ -n "$f" ] || continue
	if [ ! -f "$f" ]; then
		echo "docs-links-check: tracked Markdown file missing from the work tree: $f" >&2
		exit 1
	fi
	printf '%s/%s\n' "$ROOT" "$f" >> "$MDFILES"
	awk 'FNR == 1 { file = FILENAME }
	{
		line = $0
		while (match(line, /\]\([^()]*\)/)) {
			print file "\t" FNR "\t" substr(line, RSTART + 2, RLENGTH - 3)
			line = substr(line, RSTART + RLENGTH)
		}
	}' "$f" >> "$LINKS"
	awk -v root="$ROOT" -f "$SLUG_AWK" -f "$COLLECT_AWK" "$f" >> "$SLUGS"
done < "$FILES"

# resolve_path FILE TARGET prints the absolute path of TARGET interpreted
# relative to FILE (or to the repository root for site-absolute targets),
# normalising any . or .. segments when the directory exists.
resolve_path() {
	case "$2" in
	/*) p="$ROOT$2" ;;
	*) p="$ROOT/$(dirname "$1")/$2" ;;
	esac
	if d="$(cd "$(dirname "$p")" 2>/dev/null && pwd -P)"; then
		printf '%s/%s' "$d" "$(basename "$p")"
	else
		printf '%s' "$p"
	fi
}

status=0
checked=0
anchors=0
while IFS="$TAB" read -r file lineno target; do
	# Trim surrounding whitespace.
	target=${target#"${target%%[![:space:]]*}"}
	target=${target%"${target##*[![:space:]]}"}
	case "$target" in
	'<'*'>')
		target=${target#<}
		target=${target%>}
		;;
	esac
	[ -n "$target" ] || continue
	case "$target" in
	http://* | https://* | mailto:* | ftp://* | tel:*) continue ;;
	esac
	# Any other explicit scheme (data:, javascript:, ...) is not a local file.
	case "$target" in
	[A-Za-z][A-Za-z0-9+.-]*:*) continue ;;
	esac
	# Drop an optional link title, then split off the fragment.
	path=${target%%[[:space:]]*}
	frag=""
	case "$path" in
	*'#'*)
		frag=${path#*#}
		path=${path%%#*}
		;;
	esac

	if [ -n "$path" ]; then
		resolved="$(resolve_path "$file" "$path")"
		checked=$((checked + 1))
		if [ ! -e "$resolved" ]; then
			echo "docs-links-check: $file:$lineno: broken relative link: $path" >&2
			status=1
		fi
	else
		resolved="$ROOT/$file"
	fi

	[ -n "$frag" ] || continue
	[ -e "$resolved" ] || continue
	# Anchor extraction only covers tracked Markdown targets.
	grep -Fxq "$resolved" "$MDFILES" || continue
	slug="$(printf '%s\n' "$frag" | awk -f "$SLUG_AWK" -f "$FRAG_AWK")"
	anchors=$((anchors + 1))
	if ! grep -Fxq "$(printf '%s\t%s' "$resolved" "$slug")" "$SLUGS"; then
		display="$path"
		[ -n "$display" ] || display="$file"
		echo "docs-links-check: $file:$lineno: broken anchor: $display#$frag" >&2
		status=1
	fi
done < "$LINKS"

if [ "$status" -ne 0 ]; then
	echo "docs-links-check: FAIL" >&2
	exit 1
fi
files_count="$(awk 'END { print NR }' "$FILES")"
echo "docs-links-check: $checked local link(s) and $anchors anchor(s) across $files_count file(s) ok"
