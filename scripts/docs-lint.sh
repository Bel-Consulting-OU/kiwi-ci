#!/bin/sh
# docs-lint.sh — prose linter for the Kiwi CI' documentation
# and (with --source) source comments; prints per-file violation counts
# and a total. Advisory (always exits 0) unless a baseline is given:
# --baseline file enforces the per-file rows AND the total — any scanned
# file that exceeds its row (a scanned file without a row counts as a
# new file with baseline 0) or a total that exceeds the baseline total
# fails with exit 1; --update-baseline file regenerates the per-file set
# after deliberate rewrites. --integrity with an earlier baseline file
# adds the committed-baseline integrity check: the committed baseline
# (the file next to this script) is compared with that earlier baseline
# (typically the parent commit's) — every tracked path's row may only
# stay equal or decrease, a path new in the committed baseline is
# allowed only when listed in the adoption manifest (docs-lint-adopted.txt
# next to this script), and the total may only stay equal or decrease.
# Adoption is one-shot: an entry whose path has landed (a row in the
# committed baseline, or already in the comparison base baseline) is
# consumed and removed from the manifest on the next --integrity run
# (atomic tmp+mv; --no-write-adopted keeps the manifest read-only for
# CI), so a path dropped and later reintroduced is never silently
# re-adopted by a stale entry.
# The committed baseline ratchets toward zero, then advisory mode is removed.
# Scan scope: the five kiwicaptcha package families under packages/
# (kiwicaptcha, kiwicaptcha-php, kiwicaptcha-risk, kiwicaptcha-risk-php,
# kiwicaptcha-wasm) plus the repository's human-facing root text: the
# browser test suite under tests/browser (the Playwright specs and the
# fixture router), the design docs under protocol/, the workflow prose
# under .github/workflows/, and the product root files README.md and
# SECURITY.md. The root-level roots are scanned only when present (the
# browser suite and the design docs are product-repository trees); the
# product root files are scanned only when identifiable as the
# product's (the README's first line is the "# KiwiCaptcha" identity
# marker); unrelated repository root files are never scanned.
# Checks: em-dash density, sentence length, all-caps prose, filler
# vocabulary, 'never/not' contrast saturation, bold-emphasis density,
# nested parentheses, remediation-history wording (change words, change
# numbers, or review identifiers), and duplicate sentences across the
# scanned files.

set -u

MAX_EM=2
MAX_WORDS=40
MAX_CONTRAST=2
MAX_BOLD=2
ALLOWLIST="WCAG HTTP HTTPS WASM HTML JSON HMAC NVDA SMIL POUR SLSA CORS QUIC OIDC UUID CIDR ASCII MUST POST PATCH OPTIONS CSRF SIGTERM A11Y SHA256SUMS HMAC-SHA IP-HMAC FAIL-CLOSED KIWI RISK ARGV KEYS KEEPTTL EXPIRE TIME WAIT INCR DECR ZSET PING EVAL GETDEL ZCARD ZREM HGET SETNX TTL PHP-FPM GITHUB README SECURITY SECURITY-MAINTAINER FQCN TOCTOU RAII CAPTCHA EVALSHA NOSCRIPT PTTL SCRIPT LOAD INFO RESP SETEX SETINFO SAPI IIFE HKDF REST YAML TOML SBOM JWKS DSSE HEAD PATH DECLARES REFUSES WHOLE ARCHITECTURE FILE ROADMAP INVARIANTS CONTRIBUTING NOTICE LICENSE UNLICENSE POSIX PKCS BUILD FAIL CLOSED HELP VERSION TYPE BEFORE COMMIT WIRE SEMANTIC LLVM PGSQL TLS SSH UTC URL API CLI CI CD SPDX SHA SHA256 MD ROOT SOURCE SOFTWARE SNAPSHOT STATEMENT SUBSTRING STRPOS REGEXP REAL PROVIDED PROFILE PITR OTLP SSPL TARGET TODO WIRE-SEMANTIC GOOS GOARCH LDFLAGS PKIX AES-GCM APFS CRIU DACL TLA2TOOLS AGPL LGPL BUSL CC-BY-NC NULL LOWER HOME DOCKERFILE DOCKER ENVDOCKER ARGS PASS COPYING ALLOWLIST NO-LICENSE-FILE ALREADY-COMMITTED OPT-IN YYYY-MM-DDTHH WHERE BEGIN FAKE"

WITH_SOURCE=0
BASELINE=""
UPDATE_BASELINE=""
INTEGRITY=""
ROOT=""
NO_WRITE_ADOPTED=0
CUR_BASELINE_OVERRIDE=""
MANIFEST_OVERRIDE=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --source) WITH_SOURCE=1 ;;
    --baseline)
      shift
      if [ "$#" -eq 0 ]; then echo "docs-lint.sh: --baseline requires a file" >&2; exit 0; fi
      BASELINE="$1"
      ;;
    --update-baseline)
      shift
      if [ "$#" -eq 0 ]; then echo "docs-lint.sh: --update-baseline requires a file" >&2; exit 0; fi
      UPDATE_BASELINE="$1"
      ;;
    --integrity)
      shift
      if [ "$#" -eq 0 ]; then echo "docs-lint.sh: --integrity requires a file" >&2; exit 0; fi
      INTEGRITY="$1"
      ;;
    --current-baseline)
      shift
      if [ "$#" -eq 0 ]; then echo "docs-lint.sh: --current-baseline requires a file" >&2; exit 0; fi
      CUR_BASELINE_OVERRIDE="$1"
      ;;
    --adopted-manifest)
      shift
      if [ "$#" -eq 0 ]; then echo "docs-lint.sh: --adopted-manifest requires a file" >&2; exit 0; fi
      MANIFEST_OVERRIDE="$1"
      ;;
    --no-write-adopted) NO_WRITE_ADOPTED=1 ;;
    -h|--help)
      echo "usage: docs-lint.sh [--source] [--baseline FILE] [--update-baseline FILE] [--integrity FILE]"
      echo "                     [--current-baseline FILE] [--adopted-manifest FILE] [--no-write-adopted] [ROOT_DIR]"
      echo "prose lint over the kiwicaptcha package families and the repository's human-facing text; advisory"
      echo "(exit 0) unless --baseline FILE is given, which fails (exit 1)"
      echo "when any scanned file exceeds its per-file row or the total"
      echo "exceeds the tracked baseline; --update-baseline FILE writes"
      echo "per-file counts + total; --integrity FILE adds the"
      echo "committed-baseline integrity check against FILE (an earlier"
      echo "baseline, e.g. the parent commit's): tracked rows may only"
      echo "stay equal or decrease, new paths must be adopted in"
      echo "docs-lint-adopted.txt, and the total may only stay equal or"
      echo "decrease"
      echo ""
      echo "adoption is one-shot: an entry whose path has landed (a row in"
      echo "the current committed baseline, or already in the comparison"
      echo "base baseline) is consumed and removed from the manifest on the"
      echo "next --integrity run, so a path dropped and later reintroduced"
      echo "is NOT re-adopted by a stale entry (it needs a fresh adoption,"
      echo "and until then its implicit baseline row is zero)."
      echo "--current-baseline FILE / --adopted-manifest FILE override the"
      echo "committed baseline / adoption manifest the integrity step reads"
      echo "(defaults: the files next to this script; for tests and dry runs)."
      echo "--no-write-adopted skips the one-shot manifest rewrite: the"
      echo "integrity check still runs (a consumed entry still counts as"
      echo "adopted for that run) but the manifest is left untouched — the"
      echo "read-only/CI mode; a later writable run consumes the entry."
      exit 0
      ;;
    -*) echo "docs-lint.sh: unknown option: $1" >&2; exit 0 ;;
    *) ROOT="$1" ;;
  esac
  shift
done

if [ -n "$UPDATE_BASELINE" ] && [ -n "$BASELINE" ]; then
  echo "docs-lint.sh: --baseline and --update-baseline are mutually exclusive" >&2
  exit 0
fi
if [ -n "$INTEGRITY" ] && [ -n "$BASELINE" ]; then
  echo "docs-lint.sh: --integrity and --baseline are mutually exclusive" >&2
  exit 0
fi
if [ -n "$INTEGRITY" ] && [ -n "$UPDATE_BASELINE" ]; then
  echo "docs-lint.sh: --integrity and --update-baseline are mutually exclusive" >&2
  exit 0
fi

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
if [ -z "$ROOT" ]; then
  ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
fi
if [ ! -f "$ROOT/go.mod" ]; then
  echo "docs-lint.sh: not a repository root (no go.mod under $ROOT)" >&2
  exit 1
fi

# The scan covers only the five kiwicaptcha package families and the
# repository's human-facing root text; other packages/ entries (the
# sdk families, the packages index) are never scanned. The root-level
# roots are presence-gated: tests/browser (the Playwright specs and
# the fixture router) and protocol/ (the design docs) are
# product-repository trees, and .github/workflows/ carries the CI
# workflow prose; each is scanned only when present (find over a
# missing root yields nothing), and the workflow prose is additionally
# gated on the product identity marker like the product root files:
# an unrelated repository's own workflows are never scanned. The
# product root files (README.md, SECURITY.md) exist only in the
# product repository — they are scanned only when present and
# carrying the product identity marker (first line "# KiwiCaptcha",
# the marker the product CI's repo-sanity job enforces), so an
# unrelated repository root README is never picked up.
# Kiwi CI scan roots: docs, CI workflow prose, scripts, and the product
# root files. Source comment scanning (--source) covers internal/ and cmd/.
SCAN_ROOTS="docs
.github/workflows
scripts
formal"

product_root_readme() {
  [ -f "$ROOT/README.md" ] || return 1
  "$AWK_BIN" 'NR == 1 { exit !($0 ~ /^# Kiwi/) }' "$ROOT/README.md"
}

# The checks must behave identically everywhere the gate runs. BSD awk,
# GNU awk and mawk disagree on a few regex/normalization details, so the
# script prefers gawk when present and falls back to awk otherwise; the
# CI installs gawk so enforcement is deterministic.
AWK_BIN="$(command -v gawk 2>/dev/null || command -v awk)"

# The sentence normalization (tolower, punctuation stripping) and the
# duplicate aggregation must be byte-deterministic across machines, so
# every awk run happens under a fixed C locale regardless of the host.
export LC_ALL=C LC_CTYPE=C LANG=C

tmpd=$(mktemp -d "${TMPDIR:-/tmp}/docs-lint.XXXXXX") || exit 0
trap 'rm -rf "$tmpd"' EXIT HUP INT TERM

cat > "$tmpd/mdprose.awk" <<'MDEOF'
# mdprose.awk — strip fenced code blocks and inline code spans from markdown
BEGIN { infence = 0 }
function emit(l,  nb, s, i) {
  gsub(/`[^`]*`/, " ", l)
  nb = 0
  s = l
  while ((i = index(s, "**")) > 0) { nb++; s = substr(s, i + 2) }
  gsub(/[*_~|]/, " ", l)
  gsub(/\[/, " ", l)
  gsub(/\]/, " ", l)
  gsub(/^[ \t]*>+[ \t]*/, "", l)
  print "\001B" nb "\002" l
}
{
  if ($0 ~ /^[ \t]*(```+|~~~+)/) {
    if (!infence) print ""
    infence = (infence ? 0 : 1)
    if (!infence) print ""
    next
  }
  if (infence) next
  if ($0 ~ /^[ \t]*\|/) { next }
  emit($0)
}
MDEOF

cat > "$tmpd/checks.awk" <<'CHECKSEOF'
# checks.awk — mode=check: paragraph checks; mode=dup: sentence emission
BEGIN {
  max_em = max_em + 0
  max_words = max_words + 0
  max_contrast = max_contrast + 0
  max_bold = max_bold + 0
  n_al = split(allowlist, AL, " ")
  n_em = 0; n_long = 0; n_caps = 0; n_fill = 0
  n_contrast = 0; n_bold = 0; n_nest = 0; n_hist = 0
  pbold = 0
  pbuf = ""; pline = 0
}
function is_allowed(core,  i) {
  for (i = 1; i <= n_al; i++) if (core == AL[i]) return 1
  return 0
}
function nest_check(s,  d, c) {
  d = 0
  while (s != "") {
    c = substr(s, 1, 1)
    if (c == "(") { d++; if (d > 1) return 1 }
    if (c == ")") { if (d > 0) d-- }
    s = substr(s, 2)
  }
  return 0
}
function emit_sentences(  t, k, ns, s, n) {
  t = pbuf
  gsub(/\n/, " ", t)
  gsub(/[.!?] /, "\n", t)
  ns = split(t, S, "\n")
  for (k = 1; k <= ns; k++) {
    s = S[k]
    gsub(/^[^A-Za-z0-9]+|[^A-Za-z0-9]+$/, "", s)
    if (s == "") continue
    n = tolower(s)
    gsub(/[^A-Za-z0-9]+/, " ", n)
    gsub(/^ +| +$/, "", n)
    gsub(/  +/, " ", n)
    if (n == "") continue
    if (n ~ /^[0-9]+$/) continue
    print n
  }
}
function check_para(  t, s, k, ns, wc, n, i, tok, core, after, lw, m) {
  t = pbuf
  gsub(/\n/, " ", t)
  n = 0; s = t
  while ((i = index(s, "—")) > 0) { n++; s = substr(s, i + 3) }
  if (n > max_em) {
    printf "%s:%d: em-dash: %d em dashes in one paragraph (limit %d)\n", file, pline, n, max_em
    n_em++
  }
  s = t
  gsub(/[.!?] /, "\n", s)
  ns = split(s, S, "\n")
  for (k = 1; k <= ns; k++) {
    if (S[k] == "") continue
    wc = split(S[k], W, /[ \t]+/)
    if (wc > max_words) {
      printf "%s:%d: long-sentence: %d words (limit %d): %.70s\n", file, pline, wc, max_words, S[k]
      n_long++
    }
  }
  # Link targets and bare URLs are not prose: strip them before the
  # all-caps scan so a path like (.../README.md) is never flagged.
  t2 = t
  gsub(/https?:\/\/[^ )\t]+/, "", t2)
  gsub(/\([^()]*\.[A-Za-z0-9]+[^()]*\)/, "", t2)
  gsub(/\([A-Z][A-Z0-9_.-]{2,}\)/, "", t2)
  s = t2
  while (match(s, /[A-Z][A-Z0-9-]{3,}/)) {
    tok = substr(s, RSTART, RLENGTH)
    before = RSTART > 1 ? substr(s, RSTART - 1, 1) : ""
    after = substr(s, RSTART + RLENGTH, 1)
    if (after ~ /[a-z]/) { s = substr(s, RSTART + 1); continue }
    # A token glued to a code reference (::, ->, ., $, _, or a backtick on
    # either side) is an identifier or constant, not prose.
    if (before ~ /[:._>$`]|[-]/ && before != "-" || after == "`" || before == "`") {
      s = substr(s, RSTART + RLENGTH)
      continue
    }
    core = tok
    gsub(/[0-9-]+$/, "", core)
    # Scenario/invariant/identifier tokens (DF-BOOT-001, TestSys..., I7)
    if (tok ~ /^DF/ || tok ~ /^Test[A-Z]/ || tok ~ /^I[0-9]+$/) {
      s = substr(s, RSTART + RLENGTH)
      continue
    }
    if (length(core) >= 4 && !is_allowed(core)) {
      printf "%s:%d: all-caps: '%s'\n", file, pline, tok
      n_caps++
    }
    s = substr(s, RSTART + RLENGTH)
  }
  lw = tolower(t)
  if (index(lw, "not merely") > 0) {
    printf "%s:%d: filler: 'not merely'\n", file, pline
    n_fill++
  }
  if (index(lw, "the property you can rely on") > 0) {
    printf "%s:%d: filler: 'the property you can rely on'\n", file, pline
    n_fill++
  }
  s = lw
  while (match(s, /(^|[^A-Za-z0-9_-])(premium|seamless|robust|comprehensive|battle-tested|enterprise-grade|production-ready|best-in-class|powerful|flexible)([^A-Za-z0-9_-]|$)/)) {
    m = substr(s, RSTART, RLENGTH)
    gsub(/^[^A-Za-z]+|[^A-Za-z]+$/, "", m)
    printf "%s:%d: filler: '%s'\n", file, pline, m
    n_fill++
    s = substr(s, RSTART + RLENGTH)
  }
  # Remediation-history wording is banned from prose: the change
  # vocabulary (change, changes, changing), a numbered change, a
  # historical passive, or a review identifier. Descriptions state the
  # current contract; they never narrate what an earlier revision
  # corrected. Hyphenated forms matter, so the boundary class excludes
  # only letters, digits and underscore.
  s = lw
  while (match(s, /(^|[^a-z0-9_])(fix|fixes|fixing)([^a-z0-9_]|$)/)) {
    m = substr(s, RSTART, RLENGTH)
    gsub(/^[^A-Za-z]+|[^A-Za-z]+$/, "", m)
    printf "%s:%d: hist-ref: '%s'\n", file, pline, m
    n_hist++
    s = substr(s, RSTART + RLENGTH)
  }
  s = lw
  while (match(s, /(^|[^a-z0-9_])((was|were|gets|get|been) fixed|fixed (the|this|that|a|an) )/)) {
    printf "%s:%d: hist-ref: 'fixed'\n", file, pline
    n_hist++
    s = substr(s, RSTART + RLENGTH)
  }
  s = lw
  while (match(s, /(^|[^a-z0-9_])(audit's|pre-audit|audit[ -](finding|findings|round|rounds|item|items|fix|fixes|id|ids|number|no)|audit[- ]*[^a-z0-9_][0-9]+)([^a-z0-9_]|$)/)) {
    m = substr(s, RSTART, RLENGTH)
    gsub(/^[^A-Za-z]+|[^A-Za-z]+$/, "", m)
    printf "%s:%d: hist-ref: '%s'\n", file, pline, m
    n_hist++
    s = substr(s, RSTART + RLENGTH)
  }
  s = t
  n = gsub(/— never |, not |— and not | is not /, "", s)
  if (n > max_contrast) {
    printf "%s:%d: contrast: %d never/not constructions in one paragraph (limit %d)\n", file, pline, n, max_contrast
    n_contrast++
  }
  if (int(pbold / 2) > max_bold) {
    printf "%s:%d: bold: %d bold spans in one paragraph (limit %d)\n", file, pline, int(pbold / 2), max_bold
    n_bold++
  }
}
function flush() {
  if (pbuf == "") { pline = 0; pbold = 0; return }
  if (mode == "dup") emit_sentences()
  else check_para()
  pbuf = ""; pline = 0; pbold = 0
}
{
  nb = 0
  if (substr($0, 1, 2) == "\001B") {
    bmt = substr($0, 3)
    nb = bmt + 0
    bme = index(bmt, "\002")
    if (bme > 0) $0 = substr(bmt, bme + 1)
    else $0 = ""
  }
  if ($0 == "") { flush(); next }
  if (pline == 0) pline = NR
  pbold += nb
  pbuf = (pbuf == "" ? $0 : pbuf "\n" $0)
  if (mode != "dup" && nest_check($0) == 1) {
    printf "%s:%d: nested-parens: parentheses nested more than one level\n", file, NR
    n_nest++
  }
}
END {
  flush()
  if (mode != "dup") print "SUMMARY\t" file "\t" n_em "\t" n_long "\t" n_caps "\t" n_fill "\t" n_contrast "\t" n_bold "\t" n_nest "\t" n_hist
}
CHECKSEOF

cat > "$tmpd/comments.awk" <<'CMTEOF'
# comments.awk — emit comment text from source (lang=rs|js|php|hash);
# a block comment is one paragraph, each line comment is one paragraph;
# lang=hash (yaml, yml, sh, twig) extracts '#' line comments only
function emit(s) {
  gsub(/^[ \t]+/, "", s)
  gsub(/[ \t]+$/, "", s)
  if (s != "") print s
}
function pick(lang, line,  a, b, c, f, k) {
  a = index(line, "//")
  b = (lang == "php" || lang == "hash" ? index(line, "#") : 0)
  c = index(line, "/*")
  f = 0; k = ""
  if (lang == "hash") { f = b; k = "L" }
  else {
    if (c > 0) { f = c; k = "B" }
    if (a > 0 && (f == 0 || a < f)) { f = a; k = "L" }
    if (b > 0 && (f == 0 || b < f)) { f = b; k = "L" }
  }
  if (f == 0) return ""
  return k ":" f
}
BEGIN { inb = 0 }
{
  line = $0
  if (inb) {
    e = index(line, "*/")
    if (e > 0) {
      seg = substr(line, 1, e - 1)
      if (seg ~ /^[ \t]*\*/) seg = substr(seg, index(seg, "*") + 1)
      emit(seg)
      line = substr(line, e + 2)
      inb = 0
    } else {
      seg = line
      if (seg ~ /^[ \t]*\*/) seg = substr(seg, index(seg, "*") + 1)
      emit(seg)
      next
    }
  }
  while (line != "") {
    r = pick(lang, line)
    if (r == "") break
    split(r, fld, ":")
    pos = fld[2] + 0
    rest = substr(line, pos + 2)
    if (fld[1] == "L") { emit(rest); break }
    inb = 1
    e = index(rest, "*/")
    if (e > 0) {
      seg = substr(rest, 1, e - 1)
      if (seg ~ /^[ \t]*\*/) seg = substr(seg, index(seg, "*") + 1)
      emit(seg)
      line = substr(rest, e + 2)
      inb = 0
    } else {
      seg = rest
      if (seg ~ /^[ \t]*\*/) seg = substr(seg, index(seg, "*") + 1)
      emit(seg)
      break
    }
  }
  if (!inb) print ""
}
CMTEOF

cat > "$tmpd/dupagg.awk" <<'DUPAWK'
# dupagg.awk — aggregate normalized sentences: duplicates across files
BEGIN { FS = "\t" }
{
  key = $1; f = $2
  if (key in cnt) {
    cnt[key]++
    if ((key SUBSEP f) in seenf) seenf[key SUBSEP f]++
    else seenf[key SUBSEP f] = 1
  } else {
    cnt[key] = 1
    firstfile[key] = f
    seenf[key SUBSEP f] = 1
  }
  files[f] = 1
}
END {
  for (k in cnt) if (cnt[k] > 1) {
    printf "  duplicate sentence (%d occurrences): %.70s\n", cnt[k], k
    for (f in files) {
      c = seenf[k SUBSEP f] + 0
      if (c > 0) {
        d = c - (f == firstfile[k] ? 1 : 0)
        if (d > 0) dupc[f] += d
      }
    }
  }
  for (f in dupc) printf "DUPSUMMARY\t%s\t%d\n", f, dupc[f]
  tot = 0
  for (f in dupc) tot += dupc[f]
  printf "DUPTOTAL\t%d\n", tot
}
DUPAWK

excluded() {
  "$AWK_BIN" '
    /\/vendor\// || /\/node_modules\// || /\/target\// || /\/pkg\// || /\/assets\// || /\/resources\// || /\/Resources\/public\// || /\/\.venv\// || /\/\.pytest_cache\// || /\/\.git\// { next }
    { print }
  '
}

scan_md() {
  for r in $SCAN_ROOTS; do
    if [ "$r" = ".github/workflows" ]; then
      product_root_readme || continue
    fi
    find "$ROOT/$r" -type f -name '*.md' -print 2>/dev/null
  done
  if product_root_readme; then
    printf '%s\n' "$ROOT/README.md"
    if [ -f "$ROOT/SECURITY.md" ]; then printf '%s\n' "$ROOT/SECURITY.md"; fi
  fi
}

scan_src() {
  for r in $SCAN_ROOTS internal cmd; do
    if [ "$r" = ".github/workflows" ]; then
      product_root_readme || continue
    fi
    for ext in go sh yml yaml; do
      find "$ROOT/$r" -type f -name "*.$ext" -print 2>/dev/null
    done
  done
}

md_files=$(scan_md | excluded | sort -u)
src_files=""
if [ "$WITH_SOURCE" = 1 ]; then
  src_files=$(scan_src | excluded | sort -u)
fi

n_md=0
while IFS= read -r f; do [ -n "$f" ] && n_md=$((n_md + 1)); done <<EOF
$md_files
EOF
n_src=0
while IFS= read -r f; do [ -n "$f" ] && n_src=$((n_src + 1)); done <<EOF
$src_files
EOF

echo "== docs-lint (prose lint) =="
echo "scan root: $ROOT ($n_md markdown files, $n_src source files)"

summary_tmp="$tmpd/summary"
dup_tmp="$tmpd/dups"
dupout_tmp="$tmpd/dupout"
dupsum_tmp="$tmpd/dupsum"
out_tmp="$tmpd/out"
agg_tmp="$tmpd/agg"

{
  printf '%s\n' "$md_files" | while IFS= read -r f; do
    [ -n "$f" ] || continue
    "$AWK_BIN" -f "$tmpd/mdprose.awk" "$f" |
      "$AWK_BIN" -f "$tmpd/checks.awk" -v mode=check -v file="$f" \
          -v max_em="$MAX_EM" -v max_words="$MAX_WORDS" \
          -v max_contrast="$MAX_CONTRAST" -v max_bold="$MAX_BOLD" \
          -v allowlist="$ALLOWLIST"
  done
  if [ "$WITH_SOURCE" = 1 ]; then
    printf '%s\n' "$src_files" | while IFS= read -r f; do
      [ -n "$f" ] || continue
      case "$f" in
        *.go|*.sh) lang=hash ;;
        *.yaml|*.yml) lang=hash ;;
        *) lang=rs ;;
      esac
      "$AWK_BIN" -f "$tmpd/comments.awk" -v lang="$lang" "$f" |
        "$AWK_BIN" -f "$tmpd/checks.awk" -v mode=check -v file="$f" \
            -v max_em="$MAX_EM" -v max_words="$MAX_WORDS" \
            -v max_contrast="$MAX_CONTRAST" -v max_bold="$MAX_BOLD" \
            -v allowlist="$ALLOWLIST"
    done
  fi
} > "$out_tmp"
grep '^SUMMARY' "$out_tmp" > "$summary_tmp"
grep -v '^SUMMARY' "$out_tmp"

printf '%s\n' "$md_files" | while IFS= read -r f; do
  [ -n "$f" ] || continue
  "$AWK_BIN" -f "$tmpd/mdprose.awk" "$f" |
    "$AWK_BIN" -f "$tmpd/checks.awk" -v mode=dup |
      "$AWK_BIN" -v f="$f" '{ printf "%s\t%s\n", $0, f }'
done > "$dup_tmp"

echo ""
echo "== duplicate sentences (markdown, normalized) =="
sort "$dup_tmp" | "$AWK_BIN" -f "$tmpd/dupagg.awk" > "$dupout_tmp"
grep -v '^DUPSUMMARY' "$dupout_tmp" | grep -v '^DUPTOTAL'
grep -E '^(DUPSUMMARY|DUPTOTAL)' "$dupout_tmp" > "$dupsum_tmp"

echo ""
cat "$summary_tmp" "$dupsum_tmp" | "$AWK_BIN" -F '\t' -v root="$ROOT" '
function rel(p) {
  if (root != "" && index(p, root "/") == 1) return substr(p, length(root) + 2)
  return p
}
$1 == "SUMMARY" {
  em = $3 + 0; lg = $4 + 0; cp = $5 + 0; fl = $6 + 0
  ct = $7 + 0; bd = $8 + 0; ns = $9 + 0; hs = $10 + 0
  cnt[$2] = em + lg + cp + fl + ct + bd + ns + hs
  det[$2] = sprintf("em-dash %d, long-sentence %d, all-caps %d, filler %d, contrast %d, bold %d, nested-parens %d, history-ref %d", em, lg, cp, fl, ct, bd, ns, hs)
  nfiles++
  tot += em + lg + cp + fl + ct + bd + ns + hs
}
$1 == "DUPSUMMARY" {
  dup[$2] = $3 + 0
  cnt[$2] += $3
  tot += $3
}
END {
  for (f in cnt) {
    printf "0\t%s\t%s, duplicate %d\n", f, det[f], dup[f] + 0
    printf "COUNT\t%s\t%d\n", rel(f), cnt[f]
  }
  printf "1\tTOTAL: %d violations across %d files\n", tot, nfiles
  printf "TOTALV\t%d\n", tot
}
' > "$agg_tmp"

tot=$("$AWK_BIN" -F '\t' '/^TOTALV\t/ { print $2 }' "$agg_tmp")
tot=${tot:-0}

grep -v '^COUNT' "$agg_tmp" | grep -v '^TOTALV' | sort | sed -e 's/^0\t/  /' -e 's/^1\t/  /'

if [ -n "$UPDATE_BASELINE" ]; then
  "$AWK_BIN" -F '\t' '/^COUNT\t/ { printf "%s %s\n", $3, $2 }' "$agg_tmp" | LC_ALL=C sort -k2 > "$tmpd/baseline"
  printf 'TOTAL %s\n' "$tot" >> "$tmpd/baseline"
  if ! cat "$tmpd/baseline" > "$UPDATE_BASELINE"; then
    echo "docs-lint.sh: cannot write baseline: $UPDATE_BASELINE" >&2
    exit 1
  fi
  echo "docs-lint.sh: baseline written: $UPDATE_BASELINE (TOTAL $tot)"
  exit 0
fi

# ratchet_check: the per-file rows and the total of the scan vs a
# baseline file; prints the failures and returns 1 when either is exceeded
ratchet_check() {
  bfile=$1
  if [ ! -f "$bfile" ]; then
    echo "docs-lint.sh: baseline file not found: $bfile (generate with --update-baseline)" >&2
    return 1
  fi
  base_tot=$("$AWK_BIN" '/^TOTAL[ \t]/ { t = $2 + 0 } END { print t + 0 }' "$bfile")
  base_tot=${base_tot:-0}
  overages=$(
    "$AWK_BIN" -F '\t' -v bfile="$bfile" '
      BEGIN {
        while ((getline bl < bfile) > 0) {
          if (bl ~ /^TOTAL[ \t]/) continue
          split(bl, a, " ")
          base[a[2]] = a[1] + 0
        }
      }
      /^COUNT\t/ {
        c = $3 + 0
        b = (($2 in base) ? base[$2] : 0)
        if (c > b) printf "%s: %d (overage %d)\n", $2, c, c - b
      }
    ' "$agg_tmp"
  )
  fail=0
  if [ -n "$overages" ]; then
    echo "docs-lint.sh: FAIL: per-file baseline rows exceeded:" >&2
    printf '%s\n' "$overages" | sed 's/^/  /' >&2
    fail=1
  fi
  if [ "$tot" -gt "$base_tot" ]; then
    echo "docs-lint.sh: FAIL: total $tot exceeds baseline $base_tot ($bfile); regenerate with --update-baseline only after deliberate rewrites" >&2
    fail=1
  fi
  return $fail
}

# integrity_check: the committed baseline vs the base baseline and the
# adoption manifest — every tracked path's row may only stay equal or
# decrease (a path missing in the committed baseline is a deletion and
# is fine), a path new in the committed baseline is allowed only when
# listed in the adoption manifest, and the total may only stay equal or
# decrease; prints the failures and returns 1 when any of the three
# holds
integrity_check() {
  basefile=$1
  curfile=$2
  manifest=$3
  base_tot=$("$AWK_BIN" '/^TOTAL[ \t]/ { t = $2 + 0 } END { print t + 0 }' "$basefile")
  cur_tot=$("$AWK_BIN" '/^TOTAL[ \t]/ { t = $2 + 0 } END { print t + 0 }' "$curfile")
  base_tot=${base_tot:-0}
  cur_tot=${cur_tot:-0}
  fail=0
  increases=$(
    "$AWK_BIN" -v basefile="$basefile" -v curfile="$curfile" '
      BEGIN {
        while ((getline bl < basefile) > 0) {
          if (bl ~ /^TOTAL[ \t]/) continue
          split(bl, a, " ")
          base[a[2]] = a[1] + 0
        }
        while ((getline cl < curfile) > 0) {
          if (cl ~ /^TOTAL[ \t]/) continue
          split(cl, b, " ")
          if ((b[2] in base) && b[1] + 0 > base[b[2]]) {
            printf "%s: %d (increase %d)\n", b[2], b[1] + 0, b[1] + 0 - base[b[2]]
          }
        }
      }
    '
  )
  if [ -n "$increases" ]; then
    echo "docs-lint.sh: FAIL: baseline rows increased vs the base baseline:" >&2
    printf '%s\n' "$increases" | sed 's/^/  /' >&2
    fail=1
  fi
  newpaths=$(
    "$AWK_BIN" -v basefile="$basefile" -v curfile="$curfile" -v manifest="$manifest" '
      BEGIN {
        while ((getline bl < basefile) > 0) {
          if (bl ~ /^TOTAL[ \t]/) continue
          split(bl, a, " ")
          base[a[2]] = 1
        }
        while ((getline ml < manifest) > 0) {
          sub(/^[ \t]*/, "", ml)
          sub(/[ \t]*#.*/, "", ml)
          sub(/[ \t]+$/, "", ml)
          if (ml == "") continue
          adopted[ml] = 1
        }
        while ((getline cl < curfile) > 0) {
          if (cl ~ /^TOTAL[ \t]/) continue
          split(cl, b, " ")
          if (!(b[2] in base) && !(b[2] in adopted)) {
            printf "%s (not adopted)\n", b[2]
          }
        }
      }
    '
  )
  if [ -n "$newpaths" ]; then
    echo "docs-lint.sh: FAIL: baseline paths not in the base baseline and not adopted:" >&2
    printf '%s\n' "$newpaths" | sed 's/^/  /' >&2
    fail=1
  fi
  if [ "$cur_tot" -gt "$base_tot" ]; then
    echo "docs-lint.sh: FAIL: total $cur_tot exceeds the base baseline total $base_tot" >&2
    fail=1
  fi
  return $fail
}

if [ -n "$BASELINE" ]; then
  if ! ratchet_check "$BASELINE"; then exit 1; fi
  echo "docs-lint.sh: OK: total $tot at or below baseline $base_tot; every scanned file at or below its per-file row"
  exit 0
fi

if [ -n "$INTEGRITY" ]; then
  if [ ! -f "$INTEGRITY" ]; then
    echo "docs-lint.sh: base baseline file not found: $INTEGRITY" >&2
    exit 1
  fi
  cur_baseline="$SCRIPT_DIR/docs-lint-baseline.txt"
  manifest="$SCRIPT_DIR/docs-lint-adopted.txt"
  if [ -n "$CUR_BASELINE_OVERRIDE" ]; then cur_baseline="$CUR_BASELINE_OVERRIDE"; fi
  if [ -n "$MANIFEST_OVERRIDE" ]; then manifest="$MANIFEST_OVERRIDE"; fi
  if [ ! -f "$cur_baseline" ]; then
    echo "docs-lint.sh: committed baseline not found: $cur_baseline" >&2
    exit 1
  fi
  if [ ! -f "$manifest" ]; then
    echo "docs-lint.sh: adoption manifest not found: $manifest" >&2
    exit 1
  fi
  fail=0
  if ! ratchet_check "$cur_baseline"; then fail=1; fi
  if ! integrity_check "$INTEGRITY" "$cur_baseline" "$manifest"; then fail=1; fi

  # One-shot adoption: an entry whose path has landed — a row in the
  # current committed baseline (the adoption took effect there), or a row
  # already in the comparison base baseline (it landed in an ancestor) —
  # is consumed. Consumed entries are removed from the manifest (atomic
  # tmp+mv, comments/blank lines untouched), so a path dropped from the
  # baseline and later reintroduced is never re-adopted by a stale entry:
  # it needs a fresh adoption, and until then its implicit baseline row
  # is zero. --no-write-adopted keeps the manifest read-only (CI): the
  # entry still counts as adopted for this run; a later writable run
  # consumes it.
  consumed=$(
    "$AWK_BIN" -v basefile="$INTEGRITY" -v curfile="$cur_baseline" -v manifest="$manifest" '
      BEGIN {
        while ((getline bl < basefile) > 0) {
          if (bl ~ /^TOTAL[ \t]/) continue
          split(bl, a, " ")
          base[a[2]] = 1
        }
        while ((getline cl < curfile) > 0) {
          if (cl ~ /^TOTAL[ \t]/) continue
          split(cl, b, " ")
          cur[b[2]] = 1
        }
        while ((getline ml < manifest) > 0) {
          entry = ml
          sub(/^[ \t]*/, "", entry)
          sub(/[ \t]*#.*/, "", entry)
          sub(/[ \t]+$/, "", entry)
          if (entry == "") continue
          if ((entry in cur) || (entry in base)) print entry
        }
      }
    '
  )
  if [ -n "$consumed" ]; then
    if [ "$NO_WRITE_ADOPTED" -eq 1 ]; then
      echo "docs-lint.sh: note: consumed adoption entries kept (--no-write-adopted):"
      printf '%s\n' "$consumed" | sed 's/^/  /'
    else
      printf '%s\n' "$consumed" > "$tmpd/consumed.txt"
      manifest_out="${manifest}.docs-lint-new"
      if "$AWK_BIN" -v consumedfile="$tmpd/consumed.txt" '
        BEGIN { while ((getline cl < consumedfile) > 0) consumed[cl] = 1 }
        {
          entry = $0
          sub(/^[ \t]*/, "", entry)
          sub(/[ \t]*#.*/, "", entry)
          sub(/[ \t]+$/, "", entry)
          if (entry != "" && (entry in consumed)) next
          print
        }
      ' "$manifest" > "$manifest_out" && mv -f "$manifest_out" "$manifest"; then
        echo "docs-lint.sh: adoption manifest updated (consumed entries removed, one-shot):"
        printf '%s\n' "$consumed" | sed 's/^/  /'
      else
        rm -f "$manifest_out"
        echo "docs-lint.sh: cannot rewrite the adoption manifest: $manifest (stale entries kept)" >&2
      fi
    fi
  fi

  if [ "$fail" -eq 1 ]; then exit 1; fi
  echo "docs-lint.sh: OK: total $tot at or below the committed baseline; every scanned file at or below its per-file row; committed baseline monotonic vs the base baseline (no tracked-path increase, no un-adopted new path, total at or below the base total)"
  exit 0
fi

echo "docs-lint.sh: advisory: total $tot, no baseline given (exit 0)"
exit 0
