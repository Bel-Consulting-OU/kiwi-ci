#!/bin/sh
# merge-coverage.sh merges multiple Go coverage profiles into one.
# Usage: merge-coverage.sh OUT PROFILE...
# The first profile's mode line is used as the output mode. Counts are
# summed per coverage block key (file:startLine.startCol,endLine.endCol).
#
# Only count and atomic profiles can be merged by summing. A `set` profile
# records 0/1 per block, so summing two hits would emit an invalid count (2);
# such a profile is rejected below instead of being silently corrupted.
set -eu

OUT="$1"
shift
[ "$#" -ge 1 ] || {
    echo "merge-coverage: usage: merge-coverage.sh OUT PROFILE..." >&2
    exit 1
}

MODE=""
for f in "$@"; do
    [ -f "$f" ] || {
        echo "merge-coverage: $f not found" >&2
        exit 1
    }
    m=$(awk 'NR == 1 && /^mode:/ { print $2; exit }' "$f")
    [ -n "$m" ] || {
        echo "merge-coverage: $f has no mode line" >&2
        exit 1
    }
    case "$m" in
    count | atomic) ;;
    set)
        echo "merge-coverage: $f uses mode 'set' (0/1 coverage); summing counts would produce invalid blocks. Re-run with -covermode=atomic (or count)." >&2
        exit 1
        ;;
    *)
        echo "merge-coverage: $f has unsupported coverage mode '$m'" >&2
        exit 1
        ;;
    esac
    if [ -z "$MODE" ]; then
        MODE="$m"
    elif [ "$MODE" != "$m" ]; then
        echo "merge-coverage: mode mismatch ($MODE vs $m in $f)" >&2
        exit 1
    fi
done

# Materialize the input blocks BEFORE merging. Under `set -e` this makes a
# failing per-file awk abort the script; a `{ ...; } | awk` pipeline would
# instead take the final awk's exit status and silently drop blocks.
BLOCKS="$(mktemp)"
trap 'rm -f "$BLOCKS"' EXIT INT TERM
for f in "$@"; do
    awk 'NR > 1 && NF == 3 { print $1, $2, $3 }' "$f" >>"$BLOCKS"
done

{
    echo "mode: $MODE"
    awk '
{
    key = $1
    count = $3 + 0
    if (key in seen) {
        total[key] += count
    } else {
        seen[key] = 1
        order[++n] = key
        stmts[key] = $2
        total[key] = count
    }
}
END {
    for (i = 1; i <= n; i++) print order[i], stmts[order[i]], total[order[i]]
}
' "$BLOCKS"
} >"$OUT"

echo "merge-coverage: wrote $OUT (mode $MODE, $(($(wc -l <"$OUT") - 1)) blocks)"
