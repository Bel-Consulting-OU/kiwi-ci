package server

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// A minimal 5-field cron parser (minute hour day-of-month month
// day-of-week) built on the standard library only. It supports wildcards,
// lists, ranges, steps ("*/n", "a-b/n") and the usual 3-letter names for
// months and weekdays. Day-of-month and day-of-week are OR-ed when both are
// restricted, matching Vixie cron semantics.

type cronField struct {
	min, max int
	mask     []bool
}

var cronMonthNames = map[string]int{
	"jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5, "jun": 6,
	"jul": 7, "aug": 8, "sep": 9, "oct": 10, "nov": 11, "dec": 12,
}

var cronDowNames = map[string]int{
	"sun": 0, "mon": 1, "tue": 2, "wed": 3, "thu": 4, "fri": 5, "sat": 6,
}

// parseCronField parses one cron field into a minute-of-the-range mask.
// names maps optional symbolic values onto their numeric form.
func parseCronField(s string, min, max int, names map[string]int) (cronField, error) {
	f := cronField{min: min, max: max, mask: make([]bool, max-min+1)}
	parts := strings.Split(s, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			return f, fmt.Errorf("empty field entry")
		}
		step := 1
		base := part
		if idx := strings.Index(part, "/"); idx >= 0 {
			base = part[:idx]
			v, err := strconv.Atoi(part[idx+1:])
			if err != nil || v < 1 {
				return f, fmt.Errorf("invalid step in %q", part)
			}
			step = v
		}
		low, high := min, max
		switch {
		case base == "*" || base == "?":
		case strings.Contains(base, "-"):
			ab := strings.SplitN(base, "-", 2)
			var err error
			low, err = cronValue(ab[0], min, max, names)
			if err != nil {
				return f, err
			}
			high, err = cronValue(ab[1], min, max, names)
			if err != nil {
				return f, err
			}
		default:
			v, err := cronValue(base, min, max, names)
			if err != nil {
				return f, err
			}
			low, high = v, v
		}
		if low > high || high > max || low < min {
			return f, fmt.Errorf("invalid range in %q", part)
		}
		for v := low; v <= high; v += step {
			f.mask[v-min] = true
		}
	}
	return f, nil
}

// cronValue converts a single field entry (number or name) to its value.
func cronValue(s string, min, max int, names map[string]int) (int, error) {
	if names != nil {
		if v, ok := names[strings.ToLower(s)]; ok {
			return v, nil
		}
	}
	v, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("invalid cron value %q", s)
	}
	return v, nil
}

// cronSchedule is a parsed 5-field cron expression.
type cronSchedule struct {
	minute, hour, dom, month, dow cronField
}

// ParseCron parses a 5-field cron expression.
func ParseCron(s string) (cronSchedule, error) {
	fields := strings.Fields(s)
	if len(fields) != 5 {
		return cronSchedule{}, fmt.Errorf("cron spec %q must have 5 fields, got %d", s, len(fields))
	}
	var cs cronSchedule
	var err error
	if cs.minute, err = parseCronField(fields[0], 0, 59, nil); err != nil {
		return cs, fmt.Errorf("minute field: %w", err)
	}
	if cs.hour, err = parseCronField(fields[1], 0, 23, nil); err != nil {
		return cs, fmt.Errorf("hour field: %w", err)
	}
	if cs.dom, err = parseCronField(fields[2], 1, 31, nil); err != nil {
		return cs, fmt.Errorf("day-of-month field: %w", err)
	}
	if cs.month, err = parseCronField(fields[3], 1, 12, cronMonthNames); err != nil {
		return cs, fmt.Errorf("month field: %w", err)
	}
	if cs.dow, err = parseCronField(fields[4], 0, 6, cronDowNames); err != nil {
		return cs, fmt.Errorf("day-of-week field: %w", err)
	}
	return cs, nil
}

// matches reports whether the instant matches the cron schedule. When both
// day-of-month and day-of-week are restricted, either may match (OR
// semantics).
func (c cronSchedule) matches(t time.Time) bool {
	if !c.minute.mask[t.Minute()-c.minute.min] || !c.hour.mask[t.Hour()-c.hour.min] || !c.month.mask[int(t.Month())-c.month.min] {
		return false
	}
	domSet := c.dom.mask[t.Day()-c.dom.min]
	dowSet := c.dow.mask[int(t.Weekday())-c.dow.min]
	domRestricted, dowRestricted := c.dom.isRestricted(), c.dow.isRestricted()
	switch {
	case domRestricted && dowRestricted:
		return domSet || dowSet
	case domRestricted:
		return domSet
	case dowRestricted:
		return dowSet
	default:
		return true
	}
}

func (f cronField) isRestricted() bool {
	for _, v := range f.mask {
		if !v {
			return true
		}
	}
	return false
}

// next returns the first occurrence strictly after t, or a zero time when
// none exists within the search horizon.
func (c cronSchedule) next(t time.Time) time.Time {
	return c.nextBudget(t, nil)
}

// nextBudget is next with an optional shared scan budget. Every calendar day
// examined spends one unit; when the budget is exhausted the search stops and
// reports "no occurrence" (a zero time). A nil budget is unlimited.
//
// The search is DAY-granular, not minute-granular: for each day the
// month/day-of-month/day-of-week fields are checked first, and only a day
// that can match pays for locating the earliest matching hour/minute. This
// bounds every call to maxCronHorizonDays day steps (plus at most 24*60
// minute probes on days that can match), instead of the ~1M minute steps the
// previous minute-by-minute scan needed. The horizon is wide enough to cover
// day-of-month/day-of-week combinations that only occur across a four-year
// (or, around a skipped century leap year, eight-year) span, so a zero
// result now means the expression is genuinely unreachable rather than merely
// far away.
func (c cronSchedule) nextBudget(t time.Time, budget *cronScanBudget) time.Time {
	start := t.Truncate(time.Minute)
	day := time.Date(start.Year(), start.Month(), start.Day(), 0, 0, 0, 0, start.Location())
	for i := 0; i <= maxCronHorizonDays; i++ {
		if !budget.spend(1) {
			return time.Time{}
		}
		if c.dayMatches(day) {
			if hit := c.firstTimeOnDay(day, start); !hit.IsZero() {
				return hit
			}
		}
		day = day.AddDate(0, 0, 1)
	}
	return time.Time{}
}

// dayMatches reports whether a day satisfies the month plus the day-of-month
// / day-of-week fields (OR semantics when both are restricted), ignoring the
// time-of-day fields.
func (c cronSchedule) dayMatches(day time.Time) bool {
	if !c.month.mask[int(day.Month())-c.month.min] {
		return false
	}
	domSet := c.dom.mask[day.Day()-c.dom.min]
	dowSet := c.dow.mask[int(day.Weekday())-c.dow.min]
	domRestricted, dowRestricted := c.dom.isRestricted(), c.dow.isRestricted()
	switch {
	case domRestricted && dowRestricted:
		return domSet || dowSet
	case domRestricted:
		return domSet
	case dowRestricted:
		return dowSet
	default:
		return true
	}
}

// firstTimeOnDay returns the earliest hour/minute on day that matches the
// hour and minute fields and is strictly after start (when start is on a
// later day every time qualifies). It returns the zero time when the day has
// no matching time left.
func (c cronSchedule) firstTimeOnDay(day, start time.Time) time.Time {
	for h := c.hour.min; h <= c.hour.max; h++ {
		if !c.hour.mask[h-c.hour.min] {
			continue
		}
		for m := c.minute.min; m <= c.minute.max; m++ {
			if !c.minute.mask[m-c.minute.min] {
				continue
			}
			cand := time.Date(day.Year(), day.Month(), day.Day(), h, m, 0, 0, start.Location())
			if cand.After(start) {
				return cand
			}
		}
	}
	return time.Time{}
}

// maxCronHorizonDays bounds the next-occurrence search. Eight years (plus a
// small leap-day margin) covers every Gregorian day-of-month/day-of-week
// combination that can occur: a valid Feb-29 expression fires at least every
// eight years even across a skipped century leap year, and any other valid
// month/day combination fires within a year. An expression with no match in
// this window is genuinely unreachable and is rejected at admission.
const maxCronHorizonDays = 366*8 + 2

// cronScanBudget is a shared, per-tick bound on total cron scan work. Every
// calendar day examined by nextBudget spends one unit; when the budget is
// exhausted, remaining schedules in the tick are skipped rather than letting
// a large schedule set turn one maintenance tick into an unbounded scan.
type cronScanBudget struct {
	remaining int
}

// newCronScanBudget returns a budget of n day-steps; n <= 0 means unlimited.
// cronScanBudgetHook, when non-nil, observes every budget created for a cron
// scan. It exists so tests can assert the shared per-tick bound deterministically
// instead of relying on wall-clock timing. Production leaves it nil.
var cronScanBudgetHook func(*cronScanBudget)

func newCronScanBudget(n int) *cronScanBudget {
	if n <= 0 {
		return nil
	}
	b := &cronScanBudget{remaining: n}
	if cronScanBudgetHook != nil {
		cronScanBudgetHook(b)
	}
	return b
}

// spend deducts n units, reporting false (and leaving the budget at zero)
// when n would exceed the remainder. A nil budget is unlimited.
func (b *cronScanBudget) spend(n int) bool {
	if b == nil {
		return true
	}
	if b.remaining < n {
		b.remaining = 0
		return false
	}
	b.remaining -= n
	return true
}

// maxCronScanDaysPerTick bounds total next-occurrence scan work per
// maintenance tick across all schedules. With every call bounded by
// maxCronHorizonDays, this additionally bounds the schedule-set size's
// contribution to a single tick. A schedule the budget cannot reach is
// skipped by the caller and retried on the next tick.
const maxCronScanDaysPerTick = 250_000
