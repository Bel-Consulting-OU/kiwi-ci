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
	t = t.Truncate(time.Minute)
	for i := 1; i <= maxCronScanMinutes; i++ {
		t = t.Add(time.Minute)
		if c.matches(t) {
			return t
		}
	}
	return time.Time{}
}

// maxCronScanMinutes bounds the next-occurrence search (~2 years at
// minute granularity); beyond it the expression is treated as never
// matching.
const maxCronScanMinutes = 366 * 24 * 60 * 2

// nextN enumerates up to n upcoming occurrences after t, in order.
func (c cronSchedule) nextN(t time.Time, n int) []time.Time {
	out := []time.Time{}
	cur := t
	for i := 0; i < n; i++ {
		next := c.next(cur)
		if next.IsZero() {
			break
		}
		out = append(out, next)
		cur = next
	}
	return out
}
