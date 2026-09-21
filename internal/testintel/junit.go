// Package testintel parses test reports (JUnit XML), aggregates them into
// per-job report models, and maintains flaky-test history with deterministic
// duration-balanced sharding.
package testintel

import (
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/safefs"
)

// The hard ingestion limits live in limits.go: MaxReportFileBytes,
// MaxJobReportBytes, MaxReportCases, MaxJobCases, MaxMessageBytes and
// MaxReportFiles, plus the shared request/payload budgets the server and the
// runner enforce. Every layer (parser, runner pre-check, /tests decode) uses
// those constants, so there is exactly one size contract.
const (
	// maxReportDuration is the largest suite/case duration (in seconds,
	// about 31.7 years) accepted from a report. Non-finite, negative and
	// larger values are dropped to 0 (see sanitizeDuration).
	maxReportDuration = 1e9
)

// Suite is one <testsuite> element. Counts are the attributes when present
// and are recomputed from the cases when a producer omits them.
type Suite struct {
	Name     string  `json:"name,omitempty"`
	Tests    int     `json:"tests"`
	Failures int     `json:"failures,omitempty"`
	Errors   int     `json:"errors,omitempty"`
	Skipped  int     `json:"skipped,omitempty"`
	Time     float64 `json:"time,omitempty"`
	Cases    []Case  `json:"cases,omitempty"`
}

// Case is one <testcase> element. Failure and Error share the Failure shape
// (message attribute plus body chardata); Skipped carries an optional
// message attribute.
type Case struct {
	Name      string   `xml:"name,attr"`
	Class     string   `xml:"classname,attr"`
	Time      float64  `xml:"time,attr"`
	Failure   *Failure `xml:"failure"`
	Error     *Failure `xml:"error"`
	Skipped   *Skipped `xml:"skipped"`
	SystemErr string   `xml:"system-err"`
}

// Failure is a <failure> or <error> element.
type Failure struct {
	Message string `xml:"message,attr"`
	Body    string `xml:",chardata"`
}

// Skipped is a <skipped> element.
type Skipped struct {
	Message string `xml:"message,attr"`
}

// Report is the merged result of parsing one or more JUnit files.
type Report struct {
	Suites   []Suite
	Tests    int
	Failures int
	Errors   int
	Skipped  int
	Duration float64
	Cases    []Case
}

// ErrLimitExceeded reports that a report exceeded an ingestion limit.
var ErrLimitExceeded = errors.New("test report exceeds limits")

// Parse parses one JUnit file into a Report. The file must be a regular
// file (symlinks, sockets and devices are rejected) no larger than
// MaxReportFileBytes.
func Parse(path string) (Report, error) {
	return ParseMasked(path, nil)
}

// ParseMasked parses one JUnit file, applying mask to failure/error
// messages and system-err excerpts before they are retained. A nil mask
// keeps content verbatim.
func ParseMasked(path string, mask func(string) string) (Report, error) {
	var out Report
	fi, err := os.Lstat(path)
	if err != nil {
		return out, err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return out, fmt.Errorf("test report %s: symlinks are not allowed", path)
	}
	if fi.Size() > MaxReportFileBytes {
		return out, fmt.Errorf("%w: %s larger than %d bytes", ErrLimitExceeded, path, MaxReportFileBytes)
	}
	f, err := os.Open(path)
	if err != nil {
		return out, err
	}
	defer f.Close()
	// Stat after open: the descriptor describes the actual object, so even
	// if the path was swapped for a device between Lstat and Open the
	// regular-file check still holds.
	st, err := f.Stat()
	if err != nil {
		return out, err
	}
	if !st.Mode().IsRegular() {
		return out, fmt.Errorf("test report %s: not a regular file", path)
	}
	return parseReport(f, path, mask)
}

// parseReport decodes one already-opened, verified regular JUnit file. It is
// the shared body of ParseMasked and of the root-anchored aggregate path:
// parseReport never opens, stats or closes anything, so callers that reach a
// file through a held workspace descriptor keep that no-follow contract.
func parseReport(r io.Reader, name string, mask func(string) string) (Report, error) {
	var out Report
	dec := xml.NewDecoder(r)
	cases := 0
	seen := false
	for {
		tok, derr := dec.Token()
		if derr == io.EOF {
			break
		}
		if derr != nil {
			return out, fmt.Errorf("parse %s: %w", name, derr)
		}
		se, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}
		switch se.Name.Local {
		case "testsuites", "testsuite":
			seen = true
			suites, serr := readSuiteElement(dec, se, mask, &cases)
			if serr != nil {
				return out, fmt.Errorf("parse %s: %w", name, serr)
			}
			for _, s := range suites {
				appendSuite(&out, s)
			}
		case "testcase":
			seen = true
			c, cerr := readCase(dec, se, mask, &cases)
			if cerr != nil {
				return out, fmt.Errorf("parse %s: %w", name, cerr)
			}
			s := Suite{Name: name, Tests: 1, Time: c.Time, Cases: []Case{c}}
			switch {
			case c.Failure != nil:
				s.Failures = 1
			case c.Error != nil:
				s.Errors = 1
			case c.Skipped != nil:
				s.Skipped = 1
			}
			appendSuite(&out, s)
		default:
			if err := dec.Skip(); err != nil {
				return out, fmt.Errorf("parse %s: %w", name, err)
			}
		}
	}
	if !seen {
		return out, fmt.Errorf("parse %s: not a JUnit report (no testsuite/testcase elements)", name)
	}
	return out, nil
}

// readSuiteElement reads one <testsuite> element (recursing into nested
// suites) or a <testsuites> wrapper, returning every suite it contains.
func readSuiteElement(dec *xml.Decoder, se xml.StartElement, mask func(string) string, cases *int) ([]Suite, error) {
	if se.Name.Local == "testsuites" {
		var suites []Suite
		for {
			tok, err := dec.Token()
			if err == io.EOF {
				return nil, io.ErrUnexpectedEOF
			}
			if err != nil {
				return nil, err
			}
			switch t := tok.(type) {
			case xml.StartElement:
				switch t.Name.Local {
				case "testsuite":
					nested, nerr := readSuiteElement(dec, t, mask, cases)
					if nerr != nil {
						return nil, nerr
					}
					suites = append(suites, nested...)
				case "testcase":
					c, cerr := readCase(dec, t, mask, cases)
					if cerr != nil {
						return nil, cerr
					}
					s := Suite{Name: "testsuites", Tests: 1, Time: c.Time, Cases: []Case{c}}
					switch {
					case c.Failure != nil:
						s.Failures = 1
					case c.Error != nil:
						s.Errors = 1
					case c.Skipped != nil:
						s.Skipped = 1
					}
					suites = append(suites, s)
				default:
					if err := dec.Skip(); err != nil {
						return nil, err
					}
				}
			case xml.EndElement:
				if t.Name.Local == "testsuites" {
					return suites, nil
				}
			}
		}
	}
	var s Suite
	s.Name = attrValue(se, "name")
	s.Tests, _ = attrInt(se, "tests")
	s.Failures, _ = attrInt(se, "failures")
	s.Errors, _ = attrInt(se, "errors")
	s.Skipped, _ = attrInt(se, "skipped")
	s.Time, _ = attrFloat(se, "time")
	var extra []Suite
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			return nil, io.ErrUnexpectedEOF
		}
		if err != nil {
			return nil, err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			switch t.Name.Local {
			case "testcase":
				c, cerr := readCase(dec, t, mask, cases)
				if cerr != nil {
					return nil, cerr
				}
				s.Cases = append(s.Cases, c)
			case "testsuite":
				nested, nerr := readSuiteElement(dec, t, mask, cases)
				if nerr != nil {
					return nil, nerr
				}
				extra = append(extra, nested...)
			default:
				if err := dec.Skip(); err != nil {
					return nil, err
				}
			}
		case xml.EndElement:
			if t.Name.Local == "testsuite" {
				finalizeSuite(&s)
				return append([]Suite{s}, extra...), nil
			}
		}
	}
}

// caseXML is the decode mirror of Case used by readCase. It differs only in
// carrying the time attribute as a string: decoding straight into Case.Time
// would make encoding/xml reject the whole report for a malformed or
// out-of-range duration, while every other duration in a report is dropped
// to 0 by the numeric policy. The remaining fields are identical to Case.
type caseXML struct {
	Name      string   `xml:"name,attr"`
	Class     string   `xml:"classname,attr"`
	Time      string   `xml:"time,attr"`
	Failure   *Failure `xml:"failure"`
	Error     *Failure `xml:"error"`
	Skipped   *Skipped `xml:"skipped"`
	SystemErr string   `xml:"system-err"`
}

// readCase decodes one <testcase> element, applies the duration policy,
// masking and truncation, and enforces the per-report case limit.
func readCase(dec *xml.Decoder, se xml.StartElement, mask func(string) string, cases *int) (Case, error) {
	var cx caseXML
	if err := dec.DecodeElement(&cx, &se); err != nil {
		return Case{}, err
	}
	c := Case{
		Name:      cx.Name,
		Class:     cx.Class,
		Failure:   cx.Failure,
		Error:     cx.Error,
		Skipped:   cx.Skipped,
		SystemErr: cx.SystemErr,
	}
	if cx.Time != "" {
		if f, err := strconv.ParseFloat(strings.TrimSpace(cx.Time), 64); err == nil {
			c.Time = sanitizeDuration(f)
		}
	}
	truncateCase(&c)
	if mask != nil {
		applyMask(&c, mask)
	}
	*cases++
	if *cases > MaxReportCases {
		return c, fmt.Errorf("%w: more than %d cases", ErrLimitExceeded, MaxReportCases)
	}
	return c, nil
}

// appendSuite merges one suite into the report totals.
func appendSuite(out *Report, s Suite) {
	finalizeSuite(&s)
	out.Suites = append(out.Suites, s)
	out.Tests += s.Tests
	out.Failures += s.Failures
	out.Errors += s.Errors
	out.Skipped += s.Skipped
	out.Duration += s.Time
	out.Cases = append(out.Cases, s.Cases...)
}

// finalizeSuite derives counters from case outcomes when the producer's
// attributes are missing or smaller than the case-derived counts.
func finalizeSuite(s *Suite) {
	var fail, errs, skip int
	for _, c := range s.Cases {
		switch {
		case c.Failure != nil:
			fail++
		case c.Error != nil:
			errs++
		case c.Skipped != nil:
			skip++
		}
	}
	if s.Failures < fail {
		s.Failures = fail
	}
	if s.Errors < errs {
		s.Errors = errs
	}
	if s.Skipped < skip {
		s.Skipped = skip
	}
	if s.Tests < len(s.Cases) {
		s.Tests = len(s.Cases)
	}
}

func applyMask(c *Case, mask func(string) string) {
	if c.Failure != nil {
		c.Failure.Message = mask(c.Failure.Message)
		c.Failure.Body = mask(c.Failure.Body)
	}
	if c.Error != nil {
		c.Error.Message = mask(c.Error.Message)
		c.Error.Body = mask(c.Error.Body)
	}
	c.SystemErr = mask(c.SystemErr)
	truncateCase(c)
}

func truncateCase(c *Case) {
	truncateFailure(c.Failure)
	truncateFailure(c.Error)
}

func truncateFailure(f *Failure) {
	if f == nil {
		return
	}
	if len(f.Message) > MaxMessageBytes {
		f.Message = f.Message[:MaxMessageBytes]
	}
	if len(f.Body) > MaxMessageBytes {
		f.Body = f.Body[:MaxMessageBytes]
	}
	if len(f.Message)+len(f.Body) > MaxMessageBytes {
		keep := MaxMessageBytes - len(f.Message)
		if keep < 0 {
			keep = 0
		}
		f.Body = f.Body[:keep]
	}
}

func attrValue(se xml.StartElement, name string) string {
	for _, a := range se.Attr {
		if a.Name.Local == name {
			return a.Value
		}
	}
	return ""
}

func attrInt(se xml.StartElement, name string) (int, bool) {
	v := attrValue(se, name)
	if v == "" {
		return 0, false
	}
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil {
		return 0, false
	}
	return n, true
}

func attrFloat(se xml.StartElement, name string) (float64, bool) {
	v := attrValue(se, name)
	if v == "" {
		return 0, false
	}
	f, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
	if err != nil || !validDuration(f) {
		return 0, false
	}
	return f, true
}

// validDuration is the numeric policy for suite and case durations: only
// finite, non-negative values within maxReportDuration are usable. NaN,
// ±Inf, negatives and absurdly large values are producer garbage: a NaN
// makes every later comparison false and would survive arithmetic into
// totals, and Inf/negative values poison duration balancing.
func validDuration(f float64) bool {
	return !math.IsNaN(f) && !math.IsInf(f, 0) && f >= 0 && f <= maxReportDuration
}

// sanitizeDuration applies the numeric policy by dropping an invalid
// duration to 0 instead of failing the report: durations are producer
// metadata, so a malformed value must not reject an otherwise valid report,
// but it must never reach sums or the API either. Zero is the same default a
// missing time attribute gets, so dropping records nothing invalid.
func sanitizeDuration(f float64) float64 {
	if !validDuration(f) {
		return 0
	}
	return f
}

// Within reports whether path (already cleaned) is lexically inside
// workspace: the relative path must not escape with ".." and must not be
// absolute.
func Within(workspace, path string) bool {
	rel, err := filepath.Rel(workspace, path)
	if err != nil {
		return false
	}
	return rel != "." && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)
}

// Aggregate parses every JUnit file matching the given workspace-relative
// globs and merges them into one per-job report for flaky-test history and
// future test splitting. It is equivalent to AggregateMasked with a nil
// mask. Patterns are resolved component by component beneath the workspace
// root without ever following a symlink; matched files are opened through a
// held workspace root descriptor with the no-follow discipline, so a
// symlinked parent directory or final file can never make the host collector
// read outside the workspace.
func Aggregate(workspace string, patterns []string) (model.TestReport, error) {
	return AggregateMasked(workspace, patterns, nil)
}

// AggregateMasked is Aggregate with a secret-masking hook applied to
// failure/error messages and system-err excerpts. The mask must be safe for
// concurrent use when the caller shares it with other goroutines; the runner
// passes secrets.Masker.Mask, which takes a read lock.
func AggregateMasked(workspace string, patterns []string, mask func(string) string) (model.TestReport, error) {
	root, err := safefs.OpenWorkspaceRoot(workspace)
	if err != nil {
		return model.TestReport{}, fmt.Errorf("test reports: open workspace %s: %w", workspace, err)
	}
	defer root.Close()
	var files []string
	for _, p := range patterns {
		matches, err := reportCandidates(root, p)
		if err != nil {
			return model.TestReport{}, err
		}
		files = append(files, matches...)
	}
	sort.Strings(files)
	if len(files) > MaxReportFiles {
		return model.TestReport{}, fmt.Errorf("%w: %d matched report files exceeds the %d file cap", ErrLimitExceeded, len(files), MaxReportFiles)
	}
	// Size every match through the no-follow workspace root before any
	// content is parsed: the total-byte cap must hold even when the leading
	// files would each parse cleanly. Each descriptor is closed immediately
	// so a large match set cannot exhaust file descriptors.
	var total int64
	for _, rel := range files {
		f, size, err := openReport(root, rel)
		if err != nil {
			return model.TestReport{}, err
		}
		f.Close()
		total += size
		if total > MaxJobReportBytes {
			return model.TestReport{}, fmt.Errorf("%w: matched reports exceed %d bytes total", ErrLimitExceeded, MaxJobReportBytes)
		}
	}
	out := model.TestReport{}
	for _, rel := range files {
		f, _, err := openReport(root, rel)
		if err != nil {
			return model.TestReport{}, err
		}
		rep, err := parseReport(f, rel, mask)
		f.Close()
		if err != nil {
			return model.TestReport{}, err
		}
		if out.Path == "" {
			out.Path = rel
		} else {
			out.Path += ", " + rel
		}
		out.Tests += rep.Tests
		out.Failures += rep.Failures
		out.Errors += rep.Errors
		out.Skipped += rep.Skipped
		out.Duration += rep.Duration
		for _, c := range rep.Cases {
			r := model.TestResult{Name: c.Name, Class: c.Class, Duration: c.Time, Passed: c.Failure == nil && c.Error == nil && c.Skipped == nil, Skipped: c.Skipped != nil}
			if c.Failure != nil {
				r.Message = strings.TrimSpace(c.Failure.Message + "\n" + c.Failure.Body)
			} else if c.Error != nil {
				r.Message = strings.TrimSpace(c.Error.Message + "\n" + c.Error.Body)
			}
			if len(out.Cases) >= MaxJobCases {
				return model.TestReport{}, fmt.Errorf("%w: more than %d cases per job", ErrLimitExceeded, MaxJobCases)
			}
			out.Cases = append(out.Cases, r)
		}
	}
	// The serialized form is what the runner uploads and what the /tests
	// endpoint must decode: enforce the shared payload contract HERE, with
	// the exact encoding the runner sends, so the parser can never accept a
	// report the endpoint would have to reject for size. The payload budget
	// already reserves the request-envelope allowance, so an at-limit payload
	// always fits MaxTestReportRequestBytes.
	if err := ValidateReportPayload(out); err != nil {
		return model.TestReport{}, err
	}
	return out, nil
}

// openReport opens one workspace-relative report candidate through the held
// workspace root and returns the descriptor plus its verified size. OpenRel
// rejects absolute paths, parent traversal, symlinked parents and symlinked
// final components (its O_NOFOLLOW open plays the role of ParseMasked's
// final-component Lstat symlink check), and fstat-verifies the descriptor is
// a regular file, so every check the path-based ParseMasked makes still holds
// here without any path-component race. The per-file byte cap is enforced
// before the caller reads any content; the caller owns the returned
// descriptor.
func openReport(root *safefs.WorkspaceRoot, rel string) (*os.File, int64, error) {
	f, err := root.OpenRel(rel)
	if err != nil {
		return nil, 0, fmt.Errorf("test report %s: %w", rel, err)
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, 0, fmt.Errorf("test report %s: %w", rel, err)
	}
	if !st.Mode().IsRegular() {
		f.Close()
		return nil, 0, fmt.Errorf("test report %s: not a regular file", rel)
	}
	if st.Size() > MaxReportFileBytes {
		f.Close()
		return nil, 0, fmt.Errorf("%w: %s larger than %d bytes", ErrLimitExceeded, rel, MaxReportFileBytes)
	}
	return f, st.Size(), nil
}

// reportCandidates expands one workspace-relative glob pattern into
// candidate paths by walking the workspace one component at a time,
// anchored at the canonical workspace root: a pattern component is matched
// with filepath.Match against the entries of one directory, so "*" can
// never cross a separator and a pattern can never name an absolute path or
// a path above the workspace. Unlike filepath.Glob it never follows a
// symlink: a symlink in any matched component fails the expansion (fail
// closed) instead of being resolved, because resolving it would read files
// outside the workspace. The returned paths are workspace-relative,
// slash-separated names; the caller opens each through
// safefs.WorkspaceRoot.OpenRel, which re-verifies no-follow at read time.
//
// The component walk uses os.Lstat/os.ReadDir on names below the canonical
// root purely to enumerate candidates; a directory swapped for a symlink
// while the walk runs can at most add names, never content: OpenRel refuses
// the open, and no file is ever read by path.
func reportCandidates(root *safefs.WorkspaceRoot, pattern string) ([]string, error) {
	pat, err := reportPattern(pattern)
	if err != nil {
		return nil, err
	}
	comps := strings.Split(pat, "/")
	current := []string{""}
	for i, comp := range comps {
		last := i == len(comps)-1
		next := make([]string, 0, len(current))
		for _, base := range current {
			if !strings.ContainsAny(comp, "*?[") {
				rel := joinRel(base, comp)
				info, err := os.Lstat(rootAbs(root, rel))
				if err != nil {
					if os.IsNotExist(err) {
						continue
					}
					return nil, err
				}
				if info.Mode()&os.ModeSymlink != 0 {
					return nil, fmt.Errorf("test report %s: symlinks are not allowed", rel)
				}
				if !last && !info.IsDir() {
					continue
				}
				next = append(next, rel)
				continue
			}
			entries, err := os.ReadDir(rootAbs(root, base))
			if err != nil {
				if os.IsNotExist(err) {
					continue
				}
				return nil, err
			}
			for _, e := range entries {
				ok, merr := filepath.Match(comp, e.Name())
				if merr != nil {
					return nil, fmt.Errorf("test report pattern %q: %w", pattern, merr)
				}
				if !ok {
					continue
				}
				rel := joinRel(base, e.Name())
				if e.Type()&os.ModeSymlink != 0 {
					return nil, fmt.Errorf("test report %s: symlinks are not allowed", rel)
				}
				if !last && !e.IsDir() {
					continue
				}
				next = append(next, rel)
			}
		}
		current = next
	}
	sort.Strings(current)
	return current, nil
}

// reportPattern validates a job's workspace-relative glob pattern before it
// is expanded. Absolute patterns, backslashes, NUL bytes and ".."
// components are rejected up front so no pattern can even name a path
// outside the workspace; "." and empty patterns are rejected because they
// name no file. The pattern is normalized with path.Clean after the
// traversal check so cleaning can never hide a "..".
func reportPattern(pattern string) (string, error) {
	if pattern == "" {
		return "", fmt.Errorf("test report pattern is empty")
	}
	if strings.ContainsRune(pattern, '\x00') || strings.Contains(pattern, "\\") {
		return "", fmt.Errorf("test report pattern %q contains an invalid character", pattern)
	}
	if strings.HasPrefix(pattern, "/") || filepath.IsAbs(pattern) {
		return "", fmt.Errorf("test report pattern %q must be workspace-relative", pattern)
	}
	for _, comp := range strings.Split(pattern, "/") {
		if comp == ".." {
			return "", fmt.Errorf("test report pattern %q escapes the workspace", pattern)
		}
	}
	clean := path.Clean(pattern)
	if clean == "." || clean == "" {
		return "", fmt.Errorf("test report pattern %q does not name a file", pattern)
	}
	return clean, nil
}

func rootAbs(root *safefs.WorkspaceRoot, rel string) string {
	if rel == "" {
		return root.Canonical
	}
	return filepath.Join(root.Canonical, filepath.FromSlash(rel))
}

func joinRel(base, name string) string {
	if base == "" {
		return name
	}
	return base + "/" + name
}
