// Package testintel parses test reports (JUnit XML), aggregates them into
// per-job report models, and maintains flaky-test history with deterministic
// duration-balanced sharding.
package testintel

import (
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// Hard limits that bound report ingestion. They exist so a hostile or
// corrupted report file cannot exhaust memory or wedge the control plane.
const (
	maxReportBytes = 64 << 20 // 64 MiB per report file
	maxReportCases = 100_000  // cases per report file
	maxJobCases    = 500_000  // total cases per job across all files
	maxMessageLen  = 64 << 10 // 64 KiB per failure/error message
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
// maxReportBytes.
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
	if fi.Size() > maxReportBytes {
		return out, fmt.Errorf("%w: %s larger than 64 MiB", ErrLimitExceeded, path)
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

	dec := xml.NewDecoder(f)
	cases := 0
	seen := false
	for {
		tok, derr := dec.Token()
		if derr == io.EOF {
			break
		}
		if derr != nil {
			return out, fmt.Errorf("parse %s: %w", path, derr)
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
				return out, fmt.Errorf("parse %s: %w", path, serr)
			}
			for _, s := range suites {
				appendSuite(&out, s)
			}
		case "testcase":
			seen = true
			c, cerr := readCase(dec, se, mask, &cases)
			if cerr != nil {
				return out, fmt.Errorf("parse %s: %w", path, cerr)
			}
			s := Suite{Name: path, Tests: 1, Time: c.Time, Cases: []Case{c}}
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
				return out, fmt.Errorf("parse %s: %w", path, err)
			}
		}
	}
	if !seen {
		return out, fmt.Errorf("parse %s: not a JUnit report (no testsuite/testcase elements)", path)
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

// readCase decodes one <testcase> element, applies masking and truncation,
// and enforces the per-report case limit.
func readCase(dec *xml.Decoder, se xml.StartElement, mask func(string) string, cases *int) (Case, error) {
	var c Case
	if err := dec.DecodeElement(&c, &se); err != nil {
		return c, err
	}
	truncateCase(&c)
	if mask != nil {
		applyMask(&c, mask)
	}
	*cases++
	if *cases > maxReportCases {
		return c, fmt.Errorf("%w: more than %d cases", ErrLimitExceeded, maxReportCases)
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
	if len(f.Message) > maxMessageLen {
		f.Message = f.Message[:maxMessageLen]
	}
	if len(f.Body) > maxMessageLen {
		f.Body = f.Body[:maxMessageLen]
	}
	if len(f.Message)+len(f.Body) > maxMessageLen {
		keep := maxMessageLen - len(f.Message)
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
	if err != nil {
		return 0, false
	}
	return f, true
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
// mask. Files resolving outside the workspace are rejected.
func Aggregate(workspace string, patterns []string) (model.TestReport, error) {
	return AggregateMasked(workspace, patterns, nil)
}

// AggregateMasked is Aggregate with a secret-masking hook applied to
// failure/error messages and system-err excerpts.
func AggregateMasked(workspace string, patterns []string, mask func(string) string) (model.TestReport, error) {
	var files []string
	for _, p := range patterns {
		matches, err := filepath.Glob(filepath.Join(workspace, p))
		if err != nil {
			return model.TestReport{}, err
		}
		files = append(files, matches...)
	}
	sort.Strings(files)
	out := model.TestReport{}
	for _, f := range files {
		if !Within(workspace, f) {
			return model.TestReport{}, fmt.Errorf("test report %s resolves outside workspace", f)
		}
		rep, err := ParseMasked(f, mask)
		if err != nil {
			return model.TestReport{}, err
		}
		rel, err := filepath.Rel(workspace, f)
		if err != nil {
			rel = f
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
			if len(out.Cases) >= maxJobCases {
				return model.TestReport{}, fmt.Errorf("%w: more than %d cases per job", ErrLimitExceeded, maxJobCases)
			}
			out.Cases = append(out.Cases, r)
		}
	}
	return out, nil
}
