package testintel

import (
	"encoding/xml"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/kiwici/kiwi/internal/model"
)

type Suite struct {
	XMLName  xml.Name `xml:"testsuite"`
	Name     string   `xml:"name,attr"`
	Tests    int      `xml:"tests,attr"`
	Failures int      `xml:"failures,attr"`
	Cases    []Case   `xml:"testcase"`
}
type Case struct {
	Name    string   `xml:"name,attr"`
	Class   string   `xml:"classname,attr"`
	Time    float64  `xml:"time,attr"`
	Failure *Failure `xml:"failure"`
}
type Failure struct {
	Message string `xml:"message,attr"`
	Body    string `xml:",chardata"`
}

func Parse(path string) (Suite, error) {
	var s Suite
	b, err := os.ReadFile(path)
	if err != nil {
		return s, err
	}
	err = xml.Unmarshal(b, &s)
	return s, err
}

// Aggregate parses every JUnit file matching the given workspace-relative
// globs and merges them into one per-job report for flaky-test history and
// future test splitting.
func Aggregate(workspace string, patterns []string) (model.TestReport, error) {
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
		suite, err := Parse(f)
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
		out.Tests += suite.Tests
		out.Failures += suite.Failures
		for _, c := range suite.Cases {
			r := model.TestResult{Name: c.Name, Class: c.Class, Duration: c.Time, Passed: c.Failure == nil}
			if c.Failure != nil {
				r.Message = strings.TrimSpace(c.Failure.Message + "\n" + c.Failure.Body)
			}
			out.Cases = append(out.Cases, r)
			out.Duration += c.Time
		}
	}
	return out, nil
}
