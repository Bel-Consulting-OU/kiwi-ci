package tui

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

func TestClientAuthAndRedirectRefusal(t *testing.T) {
	var leaked bool
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			leaked = true
		}
		_, _ = w.Write([]byte("[]"))
	}))
	defer target.Close()

	var gotAuth string
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		http.Redirect(w, r, target.URL+"/elsewhere", http.StatusTemporaryRedirect)
	}))
	defer origin.Close()

	c := &Client{Server: origin.URL, Token: "s3cret"}
	// The redirect is refused (not followed), so the response surfaces as a
	// status error rather than leaking credentials to the redirect target.
	if _, err := c.ReadPage(context.Background(), "run1", 0, 10); err == nil || !strings.Contains(err.Error(), "logs 307") {
		t.Fatalf("ReadPage = %v, want a refused-redirect status error", err)
	}
	if gotAuth != "Bearer s3cret" {
		t.Fatalf("Authorization = %q, want bearer token", gotAuth)
	}
	if leaked {
		t.Fatal("credentials leaked to a redirect target")
	}

	noToken := &Client{Server: origin.URL}
	if _, err := noToken.ReadPage(context.Background(), "run1", 0, 10); err == nil {
		t.Fatal("redirect must not be followed")
	}
	if gotAuth != "" {
		t.Fatalf("Authorization = %q, want empty without a token", gotAuth)
	}
}

func TestClientCustomHTTPAndRedirectRefusal(t *testing.T) {
	hits := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		http.Redirect(w, r, "/somewhere-else", http.StatusFound)
	}))
	defer ts.Close()

	base := &http.Client{}
	cl := &Client{Server: ts.URL, HTTP: base}
	resp, err := cl.client().Get(ts.URL) //nolint:bodyclose // closed below
	if err != nil {
		t.Fatalf("client().Get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status = %d, want the un-followed redirect", resp.StatusCode)
	}
	if hits != 1 {
		t.Fatalf("redirect was followed (%d hits)", hits)
	}
	if base.CheckRedirect != nil {
		t.Fatal("custom client must not be mutated")
	}
	if cl.client() == base {
		t.Fatal("client() must return a copy of the custom client")
	}
}

func TestReadPageErrors(t *testing.T) {
	badStatus := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusInternalServerError)
	}))
	defer badStatus.Close()
	_, err := (&Client{Server: badStatus.URL}).ReadPage(context.Background(), "run1", 0, 10)
	if err == nil || !strings.Contains(err.Error(), "logs 500") {
		t.Fatalf("error = %v", err)
	}

	badJSON := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("{not json"))
	}))
	defer badJSON.Close()
	if _, err := (&Client{Server: badJSON.URL}).ReadPage(context.Background(), "run1", 0, 10); err == nil {
		t.Fatal("malformed JSON must fail")
	}

	closed := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	closed.Close()
	if _, err := (&Client{Server: closed.URL}).ReadPage(context.Background(), "run1", 0, 10); err == nil {
		t.Fatal("transport error must fail")
	}

	if _, err := (&Client{Server: "http://[::1]:namedport"}).ReadPage(context.Background(), "run1", 0, 10); err == nil {
		t.Fatal("unbuildable request URL must fail")
	}
}

func TestReadPageEscapesRunIDs(t *testing.T) {
	var rawPath string
	var query string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rawPath = r.URL.EscapedPath()
		query = r.URL.RawQuery
		_, _ = w.Write([]byte("[]"))
	}))
	defer ts.Close()

	page, err := (&Client{Server: ts.URL}).ReadPage(context.Background(), "run/with spaces", 42, 1000)
	if err != nil {
		t.Fatalf("ReadPage: %v", err)
	}
	if len(page) != 0 {
		t.Fatalf("page = %v", page)
	}
	if !strings.Contains(rawPath, "run%2Fwith%20spaces") {
		t.Fatalf("run id not escaped in path: %q", rawPath)
	}
	if !strings.Contains(query, "after=42") || !strings.Contains(query, "limit=1000") {
		t.Fatalf("query = %q", query)
	}
}

func TestStreamURLAndPaginateURLVariants(t *testing.T) {
	if got := streamURL("http://x/", "r1", 7); got != "http://x/api/v1/runs/r1/logs/stream?after=7" {
		t.Fatalf("streamURL = %q", got)
	}
	if got := paginateURL("http://x", "r 1", 0, 0); got != "http://x/api/v1/runs/r%201/logs" {
		t.Fatalf("paginateURL = %q", got)
	}
	if got := jobsURL("http://x//", "r"); got != "http://x/api/v1/runs/r/jobs" {
		t.Fatalf("jobsURL = %q", got)
	}
}

func TestFollowStreamsAndSkipsMalformed(t *testing.T) {
	// The handler holds the stream open until the test has observed the
	// first frame; the remaining frames arrive together and must each be
	// parsed (the final event: done terminates the stream).
	gotFirst := make(chan struct{})
	allowMore := make(chan struct{})
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Accept") != "text/event-stream" {
			t.Errorf("Accept = %q", r.Header.Get("Accept"))
		}
		if r.URL.Path != "/api/v1/runs/run1/logs/stream" || r.URL.Query().Get("after") != "5" {
			t.Errorf("unexpected stream request %s", r.URL)
		}
		flush := w.(http.Flusher)
		_, _ = w.Write([]byte("data: {\"seq\":6,\"job_key\":\"build\"}\n\n"))
		flush.Flush()
		<-allowMore
		_, _ = w.Write([]byte("data: not-json\n\n"))
		_, _ = w.Write([]byte("data: [DONE]\n\n"))
		_, _ = w.Write([]byte("event: done\n\n"))
		flush.Flush()
	}))
	defer ts.Close()

	var seqs []int64
	errCh := make(chan error, 1)
	go func() {
		errCh <- (&Client{Server: ts.URL, Token: "t"}).Follow(context.Background(), "run1", 5, func(e model.LogEntry) {
			seqs = append(seqs, e.Seq)
			close(gotFirst)
		})
	}()
	<-gotFirst
	close(allowMore)
	if err := <-errCh; err != nil {
		t.Fatalf("Follow: %v", err)
	}
	if len(seqs) != 1 || seqs[0] != 6 {
		t.Fatalf("emitted %v, want [6]", seqs)
	}
}

func TestFollowErrors(t *testing.T) {
	badStatus := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "closed", http.StatusGone)
	}))
	defer badStatus.Close()
	err := (&Client{Server: badStatus.URL}).Follow(context.Background(), "r", 0, func(model.LogEntry) {})
	if err == nil || !strings.Contains(err.Error(), "stream 410") {
		t.Fatalf("error = %v", err)
	}

	closed := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	closed.Close()
	if err := (&Client{Server: closed.URL}).Follow(context.Background(), "r", 0, func(model.LogEntry) {}); err == nil {
		t.Fatal("transport error must fail")
	}

	if err := (&Client{Server: "http://[::1]:namedport"}).Follow(context.Background(), "r", 0, func(model.LogEntry) {}); err == nil {
		t.Fatal("unbuildable request URL must fail")
	}
}

func TestListJobsErrors(t *testing.T) {
	badStatus := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusForbidden)
	}))
	defer badStatus.Close()
	if _, err := (&Client{Server: badStatus.URL}).ListJobs(context.Background(), "r"); err == nil || !strings.Contains(err.Error(), "jobs 403") {
		t.Fatalf("error = %v", err)
	}

	badJSON := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("nope"))
	}))
	defer badJSON.Close()
	if _, err := (&Client{Server: badJSON.URL}).ListJobs(context.Background(), "r"); err == nil {
		t.Fatal("malformed jobs JSON must fail")
	}

	if _, err := (&Client{Server: "http://[::1]:namedport"}).ListJobs(context.Background(), "r"); err == nil {
		t.Fatal("unbuildable request URL must fail")
	}

	closedList := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	closedList.Close()
	if _, err := (&Client{Server: closedList.URL}).ListJobs(context.Background(), "r"); err == nil {
		t.Fatal("transport error must fail")
	}

	emptyKeys := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`[{"key":""},{"id":"x"}]`))
	}))
	defer emptyKeys.Close()
	keys, err := (&Client{Server: emptyKeys.URL}).ListJobs(context.Background(), "r")
	if err != nil || len(keys) != 0 {
		t.Fatalf("keys = %v (err %v), want empty", keys, err)
	}
}

func TestReadSSEEdges(t *testing.T) {
	// Canceled context short-circuits.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := readSSE(ctx, strings.NewReader("data: {}\n\n"), func(string) error { return nil }); !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}

	// onData errors propagate.
	want := errors.New("stop")
	if err := readSSE(context.Background(), strings.NewReader("data: x\n"), func(string) error { return want }); !errors.Is(err, want) {
		t.Fatalf("error = %v, want stop", err)
	}

	// "data:" without a space, CRLF line endings and a final unterminated
	// line are all accepted.
	var got []string
	stream := "id: 1\r\ndata:{\"a\":1}\r\n\r\ndata: [DONE]\n\ndata: tail"
	if err := readSSE(context.Background(), strings.NewReader(stream), func(d string) error {
		got = append(got, d)
		return nil
	}); err != nil {
		t.Fatalf("readSSE: %v", err)
	}
	if len(got) != 2 || got[0] != `{"a":1}` || got[1] != "tail" {
		t.Fatalf("frames = %v", got)
	}

	// An explicit done event terminates the stream cleanly.
	if err := readSSE(context.Background(), strings.NewReader("event: done\n"), func(string) error { return nil }); err != nil {
		t.Fatalf("done event = %v", err)
	}

	// A read error other than EOF is returned.
	if err := readSSE(context.Background(), errReader{}, func(string) error { return nil }); err == nil {
		t.Fatal("read error must propagate")
	}
}

// TestReadSSEEOFWithDataProcessesAllFrames locks the fix for the merged-frame
// defect: when a single Read returns the whole payload together with io.EOF
// (common for small buffered HTTP bodies), every data frame must still be
// delivered, and [DONE] must terminate cleanly.
func TestReadSSEEOFWithDataProcessesAllFrames(t *testing.T) {
	payload := "data: {\"seq\":1}\n\ndata: {\"seq\":2}\n\ndata: {\"seq\":3}\n\ndata: [DONE]\n\nevent: done\n"
	var got []string
	if err := readSSE(context.Background(), oneShot(payload), func(d string) error {
		got = append(got, d)
		return nil
	}); err != nil {
		t.Fatalf("readSSE: %v", err)
	}
	want := []string{`{"seq":1}`, `{"seq":2}`, `{"seq":3}`}
	if len(got) != len(want) {
		t.Fatalf("frames = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("frame %d = %q, want %q", i, got[i], want[i])
		}
	}
}

type oneShotReader struct {
	s string
	i int
}

// oneShot returns everything in a single Read together with io.EOF.
func oneShot(s string) *oneShotReader { return &oneShotReader{s: s} }

func (r *oneShotReader) Read(p []byte) (int, error) {
	if r.i >= len(r.s) {
		return 0, io.EOF
	}
	n := copy(p, r.s[r.i:])
	r.i += n
	return n, io.EOF
}

func TestChunkReaderLineBuffering(t *testing.T) {
	long := strings.Repeat("a", 9000)
	br := newChunkReader(strings.NewReader(long + "\nsecond\nthird"))
	line, err := br.readLine()
	if err != nil || line != long {
		t.Fatalf("first line len = %d (err %v)", len(line), err)
	}
	if line, err = br.readLine(); err != nil || line != "second" {
		t.Fatalf("second line = %q (err %v)", line, err)
	}
	if line, err = br.readLine(); err != nil || line != "third" {
		t.Fatalf("unterminated line = %q (err %v)", line, err)
	}
	if _, err = br.readLine(); err != io.EOF {
		t.Fatalf("final error = %v, want EOF", err)
	}
	if indexByte([]byte("abc"), 'z') != -1 || indexByte(nil, 'a') != -1 {
		t.Fatal("indexByte must return -1 for a missing byte")
	}
	if indexByte([]byte("abc"), 'b') != 1 {
		t.Fatal("indexByte returned the wrong index")
	}

	// A whole payload arriving in one Read-with-EOF must still be served
	// one line per call, in order.
	br = newChunkReader(oneShot("one\ntwo\nthree"))
	want := []string{"one", "two", "three"}
	for _, w := range want {
		got, err := br.readLine()
		if err != nil || got != w {
			t.Fatalf("line = %q (err %v), want %q", got, err, w)
		}
	}
	if _, err := br.readLine(); err != io.EOF {
		t.Fatalf("drained error = %v, want EOF", err)
	}
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("read failed") }
