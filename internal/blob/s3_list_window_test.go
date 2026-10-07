package blob

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

// listTripper serves ListObjectsV2 pages without a network, with one
// configurable delay per page and the request contexts captured for
// inspection.
type listTripper struct {
	mu       sync.Mutex
	calls    int
	contexts []context.Context
	delays   []time.Duration
	pages    int
}

func (lt *listTripper) delayFor(call int) time.Duration {
	if len(lt.delays) == 0 {
		return 0
	}
	if call <= len(lt.delays) {
		return lt.delays[call-1]
	}
	return lt.delays[len(lt.delays)-1]
}

func (lt *listTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	lt.mu.Lock()
	lt.calls++
	call := lt.calls
	lt.contexts = append(lt.contexts, req.Context())
	lt.mu.Unlock()
	if d := lt.delayFor(call); d > 0 {
		select {
		case <-time.After(d):
		case <-req.Context().Done():
			return nil, req.Context().Err()
		}
	}
	truncated := call < lt.pages
	body := fmt.Sprintf(`<?xml version="1.0"?><ListBucketResult><IsTruncated>%t</IsTruncated>`, truncated)
	if truncated {
		body += fmt.Sprintf("<NextContinuationToken>p%d</NextContinuationToken>", call)
	}
	body += xmlContents([]string{digestOf(byte(call))}) + `</ListBucketResult>`
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/xml"}},
		Body:       io.NopCloser(strings.NewReader(body)),
	}, nil
}

func (lt *listTripper) snapshot() (int, []context.Context) {
	lt.mu.Lock()
	defer lt.mu.Unlock()
	return lt.calls, append([]context.Context(nil), lt.contexts...)
}

// TestS3TimeoutDefaults pins the documented defaults: 30s per ListObjectsV2
// page and 60s of body inactivity for a streamed GET.
func TestS3TimeoutDefaults(t *testing.T) {
	s := &S3{}
	if got := s.listPageTimeout(); got != 30*time.Second {
		t.Fatalf("default list page timeout = %v, want 30s", got)
	}
	if got := s.bodyInactivityTimeout(); got != 60*time.Second {
		t.Fatalf("default body inactivity timeout = %v, want 60s", got)
	}
	s.ListPageTimeout = 5 * time.Second
	s.BodyInactivityTimeout = 7 * time.Second
	if got := s.listPageTimeout(); got != 5*time.Second {
		t.Fatalf("configured list page timeout = %v, want 5s", got)
	}
	if got := s.bodyInactivityTimeout(); got != 7*time.Second {
		t.Fatalf("configured body inactivity timeout = %v, want 7s", got)
	}
}

// TestS3ListPageTimeoutFailsPageLocally proves one slow page fails with a
// page-local timeout instead of consuming a whole-pass budget: earlier pages
// are already reported, the failing page names its window, and no later page
// is attempted.
func TestS3ListPageTimeoutFailsPageLocally(t *testing.T) {
	lt := &listTripper{pages: 3, delays: []time.Duration{0, 400 * time.Millisecond, 0}}
	s := s3WithTripper(lt)
	s.ListPageTimeout = 80 * time.Millisecond

	var got []Object
	start := time.Now()
	err := s.List(context.Background(), func(o Object) error {
		got = append(got, o)
		return nil
	})
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("a page exceeding its window must fail the list")
	}
	if !strings.Contains(err.Error(), "list page") {
		t.Fatalf("page timeout error = %v, want it to name the page", err)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("page timeout error = %v, want a timeout-class error", err)
	}
	if len(got) != 1 {
		t.Fatalf("reported %d objects, want page 1's object before the page-local failure", len(got))
	}
	if calls, _ := lt.snapshot(); calls != 2 {
		t.Fatalf("made %d page requests, want 2 (no page after the failure)", calls)
	}
	if elapsed > 3*time.Second {
		t.Fatalf("page-local failure took %v", elapsed)
	}
}

// TestS3ListPerPageWindowsSurviveTotalElapsedBeyondOneSharedWindow proves the
// per-page windows are fresh: the total elapsed time exceeds one page window
// (the old implementation attached a single 2-minute context to the whole
// pagination pass), yet a listing whose pages are each healthy succeeds, and
// every request gets its own bounded context while the caller's context
// carries no deadline of List's making.
func TestS3ListPerPageWindowsSurviveTotalElapsedBeyondOneSharedWindow(t *testing.T) {
	const budget = 300 * time.Millisecond
	lt := &listTripper{pages: 4, delays: []time.Duration{80 * time.Millisecond, 80 * time.Millisecond, 80 * time.Millisecond, 80 * time.Millisecond}}
	s := s3WithTripper(lt)
	s.ListPageTimeout = budget

	callerCtx, cancelCaller := context.WithCancel(context.Background())
	defer cancelCaller()

	var got []Object
	start := time.Now()
	err := s.List(callerCtx, func(o Object) error {
		got = append(got, o)
		return nil
	})
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("healthy multi-page listing failed: %v", err)
	}
	if len(got) != 4 {
		t.Fatalf("reported %d objects, want 4", len(got))
	}
	if elapsed <= budget {
		t.Fatalf("listing finished in %v; test needs total elapsed beyond one %v window", elapsed, budget)
	}
	if elapsed > 5*time.Second {
		t.Fatalf("listing took %v", elapsed)
	}
	calls, ctxs := lt.snapshot()
	if calls != 4 {
		t.Fatalf("made %d page requests, want 4", calls)
	}
	if _, ok := ctxs[0].Deadline(); !ok {
		t.Fatal("a page request carries no per-page deadline")
	}
	first, _ := ctxs[0].Deadline()
	last, _ := ctxs[len(ctxs)-1].Deadline()
	if !last.After(first) {
		t.Fatalf("page deadlines are not fresh windows: first %v, last %v", first, last)
	}
	if _, ok := callerCtx.Deadline(); ok {
		t.Fatal("List imposed a total deadline on the caller")
	}
}

// TestS3ListCallerContextBoundsTheWholePass proves a caller that gives up
// mid-enumeration stops the pass promptly with its own cancellation, not with
// a page timeout or a KIWI-imposed total.
func TestS3ListCallerContextBoundsTheWholePass(t *testing.T) {
	lt := &listTripper{pages: 5, delays: []time.Duration{2 * time.Second}}
	s := s3WithTripper(lt)
	s.ListPageTimeout = 30 * time.Second

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()
	start := time.Now()
	err := s.List(ctx, func(Object) error { return nil })
	elapsed := time.Since(start)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled List = %v, want context.Canceled", err)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("caller cancellation took %v to stop the pass", elapsed)
	}
	if calls, _ := lt.snapshot(); calls != 1 {
		t.Fatalf("made %d page requests after cancellation, want 1", calls)
	}

	// An already-cancelled caller never issues a request at all.
	cancelled, cancelNow := context.WithCancel(context.Background())
	cancelNow()
	before, _ := lt.snapshot()
	if err := s.List(cancelled, func(Object) error { return nil }); !errors.Is(err, context.Canceled) {
		t.Fatalf("pre-cancelled List = %v, want context.Canceled", err)
	}
	if after, _ := lt.snapshot(); after != before {
		t.Fatalf("pre-cancelled List issued %d requests", after-before)
	}
}
