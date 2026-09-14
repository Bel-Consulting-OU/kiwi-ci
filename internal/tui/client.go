package tui

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// Client fetches run logs from a Kiwi control plane: paginated log reads
// plus SSE follow. Credentials are attached only to same-origin requests and
// redirects are never followed.
type Client struct {
	Server string
	Token  string
	HTTP   *http.Client
}

func (c *Client) client() *http.Client {
	if c.HTTP != nil {
		cl := *c.HTTP
		cl.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		return &cl
	}
	return &http.Client{
		Timeout: 90 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func (c *Client) auth(req *http.Request) {
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
}

// paginateURL builds the paginated log-read URL.
func paginateURL(base, runID string, after int64, limit int) string {
	u := strings.TrimRight(base, "/") + "/api/v1/runs/" + url.PathEscape(runID) + "/logs"
	vs := url.Values{}
	if after > 0 {
		vs.Set("after", strconv.FormatInt(after, 10))
	}
	if limit > 0 {
		vs.Set("limit", strconv.Itoa(limit))
	}
	if q := vs.Encode(); q != "" {
		u += "?" + q
	}
	return u
}

// streamURL builds the SSE follow URL.
func streamURL(base, runID string, after int64) string {
	return strings.TrimRight(base, "/") + "/api/v1/runs/" + url.PathEscape(runID) + "/logs/stream?after=" + strconv.FormatInt(after, 10)
}

// ReadPage fetches one page of log entries.
func (c *Client) ReadPage(ctx context.Context, runID string, after int64, limit int) ([]model.LogEntry, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, paginateURL(c.Server, runID, after, limit), nil)
	if err != nil {
		return nil, err
	}
	c.auth(req)
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("logs %s: %s", resp.Status, strings.TrimSpace(string(b)))
	}
	var out []model.LogEntry
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return out, nil
}

// Follow opens the SSE stream and delivers parsed log entries.
func (c *Client) Follow(ctx context.Context, runID string, after int64, emit func(model.LogEntry)) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, streamURL(c.Server, runID, after), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "text/event-stream")
	c.auth(req)
	resp, err := c.client().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("stream %s: %s", resp.Status, strings.TrimSpace(string(b)))
	}
	return readSSE(ctx, resp.Body, func(data string) error {
		var e model.LogEntry
		if err := json.Unmarshal([]byte(data), &e); err != nil {
			return nil // skip malformed frames; the server is authoritative
		}
		emit(e)
		return nil
	})
}

// readSSE parses a Server-Sent Events stream: lines "data: <json>" with
// optional "id: <seq>" cursors. Blank lines delimit events.
func readSSE(ctx context.Context, r io.Reader, onData func(string) error) error {
	br := newChunkReader(r)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		line, err := br.readLine()
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
		if strings.HasPrefix(line, "data: ") || strings.HasPrefix(line, "data:") {
			data := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
			if data != "" && data != "[DONE]" {
				if err := onData(data); err != nil {
					return err
				}
			}
		}
		if line == "event: done" {
			return nil
		}
	}
}

// chunkReader adapts an arbitrary reader into line reads without bufio's
// per-line allocation limits.
type chunkReader struct {
	r   io.Reader
	buf []byte
}

func newChunkReader(r io.Reader) *chunkReader { return &chunkReader{r: r} }

func (c *chunkReader) readLine() (string, error) {
	for {
		if i := indexByte(c.buf, '\n'); i >= 0 {
			line := strings.TrimRight(string(c.buf[:i]), "\r")
			c.buf = c.buf[i+1:]
			return line, nil
		}
		p := make([]byte, 4096)
		n, err := c.r.Read(p)
		c.buf = append(c.buf, p[:n]...)
		if err != nil {
			if len(c.buf) > 0 {
				line := strings.TrimRight(string(c.buf), "\r")
				c.buf = nil
				return line, nil
			}
			return "", err
		}
	}
}

func indexByte(b []byte, c byte) int {
	for i, x := range b {
		if x == c {
			return i
		}
	}
	return -1
}
