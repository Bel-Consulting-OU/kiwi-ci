package cache

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// ErrRemoteNotFound is returned by Client.Restore when the server has no entry
// for the key.
var ErrRemoteNotFound = fmt.Errorf("cache: not found on remote")

// Client is the runner-side cache client. Credentials are attached only to
// same-origin requests and redirects are never followed.
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
	return &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func (c *Client) auth(req *http.Request) {
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
}

func (c *Client) Restore(ctx context.Context, key string) (io.ReadCloser, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.Server+"/api/v1/cache/"+key, nil)
	if err != nil {
		return nil, err
	}
	c.auth(req)
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusNotFound {
		resp.Body.Close()
		return nil, ErrRemoteNotFound
	}
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		return nil, fmt.Errorf("cache restore %s: %s", resp.Status, strings.TrimSpace(string(b)))
	}
	return resp.Body, nil
}

func (c *Client) Upload(ctx context.Context, key string, r io.Reader) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, c.Server+"/api/v1/cache/"+key, r)
	if err != nil {
		return err
	}
	c.auth(req)
	resp, err := c.client().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("cache upload %s: %s", resp.Status, strings.TrimSpace(string(b)))
	}
	return nil
}
