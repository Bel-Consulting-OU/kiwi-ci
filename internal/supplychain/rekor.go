package supplychain

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// Rekor transparency-log inclusion verification. A log entry is trusted
// only through the configured Rekor public key: the signed entry timestamp
// (SET) must verify over the JCS-canonicalized entry, and the entry body
// hash and integrated time must match what the bundle claims.

const (
	// maxRekorResponseBytes bounds a single Rekor log-entry API response.
	maxRekorResponseBytes = 1 << 20
	// rekorEntryPathPrefix is the log entry lookup path under BaseURL.
	rekorEntryPathPrefix = "/api/v1/log/entries/"
)

// rekorHTTPClient builds the HTTP client used to fetch Rekor log entries.
// It times out at 20s; redirects are never followed regardless of the
// client injected (tests swap this factory to trust a local TLS server).
var rekorHTTPClient = defaultRekorHTTPClient

func defaultRekorHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 20 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// fetchRekorEntry fetches one log entry by UUID over strict HTTPS without
// following redirects, bounding the response at 1 MiB.
//
// The configured base URL is held to the shared provider-endpoint policy: it
// must be an https:// URL with a host and no userinfo, query or fragment.
// Userinfo would smuggle credentials into every request line and log it, and
// a query or fragment would survive verbatim into the assembled log-entry URL.
func fetchRekorEntry(baseURL, uuid string) ([]byte, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("supplychain: invalid Rekor base URL: %w", err)
	}
	if u.Scheme != "https" {
		return nil, fmt.Errorf("supplychain: Rekor base URL must use https:// (got %q)", baseURL)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("supplychain: Rekor base URL has no host: %q", baseURL)
	}
	if u.User != nil {
		return nil, fmt.Errorf("supplychain: Rekor base URL must not carry userinfo: %q", baseURL)
	}
	if u.RawQuery != "" || u.ForceQuery {
		return nil, fmt.Errorf("supplychain: Rekor base URL must not carry a query: %q", baseURL)
	}
	if u.Fragment != "" {
		return nil, fmt.Errorf("supplychain: Rekor base URL must not carry a fragment: %q", baseURL)
	}
	target := strings.TrimRight(baseURL, "/") + rekorEntryPathPrefix + url.PathEscape(uuid)
	c := *rekorHTTPClient()
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := c.Get(target)
	if err != nil {
		return nil, fmt.Errorf("supplychain: fetch Rekor log entry: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("supplychain: Rekor API %s: %s", resp.Status, strings.TrimSpace(string(b)))
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxRekorResponseBytes+1))
	if err != nil {
		return nil, fmt.Errorf("supplychain: read Rekor log entry: %w", err)
	}
	if len(body) > maxRekorResponseBytes {
		return nil, fmt.Errorf("supplychain: Rekor log entry response exceeds %d byte limit", maxRekorResponseBytes)
	}
	return body, nil
}

// verifyRekorInclusion verifies that the log entry identified by uuid
// contains exactly the bytes bodyHash was computed over at integratedTime,
// and that the log operator signed the entry: the signed entry timestamp
// is an Ed25519 signature over the JCS-canonicalized entry JSON without
// the "verification" member, matching Rekor's signEntry construction.
func verifyRekorInclusion(cfg RekorConfig, uuid string, wantBodyHash []byte, wantIntegratedTime int64) error {
	raw, err := fetchRekorEntry(cfg.BaseURL, uuid)
	if err != nil {
		return err
	}
	var resp map[string]json.RawMessage
	if err := json.Unmarshal(raw, &resp); err != nil {
		return fmt.Errorf("supplychain: decode Rekor response: %w", err)
	}
	entryRaw, ok := resp[uuid]
	if !ok {
		return fmt.Errorf("supplychain: Rekor response does not contain log entry %s", uuid)
	}
	var entry map[string]any
	dec := json.NewDecoder(bytes.NewReader(entryRaw))
	dec.UseNumber()
	if err := dec.Decode(&entry); err != nil {
		return fmt.Errorf("supplychain: decode Rekor log entry: %w", err)
	}
	bodyB64, _ := entry["body"].(string)
	if bodyB64 == "" {
		return fmt.Errorf("supplychain: Rekor log entry has no body")
	}
	body, err := base64.StdEncoding.DecodeString(bodyB64)
	if err != nil {
		return fmt.Errorf("supplychain: decode Rekor log entry body: %w", err)
	}
	sum := sha256.Sum256(body)
	if !bytes.Equal(sum[:], wantBodyHash) {
		return fmt.Errorf("supplychain: Rekor log entry body hash mismatch")
	}
	integratedTime, ok := entry["integratedTime"].(json.Number)
	if !ok {
		return fmt.Errorf("supplychain: Rekor log entry missing integratedTime")
	}
	it, err := integratedTime.Int64()
	if err != nil || it != wantIntegratedTime {
		return fmt.Errorf("supplychain: Rekor log entry integratedTime mismatch")
	}
	verification, _ := entry["verification"].(map[string]any)
	setB64, _ := verification["signedEntryTimestamp"].(string)
	sig, err := base64.StdEncoding.DecodeString(setB64)
	if err != nil {
		return fmt.Errorf("supplychain: decode signed entry timestamp: %w", err)
	}
	delete(entry, "verification")
	canonical, err := jcsCanonical(entry)
	if err != nil {
		return fmt.Errorf("supplychain: canonicalize Rekor log entry: %w", err)
	}
	if !ed25519.Verify(cfg.PublicKey, canonical, sig) {
		return fmt.Errorf("supplychain: invalid Rekor signed entry timestamp")
	}
	return nil
}

// jcsCanonical renders v in RFC 8785 JSON Canonicalization Scheme form.
// The supported shapes are those of Rekor log entry objects: maps of
// strings, numbers and booleans with nested maps/arrays. Numbers must be
// json.Number so their literal lexeme is preserved.
func jcsCanonical(v any) ([]byte, error) {
	var b bytes.Buffer
	if err := writeJCS(&b, v); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func writeJCS(b *bytes.Buffer, v any) error {
	switch t := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			writeJCSString(b, k)
			b.WriteByte(':')
			if err := writeJCS(b, t[k]); err != nil {
				return err
			}
		}
		b.WriteByte('}')
	case []any:
		b.WriteByte('[')
		for i, e := range t {
			if i > 0 {
				b.WriteByte(',')
			}
			if err := writeJCS(b, e); err != nil {
				return err
			}
		}
		b.WriteByte(']')
	case string:
		writeJCSString(b, t)
	case json.Number:
		b.WriteString(string(t))
	case bool:
		if t {
			b.WriteString("true")
		} else {
			b.WriteString("false")
		}
	case nil:
		b.WriteString("null")
	default:
		return fmt.Errorf("supplychain: unsupported JSON value %T", v)
	}
	return nil
}

// writeJCSString writes a JSON string with RFC 8785 escaping: only the
// minimum control characters are escaped and non-ASCII text passes through
// verbatim.
func writeJCSString(b *bytes.Buffer, s string) {
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\b':
			b.WriteString(`\b`)
		case '\t':
			b.WriteString(`\t`)
		case '\n':
			b.WriteString(`\n`)
		case '\f':
			b.WriteString(`\f`)
		case '\r':
			b.WriteString(`\r`)
		default:
			if r < 0x20 {
				fmt.Fprintf(b, `\u%04x`, r)
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
}
