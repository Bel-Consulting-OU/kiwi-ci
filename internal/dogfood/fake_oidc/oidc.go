// Package fake_oidc is a hermetic OpenID Connect relying-party emulator for
// dogfood scenarios: it mints id_tokens over chosen claims and validates
// them the way a production RP must (issuer, audience, expiry, runner
// identity), so the capability path's claim-binding defenses are exercised
// without a real identity provider.
package fake_oidc

import (
	"fmt"
	"sync"
	"time"
)

// Claims is the claim set the fake RP binds tokens to. The field names
// mirror the Kiwi OIDC surface (docs/oidc.md).
type Claims struct {
	Issuer   string    `json:"iss"`
	Subject  string    `json:"sub"`
	Audience string    `json:"aud"`
	RunnerID string    `json:"runner_id"`
	JobID    string    `json:"job_id"`
	RunID    string    `json:"run_id"`
	IssuedAt time.Time `json:"iat"`
	Expiry   time.Time `json:"exp"`
}

// Token is a minted (unsigned, hermetic) id_token plus its claims. Real
// signature verification is out of scope: the RP validates CLAIMS, which is
// where the dogfood scenarios inject errors.
type Token struct {
	ID     string
	Claims Claims
}

// Expectation is what a consumer demands of a presented token.
type Expectation struct {
	Issuer   string
	Audience string
	// RunnerID pins the token to the runner that must present it; a token
	// minted for a different (stale) runner is refused.
	RunnerID string
	JobID    string
}

// RP is the fake relying party. Safe for concurrent use.
type RP struct {
	mu     sync.Mutex
	issued map[string]Token
	seq    int
	now    func() time.Time
}

// New builds a relying party with an injectable clock (nil means wall time).
func New(now func() time.Time) *RP {
	if now == nil {
		now = time.Now
	}
	return &RP{issued: make(map[string]Token), now: now}
}

// Issue mints a token for claims. The token id is deterministic within the
// RP so scenarios can reference a minted token by its claims.
func (r *RP) Issue(c Claims) Token {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.seq++
	t := Token{ID: fmt.Sprintf("tok-%d", r.seq), Claims: c}
	r.issued[t.ID] = t
	return t
}

// Validate checks a presented token against an expectation at the RP's
// current time. Wrong issuer, wrong audience, expiry, and a stale/foreign
// runner identity are each refused with a named reason.
func (r *RP) Validate(t Token, want Expectation) error {
	r.mu.Lock()
	now := r.now()
	r.mu.Unlock()
	c := t.Claims
	if want.Issuer != "" && c.Issuer != want.Issuer {
		return fmt.Errorf("fake_oidc: issuer %q does not match expected %q", c.Issuer, want.Issuer)
	}
	if want.Audience != "" && c.Audience != want.Audience {
		return fmt.Errorf("fake_oidc: audience %q does not match expected %q", c.Audience, want.Audience)
	}
	if want.RunnerID != "" && c.RunnerID != want.RunnerID {
		return fmt.Errorf("fake_oidc: token runner %q is stale/foreign (want %q)", c.RunnerID, want.RunnerID)
	}
	if want.JobID != "" && c.JobID != want.JobID {
		return fmt.Errorf("fake_oidc: token job %q does not match expected %q", c.JobID, want.JobID)
	}
	if !c.Expiry.IsZero() && !now.Before(c.Expiry) {
		return fmt.Errorf("fake_oidc: token expired at %s", c.Expiry.UTC().Format(time.RFC3339))
	}
	if !c.IssuedAt.IsZero() && now.Before(c.IssuedAt) {
		return fmt.Errorf("fake_oidc: token issued in the future")
	}
	return nil
}

// IssuedCount is the number of tokens the RP minted — the authority for
// "exactly one credential was issued for this attempt".
func (r *RP) IssuedCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.issued)
}
