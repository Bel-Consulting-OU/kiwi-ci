package policy

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"sort"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
)

// OPA integration is a fail-closed DENY GATE layered on top of the
// deterministic capability policy. Capabilities always come from the
// Config intersection semantics; OPA contributes boolean admission only:
// a policy exposes data.kiwi.allow (boolean) and data.kiwi.deny (set of
// reason strings) and any non-empty deny set, a false or missing allow, a
// compilation error, or an evaluation error rejects the request. OPA is
// embedded in-process via the rego package; no network is used. If policies
// are later extended to fetch remote bundles, the client below enforces
// strict HTTPS and refuses redirects.

// OPAPolicy is a compiled, prepared OPA query. It is safe for concurrent
// use: PreparedEvalQuery evaluation is goroutine-safe, so a single
// OPAPolicy can gate every admission request.
type OPAPolicy struct {
	engine *rego.PreparedEvalQuery

	// bundleClient is reserved for future bundle fetching. It is
	// initialized with CheckRedirect returning http.ErrUseLastResponse so
	// redirects are never followed (redirected responses are treated as
	// the final response and rejected by the caller), and with TLS 1.2 as
	// the minimum version so bundle traffic is always strict HTTPS.
	bundleClient *http.Client
}

// OPAInput is the admission context a Rego policy sees as `input`. Every
// field is always present in the input document, with zero values when the
// caller does not supply them; slices are never nil so `input.secrets[_]`
// style iteration is always safe. Policies must only reference these keys:
//
//	repository (string), trusted (bool), branch (string), event (string),
//	runtime (string), secrets ([]string), audiences ([]string),
//	environment (string), runner_labels ([]string), network (string)
type OPAInput struct {
	Repository   string
	Trusted      bool
	Branch       string
	Event        string
	Runtime      string
	Secrets      []string
	Audiences    []string
	Environment  string
	RunnerLabels []string
	Network      string
}

// OPADecision is the outcome of one OPA evaluation. Reasons carries the
// entries of the data.kiwi.deny set (or the failure that forced the denial)
// and is empty on allow.
type OPADecision struct {
	Allow   bool
	Reasons []string
}

// opaInputFields is the strict allowlist for input.<field> references. A
// policy referencing an unknown input field almost always means a typo that
// would silently never match (a fail-open hazard), so LoadOPAPolicy rejects
// it at startup instead.
var opaInputFields = map[string]bool{
	"repository":    true,
	"trusted":       true,
	"branch":        true,
	"event":         true,
	"runtime":       true,
	"secrets":       true,
	"audiences":     true,
	"environment":   true,
	"runner_labels": true,
	"network":       true,
}

// LoadOPAPolicy parses and compiles regoSrc into a prepared query and
// verifies the policy references only the documented input fields. Policies
// must define data.kiwi.allow and data.kiwi.deny; that requirement is
// enforced fail-closed at decision time so a missing rule denies every
// request rather than failing the load. Compilation errors are returned so
// the caller refuses to start.
func LoadOPAPolicy(regoSrc string) (*OPAPolicy, error) {
	if regoSrc == "" {
		return nil, errors.New("policy: opa: empty rego source")
	}
	module, err := ast.ParseModuleWithOpts("policy.rego", regoSrc, ast.ParserOptions{RegoVersion: ast.RegoV1})
	if err != nil {
		return nil, fmt.Errorf("policy: opa: %w", err)
	}
	if err := checkInputRefs(module); err != nil {
		return nil, err
	}
	engine, err := rego.New(
		rego.ParsedModule(module),
		rego.Query("data.kiwi"),
		rego.SetRegoVersion(ast.RegoV1),
		rego.StrictBuiltinErrors(true),
	).PrepareForEval(context.Background())
	if err != nil {
		return nil, fmt.Errorf("policy: opa: %w", err)
	}
	return &OPAPolicy{
		engine:       &engine,
		bundleClient: strictBundleClient(),
	}, nil
}

// checkInputRefs rejects references to input fields outside the documented
// OPAInput schema. input[k] with a dynamic key is allowed; unknown static
// fields fail the load so a typo can never silently disable a deny rule.
func checkInputRefs(module *ast.Module) error {
	var firstErr error
	ast.WalkRefs(module, func(ref ast.Ref) bool {
		if firstErr != nil || len(ref) < 2 {
			return true
		}
		head, ok := ref[0].Value.(ast.Var)
		if !ok || !head.Equal(ast.Var("input")) {
			return true
		}
		field, ok := ref[1].Value.(ast.String)
		if !ok {
			return true
		}
		if !opaInputFields[string(field)] {
			firstErr = fmt.Errorf("policy: opa: unknown input field %q", field)
		}
		return true
	})
	return firstErr
}

// strictBundleClient builds the HTTP client reserved for future bundle
// fetching: redirects are never followed and TLS 1.2 is the floor.
func strictBundleClient() *http.Client {
	return &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
		},
	}
}

// Decide evaluates the prepared policy against the admission input. It
// never partially allows: missing or non-boolean data.kiwi.allow, missing
// data.kiwi.deny, non-set deny values, a non-empty deny set, and evaluation
// errors all produce Allow=false with explanatory reasons. An error is
// returned only for programmer misuse (nil policy), never for policy
// failures.
func (p *OPAPolicy) Decide(ctx context.Context, in OPAInput) (OPADecision, error) {
	if p == nil || p.engine == nil {
		return OPADecision{}, errors.New("policy: opa: policy not loaded")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	rs, err := p.engine.Eval(ctx, rego.EvalInput(in.asMap()))
	if err != nil {
		return OPADecision{Allow: false, Reasons: []string{"opa evaluation failed: " + err.Error()}}, nil
	}
	if len(rs) == 0 {
		return OPADecision{Allow: false, Reasons: []string{"opa policy evaluated to undefined; data.kiwi.allow and data.kiwi.deny must be defined"}}, nil
	}
	obj, ok := rs[0].Expressions[0].Value.(map[string]any)
	if !ok {
		return OPADecision{Allow: false, Reasons: []string{fmt.Sprintf("opa data.kiwi is not an object, got %T", rs[0].Expressions[0].Value)}}, nil
	}
	allowRaw, hasAllow := obj["allow"]
	denyRaw, hasDeny := obj["deny"]
	if !hasDeny {
		return OPADecision{Allow: false, Reasons: []string{"opa policy does not define data.kiwi.deny"}}, nil
	}
	if !hasAllow {
		return OPADecision{Allow: false, Reasons: []string{"opa policy does not define data.kiwi.allow"}}, nil
	}
	allow, ok := allowRaw.(bool)
	if !ok {
		return OPADecision{Allow: false, Reasons: []string{fmt.Sprintf("opa data.kiwi.allow must be boolean, got %T", allowRaw)}}, nil
	}
	denySet, ok := denyRaw.([]any)
	if !ok {
		return OPADecision{Allow: false, Reasons: []string{fmt.Sprintf("opa data.kiwi.deny must be a set, got %T", denyRaw)}}, nil
	}
	reasons := make([]string, 0, len(denySet))
	for _, entry := range denySet {
		reasons = append(reasons, denyReason(entry))
	}
	sort.Strings(reasons)
	if len(reasons) > 0 {
		return OPADecision{Allow: false, Reasons: reasons}, nil
	}
	if !allow {
		return OPADecision{Allow: false, Reasons: []string{"data.kiwi.allow is false"}}, nil
	}
	return OPADecision{Allow: true}, nil
}

// denyReason renders one data.kiwi.deny set entry as a reason string.
// String entries are used verbatim; object entries use their "message" key
// when present; anything else is formatted for diagnostics.
func denyReason(entry any) string {
	switch e := entry.(type) {
	case string:
		return e
	case map[string]any:
		if msg, ok := e["message"].(string); ok {
			return msg
		}
		return fmt.Sprintf("%v", entry)
	default:
		return fmt.Sprintf("%v", entry)
	}
}

// asMap renders the admission input as the Rego `input` document. Slices
// are converted to JSON-style arrays so policies can iterate them safely;
// they are never nil and never null.
func (in OPAInput) asMap() map[string]any {
	return map[string]any{
		"repository":    in.Repository,
		"trusted":       in.Trusted,
		"branch":        in.Branch,
		"event":         in.Event,
		"runtime":       in.Runtime,
		"secrets":       anyStrings(in.Secrets),
		"audiences":     anyStrings(in.Audiences),
		"environment":   in.Environment,
		"runner_labels": anyStrings(in.RunnerLabels),
		"network":       in.Network,
	}
}

func anyStrings(in []string) []any {
	out := make([]any, 0, len(in))
	for _, s := range in {
		out = append(out, s)
	}
	return out
}
