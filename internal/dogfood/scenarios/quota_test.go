package scenarios

import (
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/dogfood"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/executor"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// TestDFQUOTA001UntrustedHardQuotaGate is DF-QUOTA-001: the pre-checkout
// admission gate is a table-driven unit of the hard-quota rule. An untrusted
// job that requires a hard workspace quota is REJECTED when none could be
// established (the checkout itself is the window the quota protects); every
// other configuration keeps its documented behavior. The HardAvailable
// input is exactly executor.DiskQuotaStatus.Hard — never the requested
// limit.
func TestDFQUOTA001UntrustedHardQuotaGate(t *testing.T) {
	if _, ok := Lookup(ScenarioQuotaUntrustedGate); !ok {
		t.Fatal("scenario DF-QUOTA-001 missing from the registry")
	}
	// DiskQuotaStatus is the sole source of HardAvailable, so the table
	// derives each input from a realistic status pair (installed vs
	// fallback accounting vs setup failure).
	hardStatus := executor.DiskQuotaStatus{Hard: true, Limit: 5 << 20, Detail: "xfs project quota"}
	fallbackStatus := executor.DiskQuotaStatus{Hard: false, Limit: 5 << 20, Detail: "fallback step-boundary accounting"}
	setupFailStatus := executor.DiskQuotaStatus{Hard: false, Detail: "xfs setup failed"}
	noRequestStatus := executor.DiskQuotaStatus{}

	cases := []struct {
		name string
		// status is the attempt's DiskQuotaStatus; Hard is what the gate
		// must see as HardAvailable.
		status executor.DiskQuotaStatus
		// requested mirrors the plan's configured bound (the configured
		// fact must never substitute for the observed one).
		requested     int64
		untrusted     bool
		escape        bool
		runtime       string
		wantReject    bool
		wantRejectAll string // when set, the error must contain this phrase
	}{
		{
			name:       "untrusted-require-hard-available",
			status:     hardStatus,
			requested:  5 << 20,
			untrusted:  true,
			runtime:    "container",
			wantReject: false,
		},
		{
			name:          "untrusted-require-fallback-accounting-unavailable",
			status:        fallbackStatus,
			requested:     5 << 20,
			untrusted:     true,
			runtime:       "container",
			wantReject:    true,
			wantRejectAll: "requires a hard workspace disk quota",
		},
		{
			name:          "untrusted-require-setup-failed-unavailable",
			status:        setupFailStatus,
			requested:     5 << 20,
			untrusted:     true,
			runtime:       "container",
			wantReject:    true,
			wantRejectAll: "requires a hard workspace disk quota",
		},
		{
			name:      "untrusted-no-request-still-defaults-to-require",
			status:    noRequestStatus,
			requested: 0,
			untrusted: true,
			runtime:   "container",
			// The mandatory untrusted default means "no request" still
			// requires a bound; without one the job is rejected.
			wantReject:    true,
			wantRejectAll: "requires a hard workspace disk quota",
		},
		{
			name:       "untrusted-require-escape-hatch",
			status:     fallbackStatus,
			requested:  5 << 20,
			untrusted:  true,
			escape:     true,
			runtime:    "container",
			wantReject: false,
		},
		{
			name:      "untrusted-native-without-hard",
			status:    fallbackStatus,
			requested: 5 << 20,
			untrusted: true,
			runtime:   "native",
			// Only the container backend requires the hard bound.
			wantReject: false,
		},
		{
			name:          "untrusted-runtime-unresolvable-fails-closed",
			status:        fallbackStatus,
			requested:     5 << 20,
			untrusted:     true,
			runtime:       "",
			wantReject:    true,
			wantRejectAll: "could not be resolved",
		},
		{
			name:       "trusted-without-hard",
			status:     noRequestStatus,
			requested:  0,
			untrusted:  false,
			runtime:    "container",
			wantReject: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// The configured fact comes from the request; the enforced fact
			// comes from the status. The gate reads ONLY the status.
			err := dogfood.AdmitQuota(dogfood.QuotaGateInput{
				Untrusted:      tc.untrusted,
				OperatorEscape: tc.escape,
				HardAvailable:  tc.status.Hard,
				Runtime:        tc.runtime,
				Detail:         tc.status.Detail,
			})
			if tc.wantReject {
				if err == nil {
					t.Fatalf("gate admitted %+v (requested=%d)", tc.status, tc.requested)
				}
				if tc.wantRejectAll != "" && !strings.Contains(err.Error(), tc.wantRejectAll) {
					t.Fatalf("rejection %q does not name %q", err, tc.wantRejectAll)
				}
			} else if err != nil {
				t.Fatalf("gate rejected %+v: %v", tc.status, err)
			}
			// Quota truthfulness at the gate: a configured request must
			// never flip the observed fact. Rebuild the facts exactly the
			// evidence builder would and pin the enforced bit.
			facts := model.ExecutionFacts{
				Runtime:                  model.RuntimeFactContainer,
				FilesystemIsolated:       true,
				WorkspaceQuotaConfigured: tc.requested > 0 || tc.untrusted,
				NetworkMode:              model.NetworkModeFactNone,
			}
			if tc.runtime == "native" {
				facts.Runtime = model.RuntimeFactNative
				facts.FilesystemIsolated = false
				facts.NetworkMode = model.NetworkModeFactDefault
			}
			receipt := &model.ExecutionControlReceipt{
				Runtime: "docker", SandboxStarted: true,
				NetworkEnforced:        model.ObservedNetworkNone,
				WorkspaceQuotaEnforced: tc.status.Hard,
			}
			if tc.runtime == "native" {
				receipt = &model.ExecutionControlReceipt{
					Runtime: "native", NetworkEnforced: model.ObservedNetworkHost,
					WorkspaceQuotaEnforced: tc.status.Hard,
				}
			}
			if ferr := facts.ApplyObservedControl(receipt); ferr != nil {
				t.Fatalf("ApplyObservedControl: %v", ferr)
			}
			if facts.WorkspaceQuotaEnforced != tc.status.Hard {
				t.Fatalf("WorkspaceQuotaEnforced = %v, want DiskQuotaStatus.Hard %v", facts.WorkspaceQuotaEnforced, tc.status.Hard)
			}
		})
	}
}
