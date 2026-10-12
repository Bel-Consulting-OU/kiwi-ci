package storage

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// Historical compatibility corpus (testdata/contracts). These fixtures are
// the N-2/N-1 PRODUCER BYTES, not HEAD-reconstructed structs: they were
// written once and are immutable. Every value below is a frozen golden
// hash taken from that corpus; recomputing them with HEAD must reproduce
// the same digests byte-for-byte. Regenerating the fixtures under a changed
// encoding makes these constants fail — that is the firewall.
const (
	// goldenCompletionReceiptV1Hash is the frozen legacy (hash v1) completion
	// result digest of the corpus completion payload.
	goldenCompletionReceiptV1Hash = "fed0dffe1dc5e52fd166181dc6fa2b2a7fbff6aa2a4cbdc4af80db4fad76bb81"
	// goldenCompletionReceiptV2Hash is the frozen v2 completion result digest
	// (tagged kiwi-ci/completion-result/v2, nested observed-runtime/v1).
	goldenCompletionReceiptV2Hash = "d59a8c99e366ac49dff7370bddefdef6ea4d81e05f49522e73eacd6745bee21b"
	// goldenObservedRuntimeDigestV1 is the frozen observed-runtime/v1 digest
	// of the corpus observed runtime (no Control receipt).
	goldenObservedRuntimeDigestV1 = "843e54d6abc51804f85e1e867362ce2a31cd79c6345e1993b193c477f54802b4"
	// goldenObservedRuntimeDigestV2 is the frozen observed-runtime/v2 digest of
	// the same no-Control runtime (the empty Control marker is part of v2).
	goldenObservedRuntimeDigestV2 = "e1b9dae2062305173c4d5f8ab5975cdaa013d3c1099d025387b8431a6c50e71a"
)

func contractCorpusPath(t *testing.T, name string) string {
	t.Helper()
	return filepath.Join("..", "..", "testdata", "contracts", name)
}

func loadContractJSON(t *testing.T, name string, v any) {
	t.Helper()
	raw, err := os.ReadFile(contractCorpusPath(t, name))
	if err != nil {
		t.Fatalf("read contract fixture %s: %v (the historical compatibility corpus must stay committed)", name, err)
	}
	if err := json.Unmarshal(raw, v); err != nil {
		t.Fatalf("parse contract fixture %s: %v", name, err)
	}
}

type contractCompletionFixture struct {
	HashVersion int                     `json:"hash_version"`
	Receipt     model.CompletionReceipt `json:"receipt"`
	Completion  struct {
		Status          string                 `json:"status"`
		Error           string                 `json:"error,omitempty"`
		Outputs         map[string]string      `json:"outputs,omitempty"`
		ObservedRuntime *model.ObservedRuntime `json:"observed_runtime,omitempty"`
	} `json:"completion"`
	Golden struct {
		ResultHash            string `json:"result_hash"`
		ObservedRuntimeDigest string `json:"observed_runtime_digest,omitempty"`
		ObservedRuntimeTag    string `json:"observed_runtime_tag,omitempty"`
	} `json:"golden"`
}

// TestContractCorpusCompletionReceiptV1Frozen proves the legacy (hash v1)
// producer bytes still reproduce under HEAD and still replay: the stored
// receipt resolves a retried completion with the identical status/error/
// outputs. The golden hash is pinned in this file, so changing the v1
// encoding fails this test even if the fixture is regenerated.
func TestContractCorpusCompletionReceiptV1Frozen(t *testing.T) {
	var fx contractCompletionFixture
	loadContractJSON(t, "completion_receipt_v1.json", &fx)

	if fx.Golden.ResultHash != goldenCompletionReceiptV1Hash {
		t.Fatalf("fixture golden result_hash = %s, test pin = %s — corpus and test pin disagree", fx.Golden.ResultHash, goldenCompletionReceiptV1Hash)
	}
	if fx.Receipt.ResultHashVersion != CompletionResultHashVersionLegacy {
		t.Fatalf("fixture receipt version = %d, want legacy %d", fx.Receipt.ResultHashVersion, CompletionResultHashVersionLegacy)
	}

	status := model.Status(fx.Completion.Status)
	got := CompletionResultDigestV1(status, fx.Completion.Error, fx.Completion.Outputs)
	if got != goldenCompletionReceiptV1Hash {
		t.Fatalf("HEAD v1 digest = %s, want frozen %s — the legacy encoding changed", got, goldenCompletionReceiptV1Hash)
	}
	if got != fx.Receipt.ResultHash {
		t.Fatalf("HEAD v1 digest %s does not match the fixture receipt %s", got, fx.Receipt.ResultHash)
	}

	if !CompletionReceiptReplayMatches(
		fx.Receipt, got, CompletionResultHashVersionLegacy,
		status, fx.Completion.Error, fx.Completion.Outputs,
		nil, nil,
	) {
		t.Fatal("HEAD replay refused the frozen v1 receipt")
	}
}

// TestContractCorpusCompletionReceiptV2Frozen proves the FROZEN v2 producer
// bytes (nested observed-runtime/v1, no Control) still reproduce under HEAD
// and still replay. The golden hashes are pinned in this file, so changing
// the v2 encoding or the observed-runtime/v1 encoding fails this test even
// if the fixture is regenerated.
func TestContractCorpusCompletionReceiptV2Frozen(t *testing.T) {
	var fx contractCompletionFixture
	loadContractJSON(t, "completion_receipt_v2.json", &fx)

	if fx.Golden.ResultHash != goldenCompletionReceiptV2Hash {
		t.Fatalf("fixture golden result_hash = %s, test pin = %s — corpus and test pin disagree", fx.Golden.ResultHash, goldenCompletionReceiptV2Hash)
	}
	if fx.Golden.ObservedRuntimeDigest != goldenObservedRuntimeDigestV1 {
		t.Fatalf("fixture golden observed_runtime_digest = %s, test pin = %s", fx.Golden.ObservedRuntimeDigest, goldenObservedRuntimeDigestV1)
	}
	if fx.Golden.ObservedRuntimeTag != ObservedRuntimeDigestV1Version {
		t.Fatalf("fixture observed_runtime_tag = %q, want %q — v2 MUST embed observed-runtime/v1", fx.Golden.ObservedRuntimeTag, ObservedRuntimeDigestV1Version)
	}
	if fx.HashVersion != CompletionResultHashVersionV2 || fx.Receipt.ResultHashVersion != CompletionResultHashVersionV2 {
		t.Fatalf("fixture versions = hash %d receipt %d, want v2", fx.HashVersion, fx.Receipt.ResultHashVersion)
	}
	if fx.Completion.ObservedRuntime == nil {
		t.Fatal("v2 fixture must carry observed runtime evidence")
	}
	if fx.Completion.ObservedRuntime.Control != nil {
		t.Fatalf("v2 fixture observed runtime must NOT carry a Control receipt: %+v", fx.Completion.ObservedRuntime.Control)
	}

	// The nested digest MUST be the frozen observed-runtime/v1 encoding.
	runtimeV1 := ObservedRuntimeDigestV1(fx.Completion.ObservedRuntime)
	if runtimeV1 != goldenObservedRuntimeDigestV1 {
		t.Fatalf("HEAD observed-runtime/v1 digest = %s, want frozen %s — the historical runtime encoding changed", runtimeV1, goldenObservedRuntimeDigestV1)
	}

	status := model.Status(fx.Completion.Status)
	got := CompletionResultDigestV2(status, fx.Completion.Error, fx.Completion.Outputs, fx.Completion.ObservedRuntime)
	if got != goldenCompletionReceiptV2Hash {
		t.Fatalf("HEAD v2 digest = %s, want frozen %s — the v2 encoding changed", got, goldenCompletionReceiptV2Hash)
	}
	if got != fx.Receipt.ResultHash {
		t.Fatalf("HEAD v2 digest %s does not match the fixture receipt %s", got, fx.Receipt.ResultHash)
	}

	if !CompletionReceiptReplayMatches(
		fx.Receipt, got, CompletionResultHashVersionV2,
		status, fx.Completion.Error, fx.Completion.Outputs,
		fx.Completion.ObservedRuntime, fx.Completion.ObservedRuntime,
	) {
		t.Fatal("HEAD replay refused the frozen v2 receipt")
	}
}

// TestContractCorpusObservedRuntimeV1Frozen proves the bare observed-runtime
// wire bytes (no Control) keep both digest encodings stable: the frozen
// v1 hash and the current v2 hash of a Control-less runtime are pinned here,
// so either encoding changing fails the test.
func TestContractCorpusObservedRuntimeV1Frozen(t *testing.T) {
	var observed model.ObservedRuntime
	loadContractJSON(t, "observed_runtime_v1.json", &observed)

	if observed.Control != nil {
		t.Fatalf("observed_runtime_v1.json must not carry a Control receipt: %+v", observed.Control)
	}
	if observed.OS != "linux" || observed.RuntimeName != "docker" {
		t.Fatalf("unexpected corpus runtime identity: %+v", observed)
	}

	gotV1 := ObservedRuntimeDigestV1(&observed)
	if gotV1 != goldenObservedRuntimeDigestV1 {
		t.Fatalf("HEAD observed-runtime/v1 digest = %s, want frozen %s", gotV1, goldenObservedRuntimeDigestV1)
	}
	gotV2 := ObservedRuntimeDigest(&observed)
	if gotV2 != goldenObservedRuntimeDigestV2 {
		t.Fatalf("HEAD observed-runtime/v2 digest = %s, want frozen %s", gotV2, goldenObservedRuntimeDigestV2)
	}
	if gotV1 == gotV2 {
		t.Fatal("observed-runtime/v1 and /v2 must disagree on a Control-less runtime (v2 binds the empty Control marker)")
	}
}
