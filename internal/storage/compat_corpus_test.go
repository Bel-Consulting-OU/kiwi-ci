package storage

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// N-1 compatibility corpus (testdata/compat/n-1). The files are PRODUCER
// BYTES from the N-1 tree: built through a git worktree at the N-1 commit
// and emitted by that tree's own internal/storage completion-receipt and
// observed-runtime APIs (see MANIFEST.producer). This test consumes them
// under HEAD and asserts two things:
//
//  1. digest stability — every golden digest N-1 recorded is reproduced
//     byte-for-byte by HEAD's digest functions, and every corpus file still
//     hashes to the sha256 the MANIFEST froze;
//  2. replay — each frozen receipt (v1 legacy, v2 runtime-bound, v3
//     runtime+Control) still resolves a retried completion through
//     CompletionReceiptReplayMatches.
//
// The corpus is immutable. Regenerating it under a changed encoding makes
// the pinned digests and MANIFEST hashes fail — that is the firewall.

type compatManifest struct {
	Producer struct {
		Commit    string `json:"commit"`
		Method    string `json:"method"`
		GoVersion string `json:"go_version"`
	} `json:"producer"`
	Files map[string]string `json:"files"`
}

type compatReceipt struct {
	HashVersion int                     `json:"hash_version"`
	Receipt     model.CompletionReceipt `json:"receipt"`
	ResultHash  string                  `json:"result_hash"`
}

type compatCorpus struct {
	Comment  string `json:"comment"`
	Producer struct {
		Commit                string `json:"commit"`
		GoVersion             string `json:"go_version"`
		CurrentCompletionHash int    `json:"current_completion_hash_version"`
		ObservedRuntimeV1Tag  string `json:"observed_runtime_v1_tag"`
		ObservedRuntimeV2Tag  string `json:"observed_runtime_v2_tag"`
	} `json:"producer"`
	Completion struct {
		Status             string                 `json:"status"`
		Error              string                 `json:"error"`
		Outputs            map[string]string      `json:"outputs"`
		ObservedRuntime    *model.ObservedRuntime `json:"observed_runtime"`
		ObservedRuntimeCtr *model.ObservedRuntime `json:"observed_runtime_control"`
	} `json:"completion"`
	Receipts map[string]compatReceipt `json:"receipts"`
	Golden   struct {
		CompletionResultV1      string `json:"completion_result_v1"`
		CompletionResultV2      string `json:"completion_result_v2"`
		CompletionResultV3      string `json:"completion_result_v3"`
		ObservedRuntimeV1Digest string `json:"observed_runtime_v1_digest"`
		ObservedRuntimeV2Digest string `json:"observed_runtime_v2_digest"`
	} `json:"golden"`
}

func compatDir(t *testing.T) string {
	t.Helper()
	return filepath.Join("..", "..", "testdata", "compat", "n-1")
}

func compatRead(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(compatDir(t), name))
	if err != nil {
		t.Fatalf("read compat corpus %s: %v (the N-1 corpus must stay committed)", name, err)
	}
	return b
}

func compatSHA256(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// TestCompatCorpusNMinusOneConsumedByHead loads the frozen N-1
// completion-receipt / observed-runtime corpus and proves HEAD still
// consumes it: MANIFEST digests match the corpus bytes, HEAD's digest
// functions reproduce every N-1 golden digest byte-for-byte, and every
// frozen receipt still replays.
func TestCompatCorpusNMinusOneConsumedByHead(t *testing.T) {
	var man compatManifest
	if err := json.Unmarshal(compatRead(t, "MANIFEST"), &man); err != nil {
		t.Fatalf("parse MANIFEST: %v", err)
	}
	if man.Producer.Commit == "" || man.Producer.Method == "" {
		t.Fatalf("MANIFEST producer is incomplete: %+v", man.Producer)
	}
	if len(man.Files) == 0 {
		t.Fatal("MANIFEST lists no files")
	}
	// Digest stability of the corpus bytes themselves: every file must
	// still hash to what the MANIFEST froze at emission time.
	for name, want := range man.Files {
		got := compatSHA256(compatRead(t, name))
		if got != want {
			t.Fatalf("compat corpus %s sha256 = %s, MANIFEST = %s — corpus bytes changed", name, got, want)
		}
	}
	// The three corpus payload files must all be listed.
	for _, required := range []string{"completion_receipt.json", "observed_runtime.json", "observed_runtime_control.json"} {
		if _, ok := man.Files[required]; !ok {
			t.Fatalf("MANIFEST does not list required corpus file %s", required)
		}
	}

	var fx compatCorpus
	if err := json.Unmarshal(compatRead(t, "completion_receipt.json"), &fx); err != nil {
		t.Fatalf("parse completion_receipt.json: %v", err)
	}
	var runtimeNoControl, runtimeWithControl model.ObservedRuntime
	if err := json.Unmarshal(compatRead(t, "observed_runtime.json"), &runtimeNoControl); err != nil {
		t.Fatalf("parse observed_runtime.json: %v", err)
	}
	if err := json.Unmarshal(compatRead(t, "observed_runtime_control.json"), &runtimeWithControl); err != nil {
		t.Fatalf("parse observed_runtime_control.json: %v", err)
	}
	// The standalone observed-runtime files must be the same objects the
	// receipt corpus embeds — one corpus, not three drifting copies.
	if fx.Completion.ObservedRuntime == nil || fx.Completion.ObservedRuntimeCtr == nil {
		t.Fatal("completion_receipt.json is missing embedded observed runtimes")
	}
	embNo, _ := json.Marshal(fx.Completion.ObservedRuntime)
	standNo, _ := json.Marshal(&runtimeNoControl)
	if string(embNo) != string(standNo) {
		t.Fatal("observed_runtime.json disagrees with the receipt corpus embedding")
	}
	embYes, _ := json.Marshal(fx.Completion.ObservedRuntimeCtr)
	standYes, _ := json.Marshal(&runtimeWithControl)
	if string(embYes) != string(standYes) {
		t.Fatal("observed_runtime_control.json disagrees with the receipt corpus embedding")
	}

	status := model.Status(fx.Completion.Status)
	errMsg := fx.Completion.Error
	outputs := fx.Completion.Outputs

	// Digest stability N-1 → HEAD: HEAD's functions must reproduce every
	// golden digest the N-1 emitter recorded.
	if got := CompletionResultDigestV1(status, errMsg, outputs); got != fx.Golden.CompletionResultV1 {
		t.Fatalf("HEAD v1 digest = %s, N-1 golden = %s", got, fx.Golden.CompletionResultV1)
	}
	if got := CompletionResultDigestV2(status, errMsg, outputs, &runtimeNoControl); got != fx.Golden.CompletionResultV2 {
		t.Fatalf("HEAD v2 digest = %s, N-1 golden = %s", got, fx.Golden.CompletionResultV2)
	}
	if got := CompletionResultDigestV3(status, errMsg, outputs, &runtimeWithControl); got != fx.Golden.CompletionResultV3 {
		t.Fatalf("HEAD v3 digest = %s, N-1 golden = %s", got, fx.Golden.CompletionResultV3)
	}
	if got := ObservedRuntimeDigestV1(&runtimeNoControl); got != fx.Golden.ObservedRuntimeV1Digest {
		t.Fatalf("HEAD observed-runtime/v1 digest = %s, N-1 golden = %s", got, fx.Golden.ObservedRuntimeV1Digest)
	}
	if got := ObservedRuntimeDigest(&runtimeWithControl); got != fx.Golden.ObservedRuntimeV2Digest {
		t.Fatalf("HEAD observed-runtime/v2 digest = %s, N-1 golden = %s", got, fx.Golden.ObservedRuntimeV2Digest)
	}
	// The frozen v1/v2 observed-runtime encodings must also reproduce from
	// the Control-bearing object (Control is excluded from v1; v2 binds it).
	if got := ObservedRuntimeDigestV1(&runtimeWithControl); got != fx.Golden.ObservedRuntimeV1Digest {
		t.Fatalf("HEAD v1 digest over the Control runtime = %s, want the no-Control golden %s", got, fx.Golden.ObservedRuntimeV1Digest)
	}

	// Replay: every frozen N-1 receipt must still resolve a retried
	// completion under HEAD's versioned matcher.
	for _, ver := range []string{"v1", "v2", "v3"} {
		recv, ok := fx.Receipts[ver]
		if !ok {
			t.Fatalf("completion_receipt.json has no %s receipt", ver)
		}
		if recv.HashVersion != recv.Receipt.ResultHashVersion {
			t.Fatalf("%s hash_version %d disagrees with receipt.result_hash_version %d", ver, recv.HashVersion, recv.Receipt.ResultHashVersion)
		}
		if recv.ResultHash != recv.Receipt.ResultHash {
			t.Fatalf("%s result_hash %s disagrees with receipt.result_hash %s", ver, recv.ResultHash, recv.Receipt.ResultHash)
		}
		var observed *model.ObservedRuntime
		switch recv.HashVersion {
		case CompletionResultHashVersionLegacy:
			observed = nil
		case CompletionResultHashVersionV2:
			observed = &runtimeNoControl
		case CompletionResultHashVersionV3:
			observed = &runtimeWithControl
		default:
			t.Fatalf("%s: unexpected hash version %d", ver, recv.HashVersion)
		}
		// Identity replay: the request re-supplies the same hash under its
		// own version.
		if !CompletionReceiptReplayMatches(recv.Receipt, recv.ResultHash, recv.HashVersion, status, errMsg, outputs, observed, &runtimeNoControl) {
			t.Fatalf("HEAD replay refused the frozen %s receipt (identity)", ver)
		}
		// Recomputation replay: a retry that re-hashes the same payload
		// under the stored version must also match.
		if !CompletionReceiptReplayMatches(recv.Receipt, "recomputed", 0, status, errMsg, outputs, observed, &runtimeNoControl) {
			t.Fatalf("HEAD replay refused the frozen %s receipt (recomputation)", ver)
		}
		// Negative arm: a contradictory status with a fresh request hash can
		// never replay (an exact identity replay is accepted by hash alone —
		// that is the versioned contract — so the lie must recompute).
		if CompletionReceiptReplayMatches(recv.Receipt, "not-the-stored-hash", 0, model.StatusFailure, errMsg, outputs, observed, &runtimeNoControl) {
			t.Fatalf("HEAD replay accepted a contradictory status for the %s receipt", ver)
		}
	}

	// Producer metadata must name the N-1 tree that wrote the bytes.
	if fx.Producer.Commit != man.Producer.Commit {
		t.Fatalf("receipt producer commit %s disagrees with MANIFEST %s", fx.Producer.Commit, man.Producer.Commit)
	}
	if fx.Producer.ObservedRuntimeV1Tag != ObservedRuntimeDigestV1Version {
		t.Fatalf("N-1 observed-runtime/v1 tag = %q, HEAD = %q", fx.Producer.ObservedRuntimeV1Tag, ObservedRuntimeDigestV1Version)
	}
	if fx.Producer.ObservedRuntimeV2Tag != ObservedRuntimeDigestV2Version {
		t.Fatalf("N-1 observed-runtime/v2 tag = %q, HEAD = %q", fx.Producer.ObservedRuntimeV2Tag, ObservedRuntimeDigestV2Version)
	}
}
