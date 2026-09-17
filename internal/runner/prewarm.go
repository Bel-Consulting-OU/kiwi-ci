package runner

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	// prewarmDefaultInterval is how often the prewarm list is refreshed.
	prewarmDefaultInterval = 5 * time.Minute
	// prewarmMaxTracked bounds the state file: at most this many
	// successfully prewarmed references are tracked (and later removed when
	// they leave the list).
	prewarmMaxTracked = 10
	// prewarmConcurrency bounds simultaneous pulls across docker/tart.
	prewarmConcurrency = 2
	// prewarmVMNamePrefix is the local VM name prefix for prewarmed tart
	// VMs; stale prewarmed VMs are swept by this prefix.
	prewarmVMNamePrefix = "kiwi-prewarm-"
)

// prewarmRef is one parsed prewarm reference. Docker refs are plain
// digest-pinned image references; tart refs use the tart://<image>@sha256:
// <digest> form and map to a local prewarmed VM clone.
type prewarmRef struct {
	Kind   string // docker | tart
	Ref    string // docker: the full image ref; tart: the original tart:// ref
	Image  string // tart: image reference without the digest
	Digest string // tart: sha256:<hex>
	VMName string // tart: local VM name (kiwi-prewarm-...)
}

// parsePrewarmRef parses one prewarm reference. Ref without the tart://
// prefix are docker refs (validated elsewhere for digest pinning); tart://
// refs must be tart://<image>@sha256:<64-hex-digest>.
func parsePrewarmRef(raw string) (prewarmRef, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return prewarmRef{}, fmt.Errorf("prewarm: empty image reference")
	}
	if !strings.HasPrefix(raw, "tart://") {
		return prewarmRef{Kind: "docker", Ref: raw}, nil
	}
	rest := strings.TrimPrefix(raw, "tart://")
	image, digest, ok := strings.Cut(rest, "@sha256:")
	if !ok || strings.TrimSpace(image) == "" || !isSHA256Hex(digest) {
		return prewarmRef{}, fmt.Errorf("prewarm: invalid tart reference %q (want tart://<image>@sha256:<digest>)", raw)
	}
	return prewarmRef{
		Kind:   "tart",
		Ref:    raw,
		Image:  image,
		Digest: "sha256:" + digest,
		VMName: prewarmVMName(image),
	}, nil
}

// isSHA256Hex reports whether s is a 64-character hex digest.
func isSHA256Hex(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'f', c >= 'A' && c <= 'F':
		default:
			return false
		}
	}
	return true
}

// prewarmVMName derives the deterministic local VM name for a tart image:
// kiwi-prewarm-<image with non-alphanumeric runs collapsed to ->. It is
// deterministic so the same image always maps to the same VM.
func prewarmVMName(image string) string {
	var b strings.Builder
	b.WriteString(prewarmVMNamePrefix)
	lastDash := false
	for _, r := range strings.ToLower(image) {
		ok := (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')
		if !ok {
			if !lastDash {
				b.WriteByte('-')
				lastDash = true
			}
			continue
		}
		b.WriteRune(r)
		lastDash = false
	}
	return strings.TrimSuffix(b.String(), "-")
}

// validatePrewarmRefs rejects anything not pinned by digest: mutable tags
// would let a prewarm pass fetch different content than the job executes.
func validatePrewarmRefs(refs []string) error {
	for _, ref := range refs {
		ref = strings.TrimSpace(ref)
		if ref == "" {
			return fmt.Errorf("prewarm: empty image reference")
		}
		if strings.HasPrefix(ref, "tart://") {
			if _, err := parsePrewarmRef(ref); err != nil {
				return err
			}
			continue
		}
		if !strings.Contains(ref, "@sha256:") {
			return fmt.Errorf("prewarm: reference %q is not pinned by digest (require @sha256:)", ref)
		}
	}
	return nil
}

type prewarmItem struct {
	Ref  string `json:"ref"`
	Kind string `json:"kind"` // docker | tart
}

type prewarmState struct {
	Version int           `json:"version"`
	Items   []prewarmItem `json:"items"`
}

// prewarmRemovals splits the persisted state into items to remove (their
// ref left the configured list) and items to keep.
func prewarmRemovals(prev prewarmState, refs []string) (remove, keep []prewarmItem) {
	wanted := map[string]bool{}
	for _, ref := range refs {
		wanted[strings.TrimSpace(ref)] = true
	}
	for _, item := range prev.Items {
		if wanted[item.Ref] {
			keep = append(keep, item)
		} else {
			remove = append(remove, item)
		}
	}
	return remove, keep
}

// dedupePrewarmItems removes duplicate (Ref, Kind) entries while preserving
// the first occurrence order. A ref that was kept from the previous state is
// pulled again on every pass, so without dedupe it would be tracked twice
// and consume two of the maxTracked budget slots.
func dedupePrewarmItems(items []prewarmItem) []prewarmItem {
	out := make([]prewarmItem, 0, len(items))
	seen := map[prewarmItem]bool{}
	for _, item := range items {
		if seen[item] {
			continue
		}
		seen[item] = true
		out = append(out, item)
	}
	return out
}

// capPrewarmItems deterministically bounds the tracked set.
func capPrewarmItems(items []prewarmItem, max int) []prewarmItem {
	if len(items) <= max {
		return items
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Ref != items[j].Ref {
			return items[i].Ref < items[j].Ref
		}
		return items[i].Kind < items[j].Kind
	})
	return items[:max]
}

// tartVM is one entry of `tart list --format json` output. The Source field
// carries the image reference the VM was cloned from (with its digest).
type tartVM struct {
	Name   string `json:"name"`
	Source string `json:"source"`
}

// parseTartList parses `tart list --format json` output.
func parseTartList(data []byte) ([]tartVM, error) {
	var out []tartVM
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("parse tart list: %w", err)
	}
	return out, nil
}

// tartSourceDigest extracts the sha256:<hex> digest from a VM source ref,
// or "" when the source has no digest.
func tartSourceDigest(source string) string {
	if i := strings.Index(source, "@sha256:"); i >= 0 {
		return source[i+1:]
	}
	return ""
}

// tartStaleVMs returns the names of kiwi-prewarm-* VMs whose source digest
// is not in wantedDigests, sorted deterministically. A VM without a source
// digest is always stale (it cannot be verified).
func tartStaleVMs(vms []tartVM, wantedDigests map[string]bool) []string {
	var out []string
	for _, v := range vms {
		if !strings.HasPrefix(v.Name, prewarmVMNamePrefix) {
			continue
		}
		if d := tartSourceDigest(v.Source); d != "" && wantedDigests[d] {
			continue
		}
		out = append(out, v.Name)
	}
	sort.Strings(out)
	return out
}

type prewarmer struct {
	refs       []string
	stateFile  string
	maxTracked int
	dockerPath string
	tartPath   string
	logf       func(format string, args ...any)
	mu         sync.Mutex
}

func newPrewarmer(cfg Config) *prewarmer {
	dockerPath := ""
	if p, err := exec.LookPath("docker"); err == nil {
		dockerPath = p
	}
	tartPath := ""
	if p, err := exec.LookPath("tart"); err == nil {
		tartPath = p
	}
	return &prewarmer{
		refs:       append([]string{}, cfg.Prewarm...),
		stateFile:  cfg.PrewarmStateFile,
		maxTracked: prewarmMaxTracked,
		dockerPath: dockerPath,
		tartPath:   tartPath,
		logf: func(format string, args ...any) {
			fmt.Printf(format+"\n", args...)
		},
	}
}

// run refreshes the prewarmed image set: previously-prewarmed references
// that left the list are removed, stale prewarmed tart VMs (name prefix
// kiwi-prewarm- whose digest left the list) are deleted, every configured
// reference is pulled under a bounded concurrency (2), tart pulls are
// verified against `tart list --format json` by digest, and the
// successfully pulled set is persisted, bounded to maxTracked (10). Pull
// failures are logged and never fatal. Runs are serialized: the initial
// post-registration pass and the periodic refresh must not race on the
// state file.
func (p *prewarmer) run(ctx context.Context) error {
	if len(p.refs) == 0 {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	prev := p.loadState()
	remove, keep := prewarmRemovals(prev, p.refs)
	for _, item := range remove {
		p.removeItem(ctx, item)
	}
	parsed := make([]prewarmRef, 0, len(p.refs))
	wanted := map[string]bool{}
	for _, raw := range p.refs {
		pr, err := parsePrewarmRef(raw)
		if err != nil {
			p.logf("prewarm: %v", err)
			continue
		}
		parsed = append(parsed, pr)
		if pr.Kind == "tart" {
			wanted[pr.Digest] = true
		}
	}
	// Sweep stale prewarmed VMs: every kiwi-prewarm-* VM whose digest is no
	// longer in the configured tart list is deleted.
	if p.tartPath != "" {
		if vms, err := p.listTartVMs(ctx); err != nil {
			p.logf("prewarm: tart list: %v", err)
		} else {
			for _, name := range tartStaleVMs(vms, wanted) {
				if err := exec.CommandContext(ctx, p.tartPath, "delete", name).Run(); err != nil {
					p.logf("prewarm: remove stale tart VM %s: %v", name, err)
				} else {
					p.logf("prewarm: removed stale tart VM %s", name)
				}
			}
		}
	}
	next := append([]prewarmItem{}, keep...)
	var mu sync.Mutex
	sem := make(chan struct{}, prewarmConcurrency)
	var wg sync.WaitGroup
	for _, pr := range parsed {
		var bin string
		switch pr.Kind {
		case "docker":
			bin = p.dockerPath
		case "tart":
			bin = p.tartPath
		}
		if bin == "" {
			continue
		}
		wg.Add(1)
		go func(pr prewarmRef, bin string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			var err error
			switch pr.Kind {
			case "docker":
				err = prewarmPull(ctx, bin, pr.Ref)
			case "tart":
				err = p.prewarmTart(ctx, pr)
			}
			if err != nil {
				p.logf("prewarm: %s pull %s: %v", pr.Kind, pr.Ref, err)
				return
			}
			mu.Lock()
			next = append(next, prewarmItem{Ref: pr.Ref, Kind: pr.Kind})
			mu.Unlock()
		}(pr, bin)
	}
	wg.Wait()
	next = capPrewarmItems(dedupePrewarmItems(next), p.maxTracked)
	return p.saveState(prewarmState{Version: 1, Items: next})
}

func prewarmPull(ctx context.Context, bin, ref string) error {
	out, err := exec.CommandContext(ctx, bin, "pull", ref).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// listTartVMs runs `tart list --format json` and parses the output.
func (p *prewarmer) listTartVMs(ctx context.Context) ([]tartVM, error) {
	out, err := exec.CommandContext(ctx, p.tartPath, "list", "--format", "json").Output()
	if err != nil {
		return nil, fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	return parseTartList(out)
}

// prewarmTart prewarms one tart VM: pull the digest-pinned image, clone it
// to the deterministic prewarm VM name, and verify via `tart list --format
// json` that the cloned VM's source digest matches the requested digest.
func (p *prewarmer) prewarmTart(ctx context.Context, pr prewarmRef) error {
	ref := pr.Image + "@" + pr.Digest
	if out, err := exec.CommandContext(ctx, p.tartPath, "pull", ref).CombinedOutput(); err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	if out, err := exec.CommandContext(ctx, p.tartPath, "clone", ref, pr.VMName).CombinedOutput(); err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	vms, err := p.listTartVMs(ctx)
	if err != nil {
		return err
	}
	for _, v := range vms {
		if v.Name == pr.VMName {
			if tartSourceDigest(v.Source) == pr.Digest {
				return nil
			}
			return fmt.Errorf("tart VM %s digest mismatch: source %q, want %s", pr.VMName, v.Source, pr.Digest)
		}
	}
	return fmt.Errorf("tart VM %s not found in tart list after clone", pr.VMName)
}

// removeItem deletes a previously prewarmed reference that left the list.
// docker removes by image reference; tart deletes the prewarmed VM clone by
// its deterministic name.
func (p *prewarmer) removeItem(ctx context.Context, item prewarmItem) {
	switch item.Kind {
	case "docker":
		if p.dockerPath != "" {
			if err := exec.CommandContext(ctx, p.dockerPath, "image", "rm", "-f", item.Ref).Run(); err != nil {
				p.logf("prewarm: remove docker image %s: %v", item.Ref, err)
			}
		}
	case "tart":
		if p.tartPath != "" {
			name := item.Ref
			if pr, err := parsePrewarmRef(item.Ref); err == nil && pr.Kind == "tart" {
				name = pr.VMName
			}
			if err := exec.CommandContext(ctx, p.tartPath, "delete", name).Run(); err != nil {
				p.logf("prewarm: remove tart image %s: %v", item.Ref, err)
			}
		}
	}
}

func (p *prewarmer) loadState() prewarmState {
	if p.stateFile == "" {
		return prewarmState{}
	}
	b, err := os.ReadFile(p.stateFile)
	if err != nil {
		return prewarmState{}
	}
	var st prewarmState
	if err := json.Unmarshal(b, &st); err != nil {
		return prewarmState{}
	}
	return st
}

func (p *prewarmer) saveState(st prewarmState) error {
	if p.stateFile == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(p.stateFile), 0o755); err != nil {
		return err
	}
	b, err := json.Marshal(st)
	if err != nil {
		return err
	}
	tmp := p.stateFile + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, p.stateFile)
}
