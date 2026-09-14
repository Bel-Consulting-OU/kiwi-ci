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
)

// validatePrewarmRefs rejects anything not pinned by digest: mutable tags
// would let a prewarm pass fetch different content than the job executes.
func validatePrewarmRefs(refs []string) error {
	for _, ref := range refs {
		ref = strings.TrimSpace(ref)
		if ref == "" {
			return fmt.Errorf("prewarm: empty image reference")
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
// that left the list are removed, every configured reference is pulled with
// docker and tart (whichever binaries exist) under a bounded concurrency,
// and the successfully pulled set is persisted, bounded to maxTracked.
// Pull failures are logged and never fatal. Runs are serialized: the
// initial post-registration pass and the periodic refresh must not race on
// the state file.
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
	next := append([]prewarmItem{}, keep...)
	var mu sync.Mutex
	sem := make(chan struct{}, prewarmConcurrency)
	var wg sync.WaitGroup
	for _, ref := range p.refs {
		for _, kind := range []string{"docker", "tart"} {
			bin := p.dockerPath
			if kind == "tart" {
				bin = p.tartPath
			}
			if bin == "" {
				continue
			}
			wg.Add(1)
			go func(ref, kind, bin string) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()
				if err := prewarmPull(ctx, bin, ref); err != nil {
					p.logf("prewarm: %s pull %s: %v", kind, ref, err)
					return
				}
				mu.Lock()
				next = append(next, prewarmItem{Ref: ref, Kind: kind})
				mu.Unlock()
			}(strings.TrimSpace(ref), kind, bin)
		}
	}
	wg.Wait()
	next = capPrewarmItems(next, p.maxTracked)
	return p.saveState(prewarmState{Version: 1, Items: next})
}

func prewarmPull(ctx context.Context, bin, ref string) error {
	out, err := exec.CommandContext(ctx, bin, "pull", ref).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// removeItem deletes a previously prewarmed reference that left the list.
// docker removes by image reference; tart images pulled by digest are not
// name-addressable, so removal is best-effort and failures are ignored.
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
			if err := exec.CommandContext(ctx, p.tartPath, "delete", item.Ref).Run(); err != nil {
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
