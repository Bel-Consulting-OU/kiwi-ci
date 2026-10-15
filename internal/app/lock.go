package app

import (
	"encoding/json"

	"fmt"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
	"os"
	"path/filepath"
	"sort"
)

// Image lockfile (.kiwi/lock.json): human YAML keeps readable tags; the
// lockfile resolves every tag to an immutable digest and execution uses the
// digest. Upgrades show old → new before writing.

// ImageLock is one tag → digest binding.
type ImageLock struct {
	Ref    string `json:"ref"`
	Digest string `json:"digest"`
}

// Lockfile is the on-disk lock document.
type Lockfile struct {
	Version int         `json:"version"`
	Images  []ImageLock `json:"images"`
}

const lockfilePath = ".kiwi/lock.json"

// LockCommand implements `kiwi lock [--update] [-f pipeline]`.
func LockCommand(args []string) error {
	update := false
	pipelinePath := ".kiwi/pipeline.yaml"
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--update":
			update = true
		case "-f", "--file":
			if i+1 >= len(args) {
				return fmt.Errorf("-f needs a path")
			}
			pipelinePath = args[i+1]
			i++
		default:
			return fmt.Errorf("unknown flag %q", args[i])
		}
	}
	raw, err := os.ReadFile(pipelinePath)
	if err != nil {
		return fmt.Errorf("read %s: %w", pipelinePath, err)
	}
	// Enumerate refs from the PARSED spec (job, service, VM) — the same
	// model the server resolver executes. A line scan is not the pipeline
	// language and would miss component-injected and VM images.
	spec, perr := pipeline.Parse(raw)
	if perr != nil {
		// Component-only jobs need the component-aware parse.
		spec, perr = pipeline.ParseWithComponents(raw)
		if perr != nil {
			return fmt.Errorf("parse %s: %w", pipelinePath, perr)
		}
	}
	refs := spec.ImageRefs()
	if len(refs) == 0 {
		fmt.Println("no image references found")
		return nil
	}
	sort.Strings(refs)

	existing := Lockfile{Version: 1}
	if b, err := os.ReadFile(lockfilePath); err == nil {
		_ = json.Unmarshal(b, &existing)
	}
	byRef := map[string]string{}
	for _, img := range existing.Images {
		byRef[img.Ref] = img.Digest
	}

	out := Lockfile{Version: 1}
	for _, ref := range refs {
		digest, err := ResolveImageDigest(ref)
		if err != nil {
			return fmt.Errorf("resolve %s: %w", ref, err)
		}
		if old, ok := byRef[ref]; ok && old != digest {
			if !update {
				fmt.Printf("%s\n  old %s\n  new %s\n", ref, old, digest)
				return fmt.Errorf("digest changed for %s (re-run with --update to write)", ref)
			}
			fmt.Printf("%s\n  old %s\n  new %s\n", ref, old, digest)
		}
		out.Images = append(out.Images, ImageLock{Ref: ref, Digest: digest})
	}
	rawOut, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(lockfilePath), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(lockfilePath, append(rawOut, '\n'), 0o644); err != nil {
		return err
	}
	fmt.Printf("wrote %s (%d images)\n", lockfilePath, len(out.Images))
	return nil
}

// LockLookup returns the digest locked for ref in the lockfile at the given
// root (the job workspace / project dir), or "" when unknown. The root is
// required: a remote runner's process CWD is NOT the checkout, so reading
// ".kiwi/lock.json" relative to CWD would silently skip the lock for every
// distributed job.
func LockLookup(root, ref string) string {
	p := filepath.Join(root, lockfilePath)
	b, err := os.ReadFile(p)
	if err != nil {
		return ""
	}
	var f Lockfile
	if json.Unmarshal(b, &f) != nil {
		return ""
	}
	for _, img := range f.Images {
		if img.Ref == ref {
			return img.Digest
		}
	}
	return ""
}
