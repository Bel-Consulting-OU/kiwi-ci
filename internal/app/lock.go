package app

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
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
	refs := collectImageRefs(string(raw))
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

// collectImageRefs finds image: values in a Kiwi pipeline document.
func collectImageRefs(src string) []string {
	seen := map[string]bool{}
	var out []string
	for _, line := range strings.Split(src, "\n") {
		trim := strings.TrimSpace(line)
		if !strings.HasPrefix(trim, "image:") {
			continue
		}
		v := strings.TrimSpace(strings.TrimPrefix(trim, "image:"))
		v = strings.Trim(v, `"'`)
		// Strip a trailing YAML comment (`image: golang:1.27 # pin`).
		if i := strings.Index(v, " #"); i >= 0 {
			v = strings.TrimSpace(v[:i])
		}
		if v == "" || seen[v] {
			continue
		}
		// Already digest-pinned refs are kept as-is (their digest IS the ref).
		seen[v] = true
		out = append(out, v)
	}
	return out
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
