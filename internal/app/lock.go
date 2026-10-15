package app

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
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

// lockRootFor returns the project root that owns .kiwi/lock.json for a
// pipeline file. The default pipeline lives at <root>/.kiwi/pipeline.yaml,
// so the lock is a SIBLING of the pipeline — not nested at
// .kiwi/.kiwi/lock.json. Any other pipeline path keeps the lock under
// that file's directory, matching the server's repo-root-relative fetch.
func lockRootFor(pipelinePath string) string {
	dir := filepath.Dir(pipelinePath)
	if filepath.Base(dir) == ".kiwi" {
		return filepath.Dir(dir)
	}
	return dir
}

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
	// Component-injected images are not in the unparsed spec. Writing a
	// lock that cannot see them produces an incomplete authority document
	// (server-side RequireComplete would then reject every submit). Refuse
	// rather than emit a lock that lies about completeness.
	for id, j := range spec.Jobs {
		if j.Component != "" {
			return fmt.Errorf("job %q references component %q: kiwi lock cannot enumerate component-injected images; lock from the control plane after component expansion", id, j.Component)
		}
	}
	refs := spec.ImageRefs()
	if len(refs) == 0 {
		fmt.Println("no image references found")
		return nil
	}
	sort.Strings(refs)

	lockPath := filepath.Join(lockRootFor(pipelinePath), lockfilePath)
	existing := Lockfile{Version: 1}
	if b, err := os.ReadFile(lockPath); err == nil {
		// A present lockfile is an authority document: malformed content
		// must fail closed rather than silently start a fresh map that
		// would allow an --update to drop pins without the digest gate.
		if len(strings.TrimSpace(string(b))) > 0 {
			if _, perr := pipeline.ParseImageLockfile(b); perr != nil {
				return fmt.Errorf("existing %s: %w", lockPath, perr)
			}
		}
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
	if err := os.MkdirAll(filepath.Dir(lockPath), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(lockPath, append(rawOut, '\n'), 0o644); err != nil {
		return err
	}
	fmt.Printf("wrote %s (%d images)\n", lockPath, len(out.Images))
	return nil
}

// applyLocalImageLock is the local counterpart of the server's
// applyImageLockContent: parse the lockfile strictly, enforce completeness
// when one exists, and apply it to the spec BEFORE compile. Identical
// semantics to remote resolution — local and remote must never disagree
// about what the compiled graph executes.
func applyLocalImageLock(spec *pipeline.Spec, root string) error {
	b, err := os.ReadFile(filepath.Join(root, lockfilePath))
	if err != nil {
		if os.IsNotExist(err) {
			return nil // no lockfile: ordinary trusted policy
		}
		return err
	}
	if len(strings.TrimSpace(string(b))) == 0 {
		// A lockfile that EXISTS but pins nothing is not "no lockfile" —
		// it is an incomplete authority document. Server-side empty content
		// means 404/no document; a local file that is present is not a 404.
		return fmt.Errorf("image lockfile %s exists but is empty", filepath.Join(root, lockfilePath))
	}
	// Component-injected images are invisible to ImageRefs() before the
	// control plane expands components. Once a lockfile EXISTS, a local
	// completeness check can never cover those images — refuse rather than
	// accept a lock that silently omits them. (No lockfile stays ordinary
	// trusted policy; component jobs still require the control plane.)
	if spec != nil {
		for id, j := range spec.Jobs {
			if j.Component != "" {
				return fmt.Errorf("job %q references component %q: image lockfile cannot cover component-injected images locally; lock from the control plane after component expansion", id, j.Component)
			}
		}
	}
	lock, err := pipeline.ParseImageLockfile(b)
	if err != nil {
		return fmt.Errorf("image lockfile: %w", err)
	}
	m := lock.LockMap()
	if err := spec.RequireComplete(m); err != nil {
		return fmt.Errorf("image lockfile: %w", err)
	}
	spec.ApplyImageLock(m)
	return nil
}

// LockLookup returns the digest locked for ref in the lockfile at the given
// root (the job workspace / project dir), or "" when unknown. The root is
// required: a remote runner's process CWD is NOT the checkout, so reading
// ".kiwi/lock.json" relative to CWD would silently skip the lock for every
// distributed job. Prefer applyLocalImageLock — it is the authoritative
// compilation path; this lookup is a convenience for diagnostics.
func LockLookup(root, ref string) string {
	p := filepath.Join(root, lockfilePath)
	b, err := os.ReadFile(p)
	if err != nil {
		return ""
	}
	lock, err := pipeline.ParseImageLockfile(b)
	if err != nil {
		return "" // malformed lock is never a silent pin
	}
	return lock.LockMap()[ref]
}
