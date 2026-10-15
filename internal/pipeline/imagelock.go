package pipeline

import (
	"encoding/json"
	"fmt"
	"strings"
)

// ImageLockfile is the on-disk .kiwi/lock.json document: tag → immutable
// digest. It is AUTHORITATIVE at compilation — the compiled graph carries
// only the locked identities, so a remote runner never reinterprets a
// mutable authoring tag.
type ImageLockfile struct {
	Version int         `json:"version"`
	Images  []ImageLock `json:"images"`
}

// ImageLock is one tag → digest binding.
type ImageLock struct {
	Ref    string `json:"ref"`
	Digest string `json:"digest"`
}

// LockMap builds the lookup from a lockfile document.
func (f ImageLockfile) LockMap() map[string]string {
	m := make(map[string]string, len(f.Images))
	for _, img := range f.Images {
		m[img.Ref] = img.Digest
	}
	return m
}

// ParseImageLockfile parses .kiwi/lock.json content. The document is strict:
// version, nonempty unique refs and digest-pinned targets are all required.
func ParseImageLockfile(raw []byte) (ImageLockfile, error) {
	var f ImageLockfile
	if err := json.Unmarshal(raw, &f); err != nil {
		return ImageLockfile{}, fmt.Errorf("parse lockfile: %w", err)
	}
	if err := f.Validate(); err != nil {
		return ImageLockfile{}, err
	}
	return f, nil
}

// Validate enforces the lockfile contract: version 1, every entry has a
// nonempty ref and a digest-pinned target, and refs are unique. A lockfile
// is an authority document — malformed contents are fatal, never a silent
// fallback to mutable tags.
func (f ImageLockfile) Validate() error {
	if f.Version != 1 {
		return fmt.Errorf("lockfile version = %d, want 1", f.Version)
	}
	seen := map[string]bool{}
	for i, img := range f.Images {
		if img.Ref == "" {
			return fmt.Errorf("lockfile entry %d: ref is empty", i)
		}
		if seen[img.Ref] {
			return fmt.Errorf("lockfile: duplicate ref %q", img.Ref)
		}
		seen[img.Ref] = true
		if img.Digest == "" {
			return fmt.Errorf("lockfile entry %q: digest is empty", img.Ref)
		}
		// The target must be digest-pinned (…@sha256:…) so the lock never
		// points at a mutable tag.
		if !strings.Contains(img.Digest, "@sha256:") {
			return fmt.Errorf("lockfile entry %q: digest %q is not digest-pinned (@sha256:)", img.Ref, img.Digest)
		}
		if strings.Contains(img.Digest, "sha256:0000000000000000000000000000000000000000000000000000000000000000") {
			return fmt.Errorf("lockfile entry %q: digest is the all-zero placeholder", img.Ref)
		}
	}
	return nil
}

// ApplyImageLock rewrites every executable image identity (job images,
// service images, VM images) through the lock. A tag with a lock entry
// becomes its digest; a tag without an entry is left as written (the
// compiled graph still records it, and untrusted policy requires digests).
// The lock is applied BEFORE digest computation so the compiled graph and
// every downstream digest bind the immutable identity.
func (s *Spec) ApplyImageLock(lock map[string]string) {
	if s == nil || len(lock) == 0 {
		return
	}
	resolve := func(ref string) string {
		if ref == "" {
			return ref
		}
		if pinned, ok := lock[ref]; ok && pinned != "" {
			return pinned
		}
		// Already-digest refs that appear verbatim in the lock also resolve.
		for k, v := range lock {
			if k == ref {
				return v
			}
		}
		return ref
	}
	for id, j := range s.Jobs {
		j.Image = resolve(j.Image)
		j.VM = resolve(j.VM)
		for i := range j.Services {
			j.Services[i].Image = resolve(j.Services[i].Image)
		}
		s.Jobs[id] = j
	}
}

// ImageRefs collects every executable image reference in the spec (job,
// service, VM) — the set a lockfile must cover for full identity pinning.
func (s *Spec) ImageRefs() []string {
	seen := map[string]bool{}
	var out []string
	add := func(ref string) {
		ref = strings.TrimSpace(ref)
		if ref == "" || seen[ref] {
			return
		}
		seen[ref] = true
		out = append(out, ref)
	}
	for _, j := range s.Jobs {
		add(j.Image)
		add(j.VM)
		for _, svc := range j.Services {
			add(svc.Image)
		}
	}
	return out
}
