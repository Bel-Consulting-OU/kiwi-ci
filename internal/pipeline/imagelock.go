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

// ParseImageLockfile parses .kiwi/lock.json content.
func ParseImageLockfile(raw []byte) (ImageLockfile, error) {
	var f ImageLockfile
	if err := json.Unmarshal(raw, &f); err != nil {
		return ImageLockfile{}, fmt.Errorf("parse lockfile: %w", err)
	}
	return f, nil
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
