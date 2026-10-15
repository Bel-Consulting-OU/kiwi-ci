package pipeline

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
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
// unknown fields, trailing documents, version, nonempty unique refs and
// digest-pinned OCI targets are all required. A lockfile is an authority
// document — malformed contents are fatal, never a silent fallback to
// mutable tags.
func ParseImageLockfile(raw []byte) (ImageLockfile, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var f ImageLockfile
	if err := dec.Decode(&f); err != nil {
		return ImageLockfile{}, fmt.Errorf("parse lockfile: %w", err)
	}
	// Single-document check: trailing JSON is a corruption signal.
	if dec.More() {
		return ImageLockfile{}, fmt.Errorf("parse lockfile: trailing data after document")
	}
	if err := f.Validate(); err != nil {
		return ImageLockfile{}, err
	}
	return f, nil
}

// Validate enforces the lockfile contract: version 1, every entry has a
// nonempty ref and a digest-pinned OCI target, and refs are unique. The
// digest must be `name@sha256:<64 lowercase hex>` (or bare `@sha256:…`).
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
		if err := validateOCIDigestTarget(img.Digest); err != nil {
			return fmt.Errorf("lockfile entry %q: %w", img.Ref, err)
		}
	}
	return nil
}

// validateOCIDigestTarget requires `…@sha256:<64 lowercase hex>`. The
// all-zero placeholder is refused — it is not a pin.
func validateOCIDigestTarget(target string) error {
	i := strings.Index(target, "@sha256:")
	if i < 0 {
		return fmt.Errorf("digest %q is not digest-pinned (@sha256:)", target)
	}
	hexPart := target[i+len("@sha256:"):]
	if len(hexPart) != 64 {
		return fmt.Errorf("digest %q: sha256 must be 64 hex chars, got %d", target, len(hexPart))
	}
	for _, c := range hexPart {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return fmt.Errorf("digest %q: sha256 must be lowercase hex", target)
		}
	}
	if hexPart == strings.Repeat("0", 64) {
		return fmt.Errorf("digest %q is the all-zero placeholder", target)
	}
	return nil
}

// RequireComplete reports whether every mutable executable identity in the
// spec has a lock entry. When a lockfile EXISTS, incompleteness is fatal:
// a lock that silently omits a tag defeats the meaning of a lock. Already
// digest-pinned refs need no mapping.
func (s *Spec) RequireComplete(lock map[string]string) error {
	// nil means "no lockfile document at all" (ordinary trusted policy).
	// A non-nil map — including an empty one — means a lockfile EXISTS:
	// every mutable identity must be covered. An empty images list is a
	// lock that claims authority while pinning nothing, which is exactly
	// the incompleteness this function exists to refuse.
	if s == nil || lock == nil {
		return nil
	}
	var missing []string
	for _, ref := range s.ImageRefs() {
		if strings.Contains(ref, "@sha256:") {
			continue // already immutable
		}
		if _, ok := lock[ref]; !ok {
			missing = append(missing, ref)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return fmt.Errorf("image lockfile exists but does not cover %d mutable identity(ies): %s", len(missing), strings.Join(missing, ", "))
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
