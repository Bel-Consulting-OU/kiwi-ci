package server

import (
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// Observed-runtime validation bounds. The completion payload is
// runner-supplied, so every string and map is bounded before the evidence
// can reach the job payload: a malformed completion is refused with 400
// instead of persisting an oversized or control-character-laden blob.
const (
	maxObservedRuntimeNames   = 64
	maxObservedRuntimeKeyLen  = 256
	maxObservedRuntimeValLen  = 512
	maxObservedRuntimeNameLen = 64
	maxObservedRuntimeVerLen  = 160
	maxObservedRuntimePayload = 64 << 10
)

// validateObservedRuntime checks the wire shape and size of a completion's
// observed runtime. Nil is valid (the runner captured nothing). Strings must
// be valid UTF-8 free of control characters; maps are bounded in entry count,
// key and value size; the whole encoded value must fit the payload bound.
// Components is server-owned evidence and is deliberately NOT trusted from
// the wire (the completion path overwrites it from the persisted job), but a
// client-supplied map is still shape-checked so a hostile body is refused
// uniformly.
func validateObservedRuntime(obs *model.ObservedRuntime) error {
	if obs == nil {
		return nil
	}
	if err := checkObservedString("os", obs.OS, maxObservedRuntimeNameLen); err != nil {
		return err
	}
	if err := checkObservedString("arch", obs.Arch, maxObservedRuntimeNameLen); err != nil {
		return err
	}
	if err := checkObservedString("runtime_name", obs.RuntimeName, maxObservedRuntimeNameLen); err != nil {
		return err
	}
	if err := checkObservedString("runtime_version", obs.RuntimeVersion, maxObservedRuntimeVerLen); err != nil {
		return err
	}
	if err := checkObservedString("main_image", obs.MainImage, maxObservedRuntimeValLen); err != nil {
		return err
	}
	if err := checkObservedString("main_image_digest", obs.MainImageDigest, maxObservedRuntimeValLen); err != nil {
		return err
	}
	for _, m := range []struct {
		name string
		m    map[string]string
	}{
		{"service_images", obs.ServiceImages},
		{"service_image_digests", obs.ServiceImageDigests},
		{"components", obs.Components},
	} {
		if err := checkObservedMap(m.name, m.m); err != nil {
			return err
		}
	}
	enc, err := jsonMarshal(obs)
	if err != nil {
		return fmt.Errorf("observed_runtime: %w", err)
	}
	if len(enc) > maxObservedRuntimePayload {
		return fmt.Errorf("observed_runtime exceeds %d bytes", maxObservedRuntimePayload)
	}
	return nil
}

func checkObservedString(field, v string, max int) error {
	if len(v) > max {
		return fmt.Errorf("observed_runtime.%s exceeds %d bytes", field, max)
	}
	if !utf8.ValidString(v) {
		return fmt.Errorf("observed_runtime.%s is not valid UTF-8", field)
	}
	if strings.ContainsFunc(v, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		return fmt.Errorf("observed_runtime.%s contains control characters", field)
	}
	return nil
}

func checkObservedMap(field string, m map[string]string) error {
	if len(m) > maxObservedRuntimeNames {
		return fmt.Errorf("observed_runtime.%s has more than %d entries", field, maxObservedRuntimeNames)
	}
	for k, v := range m {
		if k == "" {
			return fmt.Errorf("observed_runtime.%s has an empty key", field)
		}
		if err := checkObservedString(field+" key", k, maxObservedRuntimeKeyLen); err != nil {
			return err
		}
		if err := checkObservedString(field+" value", v, maxObservedRuntimeValLen); err != nil {
			return err
		}
	}
	return nil
}

// observedRuntimeWithComponents returns the evidence to persist for a
// completion: a deep copy of the validated wire value with Components
// REPLACED by the resolved component digests of the persisted job. The
// client's Components map is never trusted. nil stays nil (the completion
// simply persists no runtime evidence).
func observedRuntimeWithComponents(obs *model.ObservedRuntime, j model.Job) *model.ObservedRuntime {
	if obs == nil {
		return nil
	}
	out := *obs
	out.ServiceImages = cloneMap(obs.ServiceImages)
	out.ServiceImageDigests = cloneMap(obs.ServiceImageDigests)
	out.Components = nil
	if j.ComponentDigest != "" {
		name := j.BaseKey
		if name == "" {
			name = j.Key
		}
		if name != "" && len(name) <= maxObservedRuntimeKeyLen && len(j.ComponentDigest) <= maxObservedRuntimeValLen {
			out.Components = map[string]string{name: j.ComponentDigest}
		}
	}
	return &out
}
