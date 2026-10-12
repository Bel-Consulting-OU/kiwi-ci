package verifyapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// The wire codec is the single source of verifyapi schema v1 shape. Every
// document is a flat JSON object: the domain fields of the value, plus a
// schema_version discriminator. encoding/json emits struct fields in
// declaration order and sorts map keys, so the encoding is byte-stable for a
// given Go value; any future shape change must bump SchemaVersion and teach
// the decoders to refuse the old one.

// wireEnvelope is the version discriminator embedded in every document.
type wireEnvelope struct {
	SchemaVersion int `json:"schema_version"`
}

// ObligationDocument is the v1 wire form of a VerificationObligation.
type ObligationDocument struct {
	SchemaVersion int `json:"schema_version"`
	VerificationObligation
}

// OutcomeDocument is the v1 wire form of a VerificationOutcome.
type OutcomeDocument struct {
	SchemaVersion int `json:"schema_version"`
	VerificationOutcome
}

// GroupDocument is the v1 wire form of a SpeculativeGroup.
type GroupDocument struct {
	SchemaVersion int `json:"schema_version"`
	SpeculativeGroup
}

// ErrorDocument is the v1 wire form of a refusal. Code carries the sentinel
// error class ("invalid", "not_found", "exists", "binding", "freshness",
// "group_binding"); Message is the detail. Error documents never contain
// stack traces or internal paths.
type ErrorDocument struct {
	SchemaVersion int    `json:"schema_version"`
	Code          string `json:"code"`
	Message       string `json:"message"`
}

// MarshalObligation encodes an obligation as schema v1 JSON.
func MarshalObligation(o VerificationObligation) ([]byte, error) {
	return marshalDoc(ObligationDocument{SchemaVersion: SchemaVersion, VerificationObligation: o})
}

// UnmarshalObligation decodes a schema v1 obligation document and validates
// it. Unknown schema versions and structurally invalid obligations are
// refused.
func UnmarshalObligation(data []byte) (VerificationObligation, error) {
	var doc ObligationDocument
	if err := unmarshalDoc(data, &doc); err != nil {
		return VerificationObligation{}, err
	}
	o := doc.VerificationObligation
	if err := o.Validate(); err != nil {
		return VerificationObligation{}, err
	}
	return o, nil
}

// MarshalOutcome encodes an outcome as schema v1 JSON.
func MarshalOutcome(v VerificationOutcome) ([]byte, error) {
	return marshalDoc(OutcomeDocument{SchemaVersion: SchemaVersion, VerificationOutcome: v})
}

// UnmarshalOutcome decodes a schema v1 outcome document and validates it.
func UnmarshalOutcome(data []byte) (VerificationOutcome, error) {
	var doc OutcomeDocument
	if err := unmarshalDoc(data, &doc); err != nil {
		return VerificationOutcome{}, err
	}
	v := doc.VerificationOutcome
	if err := v.Validate(); err != nil {
		return VerificationOutcome{}, err
	}
	return v, nil
}

// MarshalGroup encodes a speculative group as schema v1 JSON.
func MarshalGroup(g SpeculativeGroup) ([]byte, error) {
	return marshalDoc(GroupDocument{SchemaVersion: SchemaVersion, SpeculativeGroup: g})
}

// UnmarshalGroup decodes a schema v1 group document and validates it.
func UnmarshalGroup(data []byte) (SpeculativeGroup, error) {
	var doc GroupDocument
	if err := unmarshalDoc(data, &doc); err != nil {
		return SpeculativeGroup{}, err
	}
	g := doc.SpeculativeGroup
	if err := g.Validate(); err != nil {
		return SpeculativeGroup{}, err
	}
	return g, nil
}

// MarshalError encodes a refusal as a schema v1 error document. err is
// classified against the package sentinels; unrecognized errors are reported
// as "invalid" without leaking their text beyond the message field.
func MarshalError(err error) ([]byte, error) {
	code := "invalid"
	switch {
	case isSentinel(err, ErrNotFound):
		code = "not_found"
	case isSentinel(err, ErrExists):
		code = "exists"
	case isSentinel(err, ErrBinding):
		code = "binding"
	case isSentinel(err, ErrFreshness):
		code = "freshness"
	case isSentinel(err, ErrGroupBinding):
		code = "group_binding"
	}
	return marshalDoc(ErrorDocument{SchemaVersion: SchemaVersion, Code: code, Message: err.Error()})
}

func isSentinel(err, sentinel error) bool {
	return errors.Is(err, sentinel)
}

func marshalDoc(v any) ([]byte, error) {
	buf := &bytes.Buffer{}
	enc := json.NewEncoder(buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, fmt.Errorf("verifyapi: marshal: %w", err)
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// unmarshalDoc decodes a schema v1 document, rejecting trailing garbage and
// any schema_version other than SchemaVersion. Failure is fail-closed: the
// caller gets an error and a zero value.
func unmarshalDoc(data []byte, doc any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(doc); err != nil {
		return fmt.Errorf("%w: decode: %v", ErrInvalid, err)
	}
	if dec.More() {
		return fmt.Errorf("%w: trailing data after document", ErrInvalid)
	}
	// Read the envelope version through a partial decode so both flat
	// documents and future wrappers stay checkable.
	var env wireEnvelope
	if err := json.Unmarshal(data, &env); err != nil {
		return fmt.Errorf("%w: decode schema_version: %v", ErrInvalid, err)
	}
	if env.SchemaVersion != SchemaVersion {
		return fmt.Errorf("%w: unsupported schema_version %d (want %d)", ErrInvalid, env.SchemaVersion, SchemaVersion)
	}
	return nil
}

// FormatTime renders a timestamp in the wire RFC3339 (nanoseconds) form used
// by the Go time.Time JSON encoding, exposed so callers building HTTP bodies
// by hand stay byte-compatible with the codec.
func FormatTime(t time.Time) string {
	return t.Format(time.RFC3339Nano)
}
