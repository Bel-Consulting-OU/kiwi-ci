package verifyapi

import (
	"errors"
	"io"
	"net/http"
	"strings"
)

// maxBodyBytes bounds a single verifyapi request body. Obligations, outcomes
// and groups are small control-plane documents; a larger body is refused
// before it is buffered so the facade is not a memory-amplification surface.
const maxBodyBytes = 1 << 20

// Handler returns the additive HTTP facade for a registry, serving the
// /api/v1/verifications/* surface documented in the package comment. The
// facade maps one-to-one onto the Registry methods and introduces no state,
// persistence or authorization of its own: authentication, rate limiting and
// tenancy are the mounting server's responsibility. Mounting is deliberately
// not done from inside the control-plane server so this package stays free of
// server internals.
func Handler(r *Registry) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/verifications/obligations", func(w http.ResponseWriter, req *http.Request) {
		body, err := readBody(req)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		o, err := UnmarshalObligation(body)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if err := r.SubmitObligation(o); err != nil {
			writeError(w, statusFor(err), err)
			return
		}
		writeJSON(w, http.StatusCreated, func() ([]byte, error) { return MarshalObligation(o) })
	})
	mux.HandleFunc("GET /api/v1/verifications/obligations/{id}", func(w http.ResponseWriter, req *http.Request) {
		o, err := r.Obligation(req.PathValue("id"))
		if err != nil {
			writeError(w, statusFor(err), err)
			return
		}
		writeJSON(w, http.StatusOK, func() ([]byte, error) { return MarshalObligation(o) })
	})
	mux.HandleFunc("GET /api/v1/verifications/obligations/{id}/outcomes", func(w http.ResponseWriter, req *http.Request) {
		if _, err := r.Obligation(req.PathValue("id")); err != nil {
			writeError(w, statusFor(err), err)
			return
		}
		list := r.OutcomesForObligation(req.PathValue("id"))
		writeJSON(w, http.StatusOK, func() ([]byte, error) { return marshalDoc(newOutcomeListDoc(list)) })
	})
	mux.HandleFunc("POST /api/v1/verifications/outcomes", func(w http.ResponseWriter, req *http.Request) {
		body, err := readBody(req)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		v, err := UnmarshalOutcome(body)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if err := r.RecordOutcome(v); err != nil {
			writeError(w, statusFor(err), err)
			return
		}
		writeJSON(w, http.StatusCreated, func() ([]byte, error) { return MarshalOutcome(v) })
	})
	mux.HandleFunc("GET /api/v1/verifications/outcomes/{id}", func(w http.ResponseWriter, req *http.Request) {
		v, err := r.Outcome(req.PathValue("id"))
		if err != nil {
			writeError(w, statusFor(err), err)
			return
		}
		writeJSON(w, http.StatusOK, func() ([]byte, error) { return MarshalOutcome(v) })
	})
	mux.HandleFunc("POST /api/v1/verifications/groups", func(w http.ResponseWriter, req *http.Request) {
		body, err := readBody(req)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		g, err := UnmarshalGroup(body)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if err := r.RegisterGroup(g); err != nil {
			writeError(w, statusFor(err), err)
			return
		}
		writeJSON(w, http.StatusCreated, func() ([]byte, error) { return MarshalGroup(g) })
	})
	mux.HandleFunc("GET /api/v1/verifications/groups/{id}", func(w http.ResponseWriter, req *http.Request) {
		g, err := r.Group(req.PathValue("id"))
		if err != nil {
			writeError(w, statusFor(err), err)
			return
		}
		writeJSON(w, http.StatusOK, func() ([]byte, error) { return MarshalGroup(g) })
	})
	mux.HandleFunc("GET /api/v1/verifications/groups/{id}/comparison", func(w http.ResponseWriter, req *http.Request) {
		cmp, err := r.CompareGroup(req.PathValue("id"))
		if err != nil {
			writeError(w, statusFor(err), err)
			return
		}
		writeJSON(w, http.StatusOK, func() ([]byte, error) { return marshalDoc(cmp) })
	})
	return mux
}

// outcomeListDoc is the v1 wire form of an outcome collection.
type outcomeListDoc struct {
	SchemaVersion int                   `json:"schema_version"`
	Outcomes      []VerificationOutcome `json:"outcomes"`
}

func newOutcomeListDoc(list []VerificationOutcome) outcomeListDoc {
	if list == nil {
		list = []VerificationOutcome{}
	}
	return outcomeListDoc{SchemaVersion: SchemaVersion, Outcomes: list}
}

func readBody(req *http.Request) ([]byte, error) {
	body, err := io.ReadAll(http.MaxBytesReader(nil, req.Body, maxBodyBytes))
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(string(body)) == "" {
		return nil, ErrInvalid
	}
	return body, nil
}

// statusFor maps a registry refusal onto the HTTP status documented in the
// package comment. Binding and freshness refusals are 409 (the request was
// understood but the claim does not hold); structural problems are 400.
func statusFor(err error) int {
	switch {
	case errors.Is(err, ErrNotFound):
		return http.StatusNotFound
	case errors.Is(err, ErrExists):
		return http.StatusConflict
	case errors.Is(err, ErrBinding), errors.Is(err, ErrFreshness), errors.Is(err, ErrGroupBinding):
		return http.StatusConflict
	default:
		return http.StatusBadRequest
	}
}

func writeJSON(w http.ResponseWriter, status int, marshal func() ([]byte, error)) {
	payload, err := marshal()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(payload)
}

func writeError(w http.ResponseWriter, status int, err error) {
	payload, merr := MarshalError(err)
	if merr != nil {
		payload = []byte(`{"schema_version":1,"code":"invalid","message":"encode failure"}`)
		status = http.StatusInternalServerError
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(payload)
}
