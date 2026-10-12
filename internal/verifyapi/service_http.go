package verifyapi

import (
	"errors"
	"net/http"
)

// PrincipalFromRequest extracts the authenticated caller for the Service
// HTTP facade. Returning false means "no authenticated principal": the
// facade answers 401 and performs no store work (fail closed without auth).
type PrincipalFromRequest func(*http.Request) (Principal, bool)

// ServiceHandler returns the HTTP facade for a Service, serving the same
// /api/v1/verifications/* route shapes as Handler but backed by the
// production Service (Authorizer + EvidenceVerifier + VerificationStore).
// It is the mount the control-plane server uses when a Service is
// configured.
//
// Acceptance boundary on the wire:
//
//   - POST .../outcomes records a CLAIM only. The response is a claim
//     document; it is NEVER proof and must not authorize merge/deploy.
//   - POST .../outcomes/verify runs the evidence verifier and returns the
//     sealed VerifiedOutcome document. This is the only write that
//     discharges an obligation.
//   - GET .../outcomes/{id} returns the claim view (not proof).
//   - GET .../outcomes/{id}/verified returns the sealed record (QueryOutcome)
//     — the only read merge/deploy may trust.
//
// Authentication is fail closed: without a principal the facade answers 401
// before touching the store. Authorization is the Service's Authorizer,
// against the STORED obligation's SubjectRef.
func ServiceHandler(svc *Service, principal PrincipalFromRequest) http.Handler {
	mux := http.NewServeMux()
	authed := func(w http.ResponseWriter, req *http.Request, action Action, fn func(p Principal) error) {
		if principal == nil {
			writeError(w, http.StatusUnauthorized, ErrUnauthorized)
			return
		}
		p, ok := principal(req)
		if !ok {
			writeError(w, http.StatusUnauthorized, ErrUnauthorized)
			return
		}
		if err := fn(p); err != nil {
			writeError(w, serviceStatusFor(err), err)
		}
	}
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
		authed(w, req, ActionSubmitObligation, func(p Principal) error {
			if err := svc.SubmitObligation(req.Context(), p, o); err != nil {
				return err
			}
			writeJSON(w, http.StatusCreated, func() ([]byte, error) { return MarshalObligation(o) })
			return nil
		})
	})
	mux.HandleFunc("GET /api/v1/verifications/obligations/{id}", func(w http.ResponseWriter, req *http.Request) {
		authed(w, req, ActionQueryOutcome, func(p Principal) error {
			ob, err := svc.Store.GetObligation(req.Context(), req.PathValue("id"))
			if err != nil {
				return err
			}
			// Disclosure of an obligation is authorized against its own
			// subject, exactly like an outcome read.
			if err := svc.authorize(req.Context(), p, ActionQueryOutcome, ob.SubjectReference()); err != nil {
				return err
			}
			writeJSON(w, http.StatusOK, func() ([]byte, error) { return MarshalObligation(ob) })
			return nil
		})
	})
	mux.HandleFunc("GET /api/v1/verifications/obligations/{id}/outcomes", func(w http.ResponseWriter, req *http.Request) {
		authed(w, req, ActionQueryOutcome, func(p Principal) error {
			ob, err := svc.Store.GetObligation(req.Context(), req.PathValue("id"))
			if err != nil {
				return err
			}
			if err := svc.authorize(req.Context(), p, ActionQueryOutcome, ob.SubjectReference()); err != nil {
				return err
			}
			list, err := svc.Store.OutcomesForObligation(req.Context(), ob.ObligationID)
			if err != nil {
				return err
			}
			writeJSON(w, http.StatusOK, func() ([]byte, error) { return marshalDoc(newOutcomeListDoc(list)) })
			return nil
		})
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
		authed(w, req, ActionRecordClaim, func(p Principal) error {
			if err := svc.RecordClaim(req.Context(), p, v); err != nil {
				return err
			}
			writeJSON(w, http.StatusCreated, func() ([]byte, error) { return MarshalOutcome(v) })
			return nil
		})
	})
	mux.HandleFunc("POST /api/v1/verifications/outcomes/verify", func(w http.ResponseWriter, req *http.Request) {
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
		authed(w, req, ActionVerifyAndRecord, func(p Principal) error {
			seal, err := svc.VerifyAndRecord(req.Context(), p, v)
			if err != nil {
				return err
			}
			writeJSON(w, http.StatusCreated, func() ([]byte, error) { return marshalDoc(newVerifiedDoc(seal)) })
			return nil
		})
	})
	mux.HandleFunc("GET /api/v1/verifications/outcomes/{id}", func(w http.ResponseWriter, req *http.Request) {
		authed(w, req, ActionQueryOutcome, func(p Principal) error {
			v, err := svc.Store.GetOutcome(req.Context(), req.PathValue("id"))
			if err != nil {
				return err
			}
			ob, err := svc.Store.GetObligation(req.Context(), v.ObligationID)
			if err != nil {
				return err
			}
			if err := svc.authorize(req.Context(), p, ActionQueryOutcome, ob.SubjectReference()); err != nil {
				return err
			}
			writeJSON(w, http.StatusOK, func() ([]byte, error) { return MarshalOutcome(v) })
			return nil
		})
	})
	mux.HandleFunc("GET /api/v1/verifications/outcomes/{id}/verified", func(w http.ResponseWriter, req *http.Request) {
		authed(w, req, ActionQueryOutcome, func(p Principal) error {
			// QueryOutcome is the sealed read: a claim-only id answers
			// ErrUnverified here and never becomes proof on the wire.
			vo, err := svc.QueryOutcome(req.Context(), p, req.PathValue("id"))
			if err != nil {
				return err
			}
			writeJSON(w, http.StatusOK, func() ([]byte, error) { return marshalDoc(newVerifiedDoc(vo)) })
			return nil
		})
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
		authed(w, req, ActionSubmitObligation, func(p Principal) error {
			// Group registration is authorized on the zero subject unless
			// the caller is admin (groups themselves carry no SubjectRef);
			// member outcomes are authorized individually when recorded.
			if err := svc.authorize(req.Context(), p, ActionSubmitObligation, SubjectRef{}); err != nil {
				return err
			}
			if err := svc.Store.RegisterGroup(req.Context(), g); err != nil {
				return err
			}
			writeJSON(w, http.StatusCreated, func() ([]byte, error) { return MarshalGroup(g) })
			return nil
		})
	})
	mux.HandleFunc("GET /api/v1/verifications/groups/{id}", func(w http.ResponseWriter, req *http.Request) {
		authed(w, req, ActionCompareGroup, func(p Principal) error {
			g, err := svc.Store.GetGroup(req.Context(), req.PathValue("id"))
			if err != nil {
				return err
			}
			if err := svc.authorize(req.Context(), p, ActionCompareGroup, SubjectRef{}); err != nil {
				return err
			}
			writeJSON(w, http.StatusOK, func() ([]byte, error) { return MarshalGroup(g) })
			return nil
		})
	})
	mux.HandleFunc("GET /api/v1/verifications/groups/{id}/comparison", func(w http.ResponseWriter, req *http.Request) {
		authed(w, req, ActionCompareGroup, func(p Principal) error {
			cmp, err := svc.CompareGroup(req.Context(), p, req.PathValue("id"))
			if err != nil {
				return err
			}
			writeJSON(w, http.StatusOK, func() ([]byte, error) { return marshalDoc(cmp) })
			return nil
		})
	})
	return mux
}

// verifiedDoc is the v1 wire form of a sealed VerifiedOutcome. The unexported
// seal is not serialized; the document is produced only from sealed records,
// and consumers must treat the presence of the evidence block as the
// verifier's claim (the transport is trusted, the seal is process-local).
type verifiedDoc struct {
	SchemaVersion int                 `json:"schema_version"`
	Outcome       VerificationOutcome `json:"outcome"`
	Evidence      VerifiedEvidence    `json:"evidence"`
	// ProvenPass is the explicit discharge bit for merge/deploy gates.
	ProvenPass bool `json:"proven_pass"`
}

func newVerifiedDoc(v VerifiedOutcome) verifiedDoc {
	return verifiedDoc{
		SchemaVersion: SchemaVersion,
		Outcome:       v.Outcome,
		Evidence:      v.Evidence,
		ProvenPass:    v.ProvenPass(),
	}
}

// serviceStatusFor maps a service refusal onto HTTP. Authorization
// refusals are 403, missing principals 401 (handled by the authed wrapper),
// and the rest reuse the registry status mapping.
func serviceStatusFor(err error) int {
	switch {
	case errors.Is(err, ErrUnauthorized):
		return http.StatusForbidden
	case errors.Is(err, ErrUnverified):
		return http.StatusConflict
	default:
		return statusFor(err)
	}
}
