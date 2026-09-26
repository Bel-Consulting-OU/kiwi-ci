package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/staging"
)

// metricDownloadIntegrityFailures counts download responses that could not be
// proven to carry the exact advertised bytes (a preverification failure, or a
// client write that aborted). Every such response either serves nothing (503,
// preverification) or tears the connection down (abort), so a corrupt body is
// never silently accepted as a complete 200.
const metricDownloadIntegrityFailures = "kiwi_download_integrity_failures_total"

// errDownloadStagingUnavailable reports that the object could not be staged
// for preverification: no budget is configured, or the object is larger than
// the whole budget. The handler then serves only from a source it can prove
// byte-for-byte: a seekable source is hashed on the SAME open handle and
// rewound on that same handle (the file descriptor is the identity proof), so
// no pathname lookup can substitute another object; a non-seekable source is
// refused with 503 before any header is committed. Unverified bytes are never
// streamed.
var errDownloadStagingUnavailable = errors.New("download integrity staging unavailable")

// downloadAfterPreverifyHook, when non-nil, runs after a successful
// preverification and before the verified bytes are streamed. Tests use it to
// freeze a download while its staging reservation is still held. Production
// leaves it nil.
var downloadAfterPreverifyHook func()

// downloadBetweenVerifyAndServeHook, when non-nil, runs after the served
// stream has been verified (exact length + digest) and before those verified
// bytes are written to the client. Tests use it to interleave a filesystem
// mutation (for example a pathname replacement of the source) at exactly the
// point where a naive implementation would re-open the source path and serve
// the replacement; production leaves it nil.
var downloadBetweenVerifyAndServeHook func()

// verifiedSpool owns a staged file together with the byte reservation that
// accounts for it. The reservation represents LIVE DISK OCCUPANCY, not write
// activity, so it is released only after the file is removed.
type verifiedSpool struct {
	budget *staging.Budget
	path   string
	res    *staging.Reservation
	closed bool
}

// Close removes the staged file through the budget's accounting-aware
// cleanup: the reservation is released only when the file is actually gone
// (or was already absent). When the removal fails, the budget keeps the spool
// registered and the bytes charged as cleanup debt for RetryCleanup, so a
// failed removal can never silently free capacity that is still occupied. It
// is idempotent.
func (v *verifiedSpool) Close() {
	if v == nil || v.closed {
		return
	}
	v.closed = true
	if v.path != "" {
		if v.budget != nil {
			v.budget.CleanupSpool(v.path, v.res)
			return
		}
		// Defensive: no budget means no accounting can be kept, so fall back
		// to a plain removal before releasing the reservation.
		_ = os.Remove(v.path)
	}
	if v.res != nil {
		v.res.Release()
	}
}

// preverifyToSpool streams src through the shared bounded staging budget into
// a spool file and returns an owned spool proven to hold EXACTLY wantSize
// bytes. Ownership of BOTH the file and its byte reservation transfers to the
// caller, whose Close removes the file before releasing the reservation, so
// Budget.Used() always reflects bytes physically present in the staging
// directory.
func (s *Server) preverifyToSpool(ctx context.Context, src io.Reader, wantSize int64) (*verifiedSpool, error) {
	budget := s.StagingBudget()
	if budget == nil {
		return nil, errDownloadStagingUnavailable
	}
	if wantSize < 0 {
		return nil, fmt.Errorf("negative advertised size %d", wantSize)
	}
	if wantSize > budget.MaxBytes() {
		return nil, fmt.Errorf("%w: object is %d bytes, staging budget is %d", errDownloadStagingUnavailable, wantSize, budget.MaxBytes())
	}
	res, err := budget.Acquire(ctx, wantSize)
	if err != nil {
		return nil, err
	}
	sp := &verifiedSpool{budget: budget, res: res}
	path, n, err := budget.SpoolFile(src, wantSize)
	if err != nil {
		sp.Close()
		return nil, err
	}
	sp.path = path
	if n != wantSize {
		sp.Close()
		return nil, fmt.Errorf("staged object is %d bytes, want %d", n, wantSize)
	}
	return sp, nil
}

// abortDownload tears the response down so a client can never accept a
// truncated or corrupt body as complete. It prefers hijacking the underlying
// connection (HTTP/1.x) and closing it; when the writer cannot be hijacked
// (HTTP/2, or a wrapping writer) it panics with the standard library's
// sentinel, which net/http treats as an unconditional abort (the recoverer
// re-raises it). The failure is metered and logged first.
func (s *Server) abortDownload(w http.ResponseWriter, r *http.Request, scope, digest, kind string, err error) {
	s.metricAdd(metricDownloadIntegrityFailures, 1, map[string]string{"scope": scope, "kind": kind})
	s.logError("download integrity failure: aborting response", "scope", scope, "sha256", digest, "kind", kind, "error", err.Error())
	if hj, ok := w.(http.Hijacker); ok {
		if conn, _, herr := hj.Hijack(); herr == nil {
			_ = conn.Close()
			return
		}
	}
	panic(http.ErrAbortHandler)
}

// serveVerifiedDownload is the strong-integrity download path. It never
// commits headers or serves a byte until the exact advertised length and
// digest are proven:
//
//   - When the object can be staged inside the bounded staging budget it is
//     preverified into that private spool and the spool is streamed (the
//     strongest path: a private copy survives even in-place mutation of the
//     original object).
//   - When staging is unavailable (no budget, or an object larger than the
//     whole budget), a SEEKABLE source is verified by hashing the very handle
//     that will be served and is then rewound with Seek(0, io.SeekStart) on
//     that SAME handle. Content cannot be re-read from a pathname, so a
//     pathname replacement between verification and serving (unlink/rename
//     over the verified path) cannot change what this request serves.
//   - A NON-seekable source with staging unavailable is refused with 503
//     BEFORE any header is committed.
//
// Identity assumption, stated explicitly: same-FD serving is proof against
// pathname replacement, nothing more. It does NOT protect against true
// in-place mutation of the same inode (a writer that opens the file and
// rewrites its bytes without renaming); that case is covered only by the
// write-once immutability contract the CAS/local snapshot writers already
// follow (atomic rename onto content-addressed names, never in-place edits).
// The staging path covers in-place mutation because it serves a private copy.
//
// A write failure on the verified stream aborts the connection.
func (s *Server) serveVerifiedDownload(w http.ResponseWriter, r *http.Request, scope string, src io.ReadCloser, wantSize int64, wantSHA256 string, setHeaders func(http.ResponseWriter)) {
	defer src.Close()
	if sp, err := s.preverifyToSpool(r.Context(), src, wantSize); err == nil {
		defer sp.Close()
		if downloadAfterPreverifyHook != nil {
			downloadAfterPreverifyHook()
		}
		got, herr := fileSHA256(sp.path)
		if herr != nil || got != wantSHA256 {
			if herr == nil {
				herr = fmt.Errorf("staged object digest %s, want %s", got, wantSHA256)
			}
			s.metricAdd(metricDownloadIntegrityFailures, 1, map[string]string{"scope": scope, "kind": "verify"})
			s.logError("download preverification failed; no bytes served", "scope", scope, "sha256", wantSHA256, "error", herr.Error())
			http.Error(w, "download verification failed", http.StatusServiceUnavailable)
			return
		}
		// Open the VERIFIED spool before the between-hook runs and stream
		// that already-open handle: even a hostile hook that replaced the
		// spool pathname cannot change what this request serves.
		f, oerr := os.Open(sp.path)
		if oerr != nil {
			s.internalError(w, r, oerr, "")
			return
		}
		defer f.Close()
		if downloadBetweenVerifyAndServeHook != nil {
			downloadBetweenVerifyAndServeHook()
		}
		if setHeaders != nil {
			setHeaders(w)
		}
		if _, cerr := io.Copy(w, f); cerr != nil {
			s.abortDownload(w, r, scope, wantSHA256, "write", cerr)
			return
		}
		return
	} else if r.Context().Err() != nil {
		// The client is gone; there is nobody to answer.
		return
	} else if !errors.Is(err, errDownloadStagingUnavailable) && !errors.Is(err, staging.ErrBudgetExceeded) {
		s.metricAdd(metricDownloadIntegrityFailures, 1, map[string]string{"scope": scope, "kind": "verify"})
		s.logError("download preverification failed; no bytes served", "scope", scope, "sha256", wantSHA256, "error", err.Error())
		http.Error(w, "download verification failed", http.StatusServiceUnavailable)
		return
	}
	// The object could not be staged (no budget, or larger than the whole
	// budget). Server-guaranteed integrity must not be weakened: only a
	// seekable source can be verified and then served from the SAME handle.
	// The handle is the identity proof — a pathname replacement between the
	// verification pass and the serving pass cannot substitute another object
	// version, because no pathname is consulted for the serving pass. A source
	// that cannot be rewound is refused (503) before any header is committed
	// rather than streamed unverified.
	rs, seekable := src.(io.ReadSeeker)
	if !seekable {
		s.metricAdd(metricDownloadIntegrityFailures, 1, map[string]string{"scope": scope, "kind": "verify"})
		s.logError("download cannot be served with server-verified integrity: source is not seekable and staging is unavailable", "scope", scope, "sha256", wantSHA256)
		http.Error(w, "download verification unavailable", http.StatusServiceUnavailable)
		return
	}
	if err := s.verifySourceByTwoPass(r, scope, src, wantSize, wantSHA256); err != nil {
		s.metricAdd(metricDownloadIntegrityFailures, 1, map[string]string{"scope": scope, "kind": "verify"})
		s.logError("download verification failed; no bytes served", "scope", scope, "sha256", wantSHA256, "error", err.Error())
		http.Error(w, "download verification failed", http.StatusServiceUnavailable)
		return
	}
	if _, err := rs.Seek(0, io.SeekStart); err != nil {
		s.metricAdd(metricDownloadIntegrityFailures, 1, map[string]string{"scope": scope, "kind": "verify"})
		s.logError("download verification failed: source cannot be rewound; no bytes served", "scope", scope, "sha256", wantSHA256, "error", err.Error())
		http.Error(w, "download verification failed", http.StatusServiceUnavailable)
		return
	}
	if downloadBetweenVerifyAndServeHook != nil {
		downloadBetweenVerifyAndServeHook()
	}
	if setHeaders != nil {
		setHeaders(w)
	}
	if _, cerr := io.Copy(w, rs); cerr != nil {
		s.abortDownload(w, r, scope, wantSHA256, "write", cerr)
	}
}

// verifySourceByTwoPass hashes the source handle and requires the exact
// advertised length and digest. It is used when staging is unavailable but the
// source is seekable: the caller rewinds this SAME handle afterwards, so the
// bytes that were verified are the bytes that are served (a pathname cannot be
// re-resolved between the passes).
func (s *Server) verifySourceByTwoPass(r *http.Request, scope string, src io.Reader, wantSize int64, wantSHA256 string) error {
	h := sha256.New()
	n, err := io.Copy(h, src)
	if err != nil {
		return fmt.Errorf("verify pass: %w", err)
	}
	if n != wantSize {
		return fmt.Errorf("verified object is %d bytes, want %d", n, wantSize)
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != wantSHA256 {
		return fmt.Errorf("verified object digest %s, want %s", got, wantSHA256)
	}
	return nil
}

// serveStreamCheckedWithDigest streams src to the client while hashing it and
// aborts the connection when the copy fails or the stream does not match the
// advertised digest. The cache download path uses it to keep the runner-side
// hashing contract (no preverification staging) while still never silently
// accepting a corrupt body: CAS.Open's verifying reader already fails the
// stream at EOF on a digest mismatch, and that error aborts here.
func (s *Server) serveStreamCheckedWithDigest(w http.ResponseWriter, r *http.Request, scope, digest string, src io.ReadCloser) (int64, bool) {
	defer src.Close()
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(w, h), src)
	if err != nil {
		s.abortDownload(w, r, scope, digest, "write", err)
		return n, false
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != digest {
		s.abortDownload(w, r, scope, digest, "verify", fmt.Errorf("streamed digest %s, want %s", got, digest))
		return n, false
	}
	return n, true
}
