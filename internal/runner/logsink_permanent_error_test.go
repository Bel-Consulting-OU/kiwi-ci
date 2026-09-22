package runner

// Coverage for the non-retryable delivery marker the runner's log sink uses
// to distinguish 4xx-class rejections (drop the batch, fail the job
// explicitly) from retryable transport failures.

import (
	"errors"
	"testing"
)

// TestPermanentDeliveryErrorClassification: the marker is nil-safe, renders
// the wrapped message, unwraps, and is identified by the sink through
// errors.As (the same check the live drain loop performs).
func TestPermanentDeliveryErrorClassification(t *testing.T) {
	if got := PermanentDeliveryError(nil); got != nil {
		t.Fatalf("PermanentDeliveryError(nil) = %v, want nil", got)
	}
	base := errors.New("control plane rejected the batch: HTTP 403")
	wrapped := PermanentDeliveryError(base)
	if wrapped == nil {
		t.Fatal("marker dropped the error")
	}
	if wrapped.Error() != base.Error() {
		t.Fatalf("Error() = %q, want the wrapped message %q", wrapped.Error(), base.Error())
	}
	if !errors.Is(wrapped, base) {
		t.Fatal("wrapped error is not reachable through errors.Is")
	}
	var perm *permanentDeliveryError
	if !errors.As(wrapped, &perm) {
		t.Fatal("errors.As does not identify the permanent-delivery marker")
	}
	if perm.Unwrap() != base {
		t.Fatal("Unwrap did not return the original error")
	}
	// Double wrapping stays identifiable (the sink must not lose the class).
	if !errors.As(PermanentDeliveryError(wrapped), &perm) {
		t.Fatal("re-wrapping lost the marker")
	}
}
