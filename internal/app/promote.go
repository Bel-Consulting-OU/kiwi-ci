package app

import (
	"context"
	"fmt"
)

// Promote is deferred. The previous implementation claimed a signed,
// append-only blessing but only wrote a recomputable local SHA-256 over
// JSON without an attestation verification or append-only authenticated
// store. That undercuts Kiwi's evidence model (a signature is not a
// checksum). The public command fails closed until a real attestation-
// backed promotion authority exists.
func Promote(ctx context.Context, args []string) error {
	_ = ctx
	_ = args
	return fmt.Errorf("kiwi promote: deferred (not in the frozen public contract). The local blessing-ledger implementation only wrote a recomputable checksum, not a signed attestation chain; reintroducing promote requires verifying execution attestations and writing to authenticated append-only storage")
}
