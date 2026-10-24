package app

import "fmt"

// VerifySince is deferred with kiwi promote. The local blessing ledger was
// an unauthenticated SHA-256 of mutable JSON: anyone who can edit a record
// can recompute the digest. That is corruption detection, not an
// append-only tamper-proof chain. Do not present it as one.
func VerifySince(args []string) error {
	_ = args
	return fmt.Errorf("kiwi verify --since: deferred (not in the frozen public contract). The local blessing ledger was not an authenticated append-only chain; reintroducing it requires server-owned append authority or signed records")
}
