//go:build race

package secrets

import "time"

// maskMultiTimeBound is deliberately generous under the race detector, which
// slows the masking hot path by an order of magnitude; the correctness and
// complexity assertions remain in the test itself.
func maskMultiTimeBound() time.Duration { return 60 * time.Second }
