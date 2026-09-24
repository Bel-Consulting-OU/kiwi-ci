//go:build !race

package secrets

import "time"

// maskMultiTimeBound is the strict bound outside the race detector: a
// quadratic regression over a 10 MiB line would take far longer.
func maskMultiTimeBound() time.Duration { return 5 * time.Second }
