package runnerpki

import (
	"crypto/rand"
	"io"
	"sync/atomic"
)

// randReader is the entropy source for key, certificate and serial
// generation. It is an atomic seam so tests can inject read failures without
// racing goroutines that concurrently read entropy (e.g. a lingering TLS
// handshake): swapping the global crypto/rand.Reader in tests is a data race
// under -race. Production never changes it.
var randReader atomic.Pointer[io.Reader]

func init() {
	r := io.Reader(rand.Reader)
	randReader.Store(&r)
}

// randomReader returns the current entropy source.
func randomReader() io.Reader { return *randReader.Load() }
