package server

import (
	"bytes"
	"net/http"
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/cache"
)

// TestCacheUploadMaxBytesSharedContract pins W5-A at the endpoint layer: the
// upload cap IS the cache package's ONE authoritative MaxArchiveBytes (8 GiB,
// above the retired 4 GiB client cap), never a duplicated literal.
func TestCacheUploadMaxBytesSharedContract(t *testing.T) {
	if cacheUploadMaxBytes != cache.MaxArchiveBytes {
		t.Fatalf("cache upload cap = %d, want the shared cache.MaxArchiveBytes %d", cacheUploadMaxBytes, cache.MaxArchiveBytes)
	}
	if cache.MaxArchiveBytes != 8<<30 {
		t.Fatalf("cache.MaxArchiveBytes = %d, want 8 GiB", cache.MaxArchiveBytes)
	}
	if cache.MaxArchiveBytes <= 4<<30 {
		t.Fatalf("cache.MaxArchiveBytes = %d, not above the retired 4 GiB client cap", cache.MaxArchiveBytes)
	}
}

// TestCacheUploadBoundaryTinySeam runs the endpoint through the SAME shrunken
// seam (1 MiB standing in for 8 GiB) the cache client and store boundary
// tests use: seam-1 and seam are accepted, seam+1 is rejected with 413, and a
// payload whose scaled size is just over the retired 4 GiB client cap (seam/2
// at the same scale) is accepted.
func TestCacheUploadBoundaryTinySeam(t *testing.T) {
	const seam = int64(1 << 20)
	old := cacheUploadMaxBytes
	cacheUploadMaxBytes = seam
	t.Cleanup(func() { cacheUploadMaxBytes = old })

	cases := []struct {
		name string
		size int64
		want int
	}{
		{"seam-1 accepted", seam - 1, http.StatusCreated},
		{"seam accepted", seam, http.StatusCreated},
		{"seam+1 rejected", seam + 1, http.StatusRequestEntityTooLarge},
		{"above retired 4 GiB cap (scaled) accepted", seam/2 + 1, http.StatusCreated},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, _, _, hdrs, _ := cacheFixtureWithStaging(t, 2<<20)
			payload := bytes.Repeat([]byte{'a' + byte(i)}, int(tc.size))
			key := strings.Repeat(string(rune('a'+i)), 64)
			w := doRawBody(t, s, http.MethodPut, "/api/v1/jobs/job-a/cache/"+key, "runner-tok", bytes.NewReader(payload), tc.size, hdrs)
			if w.Code != tc.want {
				t.Fatalf("size %d upload = %d, want %d: %s", tc.size, w.Code, tc.want, w.Body.String())
			}
		})
	}
}
