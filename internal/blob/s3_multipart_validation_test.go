package blob

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

// TestS3MultipartKnobValidation pins the multipart knob resolvers: the
// defaults are the vetted production constants, the exact S3 bounds (5 MiB,
// 5 GiB) are accepted, and below-minimum, above-maximum and negative values
// fail fast with a clear error BEFORE any request is issued.
func TestS3MultipartKnobValidation(t *testing.T) {
	def, _ := newFakeS3Multipart(t)
	if got, err := def.multipartThreshold(); err != nil || got != s3MultipartThreshold {
		t.Fatalf("default threshold = (%d, %v), want %d", got, err, int64(s3MultipartThreshold))
	}
	if got, err := def.multipartPartSize(); err != nil || got != s3MultipartPartSize {
		t.Fatalf("default part size = (%d, %v), want %d", got, err, int64(s3MultipartPartSize))
	}
	for _, bound := range []int64{s3MultipartMinPartSize, s3MultipartMaxPartSize} {
		s, _ := newFakeS3Multipart(t)
		s.MultipartPartSize = bound
		if got, err := s.multipartPartSize(); err != nil || got != bound {
			t.Fatalf("boundary part size %d rejected: (%d, %v)", bound, got, err)
		}
	}
	cases := []struct {
		name       string
		threshold  int64
		partSize   int64
		wantSubstr string
	}{
		{"below minimum", 1, s3MultipartMinPartSize - 1, "below the S3 minimum"},
		{"above maximum", 1, s3MultipartMaxPartSize + 1, "exceeds the S3 maximum"},
		{"negative part size", 1, -1, "must not be negative"},
		{"negative threshold", -1, 0, "must not be negative"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, f := newFakeS3Multipart(t)
			s.MultipartThreshold = tc.threshold
			s.MultipartPartSize = tc.partSize
			_, err := s.Put(context.Background(), multipartTestKey, bytes.NewReader([]byte{1, 2}), 2)
			if err == nil || !strings.Contains(err.Error(), tc.wantSubstr) {
				t.Fatalf("Put = %v, want an error containing %q", err, tc.wantSubstr)
			}
			f.mu.Lock()
			calls := len(f.calls)
			f.mu.Unlock()
			if calls != 0 {
				t.Fatalf("invalid knobs issued %d request(s); validation must fail before any request", calls)
			}
		})
	}
}
