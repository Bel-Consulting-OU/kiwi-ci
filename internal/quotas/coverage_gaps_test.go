package quotas

import (
	"math"
	"testing"
)

func TestSatMulZeroOperand(t *testing.T) {
	if got := satMul(0, 5); got != 0 {
		t.Fatalf("satMul(0, 5) = %v, want 0", got)
	}
	if got := satMul(5, 0); got != 0 {
		t.Fatalf("satMul(5, 0) = %v, want 0", got)
	}
	if got := satMul(math.MaxFloat64, 2); got != math.MaxFloat64 {
		t.Fatalf("satMul overflow = %v", got)
	}
	if got := satMul(3, 4); got != 12 {
		t.Fatalf("satMul(3, 4) = %v", got)
	}
	if got := satAdd(math.MaxFloat64, 1); got != math.MaxFloat64 {
		t.Fatalf("satAdd overflow = %v", got)
	}
	if got := satAdd(2, 3); got != 5 {
		t.Fatalf("satAdd(2, 3) = %v", got)
	}
}
