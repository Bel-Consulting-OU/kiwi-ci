package secretbroker

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
)

// TestSealEnvelopeRejectsAllZeroPeerKey verifies the all-zero X25519 public
// key (the identity/low-order point) is rejected instead of producing a
// delivery anyone could open.
func TestSealEnvelopeRejectsAllZeroPeerKey(t *testing.T) {
	var zero [32]byte
	if _, err := SealEnvelope([]byte("secret"), zero, nil); err == nil {
		t.Fatal("all-zero peer public key must be rejected")
	}
}

// TestOpenEnvelopeRejectsAllZeroPrivateKey verifies a zero private key cannot
// open a legitimately sealed delivery.
func TestOpenEnvelopeRejectsAllZeroPrivateKey(t *testing.T) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var peer [32]byte
	copy(peer[:], priv.PublicKey().Bytes())
	d, err := SealEnvelope([]byte("secret"), peer, nil)
	if err != nil {
		t.Fatal(err)
	}
	var zero [32]byte
	if _, err := OpenEnvelope(d, zero, nil); err == nil {
		t.Fatal("all-zero private key must not open the delivery")
	}
}

// TestOpenEnvelopeAADFieldPermutation verifies the delivery AAD binds every
// field of the (runner, job, generation, secret) tuple: mutating any one of
// them must fail to open an envelope sealed for the original tuple.
func TestOpenEnvelopeAADFieldPermutation(t *testing.T) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var peer [32]byte
	copy(peer[:], priv.PublicKey().Bytes())
	aad := secretDeliveryAAD("runner-1", "job-1", 7, "TOKEN")
	d, err := SealEnvelope([]byte("delivered-value"), peer, aad)
	if err != nil {
		t.Fatal(err)
	}
	var own [32]byte
	copy(own[:], priv.Bytes())
	got, err := OpenEnvelope(d, own, aad)
	if err != nil || string(got) != "delivered-value" {
		t.Fatalf("same AAD must open: %q %v", got, err)
	}
	mutated := map[string][]byte{
		"runner":     secretDeliveryAAD("runner-2", "job-1", 7, "TOKEN"),
		"job":        secretDeliveryAAD("runner-1", "job-2", 7, "TOKEN"),
		"generation": secretDeliveryAAD("runner-1", "job-1", 8, "TOKEN"),
		"name":       secretDeliveryAAD("runner-1", "job-1", 7, "OTHER"),
		"prefix":     []byte("kiwi-secret-v2\x00runner-1\x00job-1\x007\x00TOKEN"),
	}
	for label, alt := range mutated {
		if _, err := OpenEnvelope(d, own, alt); err == nil {
			t.Errorf("AAD with mutated %s opened the envelope", label)
		}
	}
}

// TestOneTimeConcurrentSingleDelivery verifies the single-delivery contract
// under concurrency: exactly one caller wins, the inner broker resolves once,
// and every other caller gets ErrAlreadyDelivered.
func TestOneTimeConcurrentSingleDelivery(t *testing.T) {
	var calls atomic.Int64
	o := &OneTime{Inner: countingBroker{calls: &calls}}
	const n = 32
	var wg sync.WaitGroup
	var successes atomic.Int64
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if _, err := o.Resolve(context.Background(), "TOKEN", SecretScope{Repository: "r", Environment: "e"}); err == nil {
				successes.Add(1)
			} else if !errors.Is(err, ErrAlreadyDelivered) {
				t.Errorf("unexpected error: %v", err)
			}
		}()
	}
	close(start)
	wg.Wait()
	if got := successes.Load(); got != 1 {
		t.Fatalf("successful deliveries = %d, want 1", got)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("inner resolutions = %d, want 1", got)
	}
}

// TestOneTimeTrustScopeIsolation pins F5-C: the delivery key includes the
// trust scope, so a delivery made in an untrusted (fork) scope cannot consume
// the single delivery owed to the same secret in a trusted scope, and vice
// versa.
func TestOneTimeTrustScopeIsolation(t *testing.T) {
	var calls atomic.Int64
	o := &OneTime{Inner: countingBroker{calls: &calls}}
	ctx := context.Background()
	untrusted := SecretScope{Repository: "r", Environment: "e", Trusted: false}
	trusted := SecretScope{Repository: "r", Environment: "e", Trusted: true}

	if _, err := o.Resolve(ctx, "TOKEN", untrusted); err != nil {
		t.Fatalf("untrusted resolve: %v", err)
	}
	if _, err := o.Resolve(ctx, "TOKEN", trusted); err != nil {
		t.Fatalf("trusted resolve after untrusted delivery must succeed: %v", err)
	}
	if _, err := o.Resolve(ctx, "TOKEN", untrusted); !errors.Is(err, ErrAlreadyDelivered) {
		t.Fatalf("repeat untrusted resolve = %v, want ErrAlreadyDelivered", err)
	}
	if _, err := o.Resolve(ctx, "TOKEN", trusted); !errors.Is(err, ErrAlreadyDelivered) {
		t.Fatalf("repeat trusted resolve = %v, want ErrAlreadyDelivered", err)
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("inner resolutions = %d, want 2", got)
	}
}

// countingBroker counts resolutions and returns a constant value.
type countingBroker struct{ calls *atomic.Int64 }

func (b countingBroker) Resolve(context.Context, string, SecretScope) (string, error) {
	b.calls.Add(1)
	return "value", nil
}

// TestEnvelopeTamperEveryFieldRejected verifies each serialized field of a
// delivery is authenticated.
func TestEnvelopeTamperEveryFieldRejected(t *testing.T) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var peer [32]byte
	copy(peer[:], priv.PublicKey().Bytes())
	aad := secretDeliveryAAD("r", "j", 1, "N")
	d, err := SealEnvelope([]byte("value"), peer, aad)
	if err != nil {
		t.Fatal(err)
	}
	var own [32]byte
	copy(own[:], priv.Bytes())
	mutate := func(f func(*EncryptedDelivery)) EncryptedDelivery {
		c := EncryptedDelivery{
			Ciphertext:      append([]byte(nil), d.Ciphertext...),
			EphemeralPublic: append([]byte(nil), d.EphemeralPublic...),
			Nonce:           append([]byte(nil), d.Nonce...),
			LeaseGeneration: d.LeaseGeneration,
		}
		f(&c)
		return c
	}
	cases := map[string]EncryptedDelivery{
		"ciphertext": mutate(func(c *EncryptedDelivery) { c.Ciphertext[0] ^= 0xff }),
		"tag":        mutate(func(c *EncryptedDelivery) { c.Ciphertext[len(c.Ciphertext)-1] ^= 0xff }),
		"ephemeral":  mutate(func(c *EncryptedDelivery) { c.EphemeralPublic[0] ^= 0xff }),
		"nonce":      mutate(func(c *EncryptedDelivery) { c.Nonce[0] ^= 0xff }),
		"short nonce": mutate(func(c *EncryptedDelivery) {
			c.Nonce = c.Nonce[:len(c.Nonce)-1]
		}),
	}
	for label, c := range cases {
		if _, err := OpenEnvelope(c, own, aad); err == nil {
			t.Errorf("tampered %s opened the envelope", label)
		}
	}
	// The lease generation is transport metadata: it is not part of the AEAD
	// and must be compared by the caller (RemoteProvider does), so a delivery
	// with a different generation still opens cryptographically but must not
	// be accepted by the provider. That comparison is covered by
	// TestRemoteProviderRejectsWrongGeneration.
}
