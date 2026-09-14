package secretbroker

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"testing"
)

func TestSealOpenRoundTrip(t *testing.T) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.PublicKey().Bytes()
	var pubArr [32]byte
	copy(pubArr[:], pub)
	plain := []byte("s3cr3t-value-with-arbitrary-bytes \x00\xff")

	env, err := SealEnvelope(plain, pubArr, nil)
	if err != nil {
		t.Fatalf("SealEnvelope: %v", err)
	}
	if env.LeaseGeneration != 0 {
		t.Fatalf("unexpected lease generation %d", env.LeaseGeneration)
	}

	privArr := priv.Bytes()
	var key [32]byte
	copy(key[:], privArr)
	got, err := OpenEnvelope(env, key, nil)
	if err != nil {
		t.Fatalf("OpenEnvelope: %v", err)
	}
	if string(got) != string(plain) {
		t.Fatalf("round trip mismatch: got %q want %q", got, plain)
	}
}

func TestOpenEnvelopeWrongKeyFails(t *testing.T) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	other, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var pubArr [32]byte
	copy(pubArr[:], priv.PublicKey().Bytes())
	env, err := SealEnvelope([]byte("classified"), pubArr, nil)
	if err != nil {
		t.Fatal(err)
	}
	var otherKey [32]byte
	copy(otherKey[:], other.Bytes())
	if _, err := OpenEnvelope(env, otherKey, nil); err == nil {
		t.Fatal("expected error opening with wrong key")
	}
}

func TestOpenEnvelopeWrongAADFails(t *testing.T) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var pubArr [32]byte
	copy(pubArr[:], priv.PublicKey().Bytes())
	env, err := SealEnvelope([]byte("classified"), pubArr, []byte("kiwi-secret-v1\x00runner-1\x00job-1\x007\x00tok"))
	if err != nil {
		t.Fatal(err)
	}
	var key [32]byte
	copy(key[:], priv.Bytes())
	if _, err := OpenEnvelope(env, key, []byte("kiwi-secret-v1\x00runner-2\x00job-1\x007\x00tok")); err == nil {
		t.Fatal("expected error opening with different aad")
	}
	if got, err := OpenEnvelope(env, key, []byte("kiwi-secret-v1\x00runner-1\x00job-1\x007\x00tok")); err != nil || string(got) != "classified" {
		t.Fatalf("matching aad must decrypt: got %q, %v", got, err)
	}
}

func TestOpenEnvelopeTamperFails(t *testing.T) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var pubArr [32]byte
	copy(pubArr[:], priv.PublicKey().Bytes())
	env, err := SealEnvelope([]byte("classified"), pubArr, nil)
	if err != nil {
		t.Fatal(err)
	}
	var key [32]byte
	copy(key[:], priv.Bytes())

	tampered := env
	tampered.Ciphertext = append([]byte(nil), env.Ciphertext...)
	tampered.Ciphertext[len(tampered.Ciphertext)/2] ^= 0x01
	if _, err := OpenEnvelope(tampered, key, nil); err == nil {
		t.Fatal("expected error opening tampered ciphertext")
	}

	tampered = env
	tampered.Nonce = append([]byte(nil), env.Nonce...)
	tampered.Nonce[0] ^= 0x01
	if _, err := OpenEnvelope(tampered, key, nil); err == nil {
		t.Fatal("expected error opening tampered nonce")
	}
}

func TestOpenEnvelopeBadNonceLength(t *testing.T) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var pubArr [32]byte
	copy(pubArr[:], priv.PublicKey().Bytes())
	env, err := SealEnvelope([]byte("x"), pubArr, nil)
	if err != nil {
		t.Fatal(err)
	}
	var key [32]byte
	copy(key[:], priv.Bytes())
	env.Nonce = []byte("short")
	if _, err := OpenEnvelope(env, key, nil); err == nil {
		t.Fatal("expected error for short nonce")
	}
}

func TestHKDFSHA256RFC5869Vector(t *testing.T) {
	ikm, err := hex.DecodeString("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
	if err != nil {
		t.Fatal(err)
	}
	salt, err := hex.DecodeString("000102030405060708090a0b0c")
	if err != nil {
		t.Fatal(err)
	}
	info, err := hex.DecodeString("f0f1f2f3f4f5f6f7f8f9")
	if err != nil {
		t.Fatal(err)
	}
	okm := hkdfSHA256(ikm, salt, info)
	want := "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
	if got := hex.EncodeToString(okm); got != want {
		t.Fatalf("HKDF mismatch: got %s want %s", got, want)
	}
}

func TestOneTimeOnceOnly(t *testing.T) {
	inner := StaticBroker{"token": "abc123"}
	ot := &OneTime{Inner: inner}
	scope := SecretScope{Repository: "r", Environment: "prod"}
	ctx := context.Background()

	v, err := ot.Resolve(ctx, "token", scope)
	if err != nil || v != "abc123" {
		t.Fatalf("first resolve: v=%q err=%v", v, err)
	}
	_, err = ot.Resolve(ctx, "token", scope)
	if !errors.Is(err, ErrAlreadyDelivered) {
		t.Fatalf("second resolve: got %v, want ErrAlreadyDelivered", err)
	}
}

func TestOneTimeScopeIsolation(t *testing.T) {
	inner := StaticBroker{"token": "abc123"}
	ot := &OneTime{Inner: inner}
	ctx := context.Background()

	if _, err := ot.Resolve(ctx, "token", SecretScope{Repository: "r", Environment: "prod"}); err != nil {
		t.Fatal(err)
	}
	if _, err := ot.Resolve(ctx, "token", SecretScope{Repository: "r", Environment: "staging"}); err != nil {
		t.Fatalf("different environment should be deliverable: %v", err)
	}
	if _, err := ot.Resolve(ctx, "token", SecretScope{Repository: "r2", Environment: "prod"}); err != nil {
		t.Fatalf("different repository should be deliverable: %v", err)
	}
}

func TestOneTimeFailureDoesNotConsume(t *testing.T) {
	inner := StaticBroker{"token": "abc123"}
	ot := &OneTime{Inner: inner}
	ctx := context.Background()
	scope := SecretScope{Repository: "r", Environment: "prod"}

	if _, err := ot.Resolve(ctx, "missing", scope); err == nil {
		t.Fatal("expected error for missing secret")
	}
	v, err := ot.Resolve(ctx, "missing", scope)
	if err == nil {
		t.Fatalf("still expected error for missing secret, got %q", v)
	}
	if _, err := ot.Resolve(ctx, "token", scope); err != nil {
		t.Fatalf("failed lookups must not consume unrelated deliveries: %v", err)
	}
}

type failingBroker struct{ err error }

func (f failingBroker) Resolve(context.Context, string, SecretScope) (string, error) {
	return "", f.err
}

func TestChainBrokerFallback(t *testing.T) {
	boom := errors.New("boom")
	chain := ChainBroker{
		failingBroker{boom},
		StaticBroker{"k": "v1"},
		StaticBroker{"k": "v2"},
	}
	v, err := chain.Resolve(context.Background(), "k", SecretScope{})
	if err != nil {
		t.Fatalf("chain should fall back to second broker: %v", err)
	}
	if v != "v1" {
		t.Fatalf("got %q, want first success v1", v)
	}

	chain2 := ChainBroker{failingBroker{boom}, failingBroker{boom}}
	_, err = chain2.Resolve(context.Background(), "k", SecretScope{})
	if err == nil {
		t.Fatal("expected error when all brokers fail")
	}
	if !errors.Is(err, boom) {
		t.Fatalf("expected joined errors to include boom: %v", err)
	}

	_, err = ChainBroker{}.Resolve(context.Background(), "k", SecretScope{})
	if err == nil {
		t.Fatal("expected error for empty chain")
	}
}

func TestStaticBroker(t *testing.T) {
	s := StaticBroker{"a": "1"}
	if v, err := s.Resolve(context.Background(), "a", SecretScope{}); err != nil || v != "1" {
		t.Fatalf("got %q, %v", v, err)
	}
	if _, err := s.Resolve(context.Background(), "z", SecretScope{}); err == nil {
		t.Fatal("expected not-found error")
	}
}
