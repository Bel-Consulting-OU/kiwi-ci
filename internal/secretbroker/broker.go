// Package secretbroker resolves secrets from remote secret stores through a
// single Broker interface. Values resolved for CI runs must travel over the
// wire encrypted whenever a lease or delivery record crosses untrusted
// systems; SealEnvelope/OpenEnvelope provide X25519+HKDF+AES-GCM envelopes for
// that purpose using only the standard library.
package secretbroker

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"strconv"
	"sync"
)

// SecretScope describes the CI context a secret is resolved for.
type SecretScope struct {
	Repository  string
	Environment string
	Trusted     bool
}

// Broker resolves a named secret for a scope.
type Broker interface {
	Resolve(ctx context.Context, name string, scope SecretScope) (string, error)
}

// EncryptedDelivery is a sealed secret value plus the ephemeral key material
// needed by the recipient to open it.
type EncryptedDelivery struct {
	Ciphertext      []byte
	EphemeralPublic []byte
	Nonce           []byte
	LeaseGeneration int64
}

// randReader and generateX25519Key are test-only seams over crypto/rand
// and ephemeral key generation. Production behavior is unchanged; they let
// entropy failures in nonce and ephemeral-key generation be exercised.
var (
	randReader        io.Reader = rand.Reader
	generateX25519Key           = func() (*ecdh.PrivateKey, error) { return ecdh.X25519().GenerateKey(rand.Reader) }
)

// ErrAlreadyDelivered is returned by OneTime after a secret has already been
// delivered once for a given scope.
var ErrAlreadyDelivered = errors.New("secretbroker: secret already delivered")

// ErrNilInner is returned by OneTime.Resolve when the wrapper has no Inner
// broker, so a misconfigured wrapper fails closed instead of panicking.
var ErrNilInner = errors.New("secretbroker: broker not configured")

// OneTime wraps a Broker and guarantees each (name, repository, environment,
// trust scope) combination is delivered at most once. The trust scope is part
// of the key so an untrusted (e.g. fork) delivery cannot consume the single
// delivery of a trusted scope. A failed resolution does not consume the
// delivery.
type OneTime struct {
	mu        sync.Mutex
	delivered map[string]bool

	// Inner performs the actual resolution. Required.
	Inner Broker
}

func (o *OneTime) Resolve(ctx context.Context, name string, scope SecretScope) (string, error) {
	if o.Inner == nil {
		return "", fmt.Errorf("%w: OneTime wrapper has no Inner broker", ErrNilInner)
	}
	key := name + "\x00" + scope.Repository + "\x00" + scope.Environment + "\x00" + strconv.FormatBool(scope.Trusted)
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.delivered == nil {
		o.delivered = make(map[string]bool)
	}
	if o.delivered[key] {
		return "", fmt.Errorf("%w: %s (repo=%q env=%q trusted=%t)", ErrAlreadyDelivered, name, scope.Repository, scope.Environment, scope.Trusted)
	}
	v, err := o.Inner.Resolve(ctx, name, scope)
	if err != nil {
		return "", err
	}
	o.delivered[key] = true
	return v, nil
}

const envelopeInfo = "kiwi-ci secret-broker envelope v1"

// SealEnvelope encrypts plain for the owner of the 32-byte X25519 public key
// peerPub. The returned delivery carries the ephemeral public key and nonce
// required to open it. aad is additional authenticated data bound into the
// AEAD seal: opening with a different aad fails, so a delivery cannot be
// replayed in a different (runner, job, generation, secret) context.
func SealEnvelope(plain []byte, peerPub [32]byte, aad []byte) (EncryptedDelivery, error) {
	peer, err := ecdh.X25519().NewPublicKey(peerPub[:])
	if err != nil {
		return EncryptedDelivery{}, fmt.Errorf("seal: peer public key: %w", err)
	}
	eph, err := generateX25519Key()
	if err != nil {
		return EncryptedDelivery{}, fmt.Errorf("seal: ephemeral key: %w", err)
	}
	shared, err := eph.ECDH(peer)
	if err != nil {
		return EncryptedDelivery{}, fmt.Errorf("seal: ecdh: %w", err)
	}
	key := hkdfSHA256(shared, nil, []byte(envelopeInfo))
	block, err := aes.NewCipher(key)
	if err != nil {
		return EncryptedDelivery{}, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return EncryptedDelivery{}, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(randReader, nonce); err != nil {
		return EncryptedDelivery{}, fmt.Errorf("seal: nonce: %w", err)
	}
	return EncryptedDelivery{
		Ciphertext:      aead.Seal(nil, nonce, plain, aad),
		EphemeralPublic: eph.PublicKey().Bytes(),
		Nonce:           nonce,
	}, nil
}

// OpenEnvelope decrypts d using the recipient's 32-byte X25519 private key.
// aad must match the authenticated data SealEnvelope was called with.
func OpenEnvelope(d EncryptedDelivery, ownPriv [32]byte, aad []byte) ([]byte, error) {
	priv, err := ecdh.X25519().NewPrivateKey(ownPriv[:])
	if err != nil {
		return nil, fmt.Errorf("open: private key: %w", err)
	}
	eph, err := ecdh.X25519().NewPublicKey(d.EphemeralPublic)
	if err != nil {
		return nil, fmt.Errorf("open: ephemeral public key: %w", err)
	}
	shared, err := priv.ECDH(eph)
	if err != nil {
		return nil, fmt.Errorf("open: ecdh: %w", err)
	}
	key := hkdfSHA256(shared, nil, []byte(envelopeInfo))
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(d.Nonce) != aead.NonceSize() {
		return nil, fmt.Errorf("open: nonce length %d, want %d", len(d.Nonce), aead.NonceSize())
	}
	plain, err := aead.Open(nil, d.Nonce, d.Ciphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("open: %w", err)
	}
	return plain, nil
}

// hkdfSHA256 implements RFC 5869 HKDF with SHA-256, returning keyLen bytes.
// A nil salt is treated as a zero-filled salt of hash length.
func hkdfSHA256(secret, salt, info []byte) []byte {
	const hashLen = 32
	keyLen := hashLen
	if salt == nil {
		salt = make([]byte, hashLen)
	}
	prk := hmacSHA256(salt, secret)
	var out []byte
	var prev []byte
	for counter := byte(1); len(out) < keyLen; counter++ {
		mac := hmac.New(sha256.New, prk)
		mac.Write(prev)
		mac.Write(info)
		mac.Write([]byte{counter})
		prev = mac.Sum(nil)
		out = append(out, prev...)
	}
	return out[:keyLen]
}

func hmacSHA256(key, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}

// ChainBroker tries each broker in order and returns the first success.
type ChainBroker []Broker

func (c ChainBroker) Resolve(ctx context.Context, name string, scope SecretScope) (string, error) {
	var errs []error
	for _, b := range c {
		if b == nil {
			continue
		}
		v, err := b.Resolve(ctx, name, scope)
		if err == nil {
			return v, nil
		}
		errs = append(errs, err)
	}
	if len(errs) == 0 {
		return "", fmt.Errorf("secret %q not found: empty broker chain", name)
	}
	return "", fmt.Errorf("secret %q not found: %w", name, errors.Join(errs...))
}

// StaticBroker serves secrets from an in-memory map.
type StaticBroker map[string]string

func (s StaticBroker) Resolve(_ context.Context, name string, _ SecretScope) (string, error) {
	v, ok := s[name]
	if !ok {
		return "", fmt.Errorf("secret %q not found", name)
	}
	return v, nil
}
