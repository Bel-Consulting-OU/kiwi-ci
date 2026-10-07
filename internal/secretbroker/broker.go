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
	// Repository is the CANONICAL authorization identity of the repository
	// whose policy governs the job (storage.RepoIDForJob), never the clone
	// transport URL: a fork PR may check out a different repository than the
	// one whose policy and secrets apply.
	Repository string
	// CheckoutRepositoryURL is the transport coordinate actually cloned. It
	// exists so a scope-aware broker that needs the checkout location can
	// read it WITHOUT overloading the authorization identity above; the
	// built-in cloud brokers ignore both.
	CheckoutRepositoryURL string
	Environment           string
	Trusted               bool
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

// ChainBroker tries each broker in order and returns the first success. A
// broker failure stops the chain unless its error class is listed in
// FallbackOn: authorization, policy and malformed-response failures ALWAYS
// fail closed, and a canceled context stops the chain immediately.
//
// Brokers holds the chain in resolution order; a nil entry is skipped.
// FallbackOn lists the error classes that permit advancing to the next
// broker. A nil policy means DefaultFallbackOn ([not_found]); a non-nil
// empty policy means no class permits advancing. Only "not_found" and
// "unavailable" are valid entries; ParseFallbackOn enforces that.
//
// Exhaustion semantics: when every consulted broker fails with a
// fallback-allowed class, Resolve returns a classified aggregate whose class
// is the highest-precedence class encountered, per the declared lattice in
// errors.go (forbidden == unauthorized > malformed > unavailable >
// not_found). All-unavailable therefore yields ErrUnavailable, never
// ErrSecretNotFound, and not_found+unavailable yields ErrUnavailable; only an
// all-not-found exhaustion keeps ErrSecretNotFound. The aggregate retains
// every per-broker cause, so errors.Is still matches each encountered class
// and each underlying cause, while ErrorClass reports the winning class for
// telemetry. An unclassified error is never fallback-able: it stops the chain
// and is returned as-is. An empty chain (or one with only nil entries) yields
// ErrSecretNotFound.
type ChainBroker struct {
	Brokers    []Broker
	FallbackOn []string
}

// fallbackAllowed reports whether the class of err is listed in the chain's
// policy. An unclassified error is never fallback-able.
func (c ChainBroker) fallbackAllowed(err error) bool {
	policy := c.FallbackOn
	if policy == nil {
		policy = DefaultFallbackOn
	}
	class := ErrorClass(err)
	if class == "" || class == ClassUnknown {
		return false
	}
	for _, allowed := range policy {
		if allowed == class {
			return true
		}
	}
	return false
}

func (c ChainBroker) Resolve(ctx context.Context, name string, scope SecretScope) (string, error) {
	if isContextDone(ctx) {
		// A canceled or expired context must never trigger a broker call or
		// a fallback: classify it Unavailable and preserve the ctx error.
		return "", cancellationErr("chain", fmt.Sprintf("secret %q: resolution canceled before any broker was consulted", name), ctx.Err())
	}
	var errs []error
	consulted := 0
	for _, b := range c.Brokers {
		if b == nil {
			continue
		}
		consulted++
		v, err := b.Resolve(ctx, name, scope)
		if err == nil {
			return v, nil
		}
		errs = append(errs, err)
		if isContextDone(ctx) {
			// Cancellation/deadline: the ctx error is authoritative and no
			// later broker may be consulted.
			return "", cancellationErr("chain",
				fmt.Sprintf("secret %q: broker %q: resolution canceled (class %s, never falling back)", name, brokerName(b), ErrorClass(err)), err)
		}
		if !c.fallbackAllowed(err) {
			// Fail closed: the authoritative broker's error wins and the
			// chain annotates the class that stopped it.
			return "", fmt.Errorf("secret %q: chain stopped at broker %s (class %s is not in fallback_on): %w",
				name, brokerName(b), ErrorClass(err), err)
		}
	}
	if consulted == 0 {
		return "", classError("chain", ErrSecretNotFound, fmt.Sprintf("secret %q not found: empty broker chain", name), nil)
	}
	winner := terminalClass(errs)
	if winner == nil {
		// Defensive: fallbackAllowed only advances on classified errors, so
		// every encountered failure carries a class. If that invariant ever
		// breaks, fail closed as not-found rather than invent a class.
		winner = ErrSecretNotFound
	}
	return "", classError("chain", winner,
		fmt.Sprintf("secret %q: chain exhausted %d broker(s), terminal class %s", name, consulted, ErrorClass(winner)),
		errors.Join(errs...))
}

// brokerName names a chain broker for diagnostics. The Broker interface has
// no name method so that third-party wrappers stay unimplementable-safe;
// known providers are recognized by type and anything else falls back to its
// Go type.
func brokerName(b Broker) string {
	switch b.(type) {
	case *VaultClient:
		return "vault"
	case *SecretsManagerClient:
		return "aws"
	case *GCPClient:
		return "gcp"
	case *AzureClient:
		return "azure"
	case *OnePasswordClient:
		return "onepassword"
	case StaticBroker:
		return "static"
	case *OneTime:
		return "onetime"
	case ChainBroker:
		return "chain"
	default:
		return fmt.Sprintf("%T", b)
	}
}

// StaticBroker serves secrets from an in-memory map. A missing key is the
// NotFound class: it is the only failure the static broker can produce, and
// the only class a chain falls through on by default.
type StaticBroker map[string]string

func (s StaticBroker) Resolve(_ context.Context, name string, _ SecretScope) (string, error) {
	v, ok := s[name]
	if !ok {
		return "", classError("static", ErrSecretNotFound, fmt.Sprintf("secret %q not found", name), nil)
	}
	return v, nil
}
