package runnerpki

import (
	"crypto/ed25519"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"net/url"
)

// GenerateKeyAndCSR mints a fresh Ed25519 key pair and a certificate request
// with CN=runnerID and the spiffe://kiwi/runner/<id> URI SAN. The private key
// is returned as PKCS8 PEM.
func GenerateKeyAndCSR(runnerID string) (privPEM, csrPEM []byte, err error) {
	if runnerID == "" {
		return nil, nil, fmt.Errorf("runner id is required")
	}
	_, priv, err := ed25519.GenerateKey(randomReader())
	if err != nil {
		return nil, nil, err
	}
	uri := &url.URL{Scheme: "spiffe", Host: "kiwi", Path: "/runner/" + runnerID}
	tmpl := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: runnerID},
		URIs:    []*url.URL{uri},
	}
	der, err := x509.CreateCertificateRequest(randomReader(), tmpl, priv)
	if err != nil {
		return nil, nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, nil, err
	}
	privPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	csrPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
	return privPEM, csrPEM, nil
}
