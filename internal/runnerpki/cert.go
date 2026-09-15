package runnerpki

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"
)

// ParseCertPEM parses the first CERTIFICATE block of certPEM into an X.509
// certificate.
func ParseCertPEM(certPEM []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("invalid certificate PEM")
	}
	return x509.ParseCertificate(block.Bytes)
}

// CertValidFor reports whether certPEM parses as a certificate that stays
// valid for at least minRemaining: unparsable PEM, missing certificates and
// certificates nearer to expiry than minRemaining are all reported as not
// valid. A certificate that is not yet valid is also not valid.
func CertValidFor(certPEM []byte, minRemaining time.Duration) bool {
	cert, err := ParseCertPEM(certPEM)
	if err != nil {
		return false
	}
	now := time.Now()
	return now.After(cert.NotBefore) && now.Add(minRemaining).Before(cert.NotAfter)
}
