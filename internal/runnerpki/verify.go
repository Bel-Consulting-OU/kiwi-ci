package runnerpki

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// Pool builds a certificate pool from PEM-encoded certificates.
func Pool(certPEM []byte) *x509.CertPool {
	pool := x509.NewCertPool()
	if len(certPEM) > 0 {
		pool.AppendCertsFromPEM(certPEM)
	}
	return pool
}

// TLSClientConfig builds a client TLS configuration that verifies the server
// against caPEM and presents the certPEM/keyPEM client certificate when one
// is provided.
func TLSClientConfig(certPEM, keyPEM, caPEM []byte, serverName string) (*tls.Config, error) {
	cfg := &tls.Config{MinVersion: tls.VersionTLS13, ServerName: serverName}
	if len(caPEM) > 0 {
		cfg.RootCAs = Pool(caPEM)
	}
	if len(certPEM) > 0 || len(keyPEM) > 0 {
		cert, err := tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			return nil, fmt.Errorf("load client certificate: %w", err)
		}
		cfg.Certificates = []tls.Certificate{cert}
	}
	return cfg, nil
}

// TLSServerConfig builds a server TLS configuration from the server's own
// certificate/key pair. When a runner CA is given, client certificates are
// verified against it: requireClientCert rejects certificate-less connections
// at the handshake, otherwise presented certificates are verified and the
// application layer enforces the identity binding (so enrollment stays
// reachable before a runner holds a certificate).
func TLSServerConfig(certPEM, keyPEM []byte, ca *CA, requireClientCert bool) (*tls.Config, error) {
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("load server certificate: %w", err)
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}}
	if ca == nil || ca.Cert == nil {
		if requireClientCert {
			return nil, fmt.Errorf("runner CA required to verify client certificates")
		}
		return cfg, nil
	}
	cfg.ClientCAs = Pool(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Cert.Raw}))
	if requireClientCert {
		cfg.ClientAuth = tls.RequireAndVerifyClientCert
	} else {
		cfg.ClientAuth = tls.VerifyClientCertIfGiven
	}
	return cfg, nil
}
