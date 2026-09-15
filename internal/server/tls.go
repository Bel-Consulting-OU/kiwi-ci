package server

import (
	"crypto/tls"
	"fmt"
)

// TLSConfig builds the HTTPS listener configuration from the server's own
// certificate/key pair and the runner client CA trust settings. TLS 1.2 is
// the minimum version (TLS 1.3 is preferred by the handshake).
//
// The listener is SHARED by admin, forge, dashboard and runner traffic, so
// when a runner client CA pool is configured the handshake always uses
// VerifyClientCertIfGiven: certificate-less clients (webhooks, dashboards,
// enrollment) must still reach the listener. The mandatory-certificate
// requirement for runner-tier routes is enforced at the HTTP authorization
// layer (auth()'s tierRunner branch), which also keeps enrollment exempt.
func (s *Server) TLSConfig(certFile, keyFile string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load server certificate: %w", err)
	}
	cfg := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},
	}
	pool := s.RunnerClientCAPool
	if pool != nil {
		cfg.ClientCAs = pool
		cfg.ClientAuth = tls.VerifyClientCertIfGiven
		return cfg, nil
	}
	if s.RequireRunnerClientCerts {
		return nil, fmt.Errorf("server: RequireRunnerClientCerts requires RunnerClientCAPool")
	}
	return cfg, nil
}
