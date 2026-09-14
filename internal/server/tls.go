package server

import (
	"crypto/tls"
	"fmt"
)

// TLSConfig builds the HTTPS listener configuration from the server's own
// certificate/key pair and the runner client CA trust settings. TLS 1.2 is
// the minimum version (TLS 1.3 is preferred by the handshake). When
// RequireRunnerClientCerts is set without a pool the configuration is
// rejected rather than silently requiring an empty trust set.
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
		if s.RequireRunnerClientCerts {
			cfg.ClientAuth = tls.RequireAndVerifyClientCert
		} else {
			cfg.ClientAuth = tls.VerifyClientCertIfGiven
		}
		return cfg, nil
	}
	if s.RequireRunnerClientCerts {
		return nil, fmt.Errorf("server: RequireRunnerClientCerts requires RunnerClientCAPool")
	}
	return cfg, nil
}
