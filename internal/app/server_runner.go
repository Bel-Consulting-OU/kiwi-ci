package app

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/kiwici/kiwi/internal/runner"
	"github.com/kiwici/kiwi/internal/server"
)

func Server(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("server", flag.ContinueOnError)
	listen := fs.String("listen", ":8080", "listen address")
	token := fs.String("runner-token", os.Getenv("KIWI_RUNNER_TOKEN"), "runner/API bearer token")
	adminToken := fs.String("admin-token", os.Getenv("KIWI_ADMIN_TOKEN"), "admin bearer token (defaults to runner token)")
	webhookSecret := fs.String("github-webhook-secret", os.Getenv("KIWI_GITHUB_WEBHOOK_SECRET"), "GitHub webhook HMAC secret")
	githubToken := fs.String("github-token", os.Getenv("KIWI_GITHUB_TOKEN"), "GitHub token for private pipeline fetches")
	pipelinePath := fs.String("pipeline-path", ".kiwi/pipeline.yaml", "pipeline path in repositories")
	dataDir := fs.String("data-dir", "", "persistent state directory (default: in-memory; production deployments should always set this)")
	externalURL := fs.String("external-url", os.Getenv("KIWI_EXTERNAL_URL"), "public base URL (required for OIDC)")
	tlsCert := fs.String("tls-cert", "", "TLS certificate file (enables HTTPS)")
	tlsKey := fs.String("tls-key", "", "TLS private key file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *tlsCert == "" && *tlsKey != "" {
		return fmt.Errorf("--tls-key requires --tls-cert")
	}
	if *tlsCert != "" && *tlsKey == "" {
		return fmt.Errorf("--tls-cert requires --tls-key")
	}
	var srv *server.Server
	var err error
	if *dataDir != "" {
		srv, err = server.NewPersistent(*token, *adminToken, *dataDir)
		if err != nil {
			return err
		}
	} else {
		srv = server.New(*token)
		if *adminToken != "" {
			srv.AdminToken = *adminToken
		}
	}
	srv.GitHubWebhookSecret = *webhookSecret
	srv.GitHubToken = *githubToken
	srv.PipelinePath = *pipelinePath
	srv.ExternalURL = *externalURL
	h := &http.Server{
		Addr:              *listen,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       90 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}
	go srv.Maintain(ctx)
	go func() {
		<-ctx.Done()
		c, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = h.Shutdown(c)
	}()
	scheme := "http"
	if *tlsCert != "" {
		scheme = "https"
	}
	fmt.Printf("Kiwi server listening on %s://%s\n", scheme, *listen)
	var serveErr error
	if *tlsCert != "" {
		serveErr = h.ListenAndServeTLS(*tlsCert, *tlsKey)
	} else {
		serveErr = h.ListenAndServe()
	}
	if serveErr == http.ErrServerClosed {
		return nil
	}
	return serveErr
}
func Runner(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("runner", flag.ContinueOnError)
	url := fs.String("server", "http://127.0.0.1:8080", "Kiwi server URL")
	token := fs.String("token", os.Getenv("KIWI_RUNNER_TOKEN"), "runner token")
	name := fs.String("name", "", "runner name")
	labels := fs.String("labels", "", "comma-separated labels")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg := runner.Config{Server: strings.TrimRight(*url, "/"), Token: *token, Name: *name}
	if *labels != "" {
		cfg.Labels = strings.Split(*labels, ",")
	}
	return (&runner.Runner{Cfg: cfg}).Run(ctx)
}
