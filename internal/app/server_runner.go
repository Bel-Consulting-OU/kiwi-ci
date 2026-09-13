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
	webhookSecret := fs.String("github-webhook-secret", os.Getenv("KIWI_GITHUB_WEBHOOK_SECRET"), "GitHub webhook HMAC secret")
	githubToken := fs.String("github-token", os.Getenv("KIWI_GITHUB_TOKEN"), "GitHub token for private pipeline fetches")
	pipelinePath := fs.String("pipeline-path", ".kiwi/pipeline.yaml", "pipeline path in repositories")
	if err := fs.Parse(args); err != nil {
		return err
	}
	srv := server.New(*token)
	srv.GitHubWebhookSecret = *webhookSecret
	srv.GitHubToken = *githubToken
	srv.PipelinePath = *pipelinePath
	h := &http.Server{Addr: *listen, Handler: srv.Handler(), ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		c, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = h.Shutdown(c)
	}()
	fmt.Println("Kiwi server listening on", *listen)
	err := h.ListenAndServe()
	if err == http.ErrServerClosed {
		return nil
	}
	return err
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
