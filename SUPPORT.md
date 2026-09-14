# Support

## Documentation

Start with [README.md](README.md) for a quick start, then:

- [docs/pipeline-reference.md](docs/pipeline-reference.md) — the pipeline
  language.
- [docs/production-deployment.md](docs/production-deployment.md) —
  deploying the server and runners.
- [ARCHITECTURE.md](ARCHITECTURE.md) — how the pieces fit together.
- [ROADMAP.md](ROADMAP.md) — what exists and what is planned.

## Getting help

- **GitHub issues**: https://github.com/Bel-Consulting-OU/kiwi-ci/issues
  for bugs and feature requests. Use the issue templates when available.
- **Discussions**: pending; use issues for now.

## Troubleshooting quick checks

```bash
kiwi doctor          # host capability check (git, docker, tart, shells)
kiwi validate -f .kiwi/pipeline.yaml   # pipeline parse/validation errors
kiwi explain --why <job> -f .kiwi/pipeline.yaml  # why a job would run
kiwi config check --config kiwi.toml   # server config problems
kiwi database status --database-url $DATABASE_URL  # schema state
```

The server exposes `GET /readiness` and `GET /liveness` for health checks
and `GET /metrics` for Prometheus scraping.

## Bug reports

Include:

- `kiwi version` output;
- the pipeline YAML (redacted) or a minimal reproduction;
- the command line and the exact error;
- for server issues: `kiwi.toml` keys (redact tokens), server mode
  (dev/production), and whether PostgreSQL is used.

## Security issues

Do not file security issues publicly. See [SECURITY.md](SECURITY.md) for
private reporting channels.

## Commercial support

Kiwi CI is maintained by Bel Consulting OU. No commercial support
offering exists yet; contact the maintainers through the repository if
you need it.
