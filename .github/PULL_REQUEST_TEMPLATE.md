## Summary

What does this change do and why?

## Checklist

- [ ] Tests pass: `go test ./...`
- [ ] Build passes: `go build ./...`
- [ ] Vet passes: `go vet ./...`
- [ ] Code is formatted: `gofmt -l .` prints nothing
- [ ] Documentation updated where behavior changed (docs/ files,
      README.md, ARCHITECTURE.md, ROADMAP.md as applicable)
- [ ] `FILE_MAP.md` regenerated with `go run ./cmd/filemap` when Go files
      were added or removed
- [ ] No new third-party dependencies without justification in the
      description
- [ ] Security-sensitive changes keep deny-by-default policy and add
      regression tests
