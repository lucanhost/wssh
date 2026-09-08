# Contributing

## Development

Requires Go 1.26+.

```bash
git clone https://github.com/lucanhost/wssh.git
cd wssh
make ci  # vet + test + vulncheck
```

## Code style

- Conventional commits (`feat:`, `fix:`, `test:`, `docs:`, `chore:`)
- All exported symbols documented with godoc comments
- Internal comments minimal — only for non-obvious logic
- All tests pass with `go test ./... -race -count=1`

## Pull requests

- Squash to a single commit per logical change
- Update tests for any behavior change
- Keep PRs focused (one concern per PR)
