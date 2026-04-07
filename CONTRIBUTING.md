# Contributing

Thanks for helping improve SecOpsium CLI.

## Development Setup

Requirements:
- Go 1.24+

Useful commands:

```bash
go test ./...
go build ./cmd/secopsium
```

## Project Boundaries

This repository is intentionally open and transparent. Please keep contributions within scope:
- scanner integrations using public tools and public rules
- local-first CLI UX
- filtering, formatting, deduplication, and performance improvements
- managed installation, packaging, and cross-platform reliability

Please keep the CLI:
- local-first
- transparent in how findings are produced
- useful without requiring a hosted platform to function
- easy to review, maintain, and extend in the open

## Pull Requests

Before opening a pull request:
- run `go test ./...`
- make sure the CLI still builds with `go build ./cmd/secopsium`
- keep changes targeted and easy to review
- update `README.md` when behavior or flags change

## Reporting Bugs

Open an issue with:
- your OS and architecture
- Go version, if building from source
- the command you ran
- the relevant output or error message

For security-sensitive reports, follow the guidance in [`SECURITY.md`](./SECURITY.md).
