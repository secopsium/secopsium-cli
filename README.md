# SecOpsium CLI

[![CI](https://github.com/secopsium/secopsium-cli/actions/workflows/ci.yml/badge.svg)](https://github.com/secopsium/secopsium-cli/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/secopsium/secopsium-cli)](https://github.com/secopsium/secopsium-cli/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](./LICENSE)

SecOpsium CLI is an open-source, local-first security scanner for repositories.

Works on Windows, macOS, and Linux with no manual setup.

Download the matching binary from GitHub Releases, run `secopsium setup`, and start scanning.

## What It Does

- Detects exposed secrets with Gitleaks
- Finds configuration risks with Semgrep
- Runs lightweight JavaScript exposure checks
- Unifies findings across scanners into one consistent output format
- Supports human-readable and JSON output
- Redacts sensitive matches by default
- Supports local paths and remote Git repositories
- Includes ignore-file support, deduplication, and CI-friendly exit codes

## Quick Start

1. Download the binary for your OS and architecture from GitHub Releases.
2. Run `secopsium version` to confirm the binary you installed.
3. Run `secopsium setup` to install managed copies of scanner tools.
4. Run `secopsium scan .`

## Commands

```bash
# Show version/build metadata
secopsium version

# Local scan
secopsium scan .

# Auto-install missing tools during scan
secopsium scan . --install-missing --yes

# Raise the JS/TS scan size limit for large bundles
secopsium scan . --js-max-file-size-mb 10

# Scan a remote git repo
secopsium scan --repo https://github.com/org/repo.git

# Install managed scanner tools up front
secopsium setup

# Inspect scanner tool health
secopsium doctor

# Strict CI mode
secopsium scan . --strict --fail-on-findings

# Clone a specific branch with a shorter clone timeout
secopsium scan --repo https://github.com/org/repo.git --ref main --clone-timeout 30s

# One-off JSON output
secopsium scan . --json

# Show raw evidence only when you explicitly opt in
secopsium scan . --unsafe-raw-output

# Persist default output to JSON
secopsium output --json

# Persist default output to human format
secopsium output --human

# Initialize ignore file
secopsium ignore init

# Add patterns to ignore file
secopsium ignore add "src/generated/**" "**/*.snap"

# List effective ignore patterns
secopsium ignore list
```

## Example Output

```text
[Secrets] 3 findings
[Config Risks] 2 findings
[JS Exposure] 1 findings

[Summary]
  Total Findings: 6
  Secrets: 3
  Config Risks: 2
  JS Exposure: 1

Want fewer false positives and prioritized results?
Try the full platform: https://secopsium.com
```

## Install

SecOpsium CLI is distributed as OS-specific binaries through GitHub Releases.

After downloading the correct binary for your platform:
- run `secopsium version`
- run `secopsium setup`
- run `secopsium scan .`

The CLI auto-detects `gitleaks` and `semgrep`. If they are missing, `secopsium setup` installs managed copies into your user cache. You can also let `secopsium scan --install-missing --yes` install them on demand.

Managed installs do not require admin privileges.

JavaScript and TypeScript files over 3 MB are skipped by default to keep scans fast. Use `--js-max-file-size-mb` if you want to include larger bundles or generated frontend assets.

## Build From Source

Requirements:
- Go 1.25+

Build for your current OS:

```bash
go build -o bin/secopsium ./cmd/secopsium
```

Cross-compile examples:

```bash
# Linux
GOOS=linux GOARCH=amd64 go build -o dist/secopsium-linux-amd64 ./cmd/secopsium

# macOS Intel
GOOS=darwin GOARCH=amd64 go build -o dist/secopsium-darwin-amd64 ./cmd/secopsium

# macOS Apple Silicon
GOOS=darwin GOARCH=arm64 go build -o dist/secopsium-darwin-arm64 ./cmd/secopsium

# Windows
GOOS=windows GOARCH=amd64 go build -o dist/secopsium-windows-amd64.exe ./cmd/secopsium
```

## Releases

This repository includes [`.goreleaser.yml`](./.goreleaser.yml) and GitHub Actions workflows for:
- CI on Windows, macOS, and Linux
- tagged releases with OS-specific binaries
- dependency update tracking through Dependabot

To build release artifacts locally:

```bash
goreleaser release --snapshot --clean
```

## Why Go

Go keeps the CLI easy to distribute and fast to run:
- single binaries for Windows, macOS, and Linux
- fast filesystem scanning
- reliable subprocess and timeout handling
- straightforward CI/CD packaging

## Project Layout

```text
secopsium-cli/
  cmd/secopsium/   # CLI entrypoint and commands
  internal/        # config, runner, formatting, tooling, repo logic
  scanner/         # scanner integrations and lightweight checks
  .github/         # CI, releases, and dependency automation
```

## Contributing And Security

See [CONTRIBUTING.md](./CONTRIBUTING.md) for development guidelines and [SECURITY.md](./SECURITY.md) for vulnerability reporting.
