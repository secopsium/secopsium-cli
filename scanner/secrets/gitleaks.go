package secrets

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/secopsium/secopsium-cli/internal/model"
	"github.com/secopsium/secopsium-cli/scanner"
)

const gitleaksTool = "gitleaks"

type Scanner struct{}

func New() *Scanner {
	return &Scanner{}
}

func (s *Scanner) Name() string {
	return "gitleaks"
}

func (s *Scanner) Category() model.Category {
	return model.CategorySecret
}

type gitleaksFinding struct {
	Description string  `json:"Description"`
	File        string  `json:"File"`
	StartLine   int     `json:"StartLine"`
	StartColumn int     `json:"StartColumn"`
	RuleID      string  `json:"RuleID"`
	Match       string  `json:"Match"`
	Entropy     float64 `json:"Entropy"`
	Fingerprint string  `json:"Fingerprint"`
}

func (s *Scanner) Scan(ctx context.Context, req scanner.Request) ([]model.Finding, error) {
	if _, err := exec.LookPath(gitleaksTool); err != nil {
		return nil, &scanner.ToolUnavailableError{Tool: gitleaksTool, Err: err}
	}

	reportFile, err := os.CreateTemp("", "secopsium-gitleaks-*.json")
	if err != nil {
		return nil, fmt.Errorf("create gitleaks report file: %w", err)
	}
	reportPath := reportFile.Name()
	_ = reportFile.Close()
	defer os.Remove(reportPath)

	args := []string{
		"detect",
		"--source", req.Root,
		"--no-git",
		"--report-format", "json",
		"--report-path", reportPath,
		"--exit-code", "0",
	}
	if !req.UnsafeRawOutput {
		args = append(args, "--redact")
	}

	cmd := exec.CommandContext(ctx, gitleaksTool, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("gitleaks timed out: %w", ctx.Err())
		}
		return nil, fmt.Errorf("gitleaks execution failed: %s", strings.TrimSpace(stderr.String()))
	}

	data, err := os.ReadFile(reportPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("read gitleaks report: %w", err)
	}

	data = bytes.TrimSpace(data)
	if len(data) == 0 {
		return nil, nil
	}

	rawFindings := []gitleaksFinding{}
	if err := json.Unmarshal(data, &rawFindings); err != nil {
		return nil, fmt.Errorf("parse gitleaks json: %w", err)
	}

	findings := make([]model.Finding, 0, len(rawFindings))
	for _, item := range rawFindings {
		relFile := toRelative(req.Root, item.File)
		if req.Ignore != nil && req.Ignore.ShouldIgnore(relFile) {
			continue
		}

		title := item.Description
		if strings.TrimSpace(title) == "" {
			title = "Potential secret exposed"
		}

		evidence := redactEvidence(item.Match)
		finding := model.Finding{
			Category:    model.CategorySecret,
			Scanner:     s.Name(),
			RuleID:      item.RuleID,
			Severity:    model.SeverityHigh,
			Title:       title,
			Description: "Detected by gitleaks using public secret-detection signatures.",
			File:        model.NormalizePath(relFile),
			Line:        item.StartLine,
			Column:      item.StartColumn,
			Evidence:    evidence,
			Fingerprint: strings.TrimSpace(item.Fingerprint),
		}
		if finding.Fingerprint == "" {
			finding.Fingerprint = model.GenerateFindingID(finding)
		}
		finding.ID = model.GenerateFindingID(finding)
		findings = append(findings, finding)
	}

	return findings, nil
}

func toRelative(root string, candidate string) string {
	if strings.TrimSpace(candidate) == "" {
		return candidate
	}

	candidate = filepath.Clean(candidate)
	if !filepath.IsAbs(candidate) {
		return candidate
	}

	rel, err := filepath.Rel(root, candidate)
	if err != nil {
		return candidate
	}
	return rel
}

func redactEvidence(value string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return ""
	}
	if len(trimmed) <= 8 {
		return "********"
	}
	return trimmed[:4] + strings.Repeat("*", len(trimmed)-8) + trimmed[len(trimmed)-4:]
}
