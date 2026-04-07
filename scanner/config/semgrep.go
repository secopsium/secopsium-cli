package config

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/secopsium/secopsium-cli/internal/model"
	"github.com/secopsium/secopsium-cli/scanner"
)

const semgrepTool = "semgrep"

//go:embed rules/config-risks.yaml
var semgrepRules []byte

type Scanner struct{}

func New() *Scanner {
	return &Scanner{}
}

func (s *Scanner) Name() string {
	return "semgrep"
}

func (s *Scanner) Category() model.Category {
	return model.CategoryConfig
}

type semgrepJSON struct {
	Results []semgrepResult `json:"results"`
	Errors  []semgrepError  `json:"errors"`
}

type semgrepResult struct {
	CheckID string `json:"check_id"`
	Path    string `json:"path"`
	Start   struct {
		Line int `json:"line"`
		Col  int `json:"col"`
	} `json:"start"`
	Extra struct {
		Message     string `json:"message"`
		Severity    string `json:"severity"`
		Fingerprint string `json:"fingerprint"`
		Lines       string `json:"lines"`
	} `json:"extra"`
}

type semgrepError struct {
	Message string `json:"message"`
	Type    string `json:"type"`
}

func (s *Scanner) Scan(ctx context.Context, req scanner.Request) ([]model.Finding, error) {
	if _, err := exec.LookPath(semgrepTool); err != nil {
		return nil, &scanner.ToolUnavailableError{Tool: semgrepTool, Err: err}
	}

	rulesFile, err := os.CreateTemp("", "secopsium-semgrep-rules-*.yaml")
	if err != nil {
		return nil, fmt.Errorf("create semgrep rules file: %w", err)
	}
	rulesPath := rulesFile.Name()
	if _, err := rulesFile.Write(semgrepRules); err != nil {
		_ = rulesFile.Close()
		_ = os.Remove(rulesPath)
		return nil, fmt.Errorf("write semgrep rules file: %w", err)
	}
	_ = rulesFile.Close()
	defer os.Remove(rulesPath)

	args := []string{
		"--config", rulesPath,
		"--json",
		"--quiet",
	}
	for _, exclusion := range semgrepExcludes(req.Ignore) {
		args = append(args, "--exclude", exclusion)
	}
	args = append(args, req.Root)

	cmd := exec.CommandContext(ctx, semgrepTool, args...)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("semgrep timed out: %w", ctx.Err())
		}
		errText := strings.TrimSpace(stderr.String())
		if errText == "" {
			errText = strings.TrimSpace(stdout.String())
		}
		return nil, fmt.Errorf("semgrep execution failed: %s", errText)
	}

	payload := bytes.TrimSpace(stdout.Bytes())
	if len(payload) == 0 {
		return nil, nil
	}

	parsed := semgrepJSON{}
	if err := json.Unmarshal(payload, &parsed); err != nil {
		return nil, fmt.Errorf("parse semgrep json: %w", err)
	}

	findings := make([]model.Finding, 0, len(parsed.Results))
	for _, item := range parsed.Results {
		relFile := toRelative(req.Root, item.Path)
		if req.Ignore != nil && req.Ignore.ShouldIgnore(relFile) {
			continue
		}

		severity := mapSemgrepSeverity(item.Extra.Severity)
		title := strings.TrimSpace(item.Extra.Message)
		if title == "" {
			title = "Configuration risk detected"
		}

		finding := model.Finding{
			Category:    model.CategoryConfig,
			Scanner:     s.Name(),
			RuleID:      strings.TrimSpace(item.CheckID),
			Severity:    severity,
			Title:       title,
			Description: "Detected by Semgrep against local open config-risk rules.",
			File:        model.NormalizePath(relFile),
			Line:        item.Start.Line,
			Column:      item.Start.Col,
			Evidence:    compactLine(item.Extra.Lines),
			Fingerprint: strings.TrimSpace(item.Extra.Fingerprint),
		}
		if finding.Fingerprint == "" {
			finding.Fingerprint = model.GenerateFindingID(finding)
		}
		finding.ID = model.GenerateFindingID(finding)
		findings = append(findings, finding)
	}

	if warningMessage := semgrepWarningMessage(parsed.Errors); warningMessage != "" {
		if req.Strict {
			return findings, fmt.Errorf("semgrep reported partial scan errors: %s", warningMessage)
		}
		req.ReportWarning(model.ScannerWarning{
			Kind:    model.WarningKindScannerPartial,
			Scanner: s.Name(),
			Message: warningMessage,
		})
	}

	return findings, nil
}

func semgrepExcludes(matcher scanner.PathMatcher) []string {
	if matcher == nil {
		return nil
	}
	seen := map[string]struct{}{}
	out := []string{}
	for _, raw := range matcher.Patterns() {
		pattern := strings.TrimSpace(strings.ReplaceAll(raw, "\\", "/"))
		if pattern == "" {
			continue
		}
		// Semgrep already recursively evaluates globs, so collapse directory
		// style patterns to stable --exclude values.
		pattern = strings.TrimSuffix(pattern, "/**")
		if pattern == "" {
			continue
		}
		if _, ok := seen[pattern]; ok {
			continue
		}
		seen[pattern] = struct{}{}
		out = append(out, pattern)
	}
	return out
}

func compactLine(value string) string {
	line := strings.TrimSpace(value)
	if line == "" {
		return ""
	}
	line = strings.ReplaceAll(line, "\n", " ")
	line = strings.Join(strings.Fields(line), " ")
	if len(line) > 180 {
		return line[:177] + "..."
	}
	return line
}

func semgrepWarningMessage(errors []semgrepError) string {
	if len(errors) == 0 {
		return ""
	}

	parts := make([]string, 0, len(errors))
	seen := make(map[string]struct{}, len(errors))
	for _, item := range errors {
		message := strings.TrimSpace(item.Message)
		errorType := strings.TrimSpace(item.Type)
		if message == "" && errorType == "" {
			continue
		}

		part := message
		if errorType != "" && message != "" {
			part = errorType + ": " + message
		} else if errorType != "" {
			part = errorType
		}

		if _, exists := seen[part]; exists {
			continue
		}
		seen[part] = struct{}{}
		parts = append(parts, part)
	}

	return strings.Join(parts, "; ")
}

func mapSemgrepSeverity(raw string) model.Severity {
	switch strings.ToUpper(strings.TrimSpace(raw)) {
	case "ERROR":
		return model.SeverityHigh
	case "WARNING":
		return model.SeverityMedium
	case "INFO":
		return model.SeverityLow
	default:
		return model.SeverityInfo
	}
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
