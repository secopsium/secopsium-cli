package js

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/secopsium/secopsium-cli/internal/model"
	"github.com/secopsium/secopsium-cli/scanner"
)

const DefaultMaxFileSizeBytes int64 = 3 * 1024 * 1024 // 3MB

var jsExtensions = map[string]bool{
	".js":  true,
	".jsx": true,
	".mjs": true,
	".cjs": true,
	".ts":  true,
	".tsx": true,
}

type jsRule struct {
	ID          string
	Title       string
	Description string
	Severity    model.Severity
	Regex       *regexp.Regexp
}

var rules = []jsRule{
	{
		ID:          "secopsium-js-hardcoded-token",
		Title:       "Potential hardcoded API token in JavaScript",
		Description: "A token-like value appears hardcoded in JS/TS source.",
		Severity:    model.SeverityHigh,
		Regex:       regexp.MustCompile(`(?i)(api[_-]?key|secret|token)\s*[:=]\s*["'][A-Za-z0-9_\-\.=]{16,}["']`),
	},
	{
		ID:          "secopsium-js-bearer-token",
		Title:       "Bearer token literal found in JavaScript",
		Description: "A bearer token string is present in source or bundle output.",
		Severity:    model.SeverityHigh,
		Regex:       regexp.MustCompile(`(?i)bearer\s+[A-Za-z0-9_\-\.=]{20,}`),
	},
	{
		ID:          "secopsium-js-private-key-block",
		Title:       "Private key material found in JavaScript",
		Description: "Private key block markers were found in JS/TS code.",
		Severity:    model.SeverityCritical,
		Regex:       regexp.MustCompile(`-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----`),
	},
	{
		ID:          "secopsium-js-sensitive-localstorage",
		Title:       "Sensitive token stored in localStorage/sessionStorage",
		Description: "Persistent browser storage can expose auth artifacts to XSS.",
		Severity:    model.SeverityMedium,
		Regex:       regexp.MustCompile(`(?i)(localStorage|sessionStorage)\.setItem\(\s*['"](token|auth|session|secret)['"]`),
	},
	{
		ID:          "secopsium-js-debug-flag-enabled",
		Title:       "Debug mode enabled in JavaScript configuration",
		Description: "Debug/verbose flags in shipped frontend code can leak internals.",
		Severity:    model.SeverityLow,
		Regex:       regexp.MustCompile(`(?i)(debug|verbose|devtools)\s*[:=]\s*true`),
	},
}

type Scanner struct{}

func New() *Scanner {
	return &Scanner{}
}

func (s *Scanner) Name() string {
	return "js-static"
}

func (s *Scanner) Category() model.Category {
	return model.CategoryJS
}

func (s *Scanner) Scan(ctx context.Context, req scanner.Request) ([]model.Finding, error) {
	findings := make([]model.Finding, 0, 32)
	maxFileSize := req.JSMaxFileSizeBytes
	if maxFileSize <= 0 {
		maxFileSize = DefaultMaxFileSizeBytes
	}

	err := filepath.WalkDir(req.Root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}

		rel, err := filepath.Rel(req.Root, path)
		if err != nil {
			return err
		}
		rel = model.NormalizePath(rel)

		if req.Ignore != nil && req.Ignore.ShouldIgnore(rel) {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		if d.IsDir() {
			return nil
		}

		ext := strings.ToLower(filepath.Ext(d.Name()))
		if !jsExtensions[ext] {
			return nil
		}

		info, err := d.Info()
		if err != nil {
			return err
		}
		if info.Size() > maxFileSize {
			req.ReportWarning(model.ScannerWarning{
				Kind:    model.WarningKindScanLimit,
				Scanner: s.Name(),
				Message: fmt.Sprintf("skipped %s (%s > %s limit); raise --js-max-file-size-mb to scan larger JS bundles", rel, humanSize(info.Size()), humanSize(maxFileSize)),
			})
			return nil
		}

		fileFindings, err := scanJSFile(path, rel)
		if err != nil {
			return fmt.Errorf("scan %s: %w", rel, err)
		}
		findings = append(findings, fileFindings...)
		return nil
	})
	if err != nil {
		return nil, err
	}

	return findings, nil
}

func scanJSFile(fullPath string, relPath string) ([]model.Finding, error) {
	file, err := os.Open(fullPath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	reader := bufio.NewReader(file)
	lineNumber := 0
	findings := []model.Finding{}
	seen := map[string]struct{}{}

	for {
		line, err := reader.ReadString('\n')
		lineNumber++
		trimmed := strings.TrimSpace(line)

		for _, rule := range rules {
			match := rule.Regex.FindString(trimmed)
			if match == "" {
				continue
			}

			dedupeKey := fmt.Sprintf("%s|%d|%s|%s", relPath, lineNumber, rule.ID, match)
			if _, exists := seen[dedupeKey]; exists {
				continue
			}
			seen[dedupeKey] = struct{}{}

			finding := model.Finding{
				Category:    model.CategoryJS,
				Scanner:     "js-static",
				RuleID:      rule.ID,
				Severity:    rule.Severity,
				Title:       rule.Title,
				Description: rule.Description,
				File:        model.NormalizePath(relPath),
				Line:        lineNumber,
				Evidence:    compactEvidence(match),
			}
			finding.Fingerprint = model.GenerateFindingID(finding)
			finding.ID = model.GenerateFindingID(finding)
			findings = append(findings, finding)
		}

		if err != nil {
			if err == io.EOF {
				break
			}
			return findings, err
		}
	}

	return findings, nil
}

func compactEvidence(value string) string {
	cleaned := strings.Join(strings.Fields(strings.TrimSpace(value)), " ")
	if len(cleaned) > 160 {
		return cleaned[:157] + "..."
	}
	return cleaned
}

func humanSize(size int64) string {
	const mb = 1024 * 1024
	if size < mb {
		return fmt.Sprintf("%d KB", size/1024)
	}
	return fmt.Sprintf("%.1f MB", float64(size)/float64(mb))
}
