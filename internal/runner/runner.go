package runner

import (
	"context"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/secopsium/secopsium-cli/internal/buildinfo"
	"github.com/secopsium/secopsium-cli/internal/model"
	"github.com/secopsium/secopsium-cli/scanner"
)

type Runner struct {
	scanners          []scanner.Scanner
	timeoutPerScanner time.Duration
}

type Request struct {
	TargetPath         string
	DisplayTarget      string
	Ignore             scanner.PathMatcher
	UnsafeRawOutput    bool
	Strict             bool
	JSMaxFileSizeBytes int64
}

func New(scanners []scanner.Scanner, timeoutPerScanner time.Duration) *Runner {
	if timeoutPerScanner <= 0 {
		timeoutPerScanner = 2 * time.Minute
	}
	return &Runner{
		scanners:          scanners,
		timeoutPerScanner: timeoutPerScanner,
	}
}

func (r *Runner) Run(ctx context.Context, req Request) (model.ScanResult, error) {
	startedAt := time.Now().UTC()
	absTarget, err := filepath.Abs(req.TargetPath)
	if err != nil {
		return model.ScanResult{}, err
	}

	type scannerOutcome struct {
		name     string
		findings []model.Finding
		warnings []model.ScannerWarning
		err      error
	}

	outcomes := make(chan scannerOutcome, len(r.scanners))
	var wg sync.WaitGroup
	for _, impl := range r.scanners {
		sc := impl
		wg.Add(1)
		go func() {
			defer wg.Done()
			scanCtx, cancel := context.WithTimeout(ctx, r.timeoutPerScanner)
			defer cancel()

			scannerWarnings := make([]model.ScannerWarning, 0, 2)
			findings, scanErr := sc.Scan(scanCtx, scanner.Request{
				Root:               absTarget,
				Ignore:             req.Ignore,
				UnsafeRawOutput:    req.UnsafeRawOutput,
				Strict:             req.Strict,
				JSMaxFileSizeBytes: req.JSMaxFileSizeBytes,
				Warn: func(warning model.ScannerWarning) {
					scannerWarnings = append(scannerWarnings, warning)
				},
			})
			outcomes <- scannerOutcome{
				name:     sc.Name(),
				findings: findings,
				warnings: scannerWarnings,
				err:      scanErr,
			}
		}()
	}
	wg.Wait()
	close(outcomes)

	allFindings := make([]model.Finding, 0, 128)
	warnings := make([]model.ScannerWarning, 0, len(r.scanners))

	for outcome := range outcomes {
		if len(outcome.findings) > 0 {
			allFindings = append(allFindings, outcome.findings...)
		}
		if len(outcome.warnings) > 0 {
			warnings = append(warnings, outcome.warnings...)
		}
		if outcome.err != nil {
			warnings = append(warnings, model.ScannerWarning{
				Kind:    model.WarningKindScannerFailure,
				Scanner: outcome.name,
				Message: outcome.err.Error(),
			})
			continue
		}
	}

	deduped := dedupeFindings(allFindings)
	sortFindings(deduped)

	finishedAt := time.Now().UTC()
	target := strings.TrimSpace(req.DisplayTarget)
	if target == "" {
		target = model.NormalizePath(absTarget)
	}
	result := model.ScanResult{
		Version:    buildinfo.Version,
		Target:     target,
		StartedAt:  startedAt,
		FinishedAt: finishedAt,
		DurationMs: finishedAt.Sub(startedAt).Milliseconds(),
		Findings:   deduped,
		Warnings:   warnings,
		Summary:    model.BuildSummary(deduped, warnings, len(r.scanners)),
	}
	return result, nil
}

func dedupeFindings(findings []model.Finding) []model.Finding {
	indexByFingerprint := make(map[string]int, len(findings))
	out := make([]model.Finding, 0, len(findings))

	for _, finding := range findings {
		normalized := finding
		normalized.File = model.NormalizePath(normalized.File)
		normalized.Severity = model.NormalizeSeverity(normalized.Severity)

		if strings.TrimSpace(normalized.Fingerprint) == "" {
			normalized.Fingerprint = model.GenerateFindingID(normalized)
		}
		if strings.TrimSpace(normalized.ID) == "" {
			normalized.ID = model.GenerateFindingID(normalized)
		}

		if idx, exists := indexByFingerprint[normalized.Fingerprint]; exists {
			// Keep the higher-severity variant if duplicate fingerprints appear.
			if model.SeverityRank(normalized.Severity) > model.SeverityRank(out[idx].Severity) {
				out[idx] = normalized
			}
			continue
		}

		indexByFingerprint[normalized.Fingerprint] = len(out)
		out = append(out, normalized)
	}

	return out
}

func sortFindings(findings []model.Finding) {
	sort.SliceStable(findings, func(i, j int) bool {
		left := findings[i]
		right := findings[j]

		if model.CategoryRank(left.Category) != model.CategoryRank(right.Category) {
			return model.CategoryRank(left.Category) < model.CategoryRank(right.Category)
		}
		if model.SeverityRank(left.Severity) != model.SeverityRank(right.Severity) {
			return model.SeverityRank(left.Severity) > model.SeverityRank(right.Severity)
		}
		if left.File != right.File {
			return left.File < right.File
		}
		if left.Line != right.Line {
			return left.Line < right.Line
		}
		return left.RuleID < right.RuleID
	})
}
