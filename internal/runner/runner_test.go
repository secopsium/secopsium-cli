package runner

import (
	"context"
	"testing"
	"time"

	"github.com/secopsium/secopsium-cli/internal/model"
	"github.com/secopsium/secopsium-cli/scanner"
)

type fakeScanner struct {
	name     string
	category model.Category
	findings []model.Finding
	warnings []model.ScannerWarning
	err      error
}

func (f fakeScanner) Name() string {
	return f.name
}

func (f fakeScanner) Category() model.Category {
	return f.category
}

func (f fakeScanner) Scan(ctx context.Context, req scanner.Request) ([]model.Finding, error) {
	for _, warning := range f.warnings {
		req.ReportWarning(warning)
	}
	return f.findings, f.err
}

func TestRunnerDedupesByFingerprint(t *testing.T) {
	duplicateFingerprint := "abc123"

	secretScanner := fakeScanner{
		name:     "gitleaks",
		category: model.CategorySecret,
		findings: []model.Finding{
			{
				Category:    model.CategorySecret,
				Scanner:     "gitleaks",
				Severity:    model.SeverityHigh,
				Title:       "Secret in config",
				File:        "config/.env",
				Line:        10,
				Fingerprint: duplicateFingerprint,
			},
		},
	}

	jsScanner := fakeScanner{
		name:     "js-static",
		category: model.CategoryJS,
		findings: []model.Finding{
			{
				Category:    model.CategorySecret,
				Scanner:     "js-static",
				Severity:    model.SeverityCritical,
				Title:       "Secret in config",
				File:        "config/.env",
				Line:        10,
				Fingerprint: duplicateFingerprint,
			},
		},
	}

	r := New([]scanner.Scanner{secretScanner, jsScanner}, 5*time.Second)
	result, err := r.Run(context.Background(), Request{TargetPath: "."})
	if err != nil {
		t.Fatalf("run failed: %v", err)
	}

	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 deduped finding, got %d", len(result.Findings))
	}
	if result.Findings[0].Severity != model.SeverityCritical {
		t.Fatalf("expected highest severity finding to survive dedupe")
	}
}

func TestRunnerCollectsScannerWarnings(t *testing.T) {
	r := New([]scanner.Scanner{
		fakeScanner{
			name:     "js-static",
			category: model.CategoryJS,
			warnings: []model.ScannerWarning{{
				Kind:    model.WarningKindScanLimit,
				Scanner: "js-static",
				Message: "skipped bundle.js",
			}},
		},
	}, 5*time.Second)

	result, err := r.Run(context.Background(), Request{TargetPath: "."})
	if err != nil {
		t.Fatalf("run failed: %v", err)
	}

	if len(result.Warnings) != 1 {
		t.Fatalf("expected one warning, got %d", len(result.Warnings))
	}
	if result.Warnings[0].Kind != model.WarningKindScanLimit {
		t.Fatalf("expected scan limit warning, got %s", result.Warnings[0].Kind)
	}
}

func TestRunnerKeepsFindingsWhenScannerReturnsFindingsAndError(t *testing.T) {
	r := New([]scanner.Scanner{
		fakeScanner{
			name:     "semgrep",
			category: model.CategoryConfig,
			findings: []model.Finding{{
				Category: model.CategoryConfig,
				Scanner:  "semgrep",
				Severity: model.SeverityMedium,
				Title:    "Config issue",
				File:     "app.yaml",
				Line:     12,
			}},
			err: context.DeadlineExceeded,
		},
	}, 5*time.Second)

	result, err := r.Run(context.Background(), Request{TargetPath: "."})
	if err != nil {
		t.Fatalf("run failed: %v", err)
	}

	if len(result.Findings) != 1 {
		t.Fatalf("expected findings to be preserved, got %d", len(result.Findings))
	}
	if len(result.Warnings) != 1 {
		t.Fatalf("expected one warning, got %d", len(result.Warnings))
	}
	if result.Warnings[0].Kind != model.WarningKindScannerFailure {
		t.Fatalf("expected scanner failure warning, got %s", result.Warnings[0].Kind)
	}
}
