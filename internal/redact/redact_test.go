package redact

import (
	"testing"

	"github.com/secopsium/secopsium-cli/internal/model"
)

func TestRedactMasksLongTokens(t *testing.T) {
	input := `apiKey = "sk_live_123456789"`
	got := Redact(input)

	if got == input {
		t.Fatalf("expected redaction to change input")
	}
	if got != `apiKey = "sk_live_****6789"` {
		t.Fatalf("unexpected redacted value: %s", got)
	}
}

func TestScanResultRedactsWarningsAndEvidence(t *testing.T) {
	result := model.ScanResult{
		Findings: []model.Finding{
			{
				Title:       "Hardcoded token",
				Description: "Bearer sk_live_123456789 found",
				Evidence:    `token = "sk_live_123456789"`,
			},
		},
		Warnings: []model.ScannerWarning{
			{
				Scanner: "semgrep",
				Message: `failed to parse token "sk_live_123456789"`,
			},
		},
		Summary: model.Summary{
			Warnings: map[string]string{
				"semgrep": `failed to parse token "sk_live_123456789"`,
			},
		},
	}

	safe := ScanResult(result, false)
	if safe.Findings[0].Evidence == result.Findings[0].Evidence {
		t.Fatalf("expected finding evidence to be redacted")
	}
	if safe.Warnings[0].Message == result.Warnings[0].Message {
		t.Fatalf("expected warning message to be redacted")
	}
	if safe.Summary.Warnings["semgrep"] == result.Summary.Warnings["semgrep"] {
		t.Fatalf("expected summary warning to be redacted")
	}
}
