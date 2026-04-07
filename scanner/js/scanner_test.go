package js

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/secopsium/secopsium-cli/internal/model"
	"github.com/secopsium/secopsium-cli/scanner"
)

type noIgnoreMatcher struct{}

func (n noIgnoreMatcher) ShouldIgnore(relPath string) bool { return false }
func (n noIgnoreMatcher) Patterns() []string               { return nil }

func TestScannerFindsHardcodedToken(t *testing.T) {
	tempDir := t.TempDir()
	jsFile := filepath.Join(tempDir, "app.js")
	content := `const apiKey = "sk_live_1234567890abcdef";`
	if err := os.WriteFile(jsFile, []byte(content), 0o644); err != nil {
		t.Fatalf("write test file: %v", err)
	}

	s := New()
	findings, err := s.Scan(context.Background(), scanner.Request{
		Root:   tempDir,
		Ignore: noIgnoreMatcher{},
	})
	if err != nil {
		t.Fatalf("scan error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatalf("expected at least one finding")
	}
}

func TestScannerWarnsWhenLargeJSFileIsSkipped(t *testing.T) {
	tempDir := t.TempDir()
	jsFile := filepath.Join(tempDir, "bundle.js")
	content := strings.Repeat("a", 2048)
	if err := os.WriteFile(jsFile, []byte(content), 0o644); err != nil {
		t.Fatalf("write test file: %v", err)
	}

	warnings := make([]model.ScannerWarning, 0, 1)
	s := New()
	findings, err := s.Scan(context.Background(), scanner.Request{
		Root:               tempDir,
		Ignore:             noIgnoreMatcher{},
		JSMaxFileSizeBytes: 1024,
		Warn: func(warning model.ScannerWarning) {
			warnings = append(warnings, warning)
		},
	})
	if err != nil {
		t.Fatalf("scan error: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected no findings for skipped file, got %d", len(findings))
	}
	if len(warnings) != 1 {
		t.Fatalf("expected one warning, got %d", len(warnings))
	}
	if warnings[0].Kind != model.WarningKindScanLimit {
		t.Fatalf("expected scan limit warning, got %s", warnings[0].Kind)
	}
}
