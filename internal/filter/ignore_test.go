package filter

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMatcherShouldIgnoreDefaults(t *testing.T) {
	matcher := NewMatcher(nil)

	if !matcher.ShouldIgnore("node_modules/react/index.js") {
		t.Fatalf("expected node_modules path to be ignored")
	}
	if !matcher.ShouldIgnore("src/main.test.ts") {
		t.Fatalf("expected test file to be ignored")
	}
	if matcher.ShouldIgnore("src/app/main.ts") {
		t.Fatalf("did not expect normal source file to be ignored")
	}
}

func TestNewMatcherFromFile(t *testing.T) {
	tempDir := t.TempDir()
	ignorePath := filepath.Join(tempDir, ".secopsiumignore")
	content := "# comment\nsrc/generated/**\n\n"
	if err := os.WriteFile(ignorePath, []byte(content), 0o644); err != nil {
		t.Fatalf("write ignore file: %v", err)
	}

	matcher, err := NewMatcherFromFile(ignorePath)
	if err != nil {
		t.Fatalf("load matcher: %v", err)
	}
	if !matcher.ShouldIgnore("src/generated/client.ts") {
		t.Fatalf("expected generated path to be ignored")
	}
}
