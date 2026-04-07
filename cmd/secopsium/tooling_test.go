package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/secopsium/secopsium-cli/internal/tools"
)

func TestFormatToolIDsUsesDisplayNames(t *testing.T) {
	got := formatToolIDs([]tools.ToolID{tools.ToolGitleaks, tools.ToolSemgrep})
	want := "Gitleaks, Semgrep"
	if got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
}

func TestPromptYesNoDefaultsToYesOnBlankInput(t *testing.T) {
	var output bytes.Buffer
	answer, err := promptYesNo(strings.NewReader("\n"), &output, "Install now?", true)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if !answer {
		t.Fatalf("expected default yes answer")
	}
}

func TestPromptYesNoParsesNegativeInput(t *testing.T) {
	var output bytes.Buffer
	answer, err := promptYesNo(strings.NewReader("n\n"), &output, "Install now?", true)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if answer {
		t.Fatalf("expected negative answer")
	}
}
