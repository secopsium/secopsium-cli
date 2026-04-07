package scanner

import (
	"context"
	"fmt"

	"github.com/secopsium/secopsium-cli/internal/model"
)

type PathMatcher interface {
	ShouldIgnore(relPath string) bool
	Patterns() []string
}

type Request struct {
	Root               string
	Ignore             PathMatcher
	UnsafeRawOutput    bool
	Strict             bool
	JSMaxFileSizeBytes int64
	Warn               func(model.ScannerWarning)
}

func (r Request) ReportWarning(warning model.ScannerWarning) {
	if r.Warn != nil {
		r.Warn(warning)
	}
}

type Scanner interface {
	Name() string
	Category() model.Category
	Scan(ctx context.Context, req Request) ([]model.Finding, error)
}

type ToolUnavailableError struct {
	Tool string
	Err  error
}

func (e *ToolUnavailableError) Error() string {
	return fmt.Sprintf("%s is not available: %v", e.Tool, e.Err)
}

func (e *ToolUnavailableError) Unwrap() error {
	return e.Err
}
