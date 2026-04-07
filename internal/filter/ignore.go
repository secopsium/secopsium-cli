package filter

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/bmatcuk/doublestar/v4"
)

const DefaultIgnoreFilename = ".secopsiumignore"

var defaultPatterns = []string{
	".git/**",
	"node_modules/**",
	"vendor/**",
	"dist/**",
	"build/**",
	"coverage/**",
	"**/*.test.*",
	"**/*_test.*",
	"**/__tests__/**",
}

type Matcher struct {
	patterns []string
}

func DefaultPatterns() []string {
	out := make([]string, len(defaultPatterns))
	copy(out, defaultPatterns)
	return out
}

func NewMatcher(extraPatterns []string) *Matcher {
	patterns := append(DefaultPatterns(), extraPatterns...)
	return &Matcher{patterns: uniquePatterns(patterns)}
}

func NewMatcherFromFile(path string) (*Matcher, error) {
	if strings.TrimSpace(path) == "" {
		return NewMatcher(nil), nil
	}

	patterns, err := ReadIgnoreFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return NewMatcher(nil), nil
		}
		return nil, err
	}
	return NewMatcher(patterns), nil
}

func (m *Matcher) ShouldIgnore(relPath string) bool {
	if m == nil {
		return false
	}

	normalized := normalizePath(relPath)
	if normalized == "" {
		return false
	}

	for _, raw := range m.patterns {
		pat := normalizePath(raw)
		if pat == "" {
			continue
		}

		// Match both the raw path and a synthetic directory form so folder
		// patterns like "node_modules/**" still match "node_modules".
		if matchPath(pat, normalized) || matchPath(pat, normalized+"/") {
			return true
		}
	}
	return false
}

func (m *Matcher) Patterns() []string {
	if m == nil {
		return nil
	}
	out := make([]string, len(m.patterns))
	copy(out, m.patterns)
	return out
}

func ReadIgnoreFile(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	lines := strings.Split(string(data), "\n")
	patterns := make([]string, 0, len(lines))
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		patterns = append(patterns, trimmed)
	}
	return uniquePatterns(patterns), nil
}

func InitIgnoreFile(path string) error {
	if strings.TrimSpace(path) == "" {
		path = DefaultIgnoreFilename
	}
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("%s already exists", path)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}

	lines := []string{
		"# SecOpsium CLI ignore patterns",
		"# Uses doublestar globs, one pattern per line.",
		"# Examples:",
		"# src/generated/**",
		"# **/*.snap",
		"",
	}
	lines = append(lines, DefaultPatterns()...)

	content := strings.Join(lines, "\n") + "\n"
	return os.WriteFile(path, []byte(content), 0o644)
}

func AddPatterns(path string, incoming []string) error {
	if strings.TrimSpace(path) == "" {
		path = DefaultIgnoreFilename
	}

	existing := []string{}
	if _, err := os.Stat(path); err == nil {
		patterns, readErr := ReadIgnoreFile(path)
		if readErr != nil {
			return readErr
		}
		existing = patterns
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}

	for _, p := range incoming {
		trimmed := strings.TrimSpace(p)
		if trimmed == "" {
			continue
		}
		if !slices.Contains(existing, trimmed) {
			existing = append(existing, trimmed)
		}
	}

	lines := []string{
		"# SecOpsium CLI ignore patterns",
		"# Uses doublestar globs, one pattern per line.",
		"",
	}
	lines = append(lines, existing...)
	content := strings.Join(lines, "\n") + "\n"
	return os.WriteFile(path, []byte(content), 0o644)
}

func ResolveIgnoreFile(targetRoot string, explicitPath string) string {
	if strings.TrimSpace(explicitPath) != "" {
		return explicitPath
	}

	targetCandidate := filepath.Join(targetRoot, DefaultIgnoreFilename)
	if _, err := os.Stat(targetCandidate); err == nil {
		return targetCandidate
	}
	return ""
}

func uniquePatterns(patterns []string) []string {
	seen := make(map[string]struct{}, len(patterns))
	out := make([]string, 0, len(patterns))
	for _, pattern := range patterns {
		trimmed := strings.TrimSpace(pattern)
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		out = append(out, trimmed)
	}
	return out
}

func normalizePath(path string) string {
	normalized := filepath.ToSlash(strings.TrimSpace(path))
	normalized = strings.TrimPrefix(normalized, "./")
	return normalized
}

func matchPath(pattern string, relPath string) bool {
	match, err := doublestar.PathMatch(pattern, relPath)
	if err != nil {
		return false
	}
	return match
}
