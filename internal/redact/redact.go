package redact

import (
	"regexp"
	"strings"

	"github.com/secopsium/secopsium-cli/internal/model"
)

var (
	quotedValuePattern = regexp.MustCompile(`(["'])([^"'\s]{8,})(["'])`)
	bearerPattern      = regexp.MustCompile(`(?i)(bearer\s+)([A-Za-z0-9_\-\.=]{8,})`)
	longTokenPattern   = regexp.MustCompile(`[A-Za-z0-9_\-\.=]{12,}`)
)

func Redact(input string) string {
	trimmed := strings.TrimSpace(input)
	if trimmed == "" {
		return ""
	}

	redacted := quotedValuePattern.ReplaceAllStringFunc(trimmed, func(value string) string {
		if len(value) < 2 {
			return maskValue(value)
		}
		quote := value[:1]
		inner := value[1 : len(value)-1]
		return quote + maskValue(inner) + quote
	})

	redacted = bearerPattern.ReplaceAllStringFunc(redacted, func(value string) string {
		matches := bearerPattern.FindStringSubmatch(value)
		if len(matches) != 3 {
			return maskValue(value)
		}
		return matches[1] + maskValue(matches[2])
	})

	redacted = longTokenPattern.ReplaceAllStringFunc(redacted, func(value string) string {
		if strings.Contains(value, "****") {
			return value
		}
		return maskValue(value)
	})

	return redacted
}

func ScanResult(result model.ScanResult, unsafeRawOutput bool) model.ScanResult {
	if unsafeRawOutput {
		return result
	}

	sanitized := result
	sanitized.Findings = make([]model.Finding, len(result.Findings))
	for idx, finding := range result.Findings {
		sanitized.Findings[idx] = Finding(finding, unsafeRawOutput)
	}

	sanitized.Warnings = make([]model.ScannerWarning, len(result.Warnings))
	for idx, warning := range result.Warnings {
		sanitized.Warnings[idx] = Warning(warning, unsafeRawOutput)
	}

	if result.Summary.Warnings != nil {
		sanitized.Summary.Warnings = make(map[string]string, len(result.Summary.Warnings))
		for key, value := range result.Summary.Warnings {
			sanitized.Summary.Warnings[key] = Redact(value)
		}
	}

	return sanitized
}

func Finding(finding model.Finding, unsafeRawOutput bool) model.Finding {
	if unsafeRawOutput {
		return finding
	}

	sanitized := finding
	sanitized.Title = Redact(finding.Title)
	sanitized.Description = Redact(finding.Description)
	sanitized.Evidence = Redact(finding.Evidence)
	return sanitized
}

func Warning(warning model.ScannerWarning, unsafeRawOutput bool) model.ScannerWarning {
	if unsafeRawOutput {
		return warning
	}

	sanitized := warning
	sanitized.Message = Redact(warning.Message)
	return sanitized
}

func maskValue(value string) string {
	if strings.TrimSpace(value) == "" {
		return ""
	}
	if strings.Contains(value, "****") {
		return value
	}
	if len(value) <= 8 {
		return "****"
	}

	prefixLen := 4
	if len(value) > 12 {
		prefixLen = 8
	}
	if prefixLen >= len(value)-4 {
		prefixLen = 4
	}

	return value[:prefixLen] + "****" + value[len(value)-4:]
}
