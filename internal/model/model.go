package model

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

type Category string

const (
	CategorySecret Category = "secret"
	CategoryConfig Category = "config"
	CategoryJS     Category = "js"
)

type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

type Finding struct {
	ID          string   `json:"id"`
	Category    Category `json:"category"`
	Scanner     string   `json:"scanner"`
	RuleID      string   `json:"rule_id,omitempty"`
	Severity    Severity `json:"severity"`
	Title       string   `json:"title"`
	Description string   `json:"description,omitempty"`
	File        string   `json:"file"`
	Line        int      `json:"line,omitempty"`
	Column      int      `json:"column,omitempty"`
	Evidence    string   `json:"evidence,omitempty"`
	Fingerprint string   `json:"fingerprint,omitempty"`
}

type ScannerWarning struct {
	Kind    string `json:"kind,omitempty"`
	Scanner string `json:"scanner"`
	Message string `json:"message"`
}

const (
	WarningKindScannerFailure = "scanner_failure"
	WarningKindScannerPartial = "scanner_partial_warning"
	WarningKindScanLimit      = "scan_limit_warning"
	WarningKindCleanup        = "cleanup_warning"
	WarningKindToolInstall    = "tool_install_warning"
)

type Summary struct {
	Total            int                `json:"total"`
	ByCategory       map[Category]int   `json:"by_category"`
	BySeverity       map[Severity]int   `json:"by_severity"`
	Scanners         map[string]bool    `json:"scanners"`
	Warnings         map[string]string  `json:"warnings,omitempty"`
	Meta             map[string]float64 `json:"meta,omitempty"`
	ScannerTotal     int                `json:"scanner_total"`
	ScannerSucceeded int                `json:"scanner_succeeded"`
	ScannerFailed    int                `json:"scanner_failed"`
}

type ScanResult struct {
	Version    string           `json:"version"`
	Target     string           `json:"target"`
	StartedAt  time.Time        `json:"started_at"`
	FinishedAt time.Time        `json:"finished_at"`
	DurationMs int64            `json:"duration_ms"`
	Findings   []Finding        `json:"findings"`
	Warnings   []ScannerWarning `json:"warnings,omitempty"`
	Summary    Summary          `json:"summary"`
}

func BuildSummary(findings []Finding, warnings []ScannerWarning, totalScanners int) Summary {
	summary := Summary{
		Total:        len(findings),
		ByCategory:   map[Category]int{CategorySecret: 0, CategoryConfig: 0, CategoryJS: 0},
		BySeverity:   map[Severity]int{SeverityCritical: 0, SeverityHigh: 0, SeverityMedium: 0, SeverityLow: 0, SeverityInfo: 0},
		Scanners:     map[string]bool{},
		Warnings:     map[string]string{},
		ScannerTotal: totalScanners,
	}

	for _, finding := range findings {
		summary.ByCategory[finding.Category]++
		summary.BySeverity[NormalizeSeverity(finding.Severity)]++
		summary.Scanners[finding.Scanner] = true
	}

	for _, warning := range warnings {
		summary.Warnings[warning.Scanner] = warning.Message
		if warning.Kind == WarningKindScannerFailure {
			summary.ScannerFailed++
		}
	}

	if summary.ScannerTotal > summary.ScannerFailed {
		summary.ScannerSucceeded = summary.ScannerTotal - summary.ScannerFailed
	}

	return summary
}

func NormalizeSeverity(value Severity) Severity {
	switch strings.ToLower(string(value)) {
	case string(SeverityCritical):
		return SeverityCritical
	case string(SeverityHigh):
		return SeverityHigh
	case string(SeverityMedium):
		return SeverityMedium
	case string(SeverityLow):
		return SeverityLow
	default:
		return SeverityInfo
	}
}

func SeverityRank(value Severity) int {
	switch NormalizeSeverity(value) {
	case SeverityCritical:
		return 5
	case SeverityHigh:
		return 4
	case SeverityMedium:
		return 3
	case SeverityLow:
		return 2
	default:
		return 1
	}
}

func CategoryRank(category Category) int {
	switch category {
	case CategorySecret:
		return 1
	case CategoryConfig:
		return 2
	case CategoryJS:
		return 3
	default:
		return 99
	}
}

func GenerateFindingID(f Finding) string {
	base := fmt.Sprintf("%s|%s|%s|%s|%d|%d|%s|%s",
		f.Category,
		strings.ToLower(strings.TrimSpace(f.Scanner)),
		strings.ToLower(strings.TrimSpace(f.RuleID)),
		NormalizePath(f.File),
		f.Line,
		f.Column,
		strings.TrimSpace(f.Title),
		strings.TrimSpace(f.Evidence),
	)
	sum := sha1.Sum([]byte(base))
	return hex.EncodeToString(sum[:12])
}

func NormalizePath(path string) string {
	normalized := strings.ReplaceAll(path, "\\", "/")
	normalized = strings.TrimPrefix(normalized, "./")
	return strings.TrimSpace(normalized)
}
