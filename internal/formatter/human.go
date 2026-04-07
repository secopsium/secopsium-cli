package formatter

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/secopsium/secopsium-cli/internal/model"
)

type HumanFormatter struct {
	noColor bool
}

func NewHumanFormatter(noColor bool) *HumanFormatter {
	return &HumanFormatter{noColor: noColor}
}

func (f *HumanFormatter) Format(result model.ScanResult) string {
	styles := newStyles(f.noColor)

	var b strings.Builder
	b.WriteString(styles.banner.Render(buildBannerLine(f.noColor)))
	b.WriteString("\n")
	b.WriteString(fmt.Sprintf("%s %s\n", styles.label.Render("Target:"), result.Target))
	b.WriteString(fmt.Sprintf("%s %s\n", styles.label.Render("Started:"), result.StartedAt.Local().Format(time.RFC3339)))
	b.WriteString(fmt.Sprintf("%s %s\n", styles.label.Render("Duration:"), humanDuration(result.DurationMs)))
	b.WriteString("\n")

	for _, section := range []struct {
		Category model.Category
		Label    string
	}{
		{Category: model.CategorySecret, Label: "Secrets"},
		{Category: model.CategoryConfig, Label: "Config Risks"},
		{Category: model.CategoryJS, Label: "JS Exposure"},
	} {
		sectionFindings := filterByCategory(result.Findings, section.Category)
		b.WriteString(styles.sectionHeader.Render(fmt.Sprintf("[%s] %d findings", section.Label, len(sectionFindings))))
		b.WriteString("\n")
		if len(sectionFindings) == 0 {
			b.WriteString("  none\n\n")
			continue
		}

		for _, finding := range sectionFindings {
			b.WriteString(renderFinding(finding, styles))
			b.WriteString("\n")
		}
		b.WriteString("\n")
	}

	if len(result.Warnings) > 0 {
		b.WriteString(styles.warningHeader.Render("[Scanner Warnings]"))
		b.WriteString("\n")
		for _, warning := range result.Warnings {
			b.WriteString(fmt.Sprintf("  - %s: %s\n", warning.Scanner, warning.Message))
		}
		b.WriteString("\n")
	}

	summary := result.Summary
	b.WriteString(styles.sectionHeader.Render("[Summary]"))
	b.WriteString("\n")
	b.WriteString(fmt.Sprintf("  Total Findings: %d\n", summary.Total))
	b.WriteString(fmt.Sprintf("  Secrets: %d\n", summary.ByCategory[model.CategorySecret]))
	b.WriteString(fmt.Sprintf("  Config Risks: %d\n", summary.ByCategory[model.CategoryConfig]))
	b.WriteString(fmt.Sprintf("  JS Exposure: %d\n", summary.ByCategory[model.CategoryJS]))
	b.WriteString(fmt.Sprintf("  Scanners: %d succeeded  %d failed\n", summary.ScannerSucceeded, summary.ScannerFailed))
	b.WriteString(fmt.Sprintf("  Critical: %d  High: %d  Medium: %d  Low: %d  Info: %d\n",
		summary.BySeverity[model.SeverityCritical],
		summary.BySeverity[model.SeverityHigh],
		summary.BySeverity[model.SeverityMedium],
		summary.BySeverity[model.SeverityLow],
		summary.BySeverity[model.SeverityInfo],
	))
	b.WriteString("\n")
	b.WriteString(styles.upgrade.Render("Want fewer false positives and prioritized results?\nTry the full platform: https://secopsium.com"))
	b.WriteString("\n")

	return strings.TrimRight(b.String(), "\n")
}

type styleSet struct {
	banner        lipgloss.Style
	label         lipgloss.Style
	sectionHeader lipgloss.Style
	warningHeader lipgloss.Style
	critical      lipgloss.Style
	high          lipgloss.Style
	medium        lipgloss.Style
	low           lipgloss.Style
	info          lipgloss.Style
	path          lipgloss.Style
	meta          lipgloss.Style
	upgrade       lipgloss.Style
}

func newStyles(noColor bool) styleSet {
	if noColor {
		plain := lipgloss.NewStyle()
		return styleSet{
			banner:        plain.Border(lipgloss.RoundedBorder()).Padding(0, 1),
			label:         plain.Bold(true),
			sectionHeader: plain.Bold(true),
			warningHeader: plain.Bold(true),
			critical:      plain.Bold(true),
			high:          plain.Bold(true),
			medium:        plain.Bold(true),
			low:           plain.Bold(true),
			info:          plain.Bold(true),
			path:          plain,
			meta:          plain.Foreground(lipgloss.Color("8")),
			upgrade:       plain.Bold(true),
		}
	}

	return styleSet{
		banner:        lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(lipgloss.Color("63")).Padding(0, 1).Foreground(lipgloss.Color("252")),
		label:         lipgloss.NewStyle().Foreground(lipgloss.Color("246")),
		sectionHeader: lipgloss.NewStyle().Foreground(lipgloss.Color("39")).Bold(true),
		warningHeader: lipgloss.NewStyle().Foreground(lipgloss.Color("220")).Bold(true),
		critical:      lipgloss.NewStyle().Foreground(lipgloss.Color("196")).Bold(true),
		high:          lipgloss.NewStyle().Foreground(lipgloss.Color("208")).Bold(true),
		medium:        lipgloss.NewStyle().Foreground(lipgloss.Color("220")).Bold(true),
		low:           lipgloss.NewStyle().Foreground(lipgloss.Color("86")).Bold(true),
		info:          lipgloss.NewStyle().Foreground(lipgloss.Color("111")).Bold(true),
		path:          lipgloss.NewStyle().Foreground(lipgloss.Color("252")),
		meta:          lipgloss.NewStyle().Foreground(lipgloss.Color("244")),
		upgrade:       lipgloss.NewStyle().Foreground(lipgloss.Color("141")),
	}
}

func buildBannerLineLegacy(noColor bool) string {
	if noColor {
		return "o o o  secopsium - local scan"
	}
	dotRed := lipgloss.NewStyle().Foreground(lipgloss.Color("196")).Render("●")
	dotYellow := lipgloss.NewStyle().Foreground(lipgloss.Color("220")).Render("●")
	dotGreen := lipgloss.NewStyle().Foreground(lipgloss.Color("46")).Render("●")
	return fmt.Sprintf("%s %s %s  secopsium - local scan", dotRed, dotYellow, dotGreen)
}

func renderFinding(finding model.Finding, styles styleSet) string {
	var b strings.Builder
	sev := strings.ToUpper(string(finding.Severity))
	sevStyle := severityStyle(finding.Severity, styles)
	line := finding.Line
	if line <= 0 {
		line = 1
	}
	pathLabel := fmt.Sprintf("%s:%d", filepath.ToSlash(finding.File), line)

	b.WriteString(fmt.Sprintf("  - [%s] %s\n", sevStyle.Render(sev), finding.Title))
	b.WriteString(fmt.Sprintf("    %s\n", styles.path.Render(pathLabel)))
	if strings.TrimSpace(finding.RuleID) != "" {
		b.WriteString(fmt.Sprintf("    %s %s\n", styles.meta.Render("rule:"), finding.RuleID))
	}
	if strings.TrimSpace(finding.Evidence) != "" {
		b.WriteString(fmt.Sprintf("    %s %s\n", styles.meta.Render("match:"), finding.Evidence))
	}
	return strings.TrimRight(b.String(), "\n")
}

func severityStyle(severity model.Severity, styles styleSet) lipgloss.Style {
	switch model.NormalizeSeverity(severity) {
	case model.SeverityCritical:
		return styles.critical
	case model.SeverityHigh:
		return styles.high
	case model.SeverityMedium:
		return styles.medium
	case model.SeverityLow:
		return styles.low
	default:
		return styles.info
	}
}

func filterByCategory(findings []model.Finding, category model.Category) []model.Finding {
	out := make([]model.Finding, 0)
	for _, finding := range findings {
		if finding.Category == category {
			out = append(out, finding)
		}
	}
	return out
}

func humanDuration(durationMs int64) string {
	duration := time.Duration(durationMs) * time.Millisecond
	if duration < time.Second {
		return duration.String()
	}
	return duration.Round(100 * time.Millisecond).String()
}

func buildBannerLine(noColor bool) string {
	if noColor {
		return "o o o  secopsium - local scan"
	}

	dotRed := lipgloss.NewStyle().Foreground(lipgloss.Color("196")).Render("o")
	dotYellow := lipgloss.NewStyle().Foreground(lipgloss.Color("220")).Render("o")
	dotGreen := lipgloss.NewStyle().Foreground(lipgloss.Color("46")).Render("o")
	return fmt.Sprintf("%s %s %s  secopsium - local scan", dotRed, dotYellow, dotGreen)
}
