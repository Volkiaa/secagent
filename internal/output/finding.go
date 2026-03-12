package output

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/secagent/secagent/pkg/types"
)

// Formatter defines the interface for output formatters
type Formatter interface {
	Format(result types.ScanResult) (string, error)
}

// TableFormatter formats findings as a human-readable table
type TableFormatter struct{}

// JSONFormatter formats findings as JSON
type JSONFormatter struct{}

// MarkdownFormatter formats findings as Markdown
type MarkdownFormatter struct{}

// Format formats the scan result as a table
func (f *TableFormatter) Format(result types.ScanResult) (string, error) {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("SecAgent Security Scan Report\n"))
	sb.WriteString(fmt.Sprintf("Target: %s\n", result.Target))
	sb.WriteString(fmt.Sprintf("Scanned: %s\n", result.ScannedAt))
	sb.WriteString(fmt.Sprintf("Duration: %s\n", result.Duration))
	sb.WriteString(fmt.Sprintf("Findings: %d\n", len(result.Findings)))
	sb.WriteString("\n")

	if len(result.Findings) == 0 {
		sb.WriteString("✓ No security issues found!\n")
		return sb.String(), nil
	}

	// Group by severity
	severityOrder := []types.Severity{
		types.SeverityCritical,
		types.SeverityHigh,
		types.SeverityMedium,
		types.SeverityLow,
		types.SeverityInfo,
	}

	for _, severity := range severityOrder {
		count := 0
		for _, f := range result.Findings {
			if f.Severity == severity {
				count++
			}
		}
		if count > 0 {
			sb.WriteString(fmt.Sprintf("%s: %d\n", strings.ToUpper(string(severity)), count))
		}
	}

	sb.WriteString("\n")
	sb.WriteString("DETAILED FINDINGS\n")
	sb.WriteString(strings.Repeat("=", 80))
	sb.WriteString("\n\n")

	for i, finding := range result.Findings {
		// Skip auto-ignored findings in normal output
		if finding.AutoIgnored {
			continue
		}
		
		sb.WriteString(fmt.Sprintf("[%d] %s\n", i+1, finding.Title))
		// Show merged scanners if available
		scannerStr := ""
		if scannersRaw, ok := finding.Metadata["scanners"].([]interface{}); ok {
			scanners := make([]string, len(scannersRaw))
			for i, s := range scannersRaw {
				if str, ok := s.(string); ok {
					scanners[i] = str
				}
			}
			if len(scanners) > 1 {
				scannerStr = strings.Join(scanners, ", ")
			}
		} else if scanners, ok := finding.Metadata["scanners"].([]string); ok && len(scanners) > 1 {
			scannerStr = strings.Join(scanners, ", ")
		}
		
		if scannerStr != "" {
			sb.WriteString(fmt.Sprintf("    Scanners: %s\n", scannerStr))
		} else {
			sb.WriteString(fmt.Sprintf("    Scanner:  %s\n", finding.Scanner))
		}
		sb.WriteString(fmt.Sprintf("    Type:     %s\n", finding.Type))
		sb.WriteString(fmt.Sprintf("    Severity: %s\n", finding.Severity))
		
		// Show confidence score
		if finding.ConfidenceScore > 0 {
			confidenceEmoji := "⚪"
			if finding.ConfidenceScore >= 4 {
				confidenceEmoji = "🟢"
			} else if finding.ConfidenceScore <= 2 {
				confidenceEmoji = "🔴"
			}
			sb.WriteString(fmt.Sprintf("    Confidence: %s (%d/5)\n", confidenceEmoji, finding.ConfidenceScore))
		}
		if finding.CVE != "" {
			sb.WriteString(fmt.Sprintf("    CVE:      %s\n", finding.CVE))
		}
		if finding.Location.File != "" {
			sb.WriteString(fmt.Sprintf("    Location: %s", finding.Location.File))
			if finding.Location.Line > 0 {
				sb.WriteString(fmt.Sprintf(":%d", finding.Location.Line))
			}
			sb.WriteString("\n")
		}
		sb.WriteString(fmt.Sprintf("    Fix:      %s\n", finding.Fix))
		sb.WriteString("\n")
	}

	if len(result.Errors) > 0 {
		sb.WriteString("\nERRORS\n")
		sb.WriteString(strings.Repeat("=", 80))
		sb.WriteString("\n")
		for _, err := range result.Errors {
			sb.WriteString(fmt.Sprintf("  ✗ %s\n", err))
		}
	}

	return sb.String(), nil
}

// Format formats the scan result as JSON
func (f *JSONFormatter) Format(result types.ScanResult) (string, error) {
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// Format formats the scan result as Markdown
func (f *MarkdownFormatter) Format(result types.ScanResult) (string, error) {
	var sb strings.Builder

	sb.WriteString("# SecAgent Security Scan Report\n\n")
	sb.WriteString(fmt.Sprintf("**Target:** `%s`\n\n", result.Target))
	sb.WriteString(fmt.Sprintf("**Scanned:** %s\n\n", result.ScannedAt))
	sb.WriteString(fmt.Sprintf("**Duration:** %s\n\n", result.Duration))

	// Summary
	sb.WriteString("## Summary\n\n")
	sb.WriteString(fmt.Sprintf("| Severity | Count |\n"))
	sb.WriteString("|----------|-------|\n")

	severityCounts := make(map[types.Severity]int)
	for _, f := range result.Findings {
		severityCounts[f.Severity]++
	}

	severityOrder := []types.Severity{
		types.SeverityCritical,
		types.SeverityHigh,
		types.SeverityMedium,
		types.SeverityLow,
		types.SeverityInfo,
	}

	for _, severity := range severityOrder {
		if count, ok := severityCounts[severity]; ok {
			sb.WriteString(fmt.Sprintf("| %s | %d |\n", strings.ToUpper(string(severity)), count))
		}
	}
	sb.WriteString("\n")

	if len(result.Findings) == 0 {
		sb.WriteString("✓ **No security issues found!**\n\n")
		return sb.String(), nil
	}

	// Detailed findings
	sb.WriteString("## Detailed Findings\n\n")

	for i, finding := range result.Findings {
		sb.WriteString(fmt.Sprintf("### %d. %s\n\n", i+1, finding.Title))
		sb.WriteString(fmt.Sprintf("- **Scanner:** %s\n", finding.Scanner))
		sb.WriteString(fmt.Sprintf("- **Type:** %s\n", finding.Type))
		sb.WriteString(fmt.Sprintf("- **Severity:** %s\n", finding.Severity))
		if finding.CVE != "" {
			sb.WriteString(fmt.Sprintf("- **CVE:** %s\n", finding.CVE))
		}
		if finding.Location.File != "" {
			loc := finding.Location.File
			if finding.Location.Line > 0 {
				loc += fmt.Sprintf(":%d", finding.Location.Line)
			}
			sb.WriteString(fmt.Sprintf("- **Location:** `%s`\n", loc))
		}
		sb.WriteString(fmt.Sprintf("- **Description:** %s\n", finding.Description))
		if finding.Fix != "" {
			sb.WriteString(fmt.Sprintf("- **Fix:** %s\n", finding.Fix))
		}
		if len(finding.References) > 0 {
			sb.WriteString("- **References:**\n")
			for _, ref := range finding.References {
				sb.WriteString(fmt.Sprintf("  - %s\n", ref))
			}
		}
		sb.WriteString("\n")
	}

	if len(result.Errors) > 0 {
		sb.WriteString("## Errors\n\n")
		for _, err := range result.Errors {
			sb.WriteString(fmt.Sprintf("- %s\n", err))
		}
		sb.WriteString("\n")
	}

	return sb.String(), nil
}

// GetFormatter returns the appropriate formatter based on format string
func GetFormatter(format string) Formatter {
	switch strings.ToLower(format) {
	case "json":
		return &JSONFormatter{}
	case "markdown", "md":
		return &MarkdownFormatter{}
	default:
		return &TableFormatter{}
	}
}

// WriteOutput writes the formatted output to a file or stdout
func WriteOutput(result types.ScanResult, format string, outputFile string) error {
	formatter := GetFormatter(format)
	output, err := formatter.Format(result)
	if err != nil {
		return err
	}

	if outputFile != "" {
		return os.WriteFile(outputFile, []byte(output), 0644)
	}

	fmt.Println(output)
	return nil
}

// NewScanResult creates a new ScanResult with timestamp
func NewScanResult(target string) types.ScanResult {
	return types.ScanResult{
		Target:    target,
		Findings:  make([]types.Finding, 0),
		Errors:    make([]string, 0),
		ScannedAt: time.Now().Format(time.RFC3339),
	}
}
