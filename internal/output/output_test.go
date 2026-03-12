package output

import (
	"strings"
	"testing"
	"time"

	"github.com/secagent/secagent/pkg/types"
)

func TestTableFormatter(t *testing.T) {
	formatter := &TableFormatter{}

	t.Run("empty findings", func(t *testing.T) {
		result := types.ScanResult{
			Target:    "/test",
			Findings:  []types.Finding{},
			ScannedAt: time.Now().Format(time.RFC3339),
			Duration:  "1s",
		}

		output, err := formatter.Format(result)
		if err != nil {
			t.Errorf("Format() error = %v", err)
		}
		if !strings.Contains(output, "No security issues found") {
			t.Error("Format() should show 'No security issues found' for empty findings")
		}
	})

	t.Run("with findings", func(t *testing.T) {
		result := types.ScanResult{
			Target: "/test",
			Findings: []types.Finding{
				{
					ID:       "test-1",
					Scanner:  "gitleaks",
					Type:     types.TypeSecret,
					Severity: types.SeverityHigh,
					Title:    "Test finding",
					Location: types.Location{File: "test.go", Line: 10},
				},
			},
			ScannedAt: time.Now().Format(time.RFC3339),
			Duration:  "1s",
		}

		output, err := formatter.Format(result)
		if err != nil {
			t.Errorf("Format() error = %v", err)
		}
		if !strings.Contains(output, "HIGH: 1") {
			t.Error("Format() should show severity count")
		}
		if !strings.Contains(output, "Test finding") {
			t.Error("Format() should include finding title")
		}
		if !strings.Contains(output, "test.go:10") {
			t.Error("Format() should include location")
		}
	})

	t.Run("multiple severities", func(t *testing.T) {
		result := types.ScanResult{
			Target: "/test",
			Findings: []types.Finding{
				{ID: "1", Severity: types.SeverityCritical},
				{ID: "2", Severity: types.SeverityHigh},
				{ID: "3", Severity: types.SeverityMedium},
				{ID: "4", Severity: types.SeverityLow},
				{ID: "5", Severity: types.SeverityInfo},
			},
			ScannedAt: time.Now().Format(time.RFC3339),
			Duration:  "1s",
		}

		output, err := formatter.Format(result)
		if err != nil {
			t.Errorf("Format() error = %v", err)
		}
		if !strings.Contains(output, "CRITICAL: 1") {
			t.Error("Format() should show CRITICAL count")
		}
		if !strings.Contains(output, "HIGH: 1") {
			t.Error("Format() should show HIGH count")
		}
	})
}

func TestJSONFormatter(t *testing.T) {
	formatter := &JSONFormatter{}

	t.Run("valid json", func(t *testing.T) {
		result := types.ScanResult{
			Target: "/test",
			Findings: []types.Finding{
				{
					ID:       "test-1",
					Scanner:  "gitleaks",
					Severity: types.SeverityHigh,
					Title:    "Test",
				},
			},
			ScannedAt: time.Now().Format(time.RFC3339),
			Duration:  "1s",
		}

		output, err := formatter.Format(result)
		if err != nil {
			t.Errorf("Format() error = %v", err)
		}
		if !strings.Contains(output, `"target": "/test"`) {
			t.Error("Format() should include target in JSON")
		}
		if !strings.Contains(output, `"findings"`) {
			t.Error("Format() should include findings array")
		}
	})

	t.Run("empty findings json", func(t *testing.T) {
		result := types.ScanResult{
			Target:    "/test",
			Findings:  []types.Finding{},
			ScannedAt: time.Now().Format(time.RFC3339),
			Duration:  "1s",
		}

		output, err := formatter.Format(result)
		if err != nil {
			t.Errorf("Format() error = %v", err)
		}
		if !strings.Contains(output, `"findings": []`) {
			t.Error("Format() should show empty findings array")
		}
	})
}

func TestMarkdownFormatter(t *testing.T) {
	formatter := &MarkdownFormatter{}

	t.Run("valid markdown", func(t *testing.T) {
		result := types.ScanResult{
			Target: "/test",
			Findings: []types.Finding{
				{
					ID:       "test-1",
					Scanner:  "gitleaks",
					Severity: types.SeverityHigh,
					Title:    "Test finding",
					CVE:      "CVE-2021-1234",
				},
			},
			ScannedAt: time.Now().Format(time.RFC3339),
			Duration:  "1s",
		}

		output, err := formatter.Format(result)
		if err != nil {
			t.Errorf("Format() error = %v", err)
		}
		if !strings.Contains(output, "# SecAgent Security Scan Report") {
			t.Error("Format() should include markdown header")
		}
		if !strings.Contains(output, "CVE-2021-1234") {
			t.Error("Format() should include CVE")
		}
		if !strings.Contains(output, "| Severity | Count |") {
			t.Error("Format() should include severity table")
		}
	})
}

func TestWriteOutput(t *testing.T) {
	t.Run("stdout", func(t *testing.T) {
		result := types.ScanResult{
			Target:    "/test",
			Findings:  []types.Finding{},
			ScannedAt: time.Now().Format(time.RFC3339),
			Duration:  "1s",
		}

		// Should not error when writing to stdout
		err := WriteOutput(result, "table", "")
		if err != nil {
			t.Errorf("WriteOutput() to stdout error = %v", err)
		}
	})
}
