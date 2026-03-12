package semgrep

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/secagent/secagent/pkg/types"
	"github.com/secagent/secagent/scanners"
)

// SemgrepScanner implements the Scanner interface for semgrep
type SemgrepScanner struct{}

// semgrepResult represents the JSON output from semgrep
type semgrepResult struct {
	Results      []semgrepFinding `json:"results"`
	Errors       []semgrepError   `json:"errors"`
	Stats        semgrepStats     `json:"stats"`
	Version      string           `json:"version"`
}

type semgrepFinding struct {
	CheckID     string         `json:"check_id"`
	Path        string         `json:"path"`
	Start       semgrepLoc     `json:"start"`
	End         semgrepLoc     `json:"end"`
	Extra       semgrepExtra   `json:"extra"`
	Message     string         `json:"message"`
}

type semgrepLoc struct {
	Line   int `json:"line"`
	Column int `json:"column"`
}

type semgrepExtra struct {
	Message     string        `json:"message"`
	Metadata    semgrepMeta   `json:"metadata"`
	Severity    string        `json:"severity"`
	Fix         string        `json:"fix"`
	References  []string      `json:"references"`
	Lines       string        `json:"lines"`
}

type semgrepMeta struct {
	CWE         []string `json:"cwe,omitempty"`
	OWASP       []string `json:"owasp,omitempty"`
	Category    string   `json:"category,omitempty"`
	Technology  []string `json:"technology,omitempty"`
	References  []string `json:"references,omitempty"`
}

type semgrepError struct {
	Code      int    `json:"code"`
	Level     string `json:"level"`
	Message   string `json:"message"`
}

type semgrepStats struct {
	Findings    int `json:"findings"`
	Errors      int `json:"errors"`
	FilesScanned int `json:"files_scanned"`
	BytesScanned int `json:"bytes_scanned"`
}

// New creates a new SemgrepScanner
func New() scanners.Scanner {
	return &SemgrepScanner{}
}

// Name returns the scanner name
func (s *SemgrepScanner) Name() string {
	return "semgrep"
}

// Type returns the finding type
func (s *SemgrepScanner) Type() types.FindingType {
	return types.TypeCode
}

// Check verifies if semgrep is installed
func (s *SemgrepScanner) Check() error {
	cmd := exec.Command("semgrep", "--version")
	output, err := cmd.CombinedOutput()
	if err == nil && len(output) > 0 {
		return nil
	}
	
	// Try /tmp/semgrep
	cmd = exec.Command("/tmp/semgrep", "--version")
	output, err = cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("semgrep not found: %w", err)
	}
	if len(output) > 0 {
		return nil
	}
	return fmt.Errorf("semgrep not properly installed")
}

// Scan runs semgrep against the target directory
func (s *SemgrepScanner) Scan(ctx context.Context, target string) ([]types.Finding, error) {
	// Check if semgrep is available
	if err := s.Check(); err != nil {
		return nil, err
	}

	// Determine semgrep path
	semgrepPath := "semgrep"
	if _, err := exec.LookPath("semgrep"); err != nil {
		if _, err := os.Stat("/tmp/semgrep"); err == nil {
			semgrepPath = "/tmp/semgrep"
		}
	}

	// Run semgrep with JSON output
	// Using auto mode to automatically detect languages and apply relevant rules
	tmpFile := filepath.Join(os.TempDir(), "semgrep-result.json")
	defer os.Remove(tmpFile)

	// Run semgrep with security and bug-finding rules
	cmd := exec.CommandContext(ctx, semgrepPath, 
		"--json",
		"--output", tmpFile,
		"--config", "auto",
		"--no-git-ignore",
		target,
	)
	
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		// semgrep returns non-zero exit code when findings are found
		// This is expected behavior, so we still try to parse the output
		if _, statErr := os.Stat(tmpFile); statErr != nil {
			return nil, fmt.Errorf("semgrep failed: %w, stderr: %s", err, stderr.String())
		}
	}

	// Read the report file
	data, err := os.ReadFile(tmpFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read semgrep report: %w", err)
	}

	// Parse JSON output
	var result semgrepResult
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse semgrep output: %w", err)
	}

	// Convert to unified findings
	findings := make([]types.Finding, 0)
	for _, finding := range result.Results {
		severity := parseSeverity(finding.Extra.Severity)
		cwe := s.parseCWE(finding.Extra.Metadata.CWE)
		
		// Build references from metadata and extra
		references := finding.Extra.References
		if len(references) == 0 && len(finding.Extra.Metadata.References) > 0 {
			references = finding.Extra.Metadata.References
		}

		f := types.Finding{
			ID:          fmt.Sprintf("semgrep-%s-%s", finding.CheckID, s.hashFinding(finding)),
			Scanner:     s.Name(),
			Type:        s.Type(),
			Severity:    severity,
			Title:       finding.CheckID,
			Description: finding.Extra.Message,
			Location: types.Location{
				File:   finding.Path,
				Line:   finding.Start.Line,
				Column: finding.Start.Column,
			},
			Evidence:   finding.Extra.Lines,
			CWE:        cwe,
			Fix:        finding.Extra.Fix,
			References: references,
			Confidence: s.parseConfidence(severity),
			Metadata: map[string]interface{}{
				"check_id":   finding.CheckID,
				"category":   finding.Extra.Metadata.Category,
				"technology": finding.Extra.Metadata.Technology,
				"owasp":      finding.Extra.Metadata.OWASP,
			},
		}
		findings = append(findings, f)
	}

	return findings, nil
}

// parseSeverity converts semgrep severity to unified severity
func parseSeverity(sev string) types.Severity {
	switch strings.ToUpper(sev) {
	case "ERROR":
		return types.SeverityHigh
	case "WARNING":
		return types.SeverityMedium
	case "INFO":
		return types.SeverityLow
	default:
		return types.SeverityInfo
	}
}

// parseCWE extracts CWE ID from semgrep CWE array
func (s *SemgrepScanner) parseCWE(cwe []string) string {
	if len(cwe) == 0 {
		return ""
	}
	// CWE might be in format "CWE-123" or "CWE-123: Description"
	parts := strings.Split(cwe[0], ":")
	return strings.TrimSpace(parts[0])
}

// parseConfidence determines confidence based on severity
func (s *SemgrepScanner) parseConfidence(severity types.Severity) types.Confidence {
	switch severity {
	case types.SeverityHigh:
		return types.ConfidenceLikely
	case types.SeverityMedium:
		return types.ConfidenceLikely
	default:
		return types.ConfidencePossible
	}
}

// hashFinding creates a simple hash for the finding ID
func (s *SemgrepScanner) hashFinding(f semgrepFinding) string {
	// Simple hash based on file, line, and check_id
	return fmt.Sprintf("%s-%d-%s", filepath.Base(f.Path), f.Start.Line, f.CheckID)
}
