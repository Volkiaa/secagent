package checkov

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

// CheckovScanner implements the Scanner interface for checkov
type CheckovScanner struct{}

// checkovResult represents the JSON output from checkov
// Checkov can return either a single object or an array of results
type checkovResult struct {
	Results checkovResults `json:"results"`
}

type checkovResultArray []checkovResult

type checkovResults struct {
	FailedChecks []checkovFinding `json:"failed_checks"`
}

type checkovFinding struct {
	CheckID       string                 `json:"check_id"`
	CheckName     string                 `json:"check_name"`
	CheckResult   map[string]interface{} `json:"check_result"`
	CodeBlock     [][]interface{}        `json:"code_block"`
	FileAbsPath   string                 `json:"file_abs_path"`
	FilePath      string                 `json:"file_path"`
	RepoFile      string                 `json:"repo_file_path"`
	FileLineRange []int                  `json:"file_line_range"`
	Resource      string                 `json:"resource"`
	Guideline     string                 `json:"guideline"`
	Severity      string                 `json:"severity"`
	BcCategory    string                 `json:"bc_category"`
	Description   string                 `json:"description"`
	Details       []string               `json:"details"`
}

// New creates a new CheckovScanner
func New() scanners.Scanner {
	return &CheckovScanner{}
}

// Name returns the scanner name
func (s *CheckovScanner) Name() string {
	return "checkov"
}

// Type returns the finding type
func (s *CheckovScanner) Type() types.FindingType {
	return types.TypeIaC
}

// Check verifies if checkov is installed
func (s *CheckovScanner) Check() error {
	cmd := exec.Command("checkov", "--version")
	output, err := cmd.CombinedOutput()
	if err == nil && len(output) > 0 {
		return nil
	}
	
	// Try /tmp/checkov
	cmd = exec.Command("/tmp/checkov", "--version")
	output, err = cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("checkov not found: %w", err)
	}
	if len(output) > 0 {
		return nil
	}
	return fmt.Errorf("checkov not properly installed")
}

// Scan runs checkov against the target directory
func (s *CheckovScanner) Scan(ctx context.Context, target string) ([]types.Finding, error) {
	// Check if checkov is available
	if err := s.Check(); err != nil {
		return nil, err
	}

	// Determine checkov path
	checkovPath := "checkov"
	if _, err := exec.LookPath("checkov"); err != nil {
		if _, err := os.Stat("/tmp/checkov"); err == nil {
			checkovPath = "/tmp/checkov"
		}
	}

	// Run checkov with JSON output to stdout
	cmd := exec.CommandContext(ctx, checkovPath,
		"--directory", target,
		"--output", "json",
	)
	
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	
	// checkov returns non-zero exit code when findings are found
	// This is expected behavior, so we still try to parse stdout
	if err != nil && stdout.Len() == 0 {
		return nil, fmt.Errorf("checkov failed: %w, stderr: %s", err, stderr.String())
	}

	data := stdout.Bytes()
	if len(data) == 0 {
		return []types.Finding{}, nil
	}

	// Parse JSON output - checkov can return array or single object
	var findings []types.Finding
	
	// Try parsing as array first
	var resultArray checkovResultArray
	if err := json.Unmarshal(data, &resultArray); err == nil && len(resultArray) > 0 {
		// Successfully parsed as array
		for _, result := range resultArray {
			findings = append(findings, s.parseFindings(result.Results.FailedChecks)...)
		}
	} else {
		// Try parsing as single object
		var result checkovResult
		if err := json.Unmarshal(data, &result); err != nil {
			return nil, fmt.Errorf("failed to parse checkov output: %w", err)
		}
		findings = s.parseFindings(result.Results.FailedChecks)
	}
	
	return findings, nil
}

// parseFindings converts checkov findings to unified format
func (s *CheckovScanner) parseFindings(failedChecks []checkovFinding) []types.Finding {
	findings := make([]types.Finding, 0)
	for _, finding := range failedChecks {
		severity := parseSeverity(finding.Severity, finding.CheckID)
		
		// Build code evidence from code block (array of [line_num, code] pairs)
		var evidenceLines []string
		for _, line := range finding.CodeBlock {
			if len(line) >= 2 {
				if code, ok := line[1].(string); ok {
					evidenceLines = append(evidenceLines, code)
				}
			}
		}
		evidence := strings.Join(evidenceLines, "\n")
		
		// Extract line numbers
		startLine := 0
		endLine := 0
		if len(finding.FileLineRange) >= 2 {
			startLine = finding.FileLineRange[0]
			endLine = finding.FileLineRange[1]
		}

		f := types.Finding{
			ID:          fmt.Sprintf("checkov-%s-%s", finding.CheckID, s.hashFinding(finding)),
			Scanner:     s.Name(),
			Type:        s.Type(),
			Severity:    severity,
			Title:       finding.CheckName,
			Description: finding.Description,
			Location: types.Location{
				File: finding.FileAbsPath,
				Line: startLine,
			},
			Evidence: evidence,
			CheckID:  finding.CheckID,
			CWE:      s.extractCWE(finding.Guideline),
			Fix:      s.generateFix(finding),
			References: []string{
				finding.Guideline,
			},
			Confidence: types.ConfidenceLikely,
			Metadata: map[string]interface{}{
				"check_id":    finding.CheckID,
				"resource":    finding.Resource,
				"category":    finding.BcCategory,
				"details":     finding.Details,
				"file_path":   finding.FilePath,
				"end_line":    endLine,
			},
		}
		findings = append(findings, f)
	}

	return findings
}

// parseSeverity converts checkov severity to unified severity
// Checkov often returns null for severity, so we map based on check ID patterns
func parseSeverity(sev string, checkID string) types.Severity {
	// First try the provided severity
	switch strings.ToUpper(sev) {
	case "CRITICAL":
		return types.SeverityCritical
	case "HIGH":
		return types.SeverityHigh
	case "MEDIUM":
		return types.SeverityMedium
	case "LOW":
		return types.SeverityLow
	}
	
	// If severity is null/empty, map based on check ID patterns
	// Critical: IAM privilege escalation, public access, data exposure
	criticalPatterns := []string{
		"IAMPrivilegeEscalation", "IAMPermissionsManagement", "IAMCredentialsExposure",
		"IAMDataExfiltration", "IAMStarAction", "IAMStarResource",
		"S3PublicAccess", "SecurityGroupUnrestrictedIngress",
		"EncryptionDisabled", "LoggingDisabled",
	}
	for _, pattern := range criticalPatterns {
		if strings.Contains(checkID, pattern) || strings.Contains(checkID, "CKV_AWS_62") || 
		   strings.Contains(checkID, "CKV_AWS_63") || strings.Contains(checkID, "CKV_AWS_286") ||
		   strings.Contains(checkID, "CKV_AWS_287") || strings.Contains(checkID, "CKV_AWS_288") ||
		   strings.Contains(checkID, "CKV_AWS_289") || strings.Contains(checkID, "CKV_AWS_355") {
			return types.SeverityCritical
		}
	}
	
	// High: Overly permissive policies, open ports
	highPatterns := []string{
		"IAMAdmin", "SecurityGroup", "OpenSSH", "OpenRDP",
	}
	for _, pattern := range highPatterns {
		if strings.Contains(checkID, pattern) || strings.Contains(checkID, "CKV_AWS_20") ||
		   strings.Contains(checkID, "CKV_AWS_21") || strings.Contains(checkID, "CKV_AWS_25") ||
		   strings.Contains(checkID, "CKV_AWS_260") {
			return types.SeverityHigh
		}
	}
	
	// Medium: Missing best practices (versioning, lifecycle, etc.)
	mediumPatterns := []string{
		"Versioning", "Lifecycle", "Logging", "Replication", "KMS",
	}
	for _, pattern := range mediumPatterns {
		if strings.Contains(checkID, pattern) || strings.Contains(checkID, "CKV_AWS_18") ||
		   strings.Contains(checkID, "CKV_AWS_144") || strings.Contains(checkID, "CKV_AWS_145") {
			return types.SeverityMedium
		}
	}
	
	// Default to medium for most IaC issues (better safe than sorry)
	return types.SeverityMedium
}

// extractCWE extracts CWE ID from guideline URL if present
func (s *CheckovScanner) extractCWE(guideline string) string {
	if guideline == "" {
		return ""
	}
	// Checkov guidelines are typically URLs to bridgecrew.io
	// CWE info might be in the description instead
	return ""
}

// generateFix generates a fix recommendation based on the check
func (s *CheckovScanner) generateFix(finding checkovFinding) string {
	if len(finding.Details) > 0 && finding.Details[0] != "" {
		return finding.Details[0]
	}
	return fmt.Sprintf("Review and remediate the %s finding for resource %s", finding.CheckName, finding.Resource)
}

// hashFinding creates a simple hash for the finding ID
func (s *CheckovScanner) hashFinding(f checkovFinding) string {
	return fmt.Sprintf("%s-%d-%s", filepath.Base(f.FilePath), f.FileLineRange[0], f.CheckID)
}
