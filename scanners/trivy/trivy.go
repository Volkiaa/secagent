package trivy

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

// TrivyScanner implements the Scanner interface for trivy
type TrivyScanner struct{}

// trivyResult represents the JSON output from trivy
type trivyResult struct {
	Results []trivyTargetResult `json:"Results"`
}

type trivyTargetResult struct {
	Target      string             `json:"Target"`
	Class       string             `json:"Class"`
	Type        string             `json:"Type"`
	Vulnerabilities []trivyVuln   `json:"Vulnerabilities"`
}

type trivyVuln struct {
	VulnerabilityID string  `json:"VulnerabilityID"`
	PkgName         string  `json:"PkgName"`
	InstalledVersion string `json:"InstalledVersion"`
	FixedVersion    string  `json:"FixedVersion"`
	Title           string  `json:"Title"`
	Description     string  `json:"Description"`
	Severity        string  `json:"Severity"`
	CvssScore       float64 `json:"-"`
	PrimaryURL      string  `json:"PrimaryURL"`
}

// New creates a new TrivyScanner
func New() scanners.Scanner {
	return &TrivyScanner{}
}

// Name returns the scanner name
func (s *TrivyScanner) Name() string {
	return "trivy"
}

// Type returns the finding type
func (s *TrivyScanner) Type() types.FindingType {
	return types.TypeContainer
}

// Check verifies if trivy is installed
func (s *TrivyScanner) Check() error {
	cmd := exec.Command("trivy", "--version")
	output, err := cmd.CombinedOutput()
	if err == nil && len(output) > 0 {
		return nil
	}
	
	// Try /tmp/trivy
	cmd = exec.Command("/tmp/trivy", "--version")
	output, err = cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("trivy not found: %w", err)
	}
	if len(output) > 0 {
		return nil
	}
	return fmt.Errorf("trivy not properly installed")
}

// Scan runs trivy against the target directory
func (s *TrivyScanner) Scan(ctx context.Context, target string) ([]types.Finding, error) {
	// Check if trivy is available
	if err := s.Check(); err != nil {
		return nil, err
	}

	// Determine trivy path
	trivyPath := "trivy"
	if _, err := exec.LookPath("trivy"); err != nil {
		if _, err := os.Stat("/tmp/trivy"); err == nil {
			trivyPath = "/tmp/trivy"
		}
	}

	// Run trivy with JSON output
	tmpFile := filepath.Join(os.TempDir(), "trivy-result.json")
	defer os.Remove(tmpFile)

	cmd := exec.CommandContext(ctx, trivyPath, "fs", "--format", "json", "--output", tmpFile, target)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		// trivy returns non-zero exit code when vulnerabilities are found
		if _, statErr := os.Stat(tmpFile); statErr != nil {
			return nil, fmt.Errorf("trivy failed: %w, stderr: %s", err, stderr.String())
		}
	}

	// Read the report file
	data, err := os.ReadFile(tmpFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read trivy report: %w", err)
	}

	// Parse JSON output
	var result trivyResult
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse trivy output: %w", err)
	}

	// Convert to unified findings
	findings := make([]types.Finding, 0)
	for _, targetResult := range result.Results {
		for _, vuln := range targetResult.Vulnerabilities {
			finding := types.Finding{
				ID:          vuln.VulnerabilityID,
				Scanner:     s.Name(),
				Type:        s.Type(),
				Severity:    parseSeverity(vuln.Severity),
				Title:       vuln.Title,
				Description: vuln.Description,
				Location: types.Location{
					Package:    vuln.PkgName,
					Dependency: fmt.Sprintf("%s@%s", vuln.PkgName, vuln.InstalledVersion),
				},
				CVE: vuln.VulnerabilityID,
				Fix: fmt.Sprintf("Update %s to %s", vuln.PkgName, vuln.FixedVersion),
				References: []string{
					vuln.PrimaryURL,
				},
				Metadata: map[string]interface{}{
					"target":           targetResult.Target,
					"class":            targetResult.Class,
					"installedVersion": vuln.InstalledVersion,
					"fixedVersion":     vuln.FixedVersion,
				},
			}
			findings = append(findings, finding)
		}
	}

	return findings, nil
}

// parseSeverity converts trivy severity to unified severity
func parseSeverity(sev string) types.Severity {
	switch strings.ToUpper(sev) {
	case "CRITICAL":
		return types.SeverityCritical
	case "HIGH":
		return types.SeverityHigh
	case "MEDIUM":
		return types.SeverityMedium
	case "LOW":
		return types.SeverityLow
	default:
		return types.SeverityInfo
	}
}
