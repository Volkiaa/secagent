package osv

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/secagent/secagent/pkg/types"
	"github.com/secagent/secagent/scanners"
)

// OSVScanner implements the Scanner interface for osv-scanner
type OSVScanner struct{}

// osvResult represents the JSON output from osv-scanner v2.x
type osvResult struct {
	Results []osvSourceResult `json:"results"`
}

type osvSourceResult struct {
	Source struct {
		Path string `json:"path"`
		Type string `json:"type"`
	} `json:"source"`
	Packages []osvPackage `json:"packages"`
}

type osvPackage struct {
	Package struct {
		Name      string `json:"name"`
		Version   string `json:"version"`
		Ecosystem string `json:"ecosystem"`
	} `json:"package"`
	Groups []osvGroup `json:"groups"`
}

type osvGroup struct {
	IDs         []string `json:"ids"`
	Aliases     []string `json:"aliases"`
	MaxSeverity string   `json:"max_severity"`
}

// New creates a new OSVScanner
func New() scanners.Scanner {
	return &OSVScanner{}
}

// Name returns the scanner name
func (s *OSVScanner) Name() string {
	return "osv-scanner"
}

// Type returns the finding type
func (s *OSVScanner) Type() types.FindingType {
	return types.TypeDependency
}

// Check verifies if osv-scanner is installed
func (s *OSVScanner) Check() error {
	// Try osv-scanner in PATH first
	cmd := exec.Command("osv-scanner", "--version")
	output, err := cmd.CombinedOutput()
	if err == nil && strings.Contains(string(output), "osv-scanner") {
		return nil
	}
	
	// Try /tmp/osv-scanner
	cmd = exec.Command("/tmp/osv-scanner", "--version")
	output, err = cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("osv-scanner not found: %w", err)
	}
	if strings.Contains(string(output), "osv-scanner") {
		return nil
	}
	return fmt.Errorf("osv-scanner not properly installed")
}

// Scan runs osv-scanner against the target directory
func (s *OSVScanner) Scan(ctx context.Context, target string) ([]types.Finding, error) {
	// Check if osv-scanner is available
	if err := s.Check(); err != nil {
		return nil, err
	}

	// Determine osv-scanner path
	osvPath := "osv-scanner"
	if _, err := exec.LookPath("osv-scanner"); err != nil {
		if _, err := os.Stat("/tmp/osv-scanner"); err == nil {
			osvPath = "/tmp/osv-scanner"
		}
	}

	// Run osv-scanner with JSON output (v2.x format)
	tmpFile := filepath.Join(os.TempDir(), "osv-result.json")
	defer os.Remove(tmpFile)

	cmd := exec.CommandContext(ctx, osvPath, "scan", "source", "--format", "json", "-r", target)
	var stdout bytes.Buffer
	cmd.Stdout = &stdout

	err := cmd.Run()
	if err != nil {
		// osv-scanner returns exit code 128 when no packages are found (not an error)
		// It returns non-zero exit codes when vulnerabilities are found
		if exitErr, ok := err.(*exec.ExitError); ok {
			if exitErr.ExitCode() == 128 {
				// No packages found - return empty results, not an error
				return []types.Finding{}, nil
			}
		}
		// For other errors, check if we have output to parse
		if stdout.Len() == 0 {
			return nil, fmt.Errorf("osv-scanner failed: %w", err)
		}
	}

	// Parse JSON output - skip non-JSON lines at the beginning
	jsonStart := bytes.Index(stdout.Bytes(), []byte("{"))
	if jsonStart == -1 {
		return nil, fmt.Errorf("no JSON output from osv-scanner")
	}
	jsonData := stdout.Bytes()[jsonStart:]

	var result osvResult
	if err := json.Unmarshal(jsonData, &result); err != nil {
		return nil, fmt.Errorf("failed to parse osv-scanner output: %w, output: %s", err, string(jsonData)[:min(500, len(jsonData))])
	}

	// Convert to unified findings
	findings := make([]types.Finding, 0)
	for _, srcResult := range result.Results {
		for _, pkg := range srcResult.Packages {
			for _, group := range pkg.Groups {
				// Use first ID as primary
				vulnID := group.IDs[0]
				if len(vulnID) == 0 {
					continue
				}

				// Extract CVE from aliases
				cve := ""
				for _, alias := range group.Aliases {
					if strings.HasPrefix(alias, "CVE-") {
						cve = alias
						break
					}
				}

				// Parse CVSS score for severity
				severity := types.SeverityMedium
				if group.MaxSeverity != "" {
					score, err := strconv.ParseFloat(group.MaxSeverity, 64)
					if err == nil {
						severity = cvssToSeverity(score)
					}
				}

				finding := types.Finding{
					ID:          vulnID,
					Scanner:     s.Name(),
					Type:        s.Type(),
					Severity:    severity,
					Title:       fmt.Sprintf("Vulnerability in %s", pkg.Package.Name),
					Description: fmt.Sprintf("%s affects %s@%s", vulnID, pkg.Package.Name, pkg.Package.Version),
					Location: types.Location{
						File:       srcResult.Source.Path,
						Package:    pkg.Package.Name,
						Dependency: fmt.Sprintf("%s@%s", pkg.Package.Name, pkg.Package.Version),
					},
					CVE: cve,
					Fix: fmt.Sprintf("Update %s to a version that fixes %s", pkg.Package.Name, vulnID),
					References: []string{
						fmt.Sprintf("https://osv.dev/%s", vulnID),
					},
					Metadata: map[string]interface{}{
						"ecosystem": pkg.Package.Ecosystem,
						"version":   pkg.Package.Version,
						"aliases":   group.Aliases,
					},
				}
				findings = append(findings, finding)
			}
		}
	}

	return findings, nil
}

// cvssToSeverity converts CVSS score to severity level
func cvssToSeverity(score float64) types.Severity {
	if score >= 9.0 {
		return types.SeverityCritical
	}
	if score >= 7.0 {
		return types.SeverityHigh
	}
	if score >= 4.0 {
		return types.SeverityMedium
	}
	if score > 0.0 {
		return types.SeverityLow
	}
	return types.SeverityInfo
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
