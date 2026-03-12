package gitleaks

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

// GitleaksScanner implements the Scanner interface for gitleaks
type GitleaksScanner struct{}

// gitleaksFinding represents a finding from gitleaks (v8 format)
type gitleaksFinding struct {
	RuleID      string   `json:"RuleID"`
	Description string   `json:"Description"`
	StartLine   int      `json:"StartLine"`
	EndLine     int      `json:"EndLine"`
	StartColumn int      `json:"StartColumn"`
	EndColumn   int      `json:"EndColumn"`
	Match       string   `json:"Match"`
	Secret      string   `json:"Secret"`
	File        string   `json:"File"`
	SymlinkFile string   `json:"SymlinkFile"`
	Commit      string   `json:"Commit"`
	Entropy     float64  `json:"Entropy"`
	Tags        []string `json:"Tags"`
	Fingerprint string   `json:"Fingerprint"`
}

// New creates a new GitleaksScanner
func New() scanners.Scanner {
	return &GitleaksScanner{}
}

// Name returns the scanner name
func (s *GitleaksScanner) Name() string {
	return "gitleaks"
}

// Type returns the finding type
func (s *GitleaksScanner) Type() types.FindingType {
	return types.TypeSecret
}

// Check verifies if gitleaks is installed
func (s *GitleaksScanner) Check() error {
	// Try gitleaks in PATH first
	cmd := exec.Command("gitleaks", "version")
	output, err := cmd.CombinedOutput()
	if err == nil && len(output) > 0 {
		return nil
	}
	
	// Try /tmp/gitleaks
	cmd = exec.Command("/tmp/gitleaks", "version")
	output, err = cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("gitleaks not found: %w", err)
	}
	if len(output) > 0 {
		return nil
	}
	return fmt.Errorf("gitleaks not properly installed")
}

// Scan runs gitleaks against the target directory
func (s *GitleaksScanner) Scan(ctx context.Context, target string) ([]types.Finding, error) {
	// Check if gitleaks is available
	if err := s.Check(); err != nil {
		return nil, err
	}

	// Run gitleaks with JSON output
	tmpFile := filepath.Join(os.TempDir(), "gitleaks-result.json")
	defer os.Remove(tmpFile)

	// Determine gitleaks path
	gitleaksPath := "gitleaks"
	if _, err := exec.LookPath("gitleaks"); err != nil {
		if _, err := os.Stat("/tmp/gitleaks"); err == nil {
			gitleaksPath = "/tmp/gitleaks"
		}
	}

	// Detect if target is a git repository
	isGitRepo := s.isGitRepository(target)

	var cmd *exec.Cmd
	if isGitRepo {
		// Scan git history
		cmd = exec.CommandContext(ctx, gitleaksPath, "detect", "--source", target, "--report-path", tmpFile, "--report-format", "json")
	} else {
		// Scan directory (unstaged changes or files)
		cmd = exec.CommandContext(ctx, gitleaksPath, "detect", "--source", target, "--report-path", tmpFile, "--report-format", "json", "--no-git")
	}

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		// gitleaks returns non-zero exit code when secrets are found
		// This is expected behavior, so we still try to parse the output
		if _, statErr := os.Stat(tmpFile); statErr != nil {
			return nil, fmt.Errorf("gitleaks failed: %w, stderr: %s", err, stderr.String())
		}
	}

	// Read the report file
	data, err := os.ReadFile(tmpFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read gitleaks report: %w", err)
	}

	// Parse JSON output (gitleaks v8 outputs array of findings)
	var findings_raw []gitleaksFinding
	if err := json.Unmarshal(data, &findings_raw); err != nil {
		return nil, fmt.Errorf("failed to parse gitleaks output: %w", err)
	}

	// Convert to unified findings
	findings := make([]types.Finding, 0)
	for _, finding := range findings_raw {
		severity := s.parseSeverity(finding.Entropy, finding.Tags)
		
		f := types.Finding{
			ID:          fmt.Sprintf("gitleaks-%s-%s", finding.RuleID, s.hashFinding(finding)),
			Scanner:     s.Name(),
			Type:        s.Type(),
			Severity:    severity,
			Title:       fmt.Sprintf("Potential secret detected: %s", finding.Description),
			Description: fmt.Sprintf("Gitleaks detected a potential secret matching the pattern '%s'", finding.RuleID),
			Location: types.Location{
				File:   finding.File,
				Line:   finding.StartLine,
				Column: finding.StartColumn,
			},
			Evidence: s.redactSecret(finding.Match),
			CheckID:  finding.RuleID,
			Fix:      "Remove the secret from the code and rotate it immediately if it was committed",
			Confidence: s.parseConfidence(finding.Entropy),
			Metadata: map[string]interface{}{
				"rule_id":  finding.RuleID,
				"entropy":  finding.Entropy,
				"tags":     finding.Tags,
				"commit":   finding.Commit,
				"redacted": true,
			},
		}
		findings = append(findings, f)
	}

	return findings, nil
}

// isGitRepository checks if the target is a git repository
func (s *GitleaksScanner) isGitRepository(target string) bool {
	gitDir := filepath.Join(target, ".git")
	if _, err := os.Stat(gitDir); err == nil {
		return true
	}
	
	// Check if we're in a git worktree
	cmd := exec.Command("git", "rev-parse", "--git-dir")
	cmd.Dir = target
	err := cmd.Run()
	return err == nil
}

// parseSeverity determines severity based on entropy and tags
func (s *GitleaksScanner) parseSeverity(entropy float64, tags []string) types.Severity {
	// High entropy or sensitive tags indicate higher severity
	if entropy > 4.5 || containsTag(tags, "credential") || containsTag(tags, "password") || containsTag(tags, "api-key") {
		return types.SeverityCritical
	}
	if entropy > 4.0 || containsTag(tags, "secret") || containsTag(tags, "token") {
		return types.SeverityHigh
	}
	if entropy > 3.5 {
		return types.SeverityMedium
	}
	return types.SeverityLow
}

// parseConfidence determines confidence based on entropy
func (s *GitleaksScanner) parseConfidence(entropy float64) types.Confidence {
	if entropy > 4.5 {
		return types.ConfidenceTruePositive
	}
	if entropy > 4.0 {
		return types.ConfidenceLikely
	}
	return types.ConfidencePossible
}

// containsTag checks if a tag exists in the tags list
func containsTag(tags []string, tag string) bool {
	for _, t := range tags {
		if strings.EqualFold(t, tag) {
			return true
		}
	}
	return false
}

// redactSecret partially redacts a secret for safe display
func (s *GitleaksScanner) redactSecret(secret string) string {
	if len(secret) <= 8 {
		return "****"
	}
	// Show first 4 and last 4 characters
	return secret[:4] + strings.Repeat("*", len(secret)-8) + secret[len(secret)-4:]
}

// hashFinding creates a simple hash for the finding ID
func (s *GitleaksScanner) hashFinding(f gitleaksFinding) string {
	// Simple hash based on file, line, and rule
	return fmt.Sprintf("%s-%d-%s", filepath.Base(f.File), f.StartLine, f.RuleID)
}
