package filter

import (
	"path/filepath"
	"strings"

	"github.com/secagent/secagent/pkg/types"
)

// Filter applies ignore rules to findings and returns only non-ignored findings
func Filter(findings []types.Finding, ignore types.IgnoreConfig) []types.Finding {
	if isEmpty(ignore) {
		return findings
	}

	filtered := make([]types.Finding, 0)
	for _, finding := range findings {
		if !shouldIgnore(finding, ignore) {
			filtered = append(filtered, finding)
		}
	}
	return filtered
}

// shouldIgnore checks if a finding matches any ignore rule
func shouldIgnore(finding types.Finding, ignore types.IgnoreConfig) bool {
	// Check severity filter
	if len(ignore.Severities) > 0 {
		for _, sev := range ignore.Severities {
			if strings.EqualFold(string(finding.Severity), sev) {
				return true
			}
		}
	}

	// Check rule ID filter (supports wildcards)
	if len(ignore.Rules) > 0 {
		for _, rule := range ignore.Rules {
			if matchRule(finding, rule) {
				return true
			}
		}
	}

	// Check file path filter (supports glob patterns)
	if len(ignore.Files) > 0 {
		for _, pattern := range ignore.Files {
			if matchGlob(finding.Location.File, pattern) {
				return true
			}
		}
	}

	// Check directory path filter (supports glob patterns)
	if len(ignore.Paths) > 0 {
		for _, pattern := range ignore.Paths {
			if matchGlob(finding.Location.File, pattern) {
				return true
			}
		}
	}

	return false
}

// matchRule checks if a finding matches a rule pattern (supports * wildcard)
func matchRule(finding types.Finding, pattern string) bool {
	// Check against rule ID (from scanner-specific metadata or Title)
	ruleID := finding.ID
	if scanner, ok := finding.Metadata["check_id"]; ok {
		if s, ok := scanner.(string); ok {
			ruleID = s
		}
	}
	
	return matchGlob(ruleID, pattern)
}

// matchGlob matches a string against a glob pattern
func matchGlob(s, pattern string) bool {
	// Handle ** for recursive matching
	if strings.Contains(pattern, "**") {
		// Convert ** to regex-like pattern
		pattern = strings.ReplaceAll(pattern, "**", ".*")
		return wildcardMatch(s, pattern)
	}
	
	// Simple glob matching
	matched, _ := filepath.Match(pattern, s)
	return matched
}

// wildcardMatch performs wildcard matching with * and ?
func wildcardMatch(s, pattern string) bool {
	// Simple implementation for common cases
	if pattern == ".*" {
		return true
	}
	
	// Convert pattern to work with filepath.Match
	pattern = strings.ReplaceAll(pattern, ".*", "*")
	matched, _ := filepath.Match(pattern, s)
	return matched
}

// isEmpty checks if ignore config has any rules
func isEmpty(ignore types.IgnoreConfig) bool {
	return len(ignore.Rules) == 0 &&
		len(ignore.Files) == 0 &&
		len(ignore.Severities) == 0 &&
		len(ignore.Paths) == 0
}
