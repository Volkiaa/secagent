package confidence

import (
	"path/filepath"
	"regexp"
	"strings"
)

// ConfidenceScore represents the confidence level of a finding
type ConfidenceScore int

const (
	ConfidenceVeryLow ConfidenceScore = 1
	ConfidenceLow     ConfidenceScore = 2
	ConfidenceMedium  ConfidenceScore = 3
	ConfidenceHigh    ConfidenceScore = 4
	ConfidenceVeryHigh ConfidenceScore = 5
)

// CalculateConfidence calculates confidence score for a finding
func CalculateConfidence(scanner, filePath, evidence string, hasUserInput bool) ConfidenceScore {
	score := ConfidenceMedium // Start with medium

	// Reduce confidence for test files
	if isTestFile(filePath) {
		score -= 2
	}

	// Reduce confidence for obvious placeholders
	if isPlaceholder(evidence) {
		score -= 2
	}

	// Increase confidence for production code
	if isProductionFile(filePath) {
		score += 1
	}

	// Increase confidence if user input is detected
	if hasUserInput {
		score += 2
	}

	// Scanner-specific adjustments
	score += scannerConfidence(scanner, evidence)

	// Clamp to valid range
	if score < ConfidenceVeryLow {
		return ConfidenceVeryLow
	}
	if score > ConfidenceVeryHigh {
		return ConfidenceVeryHigh
	}

	return score
}

// isTestFile checks if file is a test file
func isTestFile(filePath string) bool {
	testPatterns := []string{
		"test_*.py", "*_test.go", "*.test.js", "*.spec.ts",
		"tests/", "test/", "__tests__/", "spec/",
		"conftest.py", "fixtures/", "mocks/",
	}

	for _, pattern := range testPatterns {
		if matched, _ := filepath.Match(pattern, filepath.Base(filePath)); matched {
			return true
		}
		if strings.Contains(filePath, pattern) {
			return true
		}
	}

	return false
}

// isProductionFile checks if file is production code
func isProductionFile(filePath string) bool {
	prodPatterns := []string{
		"src/", "lib/", "app/", "main.",
		"production", "prod/",
	}

	for _, pattern := range prodPatterns {
		if strings.Contains(filePath, pattern) {
			return true
		}
	}

	return false
}

// isPlaceholder checks if evidence looks like a placeholder
func isPlaceholder(evidence string) bool {
	placeholderPatterns := []string{
		`(?i)^foo(bar|baz)?`,
		`(?i)^test`,
		`(?i)^placeholder`,
		`(?i)^example`,
		`(?i)^your_`,
		`(?i)^xxx+`,
		`(?i)^abc123`,
		`(?i)^changeme`,
		`(?i)^todo`,
		`0123456789abcdef`, // Common test hex
		`GK0123456789`,     // Common test key prefix
	}

	for _, pattern := range placeholderPatterns {
		if matched, _ := regexp.MatchString(pattern, evidence); matched {
			return true
		}
	}

	return false
}

// scannerConfidence adjusts score based on scanner type
func scannerConfidence(scanner, evidence string) ConfidenceScore {
	switch scanner {
	case "gitleaks":
		// Gitleaks is good but has many false positives in tests
		if isPlaceholder(evidence) {
			return -2
		}
		return 0

	case "semgrep":
		// Semgrep is generally accurate
		return 1

	case "osv-scanner":
		// Dependency vulns are usually real
		return 2

	case "checkov":
		// IaC checks vary in severity
		return 0

	default:
		return 0
	}
}

// ShouldAutoIgnore returns true if finding should be auto-ignored
func ShouldAutoIgnore(score ConfidenceScore, filePath string) bool {
	// Auto-ignore very low confidence in test files
	if score <= ConfidenceVeryLow && isTestFile(filePath) {
		return true
	}

	return false
}
