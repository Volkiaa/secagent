package confidence

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/secagent/secagent/pkg/types"
)

// TriageResult represents the result of automated triage
type TriageResult struct {
	ConfidenceScore ConfidenceScore
	ShouldIgnore    bool
	Reason          string
	Suggestion      string
}

// TriageFindings analyzes findings and adds confidence scores
func TriageFindings(findings []types.Finding) []types.Finding {
	for i := range findings {
		result := AnalyzeFinding(findings[i])
		findings[i].ConfidenceScore = int(result.ConfidenceScore)
		findings[i].AutoIgnored = result.ShouldIgnore
		
		// Add triage metadata
		if findings[i].Metadata == nil {
			findings[i].Metadata = make(map[string]interface{})
		}
		findings[i].Metadata["triage_reason"] = result.Reason
		findings[i].Metadata["triage_suggestion"] = result.Suggestion
	}
	
	return findings
}

// AnalyzeFinding analyzes a single finding
func AnalyzeFinding(finding types.Finding) TriageResult {
	score := CalculateConfidence(
		finding.Scanner,
		finding.Location.File,
		finding.Evidence,
		hasUserInput(finding),
	)
	
	result := TriageResult{
		ConfidenceScore: score,
		ShouldIgnore:    ShouldAutoIgnore(score, finding.Location.File),
	}
	
	// Generate reason and suggestion
	if result.ShouldIgnore {
		result.Reason = "Low confidence + test file"
		result.Suggestion = "Auto-ignored (likely false positive)"
	} else if score <= ConfidenceLow {
		result.Reason = "Low confidence score"
		result.Suggestion = "Review manually (likely false positive)"
	} else if score >= ConfidenceHigh {
		result.Reason = "High confidence score"
		result.Suggestion = "Prioritize for fixing"
	} else {
		result.Reason = "Medium confidence"
		result.Suggestion = "Review when time permits"
	}
	
	// Add specific reasons
	if isTestFile(finding.Location.File) {
		result.Reason += " (test file)"
	}
	
	if isPlaceholder(finding.Evidence) {
		result.Reason += " (placeholder detected)"
		result.ShouldIgnore = true
	}
	
	// Scanner-specific suggestions
	switch finding.Scanner {
	case "gitleaks":
		if isPlaceholder(finding.Evidence) {
			result.ConfidenceScore = ConfidenceVeryLow
			result.ShouldIgnore = true
			result.Suggestion = "Test fixture - safe to ignore"
		} else if isTestFile(finding.Location.File) {
			result.ConfidenceScore = ConfidenceLow
			result.Suggestion = "Test file secret - likely placeholder"
		} else {
			result.Suggestion = "ROTATE IMMEDIATELY if real"
		}
		
	case "semgrep":
		// Check for SQL injection rules
		if strings.Contains(finding.CheckID, "sqlalchemy") || 
		   strings.Contains(finding.CheckID, "sql-injection") ||
		   strings.Contains(finding.CheckID, "raw-query") {
			// Check if file uses LiteralString (type-safe)
			if hasTypeSafeSQL(finding.Location.File) {
				result.ConfidenceScore = ConfidenceVeryLow
				result.ShouldIgnore = true
				result.Suggestion = "Type-safe SQL (LiteralString) - false positive"
			} else {
				result.Suggestion = "Review SQL query for injection"
			}
		}
		
	case "osv-scanner":
		result.Suggestion = "Update dependency to fix"
		
	case "checkov":
		if isTestFile(finding.Location.File) {
			result.ConfidenceScore = ConfidenceLow
			result.Suggestion = "Test infrastructure - low priority"
		}
	}
	
	return result
}

// hasUserInput checks if finding description mentions user input
func hasUserInput(finding types.Finding) bool {
	inputKeywords := []string{
		"user input", "user-controlled", "external input",
		"request parameter", "query parameter", "form input",
		"command line", "argv", "environment variable",
	}
	
	desc := strings.ToLower(finding.Description + " " + finding.Title)
	for _, keyword := range inputKeywords {
		if strings.Contains(desc, keyword) {
			return true
		}
	}
	
	return false
}

// hasTypeSafeSQL checks if a Python file uses LiteralString for SQL queries
func hasTypeSafeSQL(filePath string) bool {
	if !strings.HasSuffix(filePath, ".py") {
		return false
	}
	
	// Read the file and check for LiteralString usage
	data, err := os.ReadFile(filePath)
	if err != nil {
		return false
	}
	
	content := string(data)
	
	// Check if file imports LiteralString
	if !strings.Contains(content, "LiteralString") {
		return false
	}
	
	// Check if it's used in function signatures (type hints)
	// Pattern: def func(..., param: LiteralString, ...)
	typeSafePatterns := []string{
		": LiteralString",
		": typing.LiteralString",
		"-> LiteralString",
	}
	
	for _, pattern := range typeSafePatterns {
		if strings.Contains(content, pattern) {
			return true
		}
	}
	
	return false
}

// getFileExtension returns the file extension
func getFileExtension(filePath string) string {
	return strings.ToLower(filepath.Ext(filePath))
}

// PrintTriageSummary prints a summary of triage results
func PrintTriageSummary(findings []types.Finding) {
	total := len(findings)
	autoIgnored := 0
	highConfidence := 0
	lowConfidence := 0
	
	for _, f := range findings {
		if f.AutoIgnored {
			autoIgnored++
		}
		if f.ConfidenceScore >= 4 {
			highConfidence++
		} else if f.ConfidenceScore <= 2 {
			lowConfidence++
		}
	}
	
	fmt.Println("\n=== Automated Triage Summary ===")
	fmt.Printf("Total findings: %d\n", total)
	fmt.Printf("Auto-ignored (false positives): %d (%.1f%%)\n", 
		autoIgnored, float64(autoIgnored)/float64(total)*100)
	fmt.Printf("High confidence (fix first): %d (%.1f%%)\n", 
		highConfidence, float64(highConfidence)/float64(total)*100)
	fmt.Printf("Low confidence (review later): %d (%.1f%%)\n", 
		lowConfidence, float64(lowConfidence)/float64(total)*100)
	fmt.Println()
}
