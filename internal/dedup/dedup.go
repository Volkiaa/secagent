package dedup

import (
	"fmt"
	"strings"

	"github.com/secagent/secagent/pkg/types"
)

// Deduplicate removes duplicate findings from multiple scanners
func Deduplicate(findings []types.Finding) []types.Finding {
	seen := make(map[string]*types.Finding)
	result := make([]types.Finding, 0)

	for i := range findings {
		finding := &findings[i]
		key := generateKey(*finding)
		
		if existing, ok := seen[key]; ok {
			// Merge: keep the higher severity, combine scanners
			scanners := mergeScanners(*existing, *finding)
			if severityRank(finding.Severity) > severityRank(existing.Severity) {
				// Keep new finding but merge scanners
				if finding.Metadata == nil {
					finding.Metadata = make(map[string]interface{})
				}
				finding.Metadata["scanners"] = scanners
				seen[key] = finding
			} else {
				// Keep existing but merge scanners
				if existing.Metadata == nil {
					existing.Metadata = make(map[string]interface{})
				}
				existing.Metadata["scanners"] = scanners
			}
		} else {
			if finding.Metadata == nil {
				finding.Metadata = make(map[string]interface{})
			}
			finding.Metadata["scanners"] = []string{finding.Scanner}
			seen[key] = finding
		}
	}

	// Convert map back to slice
	for _, f := range seen {
		result = append(result, *f)
	}

	return result
}

// generateKey creates a unique key for deduplication
func generateKey(f types.Finding) string {
	// Priority 1: CVE ID (most reliable for vulns)
	if f.CVE != "" {
		return fmt.Sprintf("cve:%s", f.CVE)
	}

	// Priority 2: CWE ID + file + line (for code issues)
	if f.CWE != "" && f.Location.File != "" && f.Location.Line > 0 {
		return fmt.Sprintf("cwe:%s:%s:%d", f.CWE, f.Location.File, f.Location.Line)
	}

	// Priority 3: Package + version (for dependency vulns without CVE)
	if f.Location.Package != "" && f.Location.Dependency != "" {
		return fmt.Sprintf("pkg:%s:%s", f.Location.Package, f.Location.Dependency)
	}

	// Priority 4: File + line + title (for secrets/code issues)
	if f.Location.File != "" && f.Location.Line > 0 {
		return fmt.Sprintf("loc:%s:%d:%s", f.Location.File, f.Location.Line, normalizeTitle(f.Title))
	}

	// Fallback: Full ID (no dedup)
	return fmt.Sprintf("id:%s", f.ID)
}

// normalizeTitle normalizes a title for comparison
func normalizeTitle(title string) string {
	// Convert to lowercase and remove common prefixes
	title = strings.ToLower(title)
	title = strings.ReplaceAll(title, "potential ", "")
	title = strings.ReplaceAll(title, "detected ", "")
	title = strings.ReplaceAll(title, "identified ", "")
	// Take first 50 chars for comparison
	if len(title) > 50 {
		title = title[:50]
	}
	return strings.TrimSpace(title)
}

// severityRank returns numeric rank for severity comparison
func severityRank(sev types.Severity) int {
	switch sev {
	case types.SeverityCritical:
		return 5
	case types.SeverityHigh:
		return 4
	case types.SeverityMedium:
		return 3
	case types.SeverityLow:
		return 2
	case types.SeverityInfo:
		return 1
	default:
		return 0
	}
}

// mergeScanners combines scanner lists from two findings
func mergeScanners(a, b types.Finding) []string {
	scanners := make(map[string]bool)
	
	// Get existing scanners from metadata
	if a.Metadata != nil {
		if s, ok := a.Metadata["scanners"].([]string); ok {
			for _, scanner := range s {
				scanners[scanner] = true
			}
		}
	} else {
		scanners[a.Scanner] = true
	}
	
	if b.Metadata != nil {
		if s, ok := b.Metadata["scanners"].([]string); ok {
			for _, scanner := range s {
				scanners[scanner] = true
			}
		}
	} else {
		scanners[b.Scanner] = true
	}

	// Convert back to slice
	result := make([]string, 0, len(scanners))
	for scanner := range scanners {
		result = append(result, scanner)
	}
	return result
}
