package types

// Severity represents the severity level of a finding
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// FindingType represents the type of security finding
type FindingType string

const (
	TypeDependency FindingType = "dependency"
	TypeSecret     FindingType = "secret"
	TypeCode       FindingType = "code"
	TypeContainer  FindingType = "container"
	TypeIaC        FindingType = "iac"
	TypeNetwork    FindingType = "network"
)

// Confidence represents the confidence level of a finding
type Confidence string

const (
	ConfidenceTruePositive Confidence = "true_positive"
	ConfidenceLikely       Confidence = "likely"
	ConfidencePossible     Confidence = "possible"
)

// Location represents where a finding was discovered
type Location struct {
	File       string `json:"file,omitempty"`
	Line       int    `json:"line,omitempty"`
	Column     int    `json:"column,omitempty"`
	Container  string `json:"container,omitempty"`
	URL        string `json:"url,omitempty"`
	Package    string `json:"package,omitempty"`
	Dependency string `json:"dependency,omitempty"`
}

// Finding represents a unified security finding
type Finding struct {
	ID          string                 `json:"id"`
	Scanner     string                 `json:"scanner"`
	Type        FindingType            `json:"type"`
	Severity    Severity               `json:"severity"`
	Title       string                 `json:"title"`
	Description string                 `json:"description"`
	Location    Location               `json:"location"`
	Evidence    string                 `json:"evidence,omitempty"`
	CVE         string                 `json:"cve,omitempty"`
	CWE         string                 `json:"cwe,omitempty"`
	CVSS        float64                `json:"cvss,omitempty"`
	Fix         string                 `json:"fix,omitempty"`
	References  []string               `json:"references,omitempty"`
	Confidence  Confidence             `json:"confidence,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// ScanResult represents the result of a scan operation
type ScanResult struct {
	Target    string     `json:"target"`
	Findings  []Finding  `json:"findings"`
	Errors    []string   `json:"errors,omitempty"`
	ScannedAt string     `json:"scanned_at"`
	Duration  string     `json:"duration"`
}

// Config represents the application configuration
type Config struct {
	Scanners   map[string]bool `json:"scanners,omitempty"`
	Thresholds Thresholds      `json:"thresholds,omitempty"`
	Output     OutputConfig    `json:"output,omitempty"`
	Cache      CacheConfig     `json:"cache,omitempty"`
	Ignore     IgnoreConfig    `json:"ignore,omitempty"`
	Diff       DiffConfig      `json:"diff,omitempty"`
}

// DiffConfig defines configuration for diff scanning
type DiffConfig struct {
	Enabled bool     `json:"enabled,omitempty"`
	Commit  string   `json:"commit,omitempty"`  // Commit to diff against (e.g., "HEAD~1", "main")
	Files   []string `json:"files,omitempty"`   // Specific files to scan (from git diff)
}

// IgnoreConfig defines rules for filtering out findings
type IgnoreConfig struct {
	Rules      []string `json:"rules,omitempty"`       // Ignore specific rule/check IDs (e.g., "CKV_AWS_20", "python.lang.security.*")
	Files      []string `json:"files,omitempty"`       // Ignore files by glob pattern (e.g., "**/*.test.py", "vendor/**")
	Severities []string `json:"severities,omitempty"`  // Ignore findings by severity (e.g., "low", "info")
	Paths      []string `json:"paths,omitempty"`       // Ignore directories by glob pattern (e.g., "test/**", "vendor/**")
}

type Thresholds struct {
	FailOn Severity `json:"fail_on,omitempty"`
	WarnOn Severity `json:"warn_on,omitempty"`
}

type OutputConfig struct {
	Format  string `json:"format,omitempty"`
	Colors  bool   `json:"colors,omitempty"`
	Verbose bool   `json:"verbose,omitempty"`
}

type CacheConfig struct {
	Enabled bool   `json:"enabled,omitempty"`
	TTL     string `json:"ttl,omitempty"`
}
