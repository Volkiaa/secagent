package blastradius

import (
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

// BlastRadiusReport contains the full analysis of a secret's exposure
type BlastRadiusReport struct {
	SecretType      string        `json:"secret_type"`
	SecretValue     string        `json:"secret_value,omitempty"`
	SecretHash      string        `json:"secret_hash"`
	FirstSeen       time.Time     `json:"first_seen"`
	LastSeen        time.Time     `json:"last_seen"`
	ExposureDays    int           `json:"exposure_days"`
	CommitsAffected []CommitInfo  `json:"commits_affected"`
	AuthorsInvolved []string      `json:"authors_involved"`
	FilesAffected   []string      `json:"files_affected"`
	BranchesFound   []string      `json:"branches_found"`
	PublicExposure  bool          `json:"public_exposure"`
	ProductionUse   bool          `json:"production_use"`
	RiskScore       float64       `json:"risk_score"`
	Recommendations []string      `json:"recommendations"`
}

// CommitInfo represents a single commit that contained the secret
type CommitInfo struct {
	Hash      string    `json:"hash"`
	ShortHash string    `json:"short_hash"`
	Author    string    `json:"author"`
	Email     string    `json:"email"`
	Date      time.Time `json:"date"`
	Message   string    `json:"message"`
	File      string    `json:"file"`
	IsMerge   bool      `json:"is_merge"`
}

// Analyze performs blast radius analysis on a secret in a git repo
func Analyze(repoPath, secret string) (*BlastRadiusReport, error) {
	report := &BlastRadiusReport{
		SecretValue: maskSecret(secret),
		SecretHash:  hashSecret(secret),
		SecretType:  detectSecretType(secret),
	}

	// Get all commits containing the secret
	commits, err := getCommitsWithSecret(repoPath, secret)
	if err != nil {
		return nil, fmt.Errorf("failed to get commits: %w", err)
	}

	if len(commits) == 0 {
		return nil, fmt.Errorf("secret not found in git history")
	}

	report.CommitsAffected = commits

	// Calculate exposure window
	report.FirstSeen = commits[len(commits)-1].Date // Oldest commit
	report.LastSeen = commits[0].Date               // Newest commit
	report.ExposureDays = int(report.LastSeen.Sub(report.FirstSeen).Hours() / 24)
	if report.ExposureDays == 0 {
		report.ExposureDays = 1
	}

	// Collect unique authors
	authorMap := make(map[string]bool)
	for _, c := range commits {
		authorMap[c.Author] = true
	}
	for author := range authorMap {
		report.AuthorsInvolved = append(report.AuthorsInvolved, author)
	}

	// Collect unique files
	fileMap := make(map[string]bool)
	for _, c := range commits {
		fileMap[c.File] = true
	}
	for file := range fileMap {
		report.FilesAffected = append(report.FilesAffected, file)
	}

	// Check branches
	report.BranchesFound, _ = getBranchesWithSecret(repoPath, secret)

	// Check for public exposure
	report.PublicExposure = checkPublicExposure(repoPath)

	// Check for production use
	report.ProductionUse = checkProductionUse(repoPath, report.FilesAffected)

	// Calculate risk score
	report.RiskScore = calculateRiskScore(report)

	// Generate recommendations
	report.Recommendations = generateRecommendations(report)

	return report, nil
}

// getCommitsWithSecret finds all commits containing the secret
func getCommitsWithSecret(repoPath, secret string) ([]CommitInfo, error) {
	// Use git log -S to find commits that added/removed the secret
	cmd := exec.Command("git", "log", "-S", secret, "--pretty=format:%H|%an|%ae|%ai|%s", "--name-only")
	cmd.Dir = repoPath
	output, err := cmd.Output()
	if err != nil {
		// Secret might contain special chars, try with grep
		return getCommitsWithSecretGrep(repoPath, secret)
	}

	var commits []CommitInfo
	var currentFile string

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}

		// If line has no pipes, it's a filename
		if !strings.Contains(line, "|") {
			currentFile = line
			continue
		}

		parts := strings.SplitN(line, "|", 5)
		if len(parts) < 5 {
			continue
		}

		date, err := time.Parse("2006-01-02 15:04:05 -0700", parts[3])
		if err != nil {
			date = time.Now()
		}

		commits = append(commits, CommitInfo{
			Hash:      parts[0],
			ShortHash: parts[0][:8],
			Author:    parts[1],
			Email:     parts[2],
			Date:      date,
			Message:   parts[4],
			File:      currentFile,
			IsMerge:   strings.Contains(parts[4], "Merge"),
		})
	}

	return commits, nil
}

// getCommitsWithSecretGrep fallback for secrets with special chars
func getCommitsWithSecretGrep(repoPath, secret string) ([]CommitInfo, error) {
	// Use git grep to find the secret, then get commit info
	cmd := exec.Command("git", "grep", "-l", secret, "--all")
	cmd.Dir = repoPath
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	files := strings.Split(strings.TrimSpace(string(output)), "\n")

	// Get commit info for each file
	var commits []CommitInfo
	for _, file := range files {
		if file == "" {
			continue
		}

		cmd = exec.Command("git", "log", "--follow", "--pretty=format:%H|%an|%ae|%ai|%s", file)
		cmd.Dir = repoPath
		output, err := cmd.Output()
		if err != nil {
			continue
		}

		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			parts := strings.SplitN(line, "|", 5)
			if len(parts) < 5 {
				continue
			}

			date, _ := time.Parse("2006-01-02 15:04:05 -0700", parts[3])

			commits = append(commits, CommitInfo{
				Hash:      parts[0],
				ShortHash: parts[0][:8],
				Author:    parts[1],
				Email:     parts[2],
				Date:      date,
				Message:   parts[4],
				File:      file,
			})
		}
	}

	return commits, nil
}

// getBranchesWithSecret finds all branches containing the secret
func getBranchesWithSecret(repoPath, secret string) ([]string, error) {
	cmd := exec.Command("git", "branch", "-a", "--contains")
	cmd.Dir = repoPath
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	branches := strings.Split(strings.TrimSpace(string(output)), "\n")
	var result []string
	for _, b := range branches {
		b = strings.TrimSpace(b)
		if b != "" && !strings.HasPrefix(b, "*") {
			result = append(result, strings.TrimPrefix(b, "remotes/"))
		}
	}

	return result, nil
}

// checkPublicExposure determines if the repo is public
func checkPublicExposure(repoPath string) bool {
	// Check git remote for GitHub/GitLab public repo
	cmd := exec.Command("git", "remote", "get-url", "origin")
	cmd.Dir = repoPath
	output, err := cmd.Output()
	if err != nil {
		return false
	}

	url := string(output)
	// Check if it's a public GitHub repo
	if strings.Contains(url, "github.com") {
		// Could check GitHub API for visibility, but for now assume public if it has a remote
		return true
	}

	return false
}

// checkProductionUse looks for production indicators in file paths
func checkProductionUse(repoPath string, files []string) bool {
	prodPatterns := []string{
		"prod", "production", "live", "main", "master",
		"deploy", "release", "config/prod", "settings/prod",
		".env.prod", ".env.production", "credentials",
	}

	for _, file := range files {
		fileLower := strings.ToLower(file)
		for _, pattern := range prodPatterns {
			if strings.Contains(fileLower, pattern) {
				return true
			}
		}
	}

	return false
}

// detectSecretType identifies the type of secret
func detectSecretType(secret string) string {
	patterns := map[string]string{
		`AKIA[0-9A-Z]{16}`:                    "AWS Access Key",
		`(?i)aws[_-]?secret`:                  "AWS Secret Key",
		`sk_live_[0-9a-zA-Z]{10,}`:            "Stripe Live Key",
		`sk_test_[0-9a-zA-Z]{10,}`:            "Stripe Test Key",
		`ghp_[0-9a-zA-Z]{36}`:                 "GitHub Personal Token",
		`gho_[0-9a-zA-Z]{36}`:                 "GitHub OAuth Token",
		`xox[baprs]-[0-9a-zA-Z]{10,}`:         "Slack Token",
		`eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+`: "JWT Token",
		`(?i)password[\s]*[=:]`:               "Password",
		`(?i)(?:mongodb|postgres|mysql)://`:   "Database Connection String",
	}

	for pattern, secretType := range patterns {
		if matched, _ := regexp.MatchString(pattern, secret); matched {
			return secretType
		}
	}

	return "Unknown Secret"
}

// calculateRiskScore computes a risk score (0-10)
func calculateRiskScore(report *BlastRadiusReport) float64 {
	score := 0.0

	// Exposure duration
	if report.ExposureDays > 90 {
		score += 3.0
	} else if report.ExposureDays > 30 {
		score += 2.0
	} else if report.ExposureDays > 7 {
		score += 1.0
	}

	// Number of commits
	if len(report.CommitsAffected) > 20 {
		score += 2.0
	} else if len(report.CommitsAffected) > 5 {
		score += 1.0
	}

	// Number of authors
	if len(report.AuthorsInvolved) > 5 {
		score += 1.5
	} else if len(report.AuthorsInvolved) > 2 {
		score += 0.5
	}

	// Public exposure
	if report.PublicExposure {
		score += 2.0
	}

	// Production use
	if report.ProductionUse {
		score += 1.5
	}

	// Cap at 10
	if score > 10 {
		score = 10
	}

	return score
}

// generateRecommendations creates actionable remediation steps
func generateRecommendations(report *BlastRadiusReport) []string {
	var recs []string

	// Always recommend rotation
	recs = append(recs, fmt.Sprintf("Rotate %s immediately", report.SecretType))

	// Audit recommendations based on secret type
	switch {
	case strings.Contains(report.SecretType, "AWS"):
		recs = append(recs, "Review AWS CloudTrail logs for the exposure period")
		recs = append(recs, "Check for unauthorized EC2 instances, IAM changes, or S3 access")
	case strings.Contains(report.SecretType, "GitHub"):
		recs = append(recs, "Review GitHub audit logs for unusual repository access")
		recs = append(recs, "Check for unauthorized PRs, commits, or repository changes")
	case strings.Contains(report.SecretType, "Stripe"):
		recs = append(recs, "Review Stripe dashboard for unauthorized charges or API calls")
		recs = append(recs, "Check for new webhooks or API keys created")
	case strings.Contains(report.SecretType, "Slack"):
		recs = append(recs, "Review Slack audit logs for unauthorized bot actions")
		recs = append(recs, "Check for messages sent or channels accessed by the token")
	case strings.Contains(report.SecretType, "Database"):
		recs = append(recs, "Review database access logs for the exposure period")
		recs = append(recs, "Check for unauthorized queries, exports, or schema changes")
	}

	// Time-based recommendations
	if report.ExposureDays > 30 {
		recs = append(recs, fmt.Sprintf("Exposure was %d days - conduct thorough security review", report.ExposureDays))
	}

	// Public exposure
	if report.PublicExposure {
		recs = append(recs, "Secret was in public repo - assume compromised by automated scanners")
		recs = append(recs, "Consider this a high-severity incident")
	}

	// Multiple authors
	if len(report.AuthorsInvolved) > 3 {
		recs = append(recs, fmt.Sprintf("%d developers had access - ensure all have rotated local copies", len(report.AuthorsInvolved)))
	}

	return recs
}

// maskSecret hides most of the secret value for safe display
func maskSecret(secret string) string {
	if len(secret) <= 8 {
		return "****"
	}
	return secret[:4] + "..." + secret[len(secret)-4:]
}

// hashSecret creates a hash for tracking without storing the actual secret
func hashSecret(secret string) string {
	// Simple hash for demo - use SHA256 in production
	hash := 0
	for _, c := range secret {
		hash = hash*31 + int(c)
	}
	return fmt.Sprintf("sha256:%x", hash)
}
