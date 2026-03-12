package timeline

import (
	"fmt"
	"os/exec"
	"sort"
	"strings"
	"time"
)

// TimelineEvent represents a single event in the secret's lifecycle
type TimelineEvent struct {
	Timestamp   time.Time `json:"timestamp"`
	EventType   string    `json:"event_type"`
	Description string    `json:"description"`
	Author      string    `json:"author,omitempty"`
	File        string    `json:"file,omitempty"`
	Commit      string    `json:"commit,omitempty"`
	Branch      string    `json:"branch,omitempty"`
	Severity    string    `json:"severity"` // "info", "warning", "critical"
}

// TimelineReport contains the full lifecycle of a secret
type TimelineReport struct {
	SecretType    string          `json:"secret_type"`
	SecretHash    string          `json:"secret_hash"`
	FirstSeen     time.Time       `json:"first_seen"`
	LastSeen      time.Time       `json:"last_seen"`
	TotalDays     int             `json:"total_days"`
	Events        []TimelineEvent `json:"events"`
	EventCount    int             `json:"event_count"`
	CriticalCount int             `json:"critical_count"`
	WarningCount  int             `json:"warning_count"`
}

// Reconstruct builds a timeline of the secret's lifecycle
func Reconstruct(repoPath, secret string) (*TimelineReport, error) {
	report := &TimelineReport{
		SecretType: detectSecretType(secret),
		SecretHash: hashSecret(secret),
	}

	// Get all commits with the secret
	commits, err := getCommitsWithSecret(repoPath, secret)
	if err != nil {
		return nil, fmt.Errorf("failed to get commits: %w", err)
	}

	if len(commits) == 0 {
		return nil, fmt.Errorf("secret not found in git history")
	}

	// Build events from commits
	for _, commit := range commits {
		event := TimelineEvent{
			Timestamp: commit.Date,
			EventType: "commit",
			Severity:  "info",
			Author:    commit.Author,
			File:      commit.File,
			Commit:    commit.ShortHash,
		}

		// Determine event description based on context
		if commit.IsMerge {
			event.Description = fmt.Sprintf("Merged into %s", getBranchName(commit.Hash, repoPath))
			event.Severity = "warning"
		} else if strings.Contains(strings.ToLower(commit.Message), "prod") ||
			strings.Contains(strings.ToLower(commit.Message), "deploy") {
			event.Description = fmt.Sprintf("Deployed to production: %s", truncate(commit.Message, 60))
			event.Severity = "critical"
		} else if strings.Contains(strings.ToLower(commit.Message), "config") ||
			strings.Contains(strings.ToLower(commit.Message), "secret") ||
			strings.Contains(strings.ToLower(commit.Message), "key") ||
			strings.Contains(strings.ToLower(commit.Message), "password") {
			event.Description = fmt.Sprintf("Committed to config: %s", truncate(commit.Message, 60))
			event.Severity = "critical"
		} else {
			event.Description = fmt.Sprintf("Committed: %s", truncate(commit.Message, 60))
		}

		report.Events = append(report.Events, event)
	}

	// Add branch events
	branches, _ := getBranchesWithSecret(repoPath, secret)
	for _, branch := range branches {
		event := TimelineEvent{
			Timestamp:   report.Events[0].Timestamp, // Approximate
			EventType:   "branch",
			Description: fmt.Sprintf("Present in branch: %s", branch),
			Branch:      branch,
			Severity:    "warning",
		}

		if strings.Contains(branch, "main") || strings.Contains(branch, "master") || strings.Contains(branch, "prod") {
			event.Severity = "critical"
		}

		report.Events = append(report.Events, event)
	}

	// Check for remote exposure
	remoteURL, _ := getRemoteURL(repoPath)
	if remoteURL != "" {
		event := TimelineEvent{
			Timestamp:   report.Events[len(report.Events)-1].Timestamp,
			EventType:   "remote",
			Description: fmt.Sprintf("Pushed to remote: %s", truncate(remoteURL, 50)),
			Severity:    "critical",
		}

		if isPublicRemote(remoteURL) {
			event.Description += " (PUBLIC)"
		}

		report.Events = append(report.Events, event)
	}

	// Sort events by timestamp (oldest first)
	sort.Slice(report.Events, func(i, j int) bool {
		return report.Events[i].Timestamp.Before(report.Events[j].Timestamp)
	})

	// Calculate summary
	report.FirstSeen = report.Events[0].Timestamp
	report.LastSeen = report.Events[len(report.Events)-1].Timestamp
	report.TotalDays = int(report.LastSeen.Sub(report.FirstSeen).Hours() / 24)
	if report.TotalDays == 0 {
		report.TotalDays = 1
	}

	report.EventCount = len(report.Events)
	for _, e := range report.Events {
		switch e.Severity {
		case "critical":
			report.CriticalCount++
		case "warning":
			report.WarningCount++
		}
	}

	return report, nil
}

// CommitInfo from blastradius package (duplicated to avoid circular dependency)
type CommitInfo struct {
	Hash      string
	ShortHash string
	Author    string
	Email     string
	Date      time.Time
	Message   string
	File      string
	IsMerge   bool
}

// getCommitsWithSecret finds all commits containing the secret
func getCommitsWithSecret(repoPath, secret string) ([]CommitInfo, error) {
	cmd := exec.Command("git", "log", "-S", secret, "--pretty=format:%H|%an|%ae|%ai|%s", "--name-only")
	cmd.Dir = repoPath
	output, err := cmd.Output()
	if err != nil {
		return getCommitsWithSecretGrep(repoPath, secret)
	}

	var commits []CommitInfo
	var currentFile string

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}

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

func getCommitsWithSecretGrep(repoPath, secret string) ([]CommitInfo, error) {
	cmd := exec.Command("git", "grep", "-l", secret, "--all")
	cmd.Dir = repoPath
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	files := strings.Split(strings.TrimSpace(string(output)), "\n")
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

func getBranchName(commitHash, repoPath string) string {
	cmd := exec.Command("git", "branch", "--contains", commitHash)
	cmd.Dir = repoPath
	output, err := cmd.Output()
	if err != nil {
		return "unknown"
	}

	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	if len(lines) > 0 {
		return strings.TrimSpace(strings.TrimPrefix(lines[0], "*"))
	}

	return "unknown"
}

func getRemoteURL(repoPath string) (string, error) {
	cmd := exec.Command("git", "remote", "get-url", "origin")
	cmd.Dir = repoPath
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(string(output)), nil
}

func isPublicRemote(url string) bool {
	return strings.Contains(url, "github.com") ||
		strings.Contains(url, "gitlab.com") ||
		strings.Contains(url, "bitbucket.org")
}

func detectSecretType(secret string) string {
	if len(secret) > 20 && strings.HasPrefix(secret, "AKIA") {
		return "AWS Access Key"
	}
	if strings.HasPrefix(secret, "sk_live_") {
		return "Stripe Live Key"
	}
	if strings.HasPrefix(secret, "ghp_") {
		return "GitHub Personal Token"
	}
	return "Unknown Secret"
}

func hashSecret(secret string) string {
	hash := 0
	for _, c := range secret {
		hash = hash*31 + int(c)
	}
	return fmt.Sprintf("sha256:%x", hash)
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
