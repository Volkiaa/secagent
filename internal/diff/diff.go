package diff

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// GetChangedFiles returns a list of files changed since the specified commit
func GetChangedFiles(target, commit string) ([]string, error) {
	// Check if target is a git repository
	gitDir := filepath.Join(target, ".git")
	if _, err := os.Stat(gitDir); os.IsNotExist(err) {
		return nil, nil // Not a git repo, scan all files
	}

	// Get changed files from git
	var cmd *exec.Cmd
	if commit == "" || commit == "HEAD" {
		// Get staged + unstaged changes
		cmd = exec.Command("git", "diff", "--name-only")
	} else if commit == "staged" {
		// Only staged changes
		cmd = exec.Command("git", "diff", "--cached", "--name-only")
	} else if commit == "unstaged" {
		// Only unstaged changes
	} else {
		// Changes since specific commit
		cmd = exec.Command("git", "diff", "--name-only", commit)
	}

	cmd.Dir = target
	output, err := cmd.Output()
	if err != nil {
		// Git command failed, might not be a git repo or invalid commit
		return nil, nil
	}

	// Parse output
	files := strings.Split(strings.TrimSpace(string(output)), "\n")
	
	// Also get untracked files
	cmd = exec.Command("git", "ls-files", "--others", "--exclude-standard")
	cmd.Dir = target
	untrackedOutput, err := cmd.Output()
	if err == nil && len(untrackedOutput) > 0 {
		untrackedFiles := strings.Split(strings.TrimSpace(string(untrackedOutput)), "\n")
		files = append(files, untrackedFiles...)
	}
	var changedFiles []string
	for _, file := range files {
		file = strings.TrimSpace(file)
		if file != "" {
			// Make path absolute
			absPath := filepath.Join(target, file)
			changedFiles = append(changedFiles, absPath)
		}
	}

	return changedFiles, nil
}

// GetChangedDirectories returns unique directories containing changed files
func GetChangedDirectories(changedFiles []string) []string {
	dirs := make(map[string]bool)
	for _, file := range changedFiles {
		dir := filepath.Dir(file)
		dirs[dir] = true
	}

	result := make([]string, 0, len(dirs))
	for dir := range dirs {
		result = append(result, dir)
	}
	return result
}

// IsFileChanged checks if a specific file is in the changed files list
func IsFileChanged(filePath string, changedFiles []string) bool {
	for _, changed := range changedFiles {
		if filePath == changed {
			return true
		}
	}
	return false
}
