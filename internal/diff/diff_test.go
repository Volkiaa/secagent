package diff

import (
	"os"
	"testing"
)

func TestGetChangedFiles(t *testing.T) {
	// Skip if not in a git repository
	if _, err := os.Stat(".git"); os.IsNotExist(err) {
		t.Skip("Not in a git repository, skipping test")
	}

	tests := []struct {
		name    string
		commit  string
		wantErr bool
	}{
		{"HEAD", "HEAD", false},
		{"empty commit", "", false},
		{"invalid commit", "invalid-branch-name", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			files, err := GetChangedFiles(".", tt.commit)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetChangedFiles() error = %v, wantErr %v", err, tt.wantErr)
			}
			if files == nil && !tt.wantErr {
				t.Error("GetChangedFiles() returned nil, expected slice")
			}
		})
	}
}

func TestGetChangedDirectories(t *testing.T) {
	tests := []struct {
		name     string
		files    []string
		wantDirs []string
	}{
		{
			name:     "empty files",
			files:    []string{},
			wantDirs: []string{},
		},
		{
			name:     "single file",
			files:    []string{"/app/src/main.go"},
			wantDirs: []string{"/app/src"},
		},
		{
			name:     "multiple files same dir",
			files:    []string{"/app/src/main.go", "/app/src/utils.go"},
			wantDirs: []string{"/app/src"},
		},
		{
			name:     "multiple files different dirs",
			files:    []string{"/app/src/main.go", "/app/test/main_test.go"},
			wantDirs: []string{"/app/src", "/app/test"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dirs := GetChangedDirectories(tt.files)
			if len(dirs) != len(tt.wantDirs) {
				t.Errorf("GetChangedDirectories() returned %d dirs, want %d", len(dirs), len(tt.wantDirs))
			}
		})
	}
}

func TestIsFileChanged(t *testing.T) {
	changedFiles := []string{
		"/app/src/main.go",
		"/app/test/main_test.go",
	}

	tests := []struct {
		name     string
		filePath string
		want     bool
	}{
		{"file in list", "/app/src/main.go", true},
		{"file not in list", "/app/src/other.go", false},
		{"empty list", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsFileChanged(tt.filePath, changedFiles)
			if got != tt.want {
				t.Errorf("IsFileChanged(%q) = %v, want %v", tt.filePath, got, tt.want)
			}
		})
	}
}

func TestGetChangedFiles_NotGitRepo(t *testing.T) {
	// Create temp directory that's not a git repo
	tmpDir := t.TempDir()

	files, err := GetChangedFiles(tmpDir, "HEAD")
	if err != nil {
		t.Errorf("GetChangedFiles() in non-git repo returned error: %v", err)
	}
	if files != nil {
		t.Errorf("GetChangedFiles() in non-git repo returned %v, want nil", files)
	}
}

func TestGetChangedDirectories_Unique(t *testing.T) {
	files := []string{
		"/app/src/main.go",
		"/app/src/utils.go",
		"/app/src/main.go", // duplicate
	}

	dirs := GetChangedDirectories(files)
	
	// Should have only one unique directory
	if len(dirs) != 1 {
		t.Errorf("GetChangedDirectories() returned %d dirs, want 1", len(dirs))
	}
}

func TestGetCommonParent(t *testing.T) {
	tests := []struct {
		name    string
		target  string
		files   []string
		wantLen int
	}{
		{
			name:    "no files",
			target:  ".",
			files:   []string{},
			wantLen: 0,
		},
		{
			name:    "single file",
			target:  ".",
			files:   []string{"src/main.go"},
			wantLen: 1,
		},
		{
			name:    "multiple files",
			target:  ".",
			files:   []string{"src/main.go", "src/utils.go", "test/main_test.go"},
			wantLen: 2, // src and test directories
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dirs := GetChangedDirectories(tt.files)
			if len(dirs) != tt.wantLen {
				t.Errorf("GetChangedDirectories() returned %d dirs, want %d", len(dirs), tt.wantLen)
			}
		})
	}
}
