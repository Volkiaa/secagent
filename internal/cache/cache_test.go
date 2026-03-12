package cache

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/secagent/secagent/pkg/types"
)

func TestCacheNew(t *testing.T) {
	t.Run("cache disabled", func(t *testing.T) {
		c, err := New("", false, "24h")
		if err != nil {
			t.Errorf("New() error = %v", err)
		}
		if c.enabled {
			t.Error("New() cache should be disabled")
		}
	})

	t.Run("cache enabled", func(t *testing.T) {
		tmpDir := t.TempDir()
		c, err := New(tmpDir, true, "1h")
		if err != nil {
			t.Errorf("New() error = %v", err)
		}
		if !c.enabled {
			t.Error("New() cache should be enabled")
		}
		if c.ttl != time.Hour {
			t.Errorf("New() ttl = %v, want %v", c.ttl, time.Hour)
		}
	})

	t.Run("invalid ttl defaults to 24h", func(t *testing.T) {
		tmpDir := t.TempDir()
		c, err := New(tmpDir, true, "invalid")
		if err != nil {
			t.Errorf("New() error = %v", err)
		}
		if c.ttl != 24*time.Hour {
			t.Errorf("New() ttl = %v, want %v", c.ttl, 24*time.Hour)
		}
	})
}

func TestCacheGetSet(t *testing.T) {
	tmpDir := t.TempDir()
	c, _ := New(tmpDir, true, "24h")

	t.Run("set and get", func(t *testing.T) {
		findings := []types.Finding{
			{ID: "test-1", Scanner: "test-scanner", Severity: types.SeverityHigh},
		}

		err := c.Set("/test/target", "test-scanner", findings)
		if err != nil {
			t.Errorf("Set() error = %v", err)
		}

		got, ok := c.Get("/test/target", "test-scanner")
		if !ok {
			t.Error("Get() should return true")
		}
		if len(got) != 1 {
			t.Errorf("Get() returned %d findings, want 1", len(got))
		}
	})

	t.Run("get non-existent", func(t *testing.T) {
		_, ok := c.Get("/nonexistent", "test-scanner")
		if ok {
			t.Error("Get() should return false for non-existent key")
		}
	})

	t.Run("different scanner", func(t *testing.T) {
		findings := []types.Finding{
			{ID: "test-2", Scanner: "other-scanner"},
		}
		c.Set("/test/target", "other-scanner", findings)

		got, ok := c.Get("/test/target", "test-scanner")
		if !ok {
			t.Error("Get() should still return cached value for original scanner")
		}
		if len(got) != 1 {
			t.Errorf("Get() returned %d findings, want 1", len(got))
		}
	})
}

func TestCacheClear(t *testing.T) {
	tmpDir := t.TempDir()
	c, _ := New(tmpDir, true, "24h")

	// Set some values
	c.Set("/test/target", "scanner", []types.Finding{{ID: "test"}})

	err := c.Clear()
	if err != nil {
		t.Errorf("Clear() error = %v", err)
	}

	_, ok := c.Get("/test/target", "scanner")
	if ok {
		t.Error("Clear() should remove all cached entries")
	}
}

func TestCacheKey(t *testing.T) {
	tests := []struct {
		target  string
		scanner string
		want    string
	}{
		{"/app", "gitleaks", "gitleaks:/app"},
		{"/app/src", "semgrep", "semgrep:/app/src"},
		{"", "test", "test:"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := cacheKey(tt.target, tt.scanner)
			if got != tt.want {
				t.Errorf("cacheKey() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCachePersistence(t *testing.T) {
	tmpDir := t.TempDir()

	// Create cache and set value
	c1, _ := New(tmpDir, true, "24h")
	c1.Set("/test/target", "scanner", []types.Finding{{ID: "persistent-test"}})

	// Create new cache instance (simulates restart)
	c2, _ := New(tmpDir, true, "24h")

	got, ok := c2.Get("/test/target", "scanner")
	if !ok {
		t.Error("Cache should persist across instances")
	}
	if len(got) != 1 {
		t.Errorf("Got %d findings, want 1", len(got))
	}
}

func TestHashDirectory(t *testing.T) {
	tmpDir := t.TempDir()

	// Create test files
	os.WriteFile(filepath.Join(tmpDir, "file1.txt"), []byte("content1"), 0644)
	os.WriteFile(filepath.Join(tmpDir, "file2.txt"), []byte("content2"), 0644)

	hash1, err := hashDirectory(tmpDir)
	if err != nil {
		t.Errorf("hashDirectory() error = %v", err)
	}

	// Hash should be consistent
	hash2, err := hashDirectory(tmpDir)
	if err != nil {
		t.Errorf("hashDirectory() error = %v", err)
	}

	if hash1 != hash2 {
		t.Error("hashDirectory() should return consistent hashes")
	}

	// Modify a file
	os.WriteFile(filepath.Join(tmpDir, "file1.txt"), []byte("modified"), 0644)

	hash3, err := hashDirectory(tmpDir)
	if err != nil {
		t.Errorf("hashDirectory() error = %v", err)
	}

	if hash1 == hash3 {
		t.Error("hashDirectory() should change when files change")
	}
}
