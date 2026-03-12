package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/secagent/secagent/pkg/types"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg == nil {
		t.Fatal("DefaultConfig() returned nil")
	}

	// Check scanners
	if !cfg.Scanners["osv-scanner"] {
		t.Error("Default config should enable osv-scanner")
	}
	if !cfg.Scanners["gitleaks"] {
		t.Error("Default config should enable gitleaks")
	}

	// Check thresholds
	if cfg.Thresholds.FailOn != types.SeverityCritical {
		t.Errorf("Default FailOn = %v, want %v", cfg.Thresholds.FailOn, types.SeverityCritical)
	}
	if cfg.Thresholds.WarnOn != types.SeverityHigh {
		t.Errorf("Default WarnOn = %v, want %v", cfg.Thresholds.WarnOn, types.SeverityHigh)
	}

	// Check output
	if cfg.Output.Format != "table" {
		t.Errorf("Default Format = %v, want table", cfg.Output.Format)
	}
	if !cfg.Output.Colors {
		t.Error("Default Colors should be true")
	}
	if cfg.Output.Verbose {
		t.Error("Default Verbose should be false")
	}

	// Check cache
	if !cfg.Cache.Enabled {
		t.Error("Default Cache should be enabled")
	}
	if cfg.Cache.TTL != "24h" {
		t.Errorf("Default Cache TTL = %v, want 24h", cfg.Cache.TTL)
	}
}

func TestConfigSaveLoad(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	cfg := DefaultConfig()
	cfg.Output.Format = "json"
	cfg.Output.Verbose = true

	// Save config
	err := Save(cfg, configPath)
	if err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	// Load config
	loaded, err := Load(configPath)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if loaded.Output.Format != "json" {
		t.Errorf("Load() Format = %v, want json", loaded.Output.Format)
	}
	if !loaded.Output.Verbose {
		t.Error("Load() Verbose should be true")
	}
}

func TestConfigLoadNonExistent(t *testing.T) {
	_, err := Load("/nonexistent/path/config.yaml")
	if err == nil {
		t.Error("Load() should return error for non-existent file")
	}
}

func TestInit(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	err := Init(configPath)
	if err != nil {
		t.Fatalf("Init() error = %v", err)
	}

	// Check file exists
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		t.Error("Init() should create config file")
	}

	// Load and verify
	cfg, err := Load(configPath)
	if err != nil {
		t.Fatalf("Load() after Init() error = %v", err)
	}

	if cfg == nil {
		t.Error("Init() should create valid config")
	}
}

func TestShow(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	cfg := DefaultConfig()
	Save(cfg, configPath)

	result, err := Show(configPath)
	if err != nil {
		t.Fatalf("Show() error = %v", err)
	}

	if result["config_file"] != configPath {
		t.Errorf("Show() config_file = %v, want %v", result["config_file"], configPath)
	}
	if result["scanners"] == nil {
		t.Error("Show() should include scanners")
	}
}

func TestSet(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	cfg := DefaultConfig()
	Save(cfg, configPath)

	tests := []struct {
		key   string
		value interface{}
	}{
		{"output.format", "json"},
		{"output.colors", false},
		{"output.verbose", true},
		{"cache.enabled", false},
		{"cache.ttl", "12h"},
		{"thresholds.fail_on", "high"},
		{"thresholds.warn_on", "medium"},
	}

	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			err := Set(configPath, tt.key, tt.value)
			if err != nil {
				t.Errorf("Set(%q) error = %v", tt.key, err)
			}

			// Verify
			loaded, _ := Load(configPath)
			switch tt.key {
			case "output.format":
				if loaded.Output.Format != tt.value {
					t.Errorf("Set(%q) = %v, want %v", tt.key, loaded.Output.Format, tt.value)
				}
			case "output.colors":
				if loaded.Output.Colors != tt.value {
					t.Errorf("Set(%q) = %v, want %v", tt.key, loaded.Output.Colors, tt.value)
				}
			case "cache.ttl":
				if loaded.Cache.TTL != tt.value {
					t.Errorf("Set(%q) = %v, want %v", tt.key, loaded.Cache.TTL, tt.value)
				}
			}
		})
	}

	t.Run("unknown key", func(t *testing.T) {
		err := Set(configPath, "unknown.key", "value")
		if err == nil {
			t.Error("Set() should return error for unknown key")
		}
	})
}
