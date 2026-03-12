package config

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/viper"

	"github.com/secagent/secagent/pkg/types"
)

const (
	configDir  = ".secagent"
	configName = "config"
	configType = "yaml"
)

// DefaultConfig returns the default configuration
func DefaultConfig() *types.Config {
	return &types.Config{
		Scanners: map[string]bool{
			"osv-scanner": true,
			"gitleaks":    true,
		},
		Thresholds: types.Thresholds{
			FailOn: types.SeverityCritical,
			WarnOn: types.SeverityHigh,
		},
		Output: types.OutputConfig{
			Format:  "table",
			Colors:  true,
			Verbose: false,
		},
		Cache: types.CacheConfig{
			Enabled: true,
			TTL:     "24h",
		},
		Ignore: types.IgnoreConfig{},
	}
}

// Load loads the configuration from file
func Load() (*types.Config, error) {
	// Set up viper
	viper.SetConfigName(configName)
	viper.SetConfigType(configType)

	// Look for config in home directory
	home, err := os.UserHomeDir()
	if err == nil {
		viper.AddConfigPath(filepath.Join(home, configDir))
	}

	// Also look in current directory
	viper.AddConfigPath(".")

	// Set defaults
	cfg := DefaultConfig()
	viper.SetDefault("scanners", cfg.Scanners)
	viper.SetDefault("thresholds.fail_on", string(cfg.Thresholds.FailOn))
	viper.SetDefault("thresholds.warn_on", string(cfg.Thresholds.WarnOn))
	viper.SetDefault("output.format", cfg.Output.Format)
	viper.SetDefault("output.colors", cfg.Output.Colors)
	viper.SetDefault("output.verbose", cfg.Output.Verbose)
	viper.SetDefault("cache.enabled", cfg.Cache.Enabled)
	viper.SetDefault("cache.ttl", cfg.Cache.TTL)

	// Read config file (if it exists)
	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return cfg, fmt.Errorf("error reading config file: %w", err)
		}
		// Config file not found, use defaults
		return cfg, nil
	}

	// Unmarshal into config struct
	if err := viper.Unmarshal(cfg); err != nil {
		return cfg, fmt.Errorf("error unmarshaling config: %w", err)
	}

	return cfg, nil
}

// Save saves the configuration to file
func Save(cfg *types.Config) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("error getting home directory: %w", err)
	}

	configPath := filepath.Join(home, configDir)
	if err := os.MkdirAll(configPath, 0755); err != nil {
		return fmt.Errorf("error creating config directory: %w", err)
	}

	viper.Set("scanners", cfg.Scanners)
	viper.Set("thresholds.fail_on", string(cfg.Thresholds.FailOn))
	viper.Set("thresholds.warn_on", string(cfg.Thresholds.WarnOn))
	viper.Set("output.format", cfg.Output.Format)
	viper.Set("output.colors", cfg.Output.Colors)
	viper.Set("output.verbose", cfg.Output.Verbose)
	viper.Set("cache.enabled", cfg.Cache.Enabled)
	viper.Set("cache.ttl", cfg.Cache.TTL)
	viper.Set("ignore", cfg.Ignore)

	configFile := filepath.Join(configPath, fmt.Sprintf("%s.%s", configName, configType))
	if err := viper.WriteConfigAs(configFile); err != nil {
		return fmt.Errorf("error writing config file: %w", err)
	}

	return nil
}

// Init creates a default config file
func Init() error {
	cfg := DefaultConfig()
	return Save(cfg)
}

// Show returns the current config as a map
func Show() (map[string]interface{}, error) {
	cfg, err := Load()
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"scanners":   cfg.Scanners,
		"thresholds": cfg.Thresholds,
		"output":     cfg.Output,
		"cache":      cfg.Cache,
		"ignore":     cfg.Ignore,
		"config_file": viper.ConfigFileUsed(),
	}, nil
}

// Set sets a configuration value
func Set(key string, value interface{}) error {
	cfg, err := Load()
	if err != nil {
		return err
	}

	// Parse key and set value
	switch key {
	case "output.format":
		cfg.Output.Format = value.(string)
	case "output.colors":
		cfg.Output.Colors = value.(bool)
	case "output.verbose":
		cfg.Output.Verbose = value.(bool)
	case "cache.enabled":
		cfg.Cache.Enabled = value.(bool)
	case "cache.ttl":
		cfg.Cache.TTL = value.(string)
	case "thresholds.fail_on":
		cfg.Thresholds.FailOn = types.Severity(value.(string))
	case "thresholds.warn_on":
		cfg.Thresholds.WarnOn = types.Severity(value.(string))
	default:
		return fmt.Errorf("unknown config key: %s", key)
	}

	return Save(cfg)
}
