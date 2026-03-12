package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/secagent/secagent/internal/config"
	"github.com/secagent/secagent/internal/orchestrate"
	"github.com/secagent/secagent/internal/output"
	"github.com/secagent/secagent/pkg/types"
	"github.com/secagent/secagent/internal/diff"
	"github.com/secagent/secagent/internal/blastradius"
	"github.com/secagent/secagent/internal/timeline"
	"github.com/secagent/secagent/scanners"
	"github.com/secagent/secagent/scanners/checkov"
	"github.com/secagent/secagent/scanners/gitleaks"
	"github.com/secagent/secagent/scanners/osv"
	"github.com/secagent/secagent/scanners/semgrep"
	"github.com/secagent/secagent/scanners/trivy"
)

var (
	version   = "0.1.0"
	buildTime = "unknown"
	gitCommit = "unknown"
)

var (
	scanTarget      string
	outputFormat    string
	outputFile      string
	scannerList     []string
	allScanners     bool
	verbose         bool
	liveTarget      string
	configFile      string
	diffTarget      string
	noCache         bool
	showIgnored     bool
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "secagent",
		Short: "Developer-First Security Scanner",
		Long: `secagent - One command to run all security scanners. Unified output. Actionable results.

secagent scan ./repo    # That's it. That's the product.`,
		Version: version,
	}

	// Add commands
	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(reportCmd)
	rootCmd.AddCommand(configCmd)
	rootCmd.AddCommand(doctorCmd)
	rootCmd.AddCommand(installHooksCmd)
	rootCmd.AddCommand(blastRadiusCmd)
	rootCmd.AddCommand(timelineCmd)

	// Execute
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Show version information",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("secagent version %s\n", version)
		fmt.Printf("  Build time: %s\n", buildTime)
		fmt.Printf("  Git commit: %s\n", gitCommit)
		fmt.Printf("  Go version: %s\n", getGoVersion())
	},
}

var scanCmd = &cobra.Command{
	Use:   "scan [target]",
	Short: "Scan a directory or repository for security issues",
	Long: `Scan a directory or repository for security issues using multiple scanners.

Examples:
  secagent scan .                    # Scan current directory
  secagent scan ./my-repo            # Scan a specific directory
  secagent scan --all                # Run all available scanners
  secagent scan --format json        # Output as JSON
  secagent scan -o report.md         # Save report to file`,
	Args: cobra.MaximumNArgs(1),
	RunE: runScan,
}

var reportCmd = &cobra.Command{
	Use:   "report",
	Short: "Generate a report from the last scan",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Println("Report generation from last scan is not yet implemented.")
		fmt.Println("Use 'secagent scan' with -o flag to save reports directly.")
		return nil
	},
}

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Manage configuration",
}

var configInitCmd = &cobra.Command{
	Use:   "init",
	Short: "Create default configuration file",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := config.Init(); err != nil {
			return fmt.Errorf("failed to create config: %w", err)
		}
		fmt.Println("✓ Configuration file created at ~/.secagent/config.yaml")
		return nil
	},
}

var configShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Show current configuration",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Show()
		if err != nil {
			return err
		}
		
		fmt.Println("Current Configuration:")
		fmt.Printf("  Config file: %v\n", cfg["config_file"])
		fmt.Printf("  Scanners: %v\n", cfg["scanners"])
		fmt.Printf("  Output format: %v\n", cfg["output"].(types.OutputConfig).Format)
		fmt.Printf("  Fail on: %v\n", cfg["thresholds"].(types.Thresholds).FailOn)
		fmt.Printf("  Warn on: %v\n", cfg["thresholds"].(types.Thresholds).WarnOn)
		return nil
	},
}

var doctorCmd = &cobra.Command{
	Use:   "doctor",
	Short: "Diagnose issues with secagent",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Println("SecAgent Doctor")
		fmt.Println("===============")
		
		// Check configuration
		fmt.Println("\n[✓] Configuration")
		cfg, err := config.Load()
		if err != nil {
			fmt.Printf("  [✗] Error loading config: %v\n", err)
		} else {
			fmt.Printf("  [✓] Config loaded successfully\n")
			fmt.Printf("  [✓] Scanners enabled: %v\n", cfg.Scanners)
		}
		
		// Check scanners
		fmt.Println("\n[✓] Scanners")
		registry := scanners.NewRegistry()
		registerScanners(registry)
		
		for _, scanner := range registry.GetAll() {
			if err := scanner.Check(); err != nil {
				fmt.Printf("  [✗] %s: %v\n", scanner.Name(), err)
			} else {
				fmt.Printf("  [✓] %s: available\n", scanner.Name())
			}
		}
		
		return nil
	},
}

var installHooksCmd = &cobra.Command{
	Use:   "install-hooks",
	Short: "Install git pre-commit hooks",
	Long: `Install git pre-commit hooks for automatic security scanning.

This command installs a pre-commit hook that scans staged files for:
- Secrets and credentials (gitleaks)
- Code security issues (semgrep)

The hook runs automatically before each commit.
`,
	RunE: func(cmd *cobra.Command, args []string) error {
		// Find script location
		scriptDir := findScriptDir()
		hookScript := filepath.Join(scriptDir, "pre-commit")
		
		// Check if script exists
		if _, err := os.Stat(hookScript); os.IsNotExist(err) {
			return fmt.Errorf("pre-commit script not found at %s", hookScript)
		}
		
		// Get git hooks directory
		gitDir, err := getGitDir()
		if err != nil {
			return fmt.Errorf("not in a git repository: %w", err)
		}
		
		hooksDir := filepath.Join(gitDir, "hooks")
		if err := os.MkdirAll(hooksDir, 0755); err != nil {
			return fmt.Errorf("failed to create hooks directory: %w", err)
		}
		
		// Install pre-commit hook
		preCommitHook := filepath.Join(hooksDir, "pre-commit")
		hookContent := fmt.Sprintf(`#!/bin/bash
# secagent pre-commit hook - Auto-generated
exec "%s" "$@"
`, hookScript)
		
		if err := os.WriteFile(preCommitHook, []byte(hookContent), 0755); err != nil {
			return fmt.Errorf("failed to install hook: %w", err)
		}
		
		fmt.Println("✓ Pre-commit hook installed successfully")
		fmt.Println()
		fmt.Printf("Hook location: %s\n", preCommitHook)
		fmt.Println()
		fmt.Println("To test the hook:")
		fmt.Println("  git commit --allow-empty -m 'test commit'")
		fmt.Println()
		fmt.Println("To bypass the hook (not recommended):")
		fmt.Println("  git commit --no-verify")
		
		return nil
	},
}

// findScriptDir finds the directory containing secagent scripts
func findScriptDir() string {
	// Try relative to current directory
	if _, err := os.Stat("scripts/pre-commit"); err == nil {
		abs, _ := filepath.Abs("scripts")
		return abs
	}
	
	// Try relative to executable
	exe, err := os.Executable()
	if err == nil {
		exeDir := filepath.Dir(exe)
		if _, err := os.Stat(filepath.Join(exeDir, "../scripts/pre-commit")); err == nil {
			abs, _ := filepath.Abs(filepath.Join(exeDir, "../scripts"))
			return abs
		}
	}
	
	// Default to current directory scripts
	abs, _ := filepath.Abs("scripts")
	return abs
}

// getGitDir returns the .git directory path
func getGitDir() (string, error) {
	cmd := exec.Command("git", "rev-parse", "--git-dir")
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}
	gitDir := strings.TrimSpace(string(output))
	return filepath.Abs(gitDir)
}

func init() {
	// Scan command flags
	scanCmd.Flags().StringVarP(&outputFormat, "format", "f", "table", "Output format (table, json, markdown)")
	scanCmd.Flags().StringVarP(&outputFile, "output", "o", "", "Output file (default: stdout)")
	scanCmd.Flags().StringSliceVarP(&scannerList, "scanners", "s", []string{}, "Comma-separated list of scanners to run")
	scanCmd.Flags().BoolVar(&allScanners, "all", false, "Run all available scanners")
	scanCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Verbose output")
	scanCmd.Flags().StringVar(&liveTarget, "live", "", "Scan a live URL (requires nuclei scanner)")
	scanCmd.Flags().StringVar(&configFile, "config", "", "Config file path")
	scanCmd.Flags().StringVar(&diffTarget, "diff", "", "Scan only changed files since commit (e.g., HEAD~1, main)")
	scanCmd.Flags().BoolVar(&noCache, "no-cache", false, "Disable caching")
	scanCmd.Flags().BoolVar(&showIgnored, "show-ignored", false, "Show auto-ignored findings (false positives)")

	// Config subcommands
	configCmd.AddCommand(configInitCmd)
	configCmd.AddCommand(configShowCmd)
}

func runScan(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	// Handle interrupts
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Println("\nInterrupted, shutting down...")
		cancel()
	}()

	// Determine target
	target := "."
	if len(args) > 0 {
		target = args[0]
	}

	// Check if target exists
	if _, err := os.Stat(target); os.IsNotExist(err) {
		return fmt.Errorf("target '%s' does not exist", target)
	}

	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not load config: %v\n", err)
		cfg = config.DefaultConfig()
	}

	// Override with command-line flags
	if outputFormat != "table" {
		cfg.Output.Format = outputFormat
	}
	if verbose {
		cfg.Output.Verbose = true
	}
	if len(scannerList) > 0 {
		cfg.Scanners = make(map[string]bool)
		for _, s := range scannerList {
			cfg.Scanners[s] = true
		}
	}
	if allScanners {
		cfg.Scanners = map[string]bool{
			"osv-scanner": true,
			"gitleaks":    true,
			"trivy":       true,
			"semgrep":     true,
			"checkov":     true,
		}
	}

	// Handle diff scanning
	if diffTarget != "" {
		cfg.Diff.Enabled = true
		cfg.Diff.Commit = diffTarget
		
		// Get changed files
		changedFiles, err := diff.GetChangedFiles(target, diffTarget)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: could not get changed files: %v\n", err)
		} else if len(changedFiles) > 0 {
			cfg.Diff.Files = changedFiles
			if verbose {
				fmt.Printf("Diff mode: scanning %d changed files since %s\n", len(changedFiles), diffTarget)
			}
		} else {
			if verbose {
				fmt.Printf("Diff mode: no changed files since %s\n", diffTarget)
			}
		}
	}

	// Handle cache disable
	if noCache {
		cfg.Cache.Enabled = false
	}

	// Create scanner registry and register scanners
	registry := scanners.NewRegistry()
	registerScanners(registry)

	// Create orchestrator
	orchestrator := orchestrate.NewOrchestrator(registry, cfg)

	// Show what we're doing
	if verbose {
		fmt.Printf("Scanning: %s\n", target)
		fmt.Printf("Scanners: ")
		available := orchestrator.GetAvailableScanners()
		for _, s := range available {
			if s["available"].(bool) {
				fmt.Printf("%s ", s["name"])
			}
		}
		fmt.Println()
	}

	// Run the scan
	result, err := orchestrator.Scan(ctx, target)
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}

	// Output results
	if err := output.WriteOutput(result, cfg.Output.Format, outputFile); err != nil {
		return fmt.Errorf("failed to write output: %w", err)
	}

	// Exit with error code if critical findings
	if shouldFail(result, cfg.Thresholds.FailOn) {
		os.Exit(1)
	}

	return nil
}

func registerScanners(registry *scanners.Registry) {
	// Register all available scanners
	registry.Register(osv.New())
	registry.Register(gitleaks.New())
	registry.Register(trivy.New())
	registry.Register(semgrep.New())
	registry.Register(checkov.New())
}

func shouldFail(result types.ScanResult, threshold types.Severity) bool {
	for _, f := range result.Findings {
		if severityLevel(f.Severity) >= severityLevel(threshold) {
			return true
		}
	}
	return false
}

func severityLevel(s types.Severity) int {
	switch s {
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

func getGoVersion() string {
	return "go1.21+"
}

// Blast Radius Command
var blastRadiusCmd = &cobra.Command{
	Use:   "blast-radius [secret] [repo]",
	Short: "Analyze the blast radius of an exposed secret",
	Long: `Analyze the blast radius of an exposed secret in a git repository.

Shows exposure window, affected commits, authors, files, and provides remediation recommendations.

Examples:
  secagent blast-radius AKIAIOSFODNN7EXAMPLE .
  secagent blast-radius sk_live_abc123 ./my-repo`,
	Args: cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		secret := args[0]
		repoPath := args[1]

		if repoPath == "." {
			var err error
			repoPath, err = os.Getwd()
			if err != nil {
				return fmt.Errorf("failed to get current directory: %w", err)
			}
		}

		report, err := blastradius.Analyze(repoPath, secret)
		if err != nil {
			return fmt.Errorf("analysis failed: %w", err)
		}

		// Print report
		fmt.Println("\n🔴 BLAST RADIUS REPORT")
		fmt.Println(strings.Repeat("=", 60))
		fmt.Printf("Secret Type:    %s\n", report.SecretType)
		fmt.Printf("Secret Value:   %s\n", report.SecretValue)
		fmt.Printf("Exposure:       %d days (%s to %s)\n", 
			report.ExposureDays,
			report.FirstSeen.Format("2006-01-02"),
			report.LastSeen.Format("2006-01-02"))
		fmt.Printf("Risk Score:     %.1f/10\n\n", report.RiskScore)

		fmt.Println("📊 IMPACT SUMMARY")
		fmt.Println(strings.Repeat("-", 60))
		fmt.Printf("Commits Affected:  %d\n", len(report.CommitsAffected))
		fmt.Printf("Developers:        %d (%s)\n", len(report.AuthorsInvolved), strings.Join(report.AuthorsInvolved, ", "))
		fmt.Printf("Files Affected:    %d\n", len(report.FilesAffected))
		fmt.Printf("Branches:          %d (%s)\n", len(report.BranchesFound), strings.Join(report.BranchesFound, ", "))
		fmt.Printf("Public Exposure:   %v\n", report.PublicExposure)
		fmt.Printf("Production Use:    %v\n\n", report.ProductionUse)

		fmt.Println("📁 AFFECTED FILES")
		fmt.Println(strings.Repeat("-", 60))
		for _, file := range report.FilesAffected {
			fmt.Printf("  - %s\n", file)
		}

		fmt.Println("\n🔧 RECOMMENDATIONS")
		fmt.Println(strings.Repeat("-", 60))
		for i, rec := range report.Recommendations {
			fmt.Printf("%d. %s\n", i+1, rec)
		}

		// JSON output option
		if outputFormat == "json" {
			jsonData, _ := json.MarshalIndent(report, "", "  ")
			fmt.Println("\n" + string(jsonData))
		}

		return nil
	},
}

// Timeline Command
var timelineCmd = &cobra.Command{
	Use:   "timeline [secret] [repo]",
	Short: "Reconstruct the timeline of a secret's exposure",
	Long: `Reconstruct the timeline of a secret's exposure in a git repository.

Shows the complete lifecycle from first commit to present, including all events.

Examples:
  secagent timeline AKIAIOSFODNN7EXAMPLE .
  secagent timeline ghp_abc123 ./my-repo`,
	Args: cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		secret := args[0]
		repoPath := args[1]

		if repoPath == "." {
			var err error
			repoPath, err = os.Getwd()
			if err != nil {
				return fmt.Errorf("failed to get current directory: %w", err)
			}
		}

		report, err := timeline.Reconstruct(repoPath, secret)
		if err != nil {
			return fmt.Errorf("timeline reconstruction failed: %w", err)
		}

		// Print report
		fmt.Println("\n📅 SECRET TIMELINE")
		fmt.Println(strings.Repeat("=", 60))
		fmt.Printf("Secret Type:    %s\n", report.SecretType)
		fmt.Printf("Total Duration: %d days\n", report.TotalDays)
		fmt.Printf("Total Events:   %d\n", report.EventCount)
		fmt.Printf("Critical:       %d | Warnings: %d\n\n", report.CriticalCount, report.WarningCount)

		fmt.Println("📜 EVENTS (chronological)")
		fmt.Println(strings.Repeat("-", 60))
		
		for _, event := range report.Events {
			icon := "  "
			switch event.Severity {
			case "critical":
				icon = "🔴"
			case "warning":
				icon = "⚠️ "
			default:
				icon = "  "
			}

			fmt.Printf("%s %s  %s\n", icon, event.Timestamp.Format("2006-01-02 15:04"), event.Description)
			
			if event.Author != "" {
				fmt.Printf("    Author: %s\n", event.Author)
			}
			if event.File != "" {
				fmt.Printf("    File: %s\n", event.File)
			}
			if event.Commit != "" {
				fmt.Printf("    Commit: %s\n", event.Commit)
			}
			if event.Branch != "" {
				fmt.Printf("    Branch: %s\n", event.Branch)
			}
			fmt.Println()
		}

		// JSON output option
		if outputFormat == "json" {
			jsonData, _ := json.MarshalIndent(report, "", "  ")
			fmt.Println("\n" + string(jsonData))
		}

		return nil
	},
}
