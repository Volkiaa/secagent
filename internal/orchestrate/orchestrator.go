package orchestrate

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"
	"golang.org/x/sync/semaphore"

	"github.com/secagent/secagent/internal/cache"
	"github.com/secagent/secagent/internal/dedup"
	"github.com/secagent/secagent/internal/diff"
	"github.com/secagent/secagent/internal/filter"
	"github.com/secagent/secagent/internal/output"
	"github.com/secagent/secagent/pkg/types"
	"github.com/secagent/secagent/scanners"
)

// Orchestrator manages parallel scanner execution
type Orchestrator struct {
	registry    *scanners.Registry
	config      *types.Config
	cache       *cache.Cache
	findings    []types.Finding
	errors      []string
	mu          sync.Mutex
	startTime   time.Time
}

// ScannerResult holds the result from a single scanner
type ScannerResult struct {
	Scanner  string
	Findings []types.Finding
	Error    error
}

// NewOrchestrator creates a new orchestrator with the given registry
func NewOrchestrator(registry *scanners.Registry, config *types.Config) *Orchestrator {
	// Initialize cache
	var c *cache.Cache
	if config != nil && config.Cache.Enabled {
		home, _ := os.UserHomeDir()
		cacheDir := filepath.Join(home, ".secagent", "cache")
		ttl := "24h"
		if config.Cache.TTL != "" {
			ttl = config.Cache.TTL
		}
		c, _ = cache.New(cacheDir, true, ttl)
	} else {
		c, _ = cache.New("", false, "24h")
	}
	
	return &Orchestrator{
		registry: registry,
		config:   config,
		cache:    c,
		findings: make([]types.Finding, 0),
		errors:   make([]string, 0),
	}
}

// Scan runs all enabled scanners against the target in parallel
func (o *Orchestrator) Scan(ctx context.Context, target string) (types.ScanResult, error) {
	o.startTime = time.Now()

	// Get enabled scanners
	enabledScanners := o.getEnabledScanners()
	if len(enabledScanners) == 0 {
		return types.ScanResult{}, fmt.Errorf("no scanners available or enabled")
	}

	// Determine scan target (diff mode or full scan)
	scanTarget := target
	if o.config != nil && o.config.Diff.Enabled && len(o.config.Diff.Files) > 0 {
		// In diff mode, get unique directories to scan
		dirs := diff.GetChangedDirectories(o.config.Diff.Files)
		if len(dirs) > 0 {
			// Use the common parent directory
			scanTarget = getCommonParent(dirs, target)
		}
	}

	// Create result
	result := output.NewScanResult(target)

	// Use errgroup for parallel execution with concurrency limit
	g, ctx := errgroup.WithContext(ctx)
	
	// Limit concurrency to number of CPUs to avoid resource exhaustion
	maxConcurrent := runtime.NumCPU()
	if maxConcurrent > 4 {
		maxConcurrent = 4 // Cap at 4 for I/O-bound scanners
	}
	sem := semaphore.NewWeighted(int64(maxConcurrent))

	// Channel to collect results
	resultChan := make(chan ScannerResult, len(enabledScanners))

	// Start all scanners in parallel with concurrency limit
	for _, scanner := range enabledScanners {
		scanner := scanner // capture for closure
		
		// Acquire semaphore
		if err := sem.Acquire(ctx, 1); err != nil {
			resultChan <- ScannerResult{
				Scanner: scanner.Name(),
				Error:   err,
			}
			continue
		}
		
		g.Go(func() error {
			defer sem.Release(1)
			
			scannerName := scanner.Name()
			
			// Print progress in verbose mode
			if o.config != nil && o.config.Output.Verbose {
				fmt.Printf("  [%s] Starting scan...\n", scannerName)
			}
			
			// Check if scanner is available
			if err := scanner.Check(); err != nil {
				if o.config != nil && o.config.Output.Verbose {
					fmt.Printf("  [%s] Not available: %v\n", scannerName, err)
				}
				resultChan <- ScannerResult{
					Scanner: scannerName,
					Error:   err,
				}
				return nil // Don't fail the group, just report the error
			}

			// Try to get from cache first
			if cachedFindings, ok := o.cache.Get(scanTarget, scannerName); ok {
				if o.config != nil && o.config.Output.Verbose {
					fmt.Printf("  [%s] Cache hit ✓\n", scannerName)
				}
				resultChan <- ScannerResult{
					Scanner:  scannerName,
					Findings: cachedFindings,
					Error:    nil,
				}
				return nil
			}

			// Run the scan
			if o.config != nil && o.config.Output.Verbose {
				fmt.Printf("  [%s] Scanning...\n", scannerName)
			}
			findings, err := scanner.Scan(ctx, scanTarget)
			
			// Cache the results if successful
			if err == nil && len(findings) > 0 {
				o.cache.Set(scanTarget, scannerName, findings)
			}
			
			if o.config != nil && o.config.Output.Verbose {
				if err != nil {
					fmt.Printf("  [%s] Error: %v\n", scannerName, err)
				} else {
					fmt.Printf("  [%s] Found %d issues\n", scannerName, len(findings))
				}
			}
			
			resultChan <- ScannerResult{
				Scanner:  scannerName,
				Findings: findings,
				Error:    err,
			}
			return nil
		})
	}

	// Wait for all scanners to complete
	_ = g.Wait()
	close(resultChan)

	// Collect results
	for res := range resultChan {
		if res.Error != nil {
			o.mu.Lock()
			o.errors = append(o.errors, fmt.Sprintf("%s: %v", res.Scanner, res.Error))
			o.mu.Unlock()
		} else {
			o.mu.Lock()
			o.findings = append(o.findings, res.Findings...)
			o.mu.Unlock()
		}
	}

	// Build final result
	result.Findings = o.findings
	result.Errors = o.errors
	result.Duration = time.Since(o.startTime).String()

	// Apply ignore filters
	if o.config != nil {
		result.Findings = filter.Filter(result.Findings, o.config.Ignore)
	}

	// Deduplicate findings from multiple scanners
	result.Findings = dedup.Deduplicate(result.Findings)

	return result, nil
}

// getEnabledScanners returns the list of scanners to run
func (o *Orchestrator) getEnabledScanners() []scanners.Scanner {
	if o.config != nil && len(o.config.Scanners) > 0 {
		enabled := make([]string, 0)
		for name, isEnabled := range o.config.Scanners {
			if isEnabled {
				enabled = append(enabled, name)
			}
		}
		if len(enabled) > 0 {
			return o.registry.GetEnabled(enabled)
		}
	}
	return o.registry.GetAll()
}

// GetAvailableScanners returns information about available scanners
func (o *Orchestrator) GetAvailableScanners() []map[string]interface{} {
	scannerInfo := make([]map[string]interface{}, 0)
	
	for _, scanner := range o.registry.GetAll() {
		info := map[string]interface{}{
			"name": scanner.Name(),
			"type": scanner.Type(),
		}
		
		if err := scanner.Check(); err != nil {
			info["available"] = false
			info["error"] = err.Error()
		} else {
			info["available"] = true
		}
		
		scannerInfo = append(scannerInfo, info)
	}
	
	return scannerInfo
}

// RunScanner runs a single scanner by name
func (o *Orchestrator) RunScanner(ctx context.Context, target string, scannerName string) ([]types.Finding, error) {
	scanner, ok := o.registry.Get(scannerName)
	if !ok {
		return nil, fmt.Errorf("scanner '%s' not found", scannerName)
	}

	if err := scanner.Check(); err != nil {
		return nil, fmt.Errorf("scanner '%s' not available: %w", scannerName, err)
	}

	return scanner.Scan(ctx, target)
}

// getCommonParent finds the common parent directory of multiple paths
func getCommonParent(paths []string, fallback string) string {
	if len(paths) == 0 {
		return fallback
	}
	if len(paths) == 1 {
		return filepath.Dir(paths[0])
	}

	// Start with first path's directory
	common := filepath.Dir(paths[0])

	for _, path := range paths[1:] {
		dir := filepath.Dir(path)
		// Find common prefix
		for !filepath.HasPrefix(dir, common) && common != "/" && common != "." {
			common = filepath.Dir(common)
		}
	}

	if common == "" || common == "/" {
		return fallback
	}
	return common
}
