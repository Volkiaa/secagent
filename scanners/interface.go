package scanners

import (
	"context"

	"github.com/secagent/secagent/pkg/types"
)

// Scanner defines the interface that all security scanners must implement
type Scanner interface {
	// Name returns the scanner name (e.g., "osv-scanner", "gitleaks")
	Name() string

	// Type returns the type of findings this scanner produces
	Type() types.FindingType

	// Check verifies if the scanner is installed and available
	Check() error

	// Scan runs the scanner against the target and returns findings
	Scan(ctx context.Context, target string) ([]types.Finding, error)
}

// Registry manages available scanners
type Registry struct {
	scanners map[string]Scanner
}

// NewRegistry creates a new scanner registry
func NewRegistry() *Registry {
	return &Registry{
		scanners: make(map[string]Scanner),
	}
}

// Register adds a scanner to the registry
func (r *Registry) Register(scanner Scanner) {
	r.scanners[scanner.Name()] = scanner
}

// Get retrieves a scanner by name
func (r *Registry) Get(name string) (Scanner, bool) {
	scanner, ok := r.scanners[name]
	return scanner, ok
}

// GetAll returns all registered scanners
func (r *Registry) GetAll() []Scanner {
	scanners := make([]Scanner, 0, len(r.scanners))
	for _, s := range r.scanners {
		scanners = append(scanners, s)
	}
	return scanners
}

// GetEnabled returns scanners that are enabled in the config
func (r *Registry) GetEnabled(enabled []string) []Scanner {
	if len(enabled) == 0 {
		return r.GetAll()
	}

	scanners := make([]Scanner, 0)
	for _, name := range enabled {
		if s, ok := r.Get(name); ok {
			scanners = append(scanners, s)
		}
	}
	return scanners
}
