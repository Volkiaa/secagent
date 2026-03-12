package cache

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/secagent/secagent/pkg/types"
)

// Cache manages cached scan results
type Cache struct {
	dir      string
	enabled  bool
	ttl      time.Duration
	data     map[string]CacheEntry
}

// CacheEntry represents a cached scan result for a target directory
type CacheEntry struct {
	TargetHash string           `json:"target_hash"`
	Findings   []types.Finding  `json:"findings"`
	ScannedAt  string           `json:"scanned_at"`
	Scanner    string           `json:"scanner"`
	Target     string           `json:"target"`
}

// New creates a new cache
func New(cacheDir string, enabled bool, ttl string) (*Cache, error) {
	if !enabled {
		return &Cache{enabled: false}, nil
	}

	// Parse TTL
	duration, err := time.ParseDuration(ttl)
	if err != nil {
		duration = 24 * time.Hour // Default 24h
	}

	// Create cache directory
	if err := os.MkdirAll(cacheDir, 0755); err != nil {
		return nil, err
	}

	cache := &Cache{
		dir:     cacheDir,
		enabled: enabled,
		ttl:     duration,
		data:    make(map[string]CacheEntry),
	}

	// Load existing cache
	cache.load()

	return cache, nil
}

// Get retrieves cached findings for a target
func (c *Cache) Get(target string, scanner string) ([]types.Finding, bool) {
	if !c.enabled {
		return nil, false
	}

	targetHash, err := hashDirectory(target)
	if err != nil {
		return nil, false
	}

	key := cacheKey(target, scanner)
	entry, ok := c.data[key]
	if !ok {
		return nil, false
	}

	// Check if target has changed
	if entry.TargetHash != targetHash {
		return nil, false
	}

	// Check if cache entry is expired
	scannedAt, err := time.Parse(time.RFC3339, entry.ScannedAt)
	if err != nil || time.Since(scannedAt) > c.ttl {
		return nil, false
	}

	return entry.Findings, true
}

// Set stores findings in the cache
func (c *Cache) Set(target string, scanner string, findings []types.Finding) error {
	if !c.enabled {
		return nil
	}

	targetHash, err := hashDirectory(target)
	if err != nil {
		return err
	}

	key := cacheKey(target, scanner)
	c.data[key] = CacheEntry{
		TargetHash: targetHash,
		Findings:   findings,
		ScannedAt:  time.Now().UTC().Format(time.RFC3339),
		Scanner:    scanner,
		Target:     target,
	}

	return c.save()
}

// Clear removes all cached entries
func (c *Cache) Clear() error {
	c.data = make(map[string]CacheEntry)
	return os.RemoveAll(c.dir)
}

// cacheKey creates a unique key for a file+scanner combination
func cacheKey(filePath, scanner string) string {
	return scanner + ":" + filePath
}

// hashFile computes SHA256 hash of a file
func hashFile(filePath string) (string, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:]), nil
}

// hashDirectory computes SHA256 hash of all files in a directory
func hashDirectory(dirPath string) (string, error) {
	hasher := sha256.New()
	
	err := filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		
		// Skip directories, only hash file content
		if info.IsDir() {
			return nil
		}
		
		// Skip cache files and hidden files
		if info.Name()[0] == '.' || filepath.Ext(path) == ".cache" {
			return nil
		}
		
		// Add file path and content to hash
		hasher.Write([]byte(path))
		hasher.Write([]byte(info.ModTime().String()))
		hasher.Write([]byte(fmt.Sprintf("%d", info.Size())))
		
		return nil
	})
	
	if err != nil {
		return "", err
	}
	
	hash := hasher.Sum(nil)
	return hex.EncodeToString(hash), nil
}

// cacheFile returns the path to the cache file
func (c *Cache) cacheFile() string {
	return filepath.Join(c.dir, "cache.json")
}

// load reads the cache from disk
func (c *Cache) load() {
	cacheFile := c.cacheFile()
	data, err := os.ReadFile(cacheFile)
	if err != nil {
		return // Cache doesn't exist yet
	}

	json.Unmarshal(data, &c.data)
}

// save writes the cache to disk
func (c *Cache) save() error {
	cacheFile := c.cacheFile()
	data, err := json.MarshalIndent(c.data, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(cacheFile, data, 0644)
}
