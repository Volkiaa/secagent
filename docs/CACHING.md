# Caching Implementation Notes

## Current Status

Caching infrastructure is in place (`internal/cache/cache.go`) but not yet integrated into all scanners.

## Implementation Plan

### Phase 1: File-Level Caching (Simple)
Cache scan results per file hash. Before scanning a file:
1. Compute file hash
2. Check cache for existing results
3. If cached and not expired, use cached results
4. Otherwise, scan and cache the results

### Phase 2: Scanner Integration
Each scanner needs to support caching:
- **osv-scanner**: Cache by lockfile hash (go.mod, package-lock.json, etc.)
- **gitleaks**: Cache by file hash (but re-scan on git history changes)
- **semgrep**: Cache by file hash + rule set hash
- **trivy**: Cache by filesystem snapshot hash
- **checkov**: Cache by IaC file hash

### Phase 3: Smart Invalidation
Invalidate cache when:
- File content changes (hash mismatch)
- Scanner version changes
- Rule definitions change (semgrep, checkov)
- Vulnerability database updates (osv, trivy)

## Usage

```bash
# Enable caching (default: enabled with 24h TTL)
secagent scan .

# Disable caching
secagent scan --no-cache .

# Configure TTL in ~/.secagent/config.yaml
cache:
  enabled: true
  ttl: 12h  # Cache for 12 hours
```

## Cache Location

`~/.secagent/cache/cache.json`

## Clearing Cache

```bash
rm -rf ~/.secagent/cache
```

## Performance Impact

Expected speedup:
- First scan: No improvement (building cache)
- Second scan (no changes): 80-90% faster
- Partial changes: Proportional to unchanged files
