# secagent

**Developer-First Security Scanner** - One command to run all security scanners. Unified output. Actionable results.

```bash
secagent scan ./repo    # That's it. That's the product.
```

## Features

- 🔍 **5-in-1 Scanning** - Dependencies, secrets, code, containers, and IaC in one scan
- 🎯 **Smart Deduplication** - Same vulnerability from multiple scanners = one finding
- ⚡ **Parallel Execution** - All scanners run concurrently for fast results
- 📊 **Multiple Formats** - Table, JSON, Markdown output for different workflows
- 🚫 **Ignore Rules** - Filter by severity, rule, file, or path
- 🔗 **CI/CD Ready** - GitHub Actions, GitLab CI, SARIF support

## Quick Start

### Option 1: Binary (Linux/macOS)

```bash
# Download latest release
curl -sL https://github.com/secagent/secagent/releases/latest/download/secagent-linux-amd64 -o secagent
chmod +x secagent
sudo mv secagent /usr/local/bin/

# Verify installation
secagent version
```

### Option 2: Docker (Recommended for CI)

```bash
# Clone the repo
git clone https://github.com/secagent/secagent.git
cd secagent

# Build the image (includes all 5 scanners)
docker build -t secagent:latest .

# Scan a project
docker run --rm -v $(pwd):/app/project secagent:latest scan --all .
```

**See [docs/DOCKER.md](docs/DOCKER.md) for complete Docker guide.**

### Scan a Project

```bash
# Scan with all scanners
secagent scan --all /path/to/project

# Scan current directory
secagent scan .

# Run specific scanners
secagent scan --scanners semgrep,gitleaks .

# Output as JSON for CI/CD
secagent scan --all . --format json --output results.json
```

## Scanners

| Scanner | What It Finds | Example |
|---------|---------------|---------|
| **osv-scanner** | Dependency vulnerabilities | `lodash@4.17.10` → CVE-2021-23337 |
| **gitleaks** | Secrets & credentials | API keys, passwords, tokens |
| **semgrep** | Code security issues | SQL injection, XSS, weak crypto |
| **trivy** | Container & filesystem vulns | CVEs in OS packages, containers |
| **checkov** | IaC misconfigurations | Open S3 buckets, permissive IAM |

## Output Formats

### Table (Default)

```
SecAgent Security Scan Report
Target: ./my-project
Scanned: 2026-03-12T09:00:00Z
Duration: 15s
Findings: 42

CRITICAL: 5
HIGH: 12
MEDIUM: 20
LOW: 5

DETAILED FINDINGS
================================================================================

[1] CVE-2021-23337: Command Injection in lodash
    Scanner:  osv-scanner
    Type:     dependency
    Severity: high
    CVE:      CVE-2021-23337
    Location: ./package-lock.json
    Fix:      Update lodash to >=4.17.21
```

### JSON

```bash
secagent scan --all . --format json --output results.json
```

### Markdown

```bash
secagent scan --all . --format markdown --output report.md
```

## Configuration

Create `~/.secagent/config.yaml`:

```yaml
# Enable/disable scanners
scanners:
  osv-scanner: true
  gitleaks: true
  semgrep: true
  trivy: true
  checkov: true

# Fail CI on severity threshold
thresholds:
  fail_on: critical
  warn_on: high

# Ignore rules
ignore:
  # Ignore specific rules (supports wildcards)
  rules:
    - "CKV_AWS_IAM_*"
    - "python.lang.security.audit.md5*"
  
  # Ignore files by glob pattern
  files:
    - "**/*.test.py"
    - "vendor/**"
    - "**/test_*.go"
  
  # Ignore by severity
  severities:
    - "low"
    - "info"
  
  # Ignore directories
  paths:
    - "test/**"
    - "examples/**"
    - "docs/**"
```

## Ignore Rules

### By Rule ID

Ignore specific scanner rules:

```yaml
ignore:
  rules:
    - "CKV_AWS_*"           # All AWS checkov rules
    - "python.lang.*"       # All Python semgrep rules
    - "CVE-2021-*"          # All 2021 CVEs
```

### By File Pattern

Ignore findings in specific files:

```yaml
ignore:
  files:
    - "**/*.test.py"        # All test files
    - "vendor/**"           # Vendor directory
    - "**/*.min.js"         # Minified JS
```

### By Severity

Ignore low-priority findings:

```yaml
ignore:
  severities:
    - "low"
    - "info"
```

### By Path

Ignore entire directories:

```yaml
ignore:
  paths:
    - "test/**"
    - "examples/**"
    - "docs/**"
```

## CI/CD Integration

### GitHub Actions

Create `.github/workflows/security.yml`:

```yaml
name: Security Scan

on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Install secagent
        run: |
          curl -sL https://github.com/secagent/secagent/releases/latest/download/secagent-linux-amd64 -o secagent
          chmod +x secagent
          sudo mv secagent /usr/local/bin/
      
      - name: Run scan
        run: secagent scan --all . --format json --output results.json
      
      - name: Upload results
        uses: actions/upload-artifact@v4
        with:
          name: security-results
          path: results.json
```

### GitLab CI

Create `.gitlab-ci.yml`:

```yaml
security-scan:
  image: golang:1.21
  script:
    - curl -sL https://github.com/secagent/secagent/releases/latest/download/secagent-linux-amd64 -o secagent
    - chmod +x secagent
    - ./secagent scan --all . --format json --output results.json
  artifacts:
    paths:
      - results.json
    when: always
```

### Exit Codes

secagent returns exit codes based on severity:

- `0` - No findings above threshold
- `1` - Findings at or above `fail_on` threshold (default: critical)

Configure threshold in config:

```yaml
thresholds:
  fail_on: high  # Fail on high or critical
```

## Examples

### Scan Before Commit

```bash
# Add to .git/hooks/pre-commit
#!/bin/bash
secagent scan --scanners gitleaks,semgrep --staged
```

### Scan Dockerfile

```bash
secagent scan --scanners checkov,trivy ./Dockerfile
```

### Scan Terraform

```bash
secagent scan --scanners checkov ./terraform/
```

### Find Secrets Only

```bash
secagent scan --scanners gitleaks .
```

### Generate Report

```bash
secagent scan --all . --format markdown -o security-report.md
```

### Diff Scanning (CI Optimization)

Scan only changed files since a commit:

```bash
# Scan changes since last commit
secagent scan --diff HEAD .

# Scan changes since main branch
secagent scan --diff main .

# Scan staged changes only
secagent scan --diff staged .

# Combine with CI
secagent scan --diff HEAD~1 --format json -o results.json
```

**Benefits:**
- 10x faster on large repos with few changes
- Perfect for PR checks
- Reduces CI costs

### Caching

Enable caching to skip unchanged files:

```bash
# Enable caching (default: 24h TTL)
secagent scan .

# Disable caching
secagent scan --no-cache .

# Configure in ~/.secagent/config.yaml
cache:
  enabled: true
  ttl: 12h
```

**Cache location:** `~/.secagent/cache/cache.json`

## Test Repositories

Test secagent on intentionally vulnerable projects:

```bash
# Node.js vulnerabilities
git clone https://github.com/snyk-labs/nodejs-goof
secagent scan --all nodejs-goof

# Mobile security tests
git clone https://github.com/OWASP/owasp-mstg
secagent scan --all owasp-mstg
```

## Troubleshooting

### Scanner Not Found

Install missing scanners:

```bash
# osv-scanner
curl -sSL https://raw.githubusercontent.com/google/osv-scanner/main/install.sh | bash

# gitleaks
curl -sSL https://github.com/gitleaks/gitleaks/releases/latest/download/gitleaks-linux-amd64 -o /tmp/gitleaks
chmod +x /tmp/gitleaks && sudo mv /tmp/gitleaks /usr/local/bin/

# semgrep
pip install semgrep

# trivy
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh

# checkov
pip install checkov
```

### Check Installation

```bash
secagent doctor
```

### Slow Scans

Use diff scanning for faster CI:

```bash
secagent scan --diff HEAD~1
```

## Contributing

1. Fork the repo
2. Create a feature branch
3. Run tests: `go test ./...`
4. Submit PR

## License

MIT License - see [LICENSE](LICENSE)

## Acknowledgments

secagent integrates these amazing tools:

- [osv-scanner](https://github.com/google/osv-scanner) by Google
- [gitleaks](https://github.com/gitleaks/gitleaks) by Zachary Rice
- [semgrep](https://github.com/returntocorp/semgrep) by Return To Corp
- [trivy](https://github.com/aquasecurity/trivy) by Aqua Security
- [checkov](https://github.com/bridgecrewio/checkov) by Bridgecrew
