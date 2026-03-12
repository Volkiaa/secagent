# secagent — Developer-First Security Platform

## Vision

One command to run all security scanners. Unified output. Actionable results.

```bash
secagent scan ./repo    # That's it. That's the product.
```

## Product Philosophy

1. **Zero config by default** — Works out of the box
2. **Unified output** — One format, not 6 different JSON schemas
3. **Actionable** — Tells you what to fix first, how to fix it
4. **Fast** — Parallel execution, cached results
5. **Developer-friendly** — CLI first, CI native, no account required

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                         CLI                                  │
│                    (cmd/secagent)                            │
├─────────────────────────────────────────────────────────────┤
│                      Orchestrator                            │
│                   (internal/orchestrate)                     │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │   Scanner   │  │   Scanner   │  │   Scanner           │  │
│  │   Manager   │  │   Registry  │  │   Interface         │  │
│  └─────────────┘  └─────────────┘  └─────────────────────┘  │
├─────────────────────────────────────────────────────────────┤
│                      Output Layer                            │
│                   (internal/output)                          │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │   Unified   │  │   Report    │  │   CI/CD             │  │
│  │   Finding   │  │   Generator │  │   Formatters        │  │
│  └─────────────┘  └─────────────┘  └─────────────────────┘  │
├─────────────────────────────────────────────────────────────┤
│                    Scanner Integrations                      │
│                     (scanners/*)                             │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐       │
│  │   osv    │ │ gitleaks │ │  trivy   │ │ semgrep  │       │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘       │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐                     │
│  │ checkov  │ │ nuclei   │ │  ...     │                     │
│  └──────────┘ └──────────┘ └──────────┘                     │
└─────────────────────────────────────────────────────────────┘
```

---

## Directory Structure

```
secagent/
├── cmd/
│   └── secagent/
│       └── main.go              # CLI entry point
├── internal/
│   ├── orchestrate/
│   │   ├── orchestrator.go      # Core orchestration logic
│   │   ├── scanner_manager.go   # Scanner lifecycle
│   │   └── parallel.go          # Parallel execution
│   ├── output/
│   │   ├── finding.go           # Unified finding struct
│   │   ├── formatter.go         # Output formatters
│   │   └── report.go            # Report generation
│   ├── config/
│   │   └── config.go            # Configuration handling
│   └── cache/
│       └── cache.go             # Result caching
├── scanners/
│   ├── interface.go             # Scanner interface definition
│   ├── osv/
│   │   └── osv.go               # osv-scanner integration
│   ├── gitleaks/
│   │   └── gitleaks.go          # gitleaks integration
│   ├── trivy/
│   │   └── trivy.go             # trivy integration
│   ├── semgrep/
│   │   └── semgrep.go           # semgrep integration
│   ├── checkov/
│   │   └── checkov.go           # checkov integration
│   └── nuclei/
│       └── nuclei.go            # nuclei integration
├── pkg/
│   └── types/
│       └── types.go             # Shared types
├── configs/
│   └── default.yaml             # Default configuration
├── ci/
│   ├── github-action.yaml       # GitHub Actions template
│   ├── gitlab-ci.yaml           # GitLab CI template
│   └── circleci.yaml            # CircleCI template
├── go.mod
├── go.sum
├── Makefile
├── README.md
└── LICENSE
```

---

## Unified Finding Format

```go
type Finding struct {
    ID          string            `json:"id"`          // Unique finding ID
    Scanner     string            `json:"scanner"`     // Which scanner found it
    Type        FindingType       `json:"type"`        // dependency, secret, code, etc.
    Severity    Severity          `json:"severity"`    // critical, high, medium, low, info
    Title       string            `json:"title"`       // Short description
    Description string            `json:"description"` // Detailed description
    Location    Location          `json:"location"`    // File, line, container, URL
    Evidence    string            `json:"evidence"`    // What was found
    CVE         string            `json:"cve,omitempty"`
    CWE         string            `json:"cwe,omitempty"`
    CVSS        float64           `json:"cvss,omitempty"`
    Fix         string            `json:"fix"`         // How to fix
    References  []string          `json:"references"`  // Links
    Confidence  Confidence        `json:"confidence"`  // true_positive, likely, possible
    Metadata    map[string]any    `json:"metadata"`    // Scanner-specific data
}

type Location struct {
    File       string `json:"file,omitempty"`
    Line       int    `json:"line,omitempty"`
    Column     int    `json:"column,omitempty"`
    Container  string `json:"container,omitempty"`
    URL        string `json:"url,omitempty"`
    Package    string `json:"package,omitempty"`
    Dependency string `json:"dependency,omitempty"`
}

type Severity string
const (
    SeverityCritical Severity = "critical"
    SeverityHigh     Severity = "high"
    SeverityMedium   Severity = "medium"
    SeverityLow      Severity = "low"
    SeverityInfo     Severity = "info"
)

type FindingType string
const (
    TypeDependency FindingType = "dependency"
    TypeSecret     FindingType = "secret"
    TypeCode       FindingType = "code"
    TypeContainer  FindingType = "container"
    TypeIaC        FindingType = "iac"
    TypeNetwork    FindingType = "network"
)
```

---

## Scanner Interface

```go
type Scanner interface {
    Name() string                        // Scanner name (e.g., "osv-scanner")
    Type() FindingType                   // What it scans
    Check() error                        // Is scanner installed/available?
    Scan(ctx context.Context, target string, config Config) ([]Finding, error)
    Parse(output []byte) ([]Finding, error)  // Parse scanner output to unified format
}
```

---

## CLI Commands

```bash
# Core scanning
secagent scan <path>                    # Scan a directory/repo
secagent scan --live <url>              # Scan a live application
secagent scan --all                     # Run all applicable scanners

# Output
secagent report                         # Generate report from last scan
secagent report --format json|markdown|html
secagent report --output file.md

# Configuration
secagent config init                    # Create config file
secagent config show                    # Show current config
secagent config set <key> <value>

# Findings management
secagent findings list                  # List findings from last scan
secagent findings filter --severity high
secagent findings ignore <finding-id>   # Ignore a finding
secagent findings export                # Export findings

# CI/CD
secagent ci install                     # Install CI configuration
secagent ci validate                    # Validate CI config

# Utility
secagent version                        # Show version
secagent update                         # Check for updates
secagent doctor                         # Diagnose issues
```

---

## Configuration

```yaml
# ~/.secagent/config.yaml

# Scanners to enable
scanners:
  osv: true
  gitleaks: true
  trivy: true
  semgrep: true
  checkov: true
  nuclei: false  # Disabled by default (needs live target)

# Severity thresholds
thresholds:
  fail_on: critical  # CI fails on critical findings
  warn_on: high      # Warn on high

# Output preferences
output:
  format: table      # table, json, markdown
  colors: true
  verbose: false

# Caching
cache:
  enabled: true
  ttl: 24h           # Cache results for 24 hours

# Ignored findings
ignore:
  - finding_id_1
  - cve: CVE-2024-1234
  - rule: semgrep-rule-id

# CI/CD
ci:
  fail_on_severity: critical
  comment_on_pr: true
```

---

## Build Phases

### Phase 1: Core MVP (Weeks 1-2)
- [ ] Go module setup
- [ ] Directory structure
- [ ] Scanner interface definition
- [ ] Unified finding format
- [ ] CLI skeleton (cobra)
- [ ] osv-scanner integration (example scanner)
- [ ] Basic output (table, JSON)
- [ ] `secagent scan` command works

**Success criteria:** Can scan a repo with osv-scanner and show unified output

### Phase 2: Core Scanners (Weeks 3-4)
- [ ] gitleaks integration
- [ ] trivy integration (containers)
- [ ] semgrep integration
- [ ] checkov integration
- [ ] Parallel scanner execution
- [ ] Result caching
- [ ] Configuration file support

**Success criteria:** All P0 scanners work, parallel execution, config persists

### Phase 3: Polish (Weeks 5-6)
- [ ] nuclei integration (live scanning)
- [ ] Markdown/HTML report generation
- [ ] Finding deduplication
- [ ] Severity normalization across scanners
- [ ] CI/CD templates
- [ ] Documentation

**Success criteria:** Production-ready CLI, can use in CI

### Phase 4: OSS Launch (Week 7)
- [ ] GitHub repo setup
- [ ] README, docs
- [ ] Release binaries (goreleaser)
- [ ] Announce launch

---

## Monetization Path

| Tier | Price | Features |
|------|-------|----------|
| **OSS** | Free | CLI, all scanners, local execution |
| **Teams** | $29/dev/mo | Dashboard, shared findings, collaboration |
| **Cloud** | Usage | Hosted scanning, API, managed |
| **Enterprise** | Custom | Compliance, SSO, support |

---

## Competitive Landscape

| Tool | What They Do | Gap We Fill |
|------|--------------|-------------|
| Snyk | Full platform | We're CLI-first, OSS, simpler |
| Dependabot | Dependencies only | We cover all scanner types |
| Trivy | Multi-scanner | We orchestrate MORE tools |
| Semgrep | Code scanning | We're not single-purpose |

**Our angle:** One CLI. All scanners. Zero config.

---

## Tech Stack

- **Language:** Go 1.21+
- **CLI:** cobra
- **Config:** viper
- **Parallel:** errgroup
- **HTTP:** net/http + retry
- **Testing:** testify, gomock
- **Build:** goreleaser
- **CI:** GitHub Actions

---

## First 10 Commands

```bash
# 1. Create module
go mod init github.com/secagent/secagent

# 2. Create directory structure
mkdir -p cmd/secagent internal/orchestrate internal/output scanners pkg/types configs ci

# 3. Initialize Go files
touch cmd/secagent/main.go
touch internal/orchestrate/orchestrator.go
touch internal/output/finding.go
touch scanners/interface.go
touch scanners/osv/osv.go

# 4. Add dependencies
go get github.com/spf13/cobra
go get github.com/spf13/viper
go get golang.org/x/sync/errgroup

# 5. Build first CLI
go build -o secagent ./cmd/secagent

# 6. Test
./secagent version
./secagent scan .
```

---

## Open Questions

1. Scanner discovery: Auto-detect installed scanners vs. bundle them?
2. Update strategy: Auto-update scanners or manual?
3. Plugin system: Allow third-party scanners?
4. Database: Embedded SQLite for findings history?

---

## Next Actions

1. [ ] Create this repo on GitHub
2. [ ] Scaffold directory structure
3. [ ] Implement scanner interface
4. [ ] Build osv-scanner integration
5. [ ] Create basic CLI
