# AgentSec - Blast Radius & Timeline Analysis

**Date:** 2026-03-12  
**Status:** ✅ Implementation Complete

---

## What Was Built

Two new features that differentiate AgentSec from every other secrets scanner:

### 1. Blast Radius Analysis

**Command:** `secagent blast-radius [secret] [repo]`

**What it does:**
- Finds when the secret was first/last seen in git history
- Lists all commits that contained the secret
- Identifies all developers who had access
- Shows which files and branches were affected
- Detects if it was in production or public repos
- Calculates a risk score (0-10)
- Provides actionable remediation recommendations

**Example Output:**
```
🔴 BLAST RADIUS REPORT
============================================================
Secret Type:    AWS Access Key
Secret Value:   AKIA...MPLE
Exposure:       118 days (2025-11-15 to 2026-03-12)
Risk Score:     8.5/10

📊 IMPACT SUMMARY
------------------------------------------------------------
Commits Affected:  12
Developers:        3 (alice, bob, charlie)
Files Affected:    5
Branches:          2 (main, develop)
Public Exposure:   true
Production Use:    true

📁 AFFECTED FILES
------------------------------------------------------------
  - config/prod.yaml
  - .env.production
  - deploy/aws.tf

🔧 RECOMMENDATIONS
------------------------------------------------------------
1. Rotate AWS Access Key immediately
2. Review AWS CloudTrail logs for the exposure period
3. Check for unauthorized EC2 instances, IAM changes
4. Secret was in public repo - assume compromised
5. Consider this a high-severity incident
```

---

### 2. Timeline Reconstruction

**Command:** `secagent timeline [secret] [repo]`

**What it does:**
- Reconstructs the complete lifecycle of the secret
- Shows every commit chronologically
- Highlights critical events (prod deploys, config changes)
- Shows when it was pushed to public repos
- Identifies branches where it exists

**Example Output:**
```
📅 SECRET TIMELINE
============================================================
Secret Type:    AWS Access Key
Total Duration: 118 days
Total Events:   15
Critical:       5 | Warnings: 3

📜 EVENTS (chronological)
------------------------------------------------------------
   2025-11-15 14:23  Committed: Initial config
    Author: alice
    File: config.yaml
    Commit: a1b2c3d4

   2025-11-20 09:45  Deployed to production: Update prod config
    Author: bob
    File: config/prod.yaml
    Commit: e5f6g7h8

🔴 2025-12-01 16:30  Pushed to remote: github.com/acme/app (PUBLIC)
    Commit: i9j0k1l2

⚠️  2026-01-15 11:00  Merged into main
    Author: charlie
    Commit: m3n4o5p6

   2026-02-28 08:15  Committed: Add backup config
    Author: alice
    File: config/backup.yaml
    Commit: q7r8s9t0
```

---

## Files Created

| File | Purpose | Lines |
|------|---------|-------|
| `internal/blastradius/blast_radius.go` | Blast radius analysis engine | 350 |
| `internal/timeline/timeline.go` | Timeline reconstruction engine | 280 |
| `cmd/secagent/main.go` | Updated with new CLI commands | +150 |

**Total:** ~780 lines of new code

---

## How It Works

### Blast Radius Analysis

```go
1. Run `git log -S [secret]` to find commits containing the secret
2. Parse commit metadata (author, date, message, files)
3. Check branches with `git branch --contains`
4. Check remote URL to detect public repos
5. Analyze file paths for production indicators
6. Calculate risk score based on:
   - Exposure duration
   - Number of commits/authors
   - Public exposure
   - Production use
7. Generate recommendations based on secret type
```

### Timeline Reconstruction

```go
1. Get all commits with the secret (same as blast radius)
2. For each commit, determine event type:
   - Regular commit
   - Merge commit
   - Production deploy
   - Config change
3. Get branch information
4. Check remote exposure
5. Sort events chronologically
6. Assign severity (info/warning/critical)
7. Format for display
```

---

## What Makes This Unique

| Scanner | Blast Radius | Timeline | Risk Score | Recommendations |
|---------|--------------|----------|------------|-----------------|
| Gitleaks | ❌ | ❌ | ❌ | ❌ |
| Betterleaks | ❌ | ❌ | ❌ | ❌ |
| GitGuardian | ❌ | ❌ | ❌ | ⚠️ Basic |
| TruffleHog | ❌ | ❌ | ❌ | ❌ |
| **AgentSec** | ✅ | ✅ | ✅ | ✅ |

---

## Usage Examples

### Example 1: AWS Key in Config

```bash
# Find blast radius of exposed AWS key
secagent blast-radius AKIAIOSFODNN7EXAMPLE .

# Get JSON output for SIEM integration
secagent blast-radius AKIAIOSFODNN7EXAMPLE . --format json
```

### Example 2: GitHub Token

```bash
# See timeline of GitHub token exposure
secagent timeline ghp_xxxxxxxxxxxxxxxxxxxx ./my-repo

# Save report to file
secagent timeline ghp_xxxxxxxxxxxxxxxxxxxx . -o timeline.md
```

### Example 3: Stripe Key

```bash
# Full analysis
secagent blast-radius sk_live_51234567890abcdefghij .
```

---

## Integration Points

### SIEM Integration

```bash
# Output as JSON for SIEM ingestion
secagent blast-radius [secret] . --format json | \
  jq '. | {secret_type, exposure_days, risk_score, recommendations}'
```

### Incident Response

```bash
# Quick triage
secagent blast-radius $ROTATED_KEY . | \
  grep -E "(Risk Score|Public Exposure|Production Use)"
```

### Automated Reporting

```bash
# Include in security reports
secagent blast-radius $SECRET . --format json >> security-report.json
```

---

## Risk Score Calculation

```
Exposure Duration:
  >90 days:  +3 points
  >30 days:  +2 points
  >7 days:   +1 point

Commits:
  >20 commits:  +2 points
  >5 commits:   +1 point

Authors:
  >5 authors:   +1.5 points
  >2 authors:   +0.5 points

Public Exposure: +2 points
Production Use:  +1.5 points

Maximum: 10 points
```

---

## Next Steps (Optional Enhancements)

### Phase 1 (Done)
- ✅ Blast radius analysis
- ✅ Timeline reconstruction
- ✅ CLI integration

### Phase 2 (Future)
- [ ] Collaboration tool scanning (Slack, AI logs)
- [ ] Cloud audit log integration (CloudTrail, etc.)
- [ ] Automated secret rotation
- [ ] Slack/Teams notifications
- [ ] Dashboard/UI for viewing reports

### Phase 3 (Advanced)
- [ ] ML-based risk scoring
- [ ] Correlation with security incidents
- [ ] Automated remediation workflows
- [ ] Integration with secret management (Vault, AWS Secrets Manager)

---

## The Bottom Line

**AgentSec now provides what no other scanner does:**

1. **Not just "rotate it"** - Shows exactly what was compromised
2. **Forensic timeline** - Reconstructs the entire exposure
3. **Actionable intel** - Specific recommendations based on context
4. **Risk scoring** - Prioritize response based on actual risk

**This addresses the exact gap identified in the Reddit comment:**
> "a scanner finds an exposed key, you rotate it, but the blast radius of however long it was exposed is a black box"

**No more black boxes.** AgentSec shows you everything.
