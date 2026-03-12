package dedup

import (
	"testing"

	"github.com/secagent/secagent/pkg/types"
)

func TestDeduplicate(t *testing.T) {
	tests := []struct {
		name     string
		findings []types.Finding
		wantLen  int
	}{
		{
			name:     "empty findings",
			findings: []types.Finding{},
			wantLen:  0,
		},
		{
			name: "single finding",
			findings: []types.Finding{
				{ID: "1", CVE: "CVE-2021-1234", Scanner: "osv-scanner"},
			},
			wantLen: 1,
		},
		{
			name: "duplicate CVEs merged",
			findings: []types.Finding{
				{ID: "1", CVE: "CVE-2021-1234", Scanner: "osv-scanner", Severity: types.SeverityMedium},
				{ID: "2", CVE: "CVE-2021-1234", Scanner: "trivy", Severity: types.SeverityHigh},
			},
			wantLen: 1,
		},
		{
			name: "different CVEs not merged",
			findings: []types.Finding{
				{ID: "1", CVE: "CVE-2021-1234", Scanner: "osv-scanner"},
				{ID: "2", CVE: "CVE-2021-5678", Scanner: "trivy"},
			},
			wantLen: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := Deduplicate(tt.findings)
			if len(result) != tt.wantLen {
				t.Errorf("Deduplicate() returned %d findings, want %d", len(result), tt.wantLen)
			}
		})
	}
}

func TestGenerateKey(t *testing.T) {
	tests := []struct {
		name     string
		finding  types.Finding
		wantKey  string
	}{
		{
			name:    "CVE takes priority",
			finding: types.Finding{CVE: "CVE-2021-1234", ID: "other-id"},
			wantKey: "cve:CVE-2021-1234",
		},
		{
			name:    "CWE + file + line",
			finding: types.Finding{CWE: "CWE-79", Location: types.Location{File: "app.js", Line: 10}},
			wantKey: "cwe:CWE-79:app.js:10",
		},
		{
			name:    "Package + version",
			finding: types.Finding{Location: types.Location{Package: "lodash", Dependency: "lodash@4.17.10"}},
			wantKey: "pkg:lodash:lodash@4.17.10",
		},
		{
			name:    "Fallback to ID",
			finding: types.Finding{ID: "unique-id-123"},
			wantKey: "id:unique-id-123",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := generateKey(tt.finding)
			if key != tt.wantKey {
				t.Errorf("generateKey() = %v, want %v", key, tt.wantKey)
			}
		})
	}
}

func TestSeverityRank(t *testing.T) {
	tests := []struct {
		severity types.Severity
		wantRank int
	}{
		{types.SeverityCritical, 5},
		{types.SeverityHigh, 4},
		{types.SeverityMedium, 3},
		{types.SeverityLow, 2},
		{types.SeverityInfo, 1},
		{types.Severity(""), 0},
	}

	for _, tt := range tests {
		t.Run(string(tt.severity), func(t *testing.T) {
			rank := severityRank(tt.severity)
			if rank != tt.wantRank {
				t.Errorf("severityRank(%v) = %d, want %d", tt.severity, rank, tt.wantRank)
			}
		})
	}
}
