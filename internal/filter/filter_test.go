package filter

import (
	"testing"

	"github.com/secagent/secagent/pkg/types"
)

func TestFilter(t *testing.T) {
	tests := []struct {
		name      string
		findings  []types.Finding
		ignore    types.IgnoreConfig
		wantLen   int
	}{
		{
			name:     "empty findings",
			findings: []types.Finding{},
			ignore:   types.IgnoreConfig{},
			wantLen:  0,
		},
		{
			name: "no ignore rules",
			findings: []types.Finding{
				{ID: "1", Severity: types.SeverityHigh},
			},
			ignore:  types.IgnoreConfig{},
			wantLen: 1,
		},
		{
			name: "ignore by severity",
			findings: []types.Finding{
				{ID: "1", Severity: types.SeverityHigh},
				{ID: "2", Severity: types.SeverityLow},
			},
			ignore: types.IgnoreConfig{
				Severities: []string{"low"},
			},
			wantLen: 1,
		},
		{
			name: "ignore by rule",
			findings: []types.Finding{
				{ID: "CKV_AWS_1", Scanner: "checkov"},
				{ID: "CKV_AWS_2", Scanner: "checkov"},
			},
			ignore: types.IgnoreConfig{
				Rules: []string{"CKV_AWS_1"},
			},
			wantLen: 1,
		},
		{
			name: "ignore by file pattern",
			findings: []types.Finding{
				{ID: "1", Location: types.Location{File: "app.py"}},
				{ID: "2", Location: types.Location{File: "test_app.py"}},
			},
			ignore: types.IgnoreConfig{
				Files: []string{"test_*.py"},
			},
			wantLen: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := Filter(tt.findings, tt.ignore)
			if len(result) != tt.wantLen {
				t.Errorf("Filter() returned %d findings, want %d", len(result), tt.wantLen)
			}
		})
	}
}

func TestMatchGlob(t *testing.T) {
	tests := []struct {
		name    string
		s       string
		pattern string
		want    bool
	}{
		{"exact match", "app.py", "app.py", true},
		{"wildcard start", "test_app.py", "*_app.py", true},
		{"wildcard end", "app.py", "app.*", true},
		{"wildcard both", "test_app.py", "*_app.*", true},
		{"no match", "app.py", "test_*.py", false},
		{"recursive wildcard", "src/app.py", "**/*.py", true},
		{"recursive no match", "src/app.py", "**/*.js", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := matchGlob(tt.s, tt.pattern)
			if got != tt.want {
				t.Errorf("matchGlob(%q, %q) = %v, want %v", tt.s, tt.pattern, got, tt.want)
			}
		})
	}
}

func TestMatchRule(t *testing.T) {
	tests := []struct {
		name    string
		finding types.Finding
		pattern string
		want    bool
	}{
		{
			name:    "exact rule match",
			finding: types.Finding{ID: "CKV_AWS_1"},
			pattern: "CKV_AWS_1",
			want:    true,
		},
		{
			name:    "wildcard rule match",
			finding: types.Finding{ID: "CKV_AWS_1"},
			pattern: "CKV_AWS_*",
			want:    true,
		},
		{
			name:    "check_id in metadata",
			finding: types.Finding{Metadata: map[string]interface{}{"check_id": "python.lang.security.*"}},
			pattern: "python.lang.security.*",
			want:    true,
		},
		{
			name:    "no match",
			finding: types.Finding{ID: "CKV_AWS_1"},
			pattern: "CKV_AZURE_*",
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := matchRule(tt.finding, tt.pattern)
			if got != tt.want {
				t.Errorf("matchRule() = %v, want %v", got, tt.want)
			}
		})
	}
}
