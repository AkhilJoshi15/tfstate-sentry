package model

import "testing"

func TestSeverityConversions(t *testing.T) {
	tests := []struct {
		input string
		want  Severity
		text  string
		sarif string
	}{
		{"low", SeverityLow, "LOW", "note"},
		{" Medium ", SeverityMedium, "MEDIUM", "warning"},
		{"HIGH", SeverityHigh, "HIGH", "error"},
		{"critical", SeverityCritical, "CRITICAL", "error"},
		{"invalid", SeverityUnknown, "UNKNOWN", "note"},
	}
	for _, test := range tests {
		got := ParseSeverity(test.input)
		if got != test.want || got.String() != test.text || got.SARIFLevel() != test.sarif {
			t.Fatalf("severity %q: got (%v, %q, %q)", test.input, got, got.String(), got.SARIFLevel())
		}
	}
}

func TestNewFindingExcludesSecretValues(t *testing.T) {
	finding := NewFinding("rule", SeverityHigh, "resource", "type", "path", "message", "evidence", "remediation", "fingerprint")
	if finding.SeverityText != "HIGH" || finding.Resource != "resource" || finding.Fingerprint != "fingerprint" {
		t.Fatalf("unexpected finding: %#v", finding)
	}
}
