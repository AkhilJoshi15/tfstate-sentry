package app

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"

	"github.com/AkhilJoshi15/tfstate-sentry/internal/model"
)

func TestRunScanRedactsAndReturnsThresholdExit(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{
		"scan",
		"--schema", filepath.Join("..", "..", "testdata", "schema", "provider-schema.json"),
		"--fail-on", "high",
		filepath.Join("..", "..", "testdata", "show-plan", "unsafe.plan.json"),
	}, &stdout, &stderr)
	if code != 3 {
		t.Fatalf("expected exit 3, got %d; stderr=%s", code, stderr.String())
	}
	output := stdout.String()
	if !strings.Contains(output, "[REDACTED]") {
		t.Fatal("expected redacted marker")
	}
	if strings.Contains(output, "synthetic-password-not-valid") {
		t.Fatal("output leaked password")
	}
}

func TestRunCommandValidation(t *testing.T) {
	tests := []struct {
		args []string
		want int
	}{
		{nil, 2},
		{[]string{"unknown"}, 2},
		{[]string{"help"}, 0},
		{[]string{"scan", "--format", "xml", "input.json"}, 2},
		{[]string{"scan", "--fail-on", "severe", "input.json"}, 2},
	}
	for _, test := range tests {
		var stdout, stderr bytes.Buffer
		if got := Run(test.args, &stdout, &stderr); got != test.want {
			t.Fatalf("Run(%v)=%d, want %d", test.args, got, test.want)
		}
	}
}

func TestThresholdHelpers(t *testing.T) {
	if threshold, err := parseThreshold("none"); err != nil || threshold != model.SeverityUnknown {
		t.Fatalf("parse none: %v, %v", threshold, err)
	}
	if _, err := parseThreshold("severe"); err == nil {
		t.Fatal("expected invalid threshold error")
	}
	findings := []model.Finding{model.NewFinding("rule", model.SeverityHigh, "r", "t", "p", "m", "e", "r", "f")}
	if !meetsThreshold(findings, model.SeverityMedium) || meetsThreshold(findings, model.SeverityCritical) {
		t.Fatal("threshold comparison failed")
	}
}

func TestPlanReportsMissingTerraform(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	var stdout, stderr bytes.Buffer
	code := Run([]string{"plan", "--chdir", t.TempDir()}, &stdout, &stderr)
	if code != 1 || !strings.Contains(stderr.String(), "terraform not found") {
		t.Fatalf("expected missing terraform error, code=%d stderr=%q", code, stderr.String())
	}
}
