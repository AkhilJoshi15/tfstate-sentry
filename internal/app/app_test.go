package app

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
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
