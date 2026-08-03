package app

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestPlanCommandFailsUnsafePlansAndDoesNotLeakValues(t *testing.T) {
	terraformPath, err := exec.LookPath("terraform")
	if err != nil {
		t.Skip("terraform not installed")
	}

	tempDir := t.TempDir()
	secretValue := "ghp_deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
	writeTerraformModule(t, tempDir, fmt.Sprintf(`resource "terraform_data" "example" {
  input = %q
}

output "secret" {
  value = terraform_data.example.input
}
`, secretValue))

	if err := runTerraformCommand(terraformPath, tempDir, "init", "-input=false", "-no-color"); err != nil {
		t.Fatalf("terraform init failed: %v", err)
	}
	if err := runTerraformCommand(terraformPath, tempDir, "plan", "-input=false", "-no-color", "-out=tfplan"); err != nil {
		t.Fatalf("terraform plan failed: %v", err)
	}

	planJSONPath := filepath.Join(tempDir, "plan.json")
	if err := runTerraformShow(terraformPath, tempDir, "tfplan", planJSONPath); err != nil {
		t.Fatalf("terraform show failed: %v", err)
	}
	if !strings.Contains(string(mustReadFile(t, planJSONPath)), secretValue) {
		t.Fatalf("expected plan JSON to contain secret value %q", secretValue)
	}

	previousDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(previousDir)
	if err := os.Chdir(tempDir); err != nil {
		t.Fatal(err)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{"plan", "--fail-on", "high"}, &stdout, &stderr)
	if code != 3 {
		t.Fatalf("expected exit 3, got %d; stderr=%s", code, stderr.String())
	}

	combined := stdout.String() + stderr.String()
	if strings.Contains(combined, secretValue) {
		t.Fatalf("output leaked secret value %q", secretValue)
	}
	if !strings.Contains(combined, "[REDACTED]") {
		t.Fatalf("expected redacted output, got %q", combined)
	}
	if _, err := os.Stat(filepath.Join(tempDir, ".tfstate-sentry", "manifest.json")); err != nil {
		t.Fatalf("expected manifest file: %v", err)
	}
}

func TestPlanCommandAllowsNonSensitivePlans(t *testing.T) {
	terraformPath, err := exec.LookPath("terraform")
	if err != nil {
		t.Skip("terraform not installed")
	}

	tempDir := t.TempDir()
	writeTerraformModule(t, tempDir, `locals {
  sample = "ordinary-token-like-text"
}

output "demo" {
  value = local.sample
}`)

	if err := runTerraformCommand(terraformPath, tempDir, "init", "-input=false", "-no-color"); err != nil {
		t.Fatalf("terraform init failed: %v", err)
	}
	if err := runTerraformCommand(terraformPath, tempDir, "plan", "-input=false", "-no-color", "-out=tfplan"); err != nil {
		t.Fatalf("terraform plan failed: %v", err)
	}

	previousDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(previousDir)
	if err := os.Chdir(tempDir); err != nil {
		t.Fatal(err)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{"plan", "--fail-on", "high"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected exit 0, got %d; stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "No Terraform state exposures detected") {
		t.Fatalf("expected clean report, got %q", stdout.String())
	}
}

func writeTerraformModule(t *testing.T, dir, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "main.tf"), []byte(body), 0o600); err != nil {
		t.Fatalf("write module: %v", err)
	}
}

func runTerraformCommand(terraformPath, dir string, args ...string) error {
	cmd := exec.Command(terraformPath, args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "TF_IN_AUTOMATION=1")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

func runTerraformShow(terraformPath, dir, planPath, outputPath string) error {
	cmd := exec.Command(terraformPath, "show", "-json", planPath)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "TF_IN_AUTOMATION=1")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(output)))
	}
	return os.WriteFile(outputPath, output, 0o600)
}

func mustReadFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return data
}
