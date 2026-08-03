package detector

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/AkhilJoshi15/tfstate-sentry/internal/model"
	"github.com/AkhilJoshi15/tfstate-sentry/internal/parser"
	providerschema "github.com/AkhilJoshi15/tfstate-sentry/internal/schema"
)

func TestScanDetectsExposureWithoutLeakingValues(t *testing.T) {
	resources, err := parser.Load(filepath.Join("..", "..", "testdata", "show-plan", "unsafe.plan.json"))
	if err != nil {
		t.Fatal(err)
	}
	index, err := providerschema.Load(filepath.Join("..", "..", "testdata", "schema", "provider-schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	findings := (Scanner{Schema: index}).Scan(resources)
	if len(findings) < 3 {
		t.Fatalf("expected at least 3 findings, got %d", len(findings))
	}

	encoded, err := json.Marshal(findings)
	if err != nil {
		t.Fatal(err)
	}
	output := string(encoded)
	for _, forbidden := range []string{"synthetic-password-not-valid", "synthetic-key-not-valid"} {
		if strings.Contains(output, forbidden) {
			t.Fatalf("finding output leaked secret value %q", forbidden)
		}
	}

	foundWriteOnly := false
	for _, finding := range findings {
		if finding.Path == "password" && strings.Contains(finding.Remediation, "password_wo") {
			foundWriteOnly = true
		}
	}
	if !foundWriteOnly {
		t.Fatal("expected password_wo remediation")
	}
}

func TestScanDetectsPrivateKey(t *testing.T) {
	resources, err := parser.Load(filepath.Join("..", "..", "testdata", "raw-state", "unsafe.tfstate.json"))
	if err != nil {
		t.Fatal(err)
	}
	findings := (Scanner{Schema: providerschema.Empty()}).Scan(resources)
	found := false
	for _, finding := range findings {
		if finding.RuleID == "credential.private-key" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected private-key finding")
	}
}

func TestScanFindsListSensitivePathsAndDataSourceSchema(t *testing.T) {
	schema := providerschema.Empty()
	schema.Resources["data.aws_secretsmanager_secret"] = map[string]providerschema.Attribute{
		"credentials.password": {Sensitive: true},
	}

	resource := model.Resource{
		Address: "data.aws_secretsmanager_secret.example",
		Type:    "data.aws_secretsmanager_secret",
		Values: map[string]any{
			"credentials": []any{map[string]any{"password": "super-secret"}},
		},
		SensitiveValues: map[string]any{
			"credentials": []any{map[string]any{"password": true}},
		},
	}

	findings := Scanner{Schema: schema}.Scan([]model.Resource{resource})
	if len(findings) == 0 {
		t.Fatal("expected findings")
	}

	found := false
	for _, finding := range findings {
		if finding.Path == "credentials.[0].password" && finding.RuleID == "terraform.sensitive-persisted" {
			found = true
			break
		}
	}
	if !found {
		b, _ := json.Marshal(findings)
		t.Fatalf("expected list-based sensitive-path finding, got %s", string(b))
	}
}
