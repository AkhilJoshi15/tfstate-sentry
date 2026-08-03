package parser

import (
	"path/filepath"
	"testing"
)

func TestLoadRawState(t *testing.T) {
	resources, err := Load(filepath.Join("..", "..", "testdata", "raw-state", "unsafe.tfstate.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(resources) != 2 {
		t.Fatalf("expected 2 resources, got %d", len(resources))
	}
	if resources[0].Address != "aws_db_instance.main" {
		t.Fatalf("unexpected address: %s", resources[0].Address)
	}
}

func TestLoadShowPlan(t *testing.T) {
	resources, err := Load(filepath.Join("..", "..", "testdata", "show-plan", "unsafe.plan.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(resources) != 1 {
		t.Fatalf("expected 1 resource, got %d", len(resources))
	}
	if resources[0].SourceKind != "plan" {
		t.Fatalf("expected plan source, got %q", resources[0].SourceKind)
	}
}

func TestParseShowPlanIncludesInputsOutputsAndPriorState(t *testing.T) {
	root := map[string]any{
		"resource_changes": []any{},
		"variables": map[string]any{
			"password": map[string]any{"value": "super-secret", "sensitive": true},
		},
		"output_changes": map[string]any{
			"secret": map[string]any{"after": "output-secret", "after_sensitive": true},
		},
		"prior_state": map[string]any{
			"values": map[string]any{
				"root_module": map[string]any{
					"resources": []any{map[string]any{
						"address":          "module.demo.aws_db_instance.main",
						"type":             "aws_db_instance",
						"provider_name":    "registry.terraform.io/hashicorp/aws",
						"values":           map[string]any{"password": "old"},
						"sensitive_values": map[string]any{"password": true},
					}},
				},
			},
		},
	}

	resources := parseShowPlan(root)
	if len(resources) < 3 {
		t.Fatalf("expected at least 3 resources, got %d", len(resources))
	}

	addresses := map[string]bool{}
	for _, resource := range resources {
		addresses[resource.Address] = true
	}
	for _, want := range []string{"var.password", "output.secret", "module.demo.aws_db_instance.main"} {
		if !addresses[want] {
			t.Fatalf("expected parsed address %q", want)
		}
	}
}
