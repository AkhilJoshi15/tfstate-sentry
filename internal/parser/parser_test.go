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
