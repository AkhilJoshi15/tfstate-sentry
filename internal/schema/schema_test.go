package schema

import (
	"path/filepath"
	"testing"
)

func TestLoadAndFindWriteOnlyAlternative(t *testing.T) {
	index, err := Load(filepath.Join("..", "..", "testdata", "schema", "provider-schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	attr, ok := index.Attribute("aws_db_instance", "password")
	if !ok || !attr.Sensitive {
		t.Fatal("expected sensitive password attribute")
	}
	alternative, ok := index.WriteOnlyAlternative("aws_db_instance", "password")
	if !ok || alternative != "password_wo" {
		t.Fatalf("expected password_wo, got %q, %v", alternative, ok)
	}
}
