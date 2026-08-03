package schema

import (
	"os"
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

func TestLoadNestedAttributesAndDataSources(t *testing.T) {
	path := filepath.Join(t.TempDir(), "schema.json")
	data := `{
		"provider_schemas": {
			"registry.terraform.io/hashicorp/example": {
				"data_source_schemas": {
					"example_credentials": {
						"block": {
							"attributes": {
								"connection": {
									"nested_type": {
										"attributes": {
											"password": {"sensitive": true},
											"password_wo": {"write_only": true}
										}
									}
								}
							}
						}
					}
				}
			}
		}
	}`
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}

	index, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	attr, ok := index.Attribute("example_credentials", "connection.[0].password")
	if !ok || !attr.Sensitive {
		t.Fatal("expected normalized nested sensitive attribute")
	}
	alternative, ok := index.WriteOnlyAlternative("example_credentials", "connection.[0].password")
	if !ok || alternative != "connection.password_wo" {
		t.Fatalf("expected nested write-only alternative, got %q, %v", alternative, ok)
	}
}

func TestIndexMissingLookups(t *testing.T) {
	var nilIndex *Index
	if _, ok := nilIndex.Attribute("missing", "value"); ok {
		t.Fatal("nil index returned an attribute")
	}
	if _, ok := nilIndex.WriteOnlyAlternative("missing", "value"); ok {
		t.Fatal("nil index returned a write-only alternative")
	}
	if _, ok := Empty().Attribute("missing", "value"); ok {
		t.Fatal("missing resource returned an attribute")
	}
	if _, ok := Empty().WriteOnlyAlternative("missing", "value"); ok {
		t.Fatal("missing resource returned a write-only alternative")
	}
}
