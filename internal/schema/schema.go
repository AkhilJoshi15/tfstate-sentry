package schema

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// Attribute stores only the provider-schema metadata needed by the scanner.
type Attribute struct {
	Sensitive bool
	WriteOnly bool
}

// Index maps resource type and dot-separated attribute path to metadata.
type Index struct {
	Resources map[string]map[string]Attribute
}

func Empty() *Index {
	return &Index{Resources: map[string]map[string]Attribute{}}
}

func Load(path string) (*Index, error) {
	if strings.TrimSpace(path) == "" {
		return Empty(), nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read provider schema: %w", err)
	}

	var root map[string]any
	if err := json.Unmarshal(data, &root); err != nil {
		return nil, fmt.Errorf("decode provider schema: %w", err)
	}

	index := Empty()
	providers, _ := root["provider_schemas"].(map[string]any)
	for _, providerValue := range providers {
		provider, _ := providerValue.(map[string]any)
		resources, _ := provider["resource_schemas"].(map[string]any)
		for resourceType, resourceValue := range resources {
			resource, _ := resourceValue.(map[string]any)
			block, _ := resource["block"].(map[string]any)
			attrs := map[string]Attribute{}
			walkBlock(block, "", attrs)
			index.Resources[resourceType] = attrs
		}
	}

	return index, nil
}

func walkBlock(block map[string]any, prefix string, out map[string]Attribute) {
	attributes, _ := block["attributes"].(map[string]any)
	for name, value := range attributes {
		attribute, _ := value.(map[string]any)
		path := join(prefix, name)
		out[path] = Attribute{
			Sensitive: boolValue(attribute["sensitive"]),
			WriteOnly: boolValue(attribute["write_only"]),
		}

		// Newer provider schemas may describe nested attributes under nested_type.
		if nestedType, ok := attribute["nested_type"].(map[string]any); ok {
			walkNestedType(nestedType, path, out)
		}
	}

	blockTypes, _ := block["block_types"].(map[string]any)
	for name, value := range blockTypes {
		blockType, _ := value.(map[string]any)
		nestedBlock, _ := blockType["block"].(map[string]any)
		walkBlock(nestedBlock, join(prefix, name), out)
	}
}

func walkNestedType(nested map[string]any, prefix string, out map[string]Attribute) {
	attributes, _ := nested["attributes"].(map[string]any)
	for name, value := range attributes {
		attribute, _ := value.(map[string]any)
		path := join(prefix, name)
		out[path] = Attribute{
			Sensitive: boolValue(attribute["sensitive"]),
			WriteOnly: boolValue(attribute["write_only"]),
		}
		if child, ok := attribute["nested_type"].(map[string]any); ok {
			walkNestedType(child, path, out)
		}
	}
}

func (i *Index) Attribute(resourceType, path string) (Attribute, bool) {
	if i == nil {
		return Attribute{}, false
	}
	attrs, ok := i.Resources[resourceType]
	if !ok {
		return Attribute{}, false
	}
	normalized := normalizePath(path)
	attr, ok := attrs[normalized]
	return attr, ok
}

func (i *Index) WriteOnlyAlternative(resourceType, path string) (string, bool) {
	if i == nil {
		return "", false
	}
	attrs, ok := i.Resources[resourceType]
	if !ok {
		return "", false
	}
	path = normalizePath(path)
	parts := strings.Split(path, ".")
	if len(parts) == 0 {
		return "", false
	}
	parts[len(parts)-1] += "_wo"
	candidate := strings.Join(parts, ".")
	attr, ok := attrs[candidate]
	return candidate, ok && attr.WriteOnly
}

func normalizePath(path string) string {
	parts := strings.Split(path, ".")
	filtered := parts[:0]
	for _, part := range parts {
		if part == "" || isIndex(part) {
			continue
		}
		filtered = append(filtered, part)
	}
	return strings.Join(filtered, ".")
}

func isIndex(value string) bool {
	if len(value) < 3 || value[0] != '[' || value[len(value)-1] != ']' {
		return false
	}
	for _, r := range value[1 : len(value)-1] {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func join(prefix, name string) string {
	if prefix == "" {
		return name
	}
	return prefix + "." + name
}

func boolValue(value any) bool {
	result, _ := value.(bool)
	return result
}
