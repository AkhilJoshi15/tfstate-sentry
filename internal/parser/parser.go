package parser

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/AkhilJoshi15/tfstate-sentry/internal/model"
)

const maxInputBytes = 100 << 20 // 100 MiB

func Load(path string) ([]model.Resource, error) {
	var reader io.Reader
	if path == "-" {
		reader = os.Stdin
	} else {
		file, err := os.Open(path)
		if err != nil {
			return nil, fmt.Errorf("open input: %w", err)
		}
		defer file.Close()
		reader = file
	}

	data, err := io.ReadAll(io.LimitReader(reader, maxInputBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read input: %w", err)
	}
	if len(data) > maxInputBytes {
		return nil, fmt.Errorf("input exceeds %d MiB limit", maxInputBytes>>20)
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, fmt.Errorf("input is empty")
	}

	var root map[string]any
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := decoder.Decode(&root); err != nil {
		return nil, fmt.Errorf("decode JSON: %w", err)
	}

	switch {
	case hasMap(root, "planned_values") || hasArray(root, "resource_changes"):
		return parseShowPlan(root), nil
	case hasMap(root, "values"):
		return parseShowState(root), nil
	case hasArray(root, "resources"):
		return parseRawState(root), nil
	default:
		return nil, fmt.Errorf("unsupported JSON: expected raw tfstate or terraform show -json output")
	}
}

func parseShowPlan(root map[string]any) []model.Resource {
	// resource_changes contains after_sensitive and catches planned exposures most directly.
	if changes, ok := root["resource_changes"].([]any); ok {
		resources := make([]model.Resource, 0, len(changes))
		for _, item := range changes {
			changeResource, _ := item.(map[string]any)
			change, _ := changeResource["change"].(map[string]any)
			after := change["after"]
			if after == nil {
				continue
			}
			resources = append(resources, model.Resource{
				Address:         stringValue(changeResource["address"]),
				Type:            stringValue(changeResource["type"]),
				ProviderName:    stringValue(changeResource["provider_name"]),
				Values:          after,
				SensitiveValues: change["after_sensitive"],
				SourceKind:      "plan",
			})
		}
		return resources
	}

	plannedValues, _ := root["planned_values"].(map[string]any)
	rootModule, _ := plannedValues["root_module"].(map[string]any)
	return parseModule(rootModule, "plan")
}

func parseShowState(root map[string]any) []model.Resource {
	values, _ := root["values"].(map[string]any)
	rootModule, _ := values["root_module"].(map[string]any)
	return parseModule(rootModule, "state")
}

func parseModule(module map[string]any, kind string) []model.Resource {
	var resources []model.Resource
	items, _ := module["resources"].([]any)
	for _, item := range items {
		resource, _ := item.(map[string]any)
		resources = append(resources, model.Resource{
			Address:         stringValue(resource["address"]),
			Type:            stringValue(resource["type"]),
			ProviderName:    stringValue(resource["provider_name"]),
			Values:          resource["values"],
			SensitiveValues: resource["sensitive_values"],
			SourceKind:      kind,
		})
	}
	children, _ := module["child_modules"].([]any)
	for _, item := range children {
		child, _ := item.(map[string]any)
		resources = append(resources, parseModule(child, kind)...)
	}
	return resources
}

func parseRawState(root map[string]any) []model.Resource {
	var resources []model.Resource
	items, _ := root["resources"].([]any)
	for _, item := range items {
		resource, _ := item.(map[string]any)
		modulePrefix := stringValue(resource["module"])
		resourceType := stringValue(resource["type"])
		name := stringValue(resource["name"])
		instances, _ := resource["instances"].([]any)
		for index, instanceValue := range instances {
			instance, _ := instanceValue.(map[string]any)
			address := buildAddress(modulePrefix, resourceType, name, instance, index, len(instances))
			resources = append(resources, model.Resource{
				Address:         address,
				Type:            resourceType,
				ProviderName:    stringValue(resource["provider"]),
				Values:          instance["attributes"],
				SensitiveValues: sensitiveTree(instance),
				SourceKind:      "raw-state",
			})
		}
	}
	return resources
}

func sensitiveTree(instance map[string]any) any {
	// Raw state often stores sensitive paths as arrays. Convert simple paths to a tree.
	paths, _ := instance["sensitive_attributes"].([]any)
	root := map[string]any{}
	for _, pathValue := range paths {
		steps, _ := pathValue.([]any)
		cursor := root
		for index, stepValue := range steps {
			step := fmt.Sprint(stepValue)
			if index == len(steps)-1 {
				cursor[step] = true
				continue
			}
			next, ok := cursor[step].(map[string]any)
			if !ok {
				next = map[string]any{}
				cursor[step] = next
			}
			cursor = next
		}
	}
	return root
}

func buildAddress(modulePrefix, resourceType, name string, instance map[string]any, index, count int) string {
	base := strings.Trim(strings.Join([]string{modulePrefix, resourceType, name}, "."), ".")
	if key, ok := instance["index_key"]; ok {
		switch value := key.(type) {
		case string:
			return fmt.Sprintf(`%s[%q]`, base, value)
		default:
			return fmt.Sprintf("%s[%v]", base, value)
		}
	}
	if count > 1 {
		return fmt.Sprintf("%s[%d]", base, index)
	}
	return base
}

func hasMap(root map[string]any, key string) bool {
	_, ok := root[key].(map[string]any)
	return ok
}

func hasArray(root map[string]any, key string) bool {
	_, ok := root[key].([]any)
	return ok
}

func stringValue(value any) string {
	result, _ := value.(string)
	return result
}
