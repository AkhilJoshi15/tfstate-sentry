package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/AkhilJoshi15/tfstate-sentry/internal/buildinfo"
	"github.com/AkhilJoshi15/tfstate-sentry/internal/model"
)

func Write(format string, writer io.Writer, input string, findings []model.Finding) error {
	switch strings.ToLower(format) {
	case "text", "":
		return writeText(writer, findings)
	case "json":
		encoder := json.NewEncoder(writer)
		encoder.SetIndent("", "  ")
		return encoder.Encode(map[string]any{
			"tool":     "tfstate-sentry",
			"findings": findings,
			"summary":  summary(findings),
		})
	case "sarif":
		return writeSARIF(writer, input, findings)
	default:
		return fmt.Errorf("unsupported output format %q", format)
	}
}

func writeText(writer io.Writer, findings []model.Finding) error {
	if len(findings) == 0 {
		_, err := fmt.Fprintln(writer, "No Terraform state exposures detected.")
		return err
	}

	for index, finding := range findings {
		if index > 0 {
			fmt.Fprintln(writer)
		}
		fmt.Fprintf(writer, "%s  %s\n", finding.Severity.String(), finding.RuleID)
		fmt.Fprintf(writer, "Resource:    %s\n", finding.Resource)
		fmt.Fprintf(writer, "Path:        %s\n", finding.Path)
		fmt.Fprintf(writer, "Finding:     %s\n", finding.Message)
		fmt.Fprintf(writer, "Evidence:    %s\n", finding.Evidence)
		fmt.Fprintf(writer, "Remediation: %s\n", finding.Remediation)
		fmt.Fprintf(writer, "Value:       [REDACTED]\n")
		fmt.Fprintf(writer, "Fingerprint: %s\n", finding.Fingerprint)
	}

	counts := summary(findings)
	_, err := fmt.Fprintf(writer, "\nSummary: %d critical, %d high, %d medium, %d low\n", counts["critical"], counts["high"], counts["medium"], counts["low"])
	return err
}

func writeSARIF(writer io.Writer, input string, findings []model.Finding) error {
	rules := map[string]map[string]any{}
	results := make([]map[string]any, 0, len(findings))
	for _, finding := range findings {
		rules[finding.RuleID] = map[string]any{
			"id":               finding.RuleID,
			"shortDescription": map[string]string{"text": finding.Message},
			"help":             map[string]string{"text": finding.Remediation},
			"properties":       map[string]any{"security-severity": numericSecuritySeverity(finding.Severity)},
		}
		results = append(results, map[string]any{
			"ruleId":  finding.RuleID,
			"level":   finding.Severity.SARIFLevel(),
			"message": map[string]string{"text": fmt.Sprintf("%s Resource: %s. Attribute: %s. Secret value omitted.", finding.Message, finding.Resource, finding.Path)},
			"locations": []map[string]any{{
				"physicalLocation": map[string]any{
					"artifactLocation": map[string]string{"uri": input},
					"region":           map[string]int{"startLine": 1},
				},
				"logicalLocations": []map[string]string{{"name": finding.Resource + "." + finding.Path, "kind": "terraformAttribute"}},
			}},
			"partialFingerprints": map[string]string{"primaryLocationLineHash": finding.Fingerprint},
			"properties":          map[string]string{"resourceType": finding.ResourceType, "fingerprint": finding.Fingerprint},
		})
	}

	ruleList := make([]map[string]any, 0, len(rules))
	for _, rule := range rules {
		ruleList = append(ruleList, rule)
	}

	document := map[string]any{
		"version": "2.1.0",
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
		"runs": []map[string]any{{
			"tool": map[string]any{"driver": map[string]any{
				"name":            "tfstate-sentry",
				"informationUri":  "https://github.com/AkhilJoshi15/tfstate-sentry",
				"semanticVersion": buildinfo.Version,
				"rules":           ruleList,
			}},
			"results": results,
			"invocations": []map[string]any{{
				"executionSuccessful": true,
				"endTimeUtc":          time.Now().UTC().Format(time.RFC3339),
			}},
		}},
	}

	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", "  ")
	return encoder.Encode(document)
}

func summary(findings []model.Finding) map[string]int {
	result := map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0, "total": len(findings)}
	for _, finding := range findings {
		switch finding.Severity {
		case model.SeverityCritical:
			result["critical"]++
		case model.SeverityHigh:
			result["high"]++
		case model.SeverityMedium:
			result["medium"]++
		case model.SeverityLow:
			result["low"]++
		}
	}
	return result
}

func numericSecuritySeverity(severity model.Severity) string {
	switch severity {
	case model.SeverityCritical:
		return "9.5"
	case model.SeverityHigh:
		return "8.0"
	case model.SeverityMedium:
		return "5.5"
	default:
		return "3.0"
	}
}
