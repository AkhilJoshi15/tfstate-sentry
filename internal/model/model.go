package model

import "strings"

// Severity represents the impact of a detected state exposure.
type Severity int

const (
	SeverityUnknown Severity = iota
	SeverityLow
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

func ParseSeverity(value string) Severity {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "low":
		return SeverityLow
	case "medium":
		return SeverityMedium
	case "high":
		return SeverityHigh
	case "critical":
		return SeverityCritical
	default:
		return SeverityUnknown
	}
}

func (s Severity) String() string {
	switch s {
	case SeverityLow:
		return "LOW"
	case SeverityMedium:
		return "MEDIUM"
	case SeverityHigh:
		return "HIGH"
	case SeverityCritical:
		return "CRITICAL"
	default:
		return "UNKNOWN"
	}
}

func (s Severity) SARIFLevel() string {
	switch s {
	case SeverityCritical, SeverityHigh:
		return "error"
	case SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}

// Resource is a normalized Terraform resource from raw state or terraform show JSON.
type Resource struct {
	Address         string
	Type            string
	ProviderName    string
	Values          any
	SensitiveValues any
	SourceKind      string
}

// Finding deliberately excludes the detected value.
type Finding struct {
	RuleID       string   `json:"rule_id"`
	Severity     Severity `json:"-"`
	SeverityText string   `json:"severity"`
	Resource     string   `json:"resource"`
	ResourceType string   `json:"resource_type,omitempty"`
	Path         string   `json:"path"`
	Message      string   `json:"message"`
	Evidence     string   `json:"evidence"`
	Remediation  string   `json:"remediation"`
	Fingerprint  string   `json:"fingerprint"`
}

func NewFinding(ruleID string, severity Severity, resource, resourceType, path, message, evidence, remediation, fingerprint string) Finding {
	return Finding{
		RuleID:       ruleID,
		Severity:     severity,
		SeverityText: severity.String(),
		Resource:     resource,
		ResourceType: resourceType,
		Path:         path,
		Message:      message,
		Evidence:     evidence,
		Remediation:  remediation,
		Fingerprint:  fingerprint,
	}
}
