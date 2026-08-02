package detector

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/AkhilJoshi15/tfstate-sentry/internal/model"
	providerschema "github.com/AkhilJoshi15/tfstate-sentry/internal/schema"
)

var secretNamePattern = regexp.MustCompile(`(?i)(^|[_\-.])(password|passwd|pwd|secret|secret_key|api_key|apikey|access_key|private_key|client_secret|auth_token|refresh_token|bearer_token|connection_string|sas_token|token)($|[_\-.])`)

var credentialPatterns = []struct {
	id          string
	pattern     *regexp.Regexp
	severity    model.Severity
	message     string
	remediation string
}{
	{"credential.private-key", regexp.MustCompile(`-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----`), model.SeverityCritical, "Private key material is persisted in Terraform data.", "Generate or retrieve the private key outside Terraform state, then pass only a reference or use a supported write-only argument."},
	{"credential.aws-access-key", regexp.MustCompile(`\b(?:AKIA|ASIA)[A-Z0-9]{16}\b`), model.SeverityCritical, "An AWS access key identifier is persisted in Terraform data.", "Use workload identity or short-lived credentials. Rotate the exposed credential and remove it from state history."},
	{"credential.github-token", regexp.MustCompile(`\b(?:gh[pousr]_[A-Za-z0-9_]{20,255}|github_pat_[A-Za-z0-9_]{20,255})\b`), model.SeverityCritical, "A GitHub token is persisted in Terraform data.", "Use GitHub OIDC or inject the token ephemerally. Revoke and replace any real exposed token."},
	{"credential.jwt", regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b`), model.SeverityHigh, "A JWT-like token is persisted in Terraform data.", "Keep runtime tokens outside Terraform and use a secret manager reference or ephemeral value."},
	{"credential.uri-userinfo", regexp.MustCompile(`(?i)\b[a-z][a-z0-9+.-]*://[^\s/:]+:[^\s/@]+@`), model.SeverityHigh, "A URI containing embedded credentials is persisted in Terraform data.", "Store credentials separately and construct or retrieve the connection at runtime without persisting userinfo in state."},
}

var highRiskResources = map[string]string{
	"random_password":                      "Generated passwords are normally persisted in state unless an ephemeral resource is used.",
	"tls_private_key":                      "Generated private key material is persisted in state.",
	"aws_iam_access_key":                   "The secret access key can be persisted in state.",
	"aws_secretsmanager_secret_version":    "The secret string or binary value can be persisted in state.",
	"azurerm_key_vault_secret":             "The secret value can be persisted in state.",
	"google_secret_manager_secret_version": "The secret payload can be persisted in state.",
	"google_service_account_key":           "Private key material can be persisted in state.",
	"kubernetes_secret":                    "Secret data can be persisted in state.",
	"kubernetes_secret_v1":                 "Secret data can be persisted in state.",
}

type Scanner struct {
	Schema *providerschema.Index
}

func (s Scanner) Scan(resources []model.Resource) []model.Finding {
	seen := map[string]struct{}{}
	var findings []model.Finding

	for _, resource := range resources {
		if reason, ok := highRiskResources[resource.Type]; ok {
			finding := s.finding("resource.high-risk", model.SeverityHigh, resource, "$", "Secret-producing resource detected.", reason, "Prefer an ephemeral resource, a write-only argument, or create only the secret container and let the workload populate/retrieve the value at runtime.")
			appendUnique(&findings, seen, finding)
		}

		walk(resource.Values, "", func(path string, value any) {
			if value == nil {
				return
			}

			if isSensitivePath(resource.SensitiveValues, path) {
				remediation := s.remediation(resource.Type, path)
				finding := s.finding("terraform.sensitive-persisted", model.SeverityHigh, resource, path, "A Terraform-sensitive value is persisted in plan or state data.", "Terraform sensitivity metadata marks this attribute as sensitive, but the JSON representation still contains the value.", remediation)
				appendUnique(&findings, seen, finding)
			}

			if attr, ok := s.Schema.Attribute(resource.Type, path); ok && attr.Sensitive {
				remediation := s.remediation(resource.Type, path)
				finding := s.finding("provider.sensitive-persisted", model.SeverityHigh, resource, path, "A provider-sensitive attribute is persisted in plan or state data.", "The installed provider schema marks this attribute as sensitive.", remediation)
				appendUnique(&findings, seen, finding)
			}

			leaf := leafName(path)
			if secretNamePattern.MatchString("_"+leaf+"_") && isNonEmptyScalar(value) {
				finding := s.finding("heuristic.secret-name", model.SeverityMedium, resource, path, "A secret-like attribute name contains a persisted value.", "The attribute name matches a secret-bearing naming pattern.", s.remediation(resource.Type, path))
				appendUnique(&findings, seen, finding)
			}

			text, ok := value.(string)
			if !ok || text == "" {
				return
			}
			for _, pattern := range credentialPatterns {
				if pattern.pattern.MatchString(text) {
					finding := s.finding(pattern.id, pattern.severity, resource, path, pattern.message, "The value matches a known credential structure. The value is intentionally omitted.", pattern.remediation)
					appendUnique(&findings, seen, finding)
				}
			}

			// Secret-bearing JSON is common in attributes such as secret_string.
			if looksLikeJSON(text) {
				var nested any
				if json.Unmarshal([]byte(text), &nested) == nil {
					walk(nested, path+".<json>", func(nestedPath string, nestedValue any) {
						if secretNamePattern.MatchString("_"+leafName(nestedPath)+"_") && isNonEmptyScalar(nestedValue) {
							finding := s.finding("heuristic.nested-json-secret", model.SeverityHigh, resource, nestedPath, "A secret-like field is embedded inside a persisted JSON string.", "Recursive JSON inspection found a secret-bearing key. The value is intentionally omitted.", s.remediation(resource.Type, path))
							appendUnique(&findings, seen, finding)
						}
					})
				}
			}
		})
	}

	sort.SliceStable(findings, func(i, j int) bool {
		if findings[i].Severity != findings[j].Severity {
			return findings[i].Severity > findings[j].Severity
		}
		if findings[i].Resource != findings[j].Resource {
			return findings[i].Resource < findings[j].Resource
		}
		if findings[i].Path != findings[j].Path {
			return findings[i].Path < findings[j].Path
		}
		return findings[i].RuleID < findings[j].RuleID
	})

	return findings
}

func (s Scanner) remediation(resourceType, path string) string {
	if alternative, ok := s.Schema.WriteOnlyAlternative(resourceType, path); ok {
		return fmt.Sprintf("Replace %s with provider-supported write-only argument %s and supply it from an ephemeral value where possible.", normalizePath(path), alternative)
	}
	return "Keep the secret outside Terraform state. Prefer a runtime secret-manager reference, an ephemeral value, or a provider-supported write-only argument when available."
}

func (s Scanner) finding(ruleID string, severity model.Severity, resource model.Resource, path, message, evidence, remediation string) model.Finding {
	if path == "" {
		path = "$"
	}
	fingerprintSource := strings.Join([]string{ruleID, resource.Address, normalizePath(path)}, "|")
	sum := sha256.Sum256([]byte(fingerprintSource))
	return model.NewFinding(ruleID, severity, resource.Address, resource.Type, path, message, evidence, remediation, hex.EncodeToString(sum[:16]))
}

func appendUnique(findings *[]model.Finding, seen map[string]struct{}, finding model.Finding) {
	key := finding.RuleID + "|" + finding.Resource + "|" + finding.Path
	if _, ok := seen[key]; ok {
		return
	}
	seen[key] = struct{}{}
	*findings = append(*findings, finding)
}

func walk(value any, path string, visit func(string, any)) {
	switch typed := value.(type) {
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			next := join(path, key)
			child := typed[key]
			visit(next, child)
			walk(child, next, visit)
		}
	case []any:
		for index, child := range typed {
			next := fmt.Sprintf("%s.[%d]", path, index)
			visit(next, child)
			walk(child, next, visit)
		}
	}
}

func isSensitivePath(tree any, path string) bool {
	if tree == nil {
		return false
	}
	cursor := tree
	for _, part := range strings.Split(normalizePath(path), ".") {
		object, ok := cursor.(map[string]any)
		if !ok {
			return false
		}
		cursor, ok = object[part]
		if !ok {
			return false
		}
	}
	flag, _ := cursor.(bool)
	return flag
}

func normalizePath(path string) string {
	parts := strings.Split(path, ".")
	filtered := parts[:0]
	for _, part := range parts {
		if part == "" || strings.HasPrefix(part, "[") || part == "<json>" {
			continue
		}
		filtered = append(filtered, part)
	}
	return strings.Join(filtered, ".")
}

func leafName(path string) string {
	normalized := normalizePath(path)
	parts := strings.Split(normalized, ".")
	if len(parts) == 0 {
		return ""
	}
	return parts[len(parts)-1]
}

func join(prefix, name string) string {
	if prefix == "" {
		return name
	}
	return prefix + "." + name
}

func isNonEmptyScalar(value any) bool {
	switch typed := value.(type) {
	case string:
		return strings.TrimSpace(typed) != ""
	case bool, json.Number, float64, float32, int, int64:
		return true
	default:
		return false
	}
}

func looksLikeJSON(value string) bool {
	trimmed := strings.TrimSpace(value)
	return (strings.HasPrefix(trimmed, "{") && strings.HasSuffix(trimmed, "}")) || (strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]"))
}
