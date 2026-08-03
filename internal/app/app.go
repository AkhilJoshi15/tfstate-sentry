package app

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/AkhilJoshi15/tfstate-sentry/internal/buildinfo"
	"github.com/AkhilJoshi15/tfstate-sentry/internal/detector"
	"github.com/AkhilJoshi15/tfstate-sentry/internal/model"
	"github.com/AkhilJoshi15/tfstate-sentry/internal/parser"
	"github.com/AkhilJoshi15/tfstate-sentry/internal/report"
	providerschema "github.com/AkhilJoshi15/tfstate-sentry/internal/schema"
)

type options struct {
	input       string
	chdir       string
	schema      string
	format      string
	output      string
	failOn      string
	discardPlan bool
}

func Run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stderr)
		return 2
	}

	switch args[0] {
	case "version", "--version", "-version":
		fmt.Fprintln(stdout, buildinfo.Version)
		return 0
	case "scan":
		return runScan(args[1:], stdout, stderr)
	case "plan":
		return runPlan(args[1:], stdout, stderr)
	case "help", "--help", "-h":
		usage(stdout)
		return 0
	default:
		fmt.Fprintf(stderr, "unknown command %q\n\n", args[0])
		usage(stderr)
		return 2
	}
}

func runScan(args []string, stdout, stderr io.Writer) int {
	set := flag.NewFlagSet("scan", flag.ContinueOnError)
	set.SetOutput(stderr)
	var opts options
	set.StringVar(&opts.schema, "schema", "", "path to terraform providers schema -json output")
	set.StringVar(&opts.format, "format", "text", "output format: text, json, or sarif")
	set.StringVar(&opts.output, "output", "", "write report to a file instead of stdout")
	set.StringVar(&opts.failOn, "fail-on", "high", "exit 3 when findings meet threshold: none, low, medium, high, critical")
	set.Usage = func() { scanUsage(stderr) }
	if err := set.Parse(args); err != nil {
		return 2
	}
	if set.NArg() != 1 {
		scanUsage(stderr)
		return 2
	}
	opts.input = set.Arg(0)

	if !validFormat(opts.format) {
		fmt.Fprintf(stderr, "invalid --format %q\n", opts.format)
		return 2
	}
	threshold, err := parseThreshold(opts.failOn)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}

	resources, err := parser.Load(opts.input)
	if err != nil {
		fmt.Fprintf(stderr, "scan failed: %v\n", err)
		return 1
	}

	schemaIndex, err := providerschema.Load(opts.schema)
	if err != nil {
		fmt.Fprintf(stderr, "scan failed: %v\n", err)
		return 1
	}

	findings := detector.Scanner{Schema: schemaIndex}.Scan(resources)

	writer := stdout
	var file *os.File
	if opts.output != "" {
		file, err = os.OpenFile(opts.output, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
		if err != nil {
			fmt.Fprintf(stderr, "create report: %v\n", err)
			return 1
		}
		defer file.Close()
		writer = file
	}

	if err := report.Write(opts.format, writer, opts.input, findings); err != nil {
		fmt.Fprintf(stderr, "write report: %v\n", err)
		return 1
	}

	if meetsThreshold(findings, threshold) {
		return 3
	}
	return 0
}

func runPlan(args []string, stdout, stderr io.Writer) int {
	set := flag.NewFlagSet("plan", flag.ContinueOnError)
	set.SetOutput(stderr)
	var opts options
	set.StringVar(&opts.schema, "schema", "", "path to terraform providers schema -json output")
	set.StringVar(&opts.format, "format", "text", "output format: text, json, or sarif")
	set.StringVar(&opts.output, "output", "", "write report to a file instead of stdout")
	set.StringVar(&opts.failOn, "fail-on", "high", "exit 3 when findings meet threshold: none, low, medium, high, critical")
	set.StringVar(&opts.chdir, "chdir", "", "working directory for terraform plan")
	set.BoolVar(&opts.discardPlan, "discard-plan", false, "delete the saved plan after scanning even when approved")
	set.Usage = func() { planUsage(stderr) }
	if err := set.Parse(args); err != nil {
		return 2
	}
	if !validFormat(opts.format) {
		fmt.Fprintf(stderr, "invalid --format %q\n", opts.format)
		return 2
	}
	threshold, err := parseThreshold(opts.failOn)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}

	workingDir := "."
	if opts.chdir != "" {
		workingDir = opts.chdir
	}
	workingDirAbs, err := filepath.Abs(workingDir)
	if err != nil {
		fmt.Fprintf(stderr, "resolve working directory: %v\n", err)
		return 1
	}
	stateDir := filepath.Join(workingDirAbs, ".tfstate-sentry")
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		fmt.Fprintf(stderr, "create state dir: %v\n", err)
		return 1
	}
	planPath := filepath.Join(stateDir, "tfplan")
	schemaPath := filepath.Join(stateDir, "provider-schema.json")
	planJSONPath := filepath.Join(stateDir, "plan.json")
	manifestPath := filepath.Join(stateDir, "manifest.json")
	planApproved := false
	defer func() {
		_ = os.Remove(planJSONPath)
		_ = os.Remove(schemaPath)
		if !planApproved || opts.discardPlan {
			_ = os.Remove(planPath)
		}
	}()

	terraformPath, err := exec.LookPath("terraform")
	if err != nil {
		fmt.Fprintf(stderr, "terraform not found: %v\n", err)
		return 1
	}

	previousDir, err := os.Getwd()
	if err != nil {
		fmt.Fprintf(stderr, "get working directory: %v\n", err)
		return 1
	}
	if err := os.Chdir(workingDirAbs); err != nil {
		fmt.Fprintf(stderr, "change working directory: %v\n", err)
		return 1
	}
	defer os.Chdir(previousDir)

	if output, err := runTerraform(terraformPath, workingDirAbs, "init", "-input=false", "-no-color"); err != nil {
		fmt.Fprintf(stderr, "terraform init failed: %v\n%s", err, output)
		return 1
	}
	if output, err := runTerraform(terraformPath, workingDirAbs, "plan", "-input=false", "-no-color", "-out", planPath); err != nil {
		fmt.Fprintf(stderr, "terraform plan failed: %v\n%s", err, output)
		return 1
	}
	if err := os.Chmod(planPath, 0o600); err != nil {
		fmt.Fprintf(stderr, "protect saved plan: %v\n", err)
		return 1
	}
	var schemaOutput string
	if opts.schema != "" {
		schemaBytes, readErr := os.ReadFile(opts.schema)
		if readErr != nil {
			fmt.Fprintf(stderr, "read schema input: %v\n", readErr)
			return 1
		}
		schemaOutput = string(schemaBytes)
	} else {
		schemaOutput, err = runTerraform(terraformPath, workingDirAbs, "providers", "schema", "-json")
		if err != nil {
			fmt.Fprintf(stderr, "terraform providers schema failed: %v\n%s", err, schemaOutput)
			return 1
		}
	}
	if err := os.WriteFile(schemaPath, []byte(schemaOutput), 0o600); err != nil {
		fmt.Fprintf(stderr, "write schema output: %v\n", err)
		return 1
	}
	planOutput, err := runTerraform(terraformPath, workingDirAbs, "show", "-json", planPath)
	if err != nil {
		fmt.Fprintf(stderr, "terraform show failed: %v\n%s", err, planOutput)
		return 1
	}
	if err := os.WriteFile(planJSONPath, []byte(planOutput), 0o600); err != nil {
		fmt.Fprintf(stderr, "write plan output: %v\n", err)
		return 1
	}

	resources, err := parser.Load(planJSONPath)
	if err != nil {
		fmt.Fprintf(stderr, "scan failed: %v\n", err)
		return 1
	}

	schemaIndex, err := providerschema.Load(schemaPath)
	if err != nil {
		fmt.Fprintf(stderr, "scan failed: %v\n", err)
		return 1
	}
	findings := detector.Scanner{Schema: schemaIndex}.Scan(resources)

	writer := stdout
	var file *os.File
	if opts.output != "" {
		file, err = os.OpenFile(opts.output, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
		if err != nil {
			fmt.Fprintf(stderr, "create report: %v\n", err)
			return 1
		}
		defer file.Close()
		writer = file
	}
	if err := report.Write(opts.format, writer, planJSONPath, findings); err != nil {
		fmt.Fprintf(stderr, "write report: %v\n", err)
		return 1
	}

	manifest := map[string]any{
		"plan_sha256":       sha256Hash(planPath),
		"scanner_version":   buildinfo.Version,
		"terraform_version": terraformVersion(terraformPath),
		"working_directory": workingDirAbs,
		"scan_threshold":    opts.failOn,
		"scan_timestamp":    time.Now().UTC().Format(time.RFC3339),
		"finding_summary": map[string]int{
			"critical": 0,
			"high":     0,
			"medium":   0,
			"low":      0,
			"total":    len(findings),
		},
	}
	for _, finding := range findings {
		switch finding.Severity {
		case model.SeverityCritical:
			manifest["finding_summary"].(map[string]int)["critical"]++
		case model.SeverityHigh:
			manifest["finding_summary"].(map[string]int)["high"]++
		case model.SeverityMedium:
			manifest["finding_summary"].(map[string]int)["medium"]++
		case model.SeverityLow:
			manifest["finding_summary"].(map[string]int)["low"]++
		}
	}
	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		fmt.Fprintf(stderr, "marshal manifest: %v\n", err)
		return 1
	}
	if err := os.WriteFile(manifestPath, manifestBytes, 0o600); err != nil {
		fmt.Fprintf(stderr, "write manifest: %v\n", err)
		return 1
	}

	if meetsThreshold(findings, threshold) {
		return 3
	}
	planApproved = true
	return 0
}

func runTerraform(terraformPath, dir string, args ...string) (string, error) {
	cmd := exec.Command(terraformPath, args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "TF_IN_AUTOMATION=1")
	output, err := cmd.CombinedOutput()
	return string(output), err
}

func terraformVersion(terraformPath string) string {
	cmd := exec.Command(terraformPath, "version", "-json")
	cmd.Env = append(os.Environ(), "TF_IN_AUTOMATION=1")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "unknown"
	}
	var payload struct {
		TerraformVersion string `json:"terraform_version"`
	}
	if err := json.Unmarshal(output, &payload); err == nil && payload.TerraformVersion != "" {
		return payload.TerraformVersion
	}
	return strings.TrimSpace(string(output))
}

func sha256Hash(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func parseThreshold(value string) (model.Severity, error) {
	if strings.EqualFold(value, "none") {
		return model.SeverityUnknown, nil
	}
	severity := model.ParseSeverity(value)
	if severity == model.SeverityUnknown {
		return severity, errors.New("--fail-on must be one of: none, low, medium, high, critical")
	}
	return severity, nil
}

func meetsThreshold(findings []model.Finding, threshold model.Severity) bool {
	if threshold == model.SeverityUnknown {
		return false
	}
	for _, finding := range findings {
		if finding.Severity >= threshold {
			return true
		}
	}
	return false
}

func validFormat(format string) bool {
	switch strings.ToLower(format) {
	case "text", "json", "sarif":
		return true
	default:
		return false
	}
}

func usage(writer io.Writer) {
	fmt.Fprintln(writer, `tfstate-sentry detects confidential values persisted in Terraform plan and state data.

Usage:
  tfstate-sentry scan [flags] <state-or-plan.json>
  tfstate-sentry plan [flags]
  tfstate-sentry version

Run "tfstate-sentry scan -h" or "tfstate-sentry plan -h" for flags.`)
}

func scanUsage(writer io.Writer) {
	fmt.Fprintln(writer, `Usage:
  tfstate-sentry scan [flags] <state-or-plan.json>

Input may be:
  - raw terraform.tfstate JSON
  - terraform show -json state output
  - terraform show -json plan output
  - stdin using -

Flags:
  --schema <path>       terraform providers schema -json output
  --format <format>     text, json, or sarif (default: text)
  --output <path>       report destination; files are created with mode 0600
  --fail-on <severity>  none, low, medium, high, critical (default: high)`)
}

func planUsage(writer io.Writer) {
	fmt.Fprintln(writer, `Usage:
  tfstate-sentry plan [flags]

Runs terraform init, terraform plan, terraform providers schema, and terraform show -json in the chosen working directory, then scans the saved plan and writes a manifest.

Flags:
  --chdir <path>        working directory for terraform plan (default: current directory)
  --discard-plan        delete the saved plan after a successful scan
  --schema <path>       use an existing provider schema instead of querying Terraform
  --format <format>     text, json, or sarif (default: text)
  --output <path>       report destination; files are created with mode 0600
  --fail-on <severity>  none, low, medium, high, critical (default: high)`)
}
