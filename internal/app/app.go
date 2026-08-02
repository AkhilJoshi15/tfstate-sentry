package app

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/AkhilJoshi15/tfstate-sentry/internal/buildinfo"
	"github.com/AkhilJoshi15/tfstate-sentry/internal/detector"
	"github.com/AkhilJoshi15/tfstate-sentry/internal/model"
	"github.com/AkhilJoshi15/tfstate-sentry/internal/parser"
	"github.com/AkhilJoshi15/tfstate-sentry/internal/report"
	providerschema "github.com/AkhilJoshi15/tfstate-sentry/internal/schema"
)

type options struct {
	input  string
	schema string
	format string
	output string
	failOn string
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
  tfstate-sentry version

Run "tfstate-sentry scan -h" for scan flags.`)
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
