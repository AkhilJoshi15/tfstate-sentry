package report

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/AkhilJoshi15/tfstate-sentry/internal/model"
)

func sampleFinding() model.Finding {
	return model.NewFinding("test.rule", model.SeverityHigh, "terraform_data.example", "terraform_data", "input.password", "Persisted secret detected.", "Metadata confirms exposure.", "Use an ephemeral value.", "abc123")
}

func TestWriteFormats(t *testing.T) {
	for _, format := range []string{"text", "json", "sarif"} {
		t.Run(format, func(t *testing.T) {
			var output bytes.Buffer
			if err := Write(format, &output, "synthetic.json", []model.Finding{sampleFinding()}); err != nil {
				t.Fatal(err)
			}
			if strings.Contains(output.String(), "secret-value") || !strings.Contains(output.String(), "test.rule") {
				t.Fatalf("unexpected %s output: %s", format, output.String())
			}
			if format == "json" || format == "sarif" {
				var document any
				if err := json.Unmarshal(output.Bytes(), &document); err != nil {
					t.Fatalf("invalid JSON: %v", err)
				}
			}
		})
	}
}

func TestWriteEmptyAndInvalidFormat(t *testing.T) {
	var output bytes.Buffer
	if err := Write("text", &output, "", nil); err != nil || !strings.Contains(output.String(), "No Terraform") {
		t.Fatalf("unexpected empty report: %q, %v", output.String(), err)
	}
	if err := Write("xml", &output, "", nil); err == nil {
		t.Fatal("expected unsupported format error")
	}
}

func TestWritePropagatesWriterErrors(t *testing.T) {
	if err := Write("text", failingWriter{}, "", []model.Finding{sampleFinding()}); err == nil {
		t.Fatal("expected writer error")
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("synthetic write failure") }
