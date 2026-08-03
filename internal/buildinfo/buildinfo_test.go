package buildinfo

import "testing"

func TestDevelopmentBuildMetadata(t *testing.T) {
	if Version != "0.2.0-dev" {
		t.Fatalf("unexpected development version %q", Version)
	}
	if Commit == "" || Date == "" {
		t.Fatal("build metadata defaults must not be empty")
	}
}
