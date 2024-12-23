package test

import (
	"testing"
  "api/internal/scanner"
)

func TestRunHttpx(t *testing.T) {
	subdomains := []string{"essd.psu.edu.eg", "phyd.psu.edu.eg", "staff.psu.edu.eg"}

	results, err := scanner.RunHttpx(subdomains)
	if err != nil {
		t.Fatalf("RunHttpx failed: %v", err)
	}

	if len(results) != 3 {
		t.Errorf("expected 3 results, got %d", len(results))
	}
}

