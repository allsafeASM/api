package test

import (
	"testing"
  "api/internal/scanner"
  "api/internal/models"
)

func TestRunSubfinder(t *testing.T) {
	req := models.ScanRequest{
    ScanID: 1,
    Domain: "psu.edu.eg",
  }

	// Run Subfinder on a test domain
	subdomains := scanner.RunSubfinder(req)

  // Check if it returns any subdomains
  if len(subdomains.Subdomains) == 0 {
    t.Errorf("RunSubfinder() returned no subdomains")
  }

  // Print the Subdomains
  for num, subdomain := range subdomains.Subdomains {
    t.Logf("Subdomain %d: %s", num + 1, subdomain.Name)
  }
}

