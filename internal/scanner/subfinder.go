package scanner

import (
	"bytes"
	"context"
	"io"
	"log"
  "api/internal/models"

	"github.com/projectdiscovery/subfinder/v2/pkg/runner"
)

func RunSubfinder(domain string) []models.SubdomainInfo {
	// Configure Subfinder options
	subfinderOpts := &runner.Options{
		Threads:            10,
		Timeout:            30,
		MaxEnumerationTime: 10,
	}

	// Disable timestamps in logs
	log.SetFlags(0)

	// Create Subfinder runner
	subfinder, err := runner.NewRunner(subfinderOpts)
	if err != nil {
    log.Fatalf("failed to create subfinder runner: %v", err)
  }

	// Capture Subfinder output
	output := &bytes.Buffer{}
	if err := subfinder.EnumerateSingleDomainWithCtx(context.Background(), domain, []io.Writer{output}); err != nil {
		log.Fatalf("failed to enumerate single domain: %v", err)
	}

	// Process output to extract subdomains
	var subdomains []models.SubdomainInfo
	lines := bytes.Split(output.Bytes(), []byte("\n"))
	for _, line := range lines {
		if len(line) > 0 {
      subdomains = append(subdomains, models.SubdomainInfo{Name: string(line)})
		}
	}

	return subdomains
}


