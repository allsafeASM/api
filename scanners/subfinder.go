package scanners

import (
	"bytes"
	"context"
	"io"
	"log"
	"strings"

	"github.com/projectdiscovery/subfinder/v2/pkg/runner"
)

func RunSubfinder(ctx context.Context, domain string) ([]string, error) {
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
		return nil, err
	}

	// Capture Subfinder output
	output := &bytes.Buffer{}
	if _, err = subfinder.EnumerateSingleDomainWithCtx(ctx, domain, []io.Writer{output}); err != nil {
		return nil, err
	}

	// Process output to extract subdomains
	var subdomains []string

	// Split the buffer's content into lines using the newline byte.
	lines := bytes.SplitSeq(output.Bytes(), []byte("\n"))

	for lineBytes := range lines {
		// Convert the []byte line to a string and trim whitespace.
		// This handles cases where a line might just be spaces or empty after trimming.
		lineStr := strings.TrimSpace(string(lineBytes))

		// If the line is not empty after trimming, append it to subdomains.
		if len(lineStr) > 0 {
			subdomains = append(subdomains, lineStr)
		}
	}
	return subdomains, nil
}
