package scanners

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/subfinder/v2/pkg/runner"
)

func RunSubfinder(ctx context.Context, domain string) ([]string, error) {
	// Configure Subfinder options with more reasonable timeouts
	subfinderOpts := &runner.Options{
		Threads:            10,
		Timeout:            60, // Increased from 30 to 60 seconds
		MaxEnumerationTime: 30, // Increased from 10 to 30 seconds
	}

	// Create Subfinder runner
	subfinder, err := runner.NewRunner(subfinderOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to create subfinder runner: %w", err)
	}

	// Capture Subfinder output
	output := &bytes.Buffer{}

	// Run subfinder with context
	if _, err = subfinder.EnumerateSingleDomainWithCtx(ctx, domain, []io.Writer{output}); err != nil {
		// Check if context was cancelled
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
			return nil, fmt.Errorf("subfinder enumeration failed: %w", err)
		}
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

	gologger.Debug().Msgf("Subfinder found %d subdomains for domain: %s", len(subdomains), domain)
	return subdomains, nil
}
