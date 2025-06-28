package scanners

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/projectdiscovery/dnsx/libs/dnsx"
)

func RunDNSX(ctx context.Context, hostfile string) ([]string, error) {
	// Check if input file exists
	if _, err := os.Stat(hostfile); os.IsNotExist(err) {
		return nil, fmt.Errorf("hostfile does not exist: %s", hostfile)
	}

	// Read hostnames from file
	hostnames, err := readHostnamesFromFile(hostfile)
	if err != nil {
		return nil, fmt.Errorf("failed to read hostnames: %w", err)
	}

	if len(hostnames) == 0 {
		return nil, fmt.Errorf("no hostnames found in file: %s", hostfile)
	}

	// Create DNSX instance
	dnsClient, err := dnsx.New(dnsx.Options{
		BaseResolvers: []string{
			"8.8.8.8:53",
			"8.8.4.4:53",
			"1.1.1.1:53",
		},
		MaxRetries: 3,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create DNSX client: %w", err)
	}

	// Prepare output file
	outputFile := fmt.Sprintf("%s_dnsx_results.txt", strings.TrimSuffix(hostfile, ".txt"))
	file, err := os.Create(outputFile)
	if err != nil {
		return nil, fmt.Errorf("failed to create output file: %w", err)
	}
	defer file.Close()

	var results []string

	// Process each hostname
	for _, hostname := range hostnames {
		hostname = strings.TrimSpace(hostname)
		if hostname == "" {
			continue
		}

		// Check if context is cancelled
		select {
		case <-ctx.Done():
			return results, ctx.Err()
		default:
		}

		// Run DNSX scan
		ips, err := dnsClient.Lookup(hostname)
		if err != nil {
			// Log error but continue with other hostnames
			fmt.Fprintf(file, "%s: ERROR - %v\n", hostname, err)
			continue
		}

		if len(ips) > 0 {
			// Write results to file
			result := fmt.Sprintf("%s: %s\n", hostname, strings.Join(ips, ", "))
			fmt.Fprint(file, result)
			results = append(results, result)
		} else {
			// No results found
			result := fmt.Sprintf("%s: NO_RESOLUTION\n", hostname)
			fmt.Fprint(file, result)
			results = append(results, result)
		}
	}

	return results, nil
}

// readHostnamesFromFile reads hostnames from a file, one per line
func readHostnamesFromFile(filename string) ([]string, error) {
	content, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	lines := strings.Split(string(content), "\n")
	var hostnames []string

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			hostnames = append(hostnames, line)
		}
	}

	return hostnames, nil
}
