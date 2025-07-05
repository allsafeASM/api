package scanners

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/allsafeASM/api/internal/common"
	"github.com/allsafeASM/api/internal/models"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/subfinder/v2/pkg/runner"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
	"golang.org/x/exp/maps"
)

// SubfinderScanner implements the Scanner interface for subfinder
type SubfinderScanner struct {
	*BaseScanner
	apiKey string
}

// NewSubfinderScanner creates a new subfinder scanner
func NewSubfinderScanner() *SubfinderScanner {
	apiKey := os.Getenv("SUBDOMAIN_API_KEY")
	return &SubfinderScanner{
		BaseScanner: NewBaseScanner(),
		apiKey:      apiKey,
	}
}

func (s *SubfinderScanner) Execute(ctx context.Context, input interface{}) (models.ScannerResult, error) {
	// Type assert and validate input
	subfinderInput, ok := input.(models.SubfinderInput)
	if !ok {
		return nil, common.NewValidationError("input", "invalid input type, expected SubfinderInput")
	}

	// Validate input using base scanner
	if err := s.ValidateInput(subfinderInput); err != nil {
		return nil, err
	}

	// Collect subdomains from multiple sources
	var allSubdomains []string

	// 1. Get subdomains from API if API key is available
	if s.apiKey != "" {
		apiSubdomains, err := s.fetchSubdomainsFromAPI(ctx, subfinderInput.Domain)
		if err != nil {
			gologger.Warning().Msgf("Failed to fetch subdomains from API: %v", err)
		} else {
			allSubdomains = append(allSubdomains, apiSubdomains...)
			gologger.Info().Msgf("API found %d subdomains for domain: %s", len(apiSubdomains), subfinderInput.Domain)
		}
	}

	// 2. Get subdomains from subfinder tool
	subfinderSubdomains, err := s.runSubfinder(ctx, subfinderInput.Domain)
	if err != nil {
		gologger.Warning().Msgf("Failed to run subfinder: %v", err)
	} else {
		allSubdomains = append(allSubdomains, subfinderSubdomains...)
		gologger.Info().Msgf("Subfinder found %d subdomains for domain: %s", len(subfinderSubdomains), subfinderInput.Domain)
	}

	// Remove duplicates and sort
	uniqueSubdomains := s.removeDuplicates(allSubdomains)
	sort.Strings(uniqueSubdomains)

	// Ensure the main domain is included
	if !s.contains(uniqueSubdomains, subfinderInput.Domain) {
		uniqueSubdomains = append(uniqueSubdomains, subfinderInput.Domain)
		sort.Strings(uniqueSubdomains)
	}

	gologger.Info().Msgf("Total unique subdomains found: %d for domain: %s", len(uniqueSubdomains), subfinderInput.Domain)

	return models.SubfinderResult{
		Domain:     subfinderInput.Domain,
		Subdomains: uniqueSubdomains,
	}, nil
}

// fetchSubdomainsFromAPI makes an HTTP request to the subdomain API endpoint
func (s *SubfinderScanner) fetchSubdomainsFromAPI(ctx context.Context, domain string) ([]string, error) {
	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	// Create request
	url := fmt.Sprintf("https://api.subbdom.com/v1/search?z=%s", domain)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Add API key header
	req.Header.Set("x-api-key", s.apiKey)

	// Make the request
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()

	// Check response status
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API returned non-200 status: %d", resp.StatusCode)
	}

	// Parse JSON response
	var subdomains []string
	if err := json.NewDecoder(resp.Body).Decode(&subdomains); err != nil {
		return nil, fmt.Errorf("failed to decode JSON response: %w", err)
	}

	return subdomains, nil
}

// runSubfinder executes the subfinder tool and returns the results
func (s *SubfinderScanner) runSubfinder(ctx context.Context, domain string) ([]string, error) {
	// Configure Subfinder options with optimized settings
	subfinderOpts := &runner.Options{
		Threads:            10,
		Timeout:            60, // 60 seconds timeout
		MaxEnumerationTime: 30, // 30 seconds max enumeration time
		RateLimit:          1000,
		All:                true,
		ProviderConfig:     "/root/.config/subfinder/provider-config.yaml",
		//ExcludeSources:     []string{"bufferover", "crtsh", "dnsdumpster", "hackertarget", "rapiddns", "threatcrowd", "virustotal", "zoomeye"},
	}

	// Create Subfinder runner
	subfinder, err := runner.NewRunner(subfinderOpts)
	if err != nil {
		return nil, common.NewScannerError("failed to create subfinder runner", err)
	}

	// Capture Subfinder output
	output := &bytes.Buffer{}

	// Run subfinder with context
	if _, err = subfinder.EnumerateSingleDomainWithCtx(ctx, domain, []io.Writer{output}); err != nil {
		// Check if context was cancelled
		select {
		case <-ctx.Done():
			return nil, common.NewTimeoutError("subfinder execution cancelled", ctx.Err())
		default:
			return nil, common.NewScannerError("subfinder enumeration failed", err)
		}
	}

	// Process output to extract subdomains
	subdomains := s.processSubfinderOutput(output.Bytes())

	// Print the scan statistics
	stats := subfinder.GetStatistics()
	printStatistics(stats)

	return subdomains, nil
}

// processSubfinderOutput processes the raw output from subfinder and extracts subdomains
func (s *SubfinderScanner) processSubfinderOutput(output []byte) []string {
	var subdomains []string

	// Split the buffer's content into lines using the newline byte
	lines := bytes.SplitSeq(output, []byte("\n"))

	for lineBytes := range lines {
		// Convert the []byte line to a string and trim whitespace
		lineStr := strings.TrimSpace(string(lineBytes))

		// If the line is not empty after trimming, append it to subdomains
		if len(lineStr) > 0 {
			subdomains = append(subdomains, lineStr)
		}
	}

	return subdomains
}

// removeDuplicates removes duplicate subdomains from the slice
func (s *SubfinderScanner) removeDuplicates(subdomains []string) []string {
	seen := make(map[string]bool)
	var result []string

	for _, subdomain := range subdomains {
		if !seen[subdomain] {
			seen[subdomain] = true
			result = append(result, subdomain)
		}
	}

	return result
}

// contains checks if a slice contains a specific string
func (s *SubfinderScanner) contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func (s *SubfinderScanner) GetName() string {
	return "subfinder"
}

func printStatistics(stats map[string]subscraping.Statistics) {

	sources := maps.Keys(stats)
	sort.Strings(sources)

	var lines []string
	var skipped []string

	for _, source := range sources {
		sourceStats := stats[source]
		if sourceStats.Skipped {
			skipped = append(skipped, fmt.Sprintf(" %s", source))
		} else {
			lines = append(lines, fmt.Sprintf(" %-20s %-10s %10d %10d", source, sourceStats.TimeTaken.Round(time.Millisecond).String(), sourceStats.Results, sourceStats.Errors))
		}
	}

	if len(lines) > 0 {
		gologger.Print().Msgf("\n Source               Duration      Results     Errors\n%s\n", strings.Repeat("─", 56))
		gologger.Print().Msg(strings.Join(lines, "\n"))
		gologger.Print().Msgf("\n")
	}

	if len(skipped) > 0 {
		gologger.Print().Msgf("\n The following sources were included but skipped...\n\n")
		gologger.Print().Msg(strings.Join(skipped, "\n"))
		gologger.Print().Msgf("\n\n")
	}
}
