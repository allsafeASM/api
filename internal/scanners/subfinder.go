package scanners

import (
	"bytes"
	"context"
	"fmt"
	"io"
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
}

// NewSubfinderScanner creates a new subfinder scanner
func NewSubfinderScanner() *SubfinderScanner {
	return &SubfinderScanner{
		BaseScanner: NewBaseScanner(),
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
	if _, err = subfinder.EnumerateSingleDomainWithCtx(ctx, subfinderInput.Domain, []io.Writer{output}); err != nil {
		// Check if context was cancelled
		select {
		case <-ctx.Done():
			return nil, common.NewTimeoutError("subfinder execution cancelled", ctx.Err())
		default:
			return nil, common.NewScannerError("subfinder enumeration failed", err)
		}
	}

	// Process output to extract subdomains
	subdomains := s.processSubfinderOutput(output.Bytes(), subfinderInput.Domain)

	gologger.Debug().Msgf("Subfinder found %d subdomains for domain: %s", len(subdomains), subfinderInput.Domain)

	// Print the scan statistics
	stats := subfinder.GetStatistics()
	printStatistics(stats)

	return models.SubfinderResult{
		Domain:     subfinderInput.Domain,
		Subdomains: subdomains,
	}, nil
}

// processSubfinderOutput processes the raw output from subfinder and extracts subdomains
func (s *SubfinderScanner) processSubfinderOutput(output []byte, domain string) []string {
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
	// Add the domain to the subdomains
	subdomains = append(subdomains, domain)

	return subdomains
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
