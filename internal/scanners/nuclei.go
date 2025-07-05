package scanners

import (
	"context"
	"strings"
	"time"

	"github.com/allsafeASM/api/internal/azure"
	"github.com/allsafeASM/api/internal/common"
	"github.com/allsafeASM/api/internal/models"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
	nuclei "github.com/projectdiscovery/nuclei/v3/lib"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
)

// NucleiScanner implements the Scanner interface for nuclei
type NucleiScanner struct {
	*BaseScanner
	blobClient *azure.BlobStorageClient
}

// NewNucleiScanner creates a new nuclei scanner
func NewNucleiScanner() *NucleiScanner {
	return &NucleiScanner{
		BaseScanner: NewBaseScanner(),
	}
}

// SetBlobClient sets the blob client for the Nuclei scanner
func (s *NucleiScanner) SetBlobClient(blobClient *azure.BlobStorageClient) {
	s.blobClient = blobClient
}

func (s *NucleiScanner) Execute(ctx context.Context, input interface{}) (models.ScannerResult, error) {
	// Type assert and validate input
	nucleiInput, ok := input.(models.NucleiInput)
	if !ok {
		return nil, common.NewValidationError("input", "invalid input type, expected NucleiInput")
	}

	// Validate input using base scanner
	if err := s.ValidateInput(nucleiInput); err != nil {
		return nil, err
	}

	// Check if context is cancelled
	select {
	case <-ctx.Done():
		return nil, common.NewTimeoutError("nuclei execution cancelled", ctx.Err())
	default:
	}

	gologger.Info().Msgf("Starting nuclei scan for domain: %s with type: %s", nucleiInput.Domain, nucleiInput.Type)

	// Set log level to fatal to reduce noise during nuclei execution
	gologger.DefaultLogger.SetMaxLevel(levels.LevelFatal)

	var hosts []string
	if nucleiInput.HostsFileLocation != "" {
		if s.blobClient == nil {
			return nil, common.NewValidationError("blob_client", "hosts file location provided but blob client is not initialized")
		}
		gologger.Debug().Msgf("Reading hosts file from blob storage: %s", nucleiInput.HostsFileLocation)
		hostsFileContent, err := s.blobClient.ReadHostsFileFromBlob(ctx, nucleiInput.HostsFileLocation)
		if err != nil {
			return nil, common.NewScannerError("failed to read hosts file from blob storage", err)
		}
		for line := range strings.SplitSeq(hostsFileContent, "\n") {
			clean := strings.TrimSpace(line)
			if clean != "" {
				hosts = append(hosts, clean)
			}
		}
		gologger.Debug().Msgf("Loaded %d hosts from blob storage", len(hosts))
	} else {
		hosts = []string{nucleiInput.Domain}
	}

	if len(hosts) == 0 {
		return models.NucleiResult{
			Domain:          nucleiInput.Domain,
			Vulnerabilities: []models.NucleiVulnerability{},
		}, nil
	}

	// Create nuclei engine with protocol filtering based on input Type
	var engineOpts []nuclei.NucleiSDKOptions

	// Set scan strategy to host-spray for better reliability and maximum coverage
	engineOpts = append(engineOpts, nuclei.WithScanStrategy("host-spray"))

	// Set optimized concurrency for maximum results while reducing dropped requests
	engineOpts = append(engineOpts, nuclei.WithConcurrency(nuclei.Concurrency{
		TemplateConcurrency:           200, // Reduced from 500 to prevent overwhelming
		HostConcurrency:               10,  // Increased from 5 for better throughput
		HeadlessHostConcurrency:       10,  // Increased from 5
		HeadlessTemplateConcurrency:   50,  // Increased from 25
		JavascriptTemplateConcurrency: 50,  // Increased from 25
		TemplatePayloadConcurrency:    50,  // Increased from 25
		ProbeConcurrency:              100, // Increased from 50
	}))

	// Set rate limit to 1000 requests per second
	engineOpts = append(engineOpts, nuclei.WithGlobalRateLimitCtx(ctx, 500, time.Second))

	// Set protocol filters as before
	if nucleiInput.Type == "http" {
		engineOpts = append(engineOpts, nuclei.WithTemplateFilters(nuclei.TemplateFilters{ProtocolTypes: "http"}))
	} else {
		engineOpts = append(engineOpts, nuclei.WithTemplateFilters(nuclei.TemplateFilters{ExcludeProtocolTypes: "http"}))
	}

	// Disable template update check
	engineOpts = append(engineOpts, nuclei.DisableUpdateCheck())

	// Set template path to /root/nuclei-templates
	engineOpts = append(engineOpts, nuclei.WithTemplatesOrWorkflows(nuclei.TemplateSources{
		Templates: []string{"/root/nuclei-templates"},
	}))

	// Restore log level to info after nuclei execution
	defer func() {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelInfo)
		gologger.Info().Msgf("Nuclei scan completed for domain: %s", nucleiInput.Domain)
	}()
	// Note: Additional options like retries, timeout, and headless mode
	// are not available in the current Nuclei SDK version
	// The configuration above focuses on concurrency and rate limiting
	// to maximize results while reducing dropped requests
	ne, err := nuclei.NewNucleiEngineCtx(ctx, engineOpts...)
	if err != nil {
		return nil, common.NewScannerError("failed to create nuclei engine", err)
	}
	defer ne.Close()

	// Load targets
	ne.LoadTargets(hosts, false)

	// Collect vulnerabilities
	vulnerabilities := make([]models.NucleiVulnerability, 0)

	// Execute with callback to collect results
	err = ne.ExecuteWithCallback(func(event *output.ResultEvent) {
		// Handle the event and convert to our model
		if event != nil {
			// Convert severity from severity.Holder to string
			severityStr := ""
			if event.Info.SeverityHolder.Severity != 0 {
				severityStr = event.Info.SeverityHolder.Severity.String()
			}

			// Convert Reference from RawStringSlice to []string
			var references []string
			if event.Info.Reference != nil {
				references = event.Info.Reference.ToSlice()
			}
			vuln := models.NucleiVulnerability{
				TemplateID:  event.TemplateID,
				Type:        event.Type,
				Host:        event.Host,
				MatchedAt:   event.Matched,
				Request:     event.Request,
				Response:    event.Response,
				Name:        event.Info.Name,
				Description: event.Info.Description,
				Reference:   references,
				Severity:    severityStr,
			}

			vulnerabilities = append(vulnerabilities, vuln)
		}
	})

	if err != nil {
		return nil, common.NewScannerError("failed to execute nuclei scan", err)
	}

	return models.NucleiResult{
		Domain:          nucleiInput.Domain,
		Vulnerabilities: vulnerabilities,
	}, nil
}

func (s *NucleiScanner) GetName() string {
	return "nuclei"
}
