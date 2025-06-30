package scanners

import (
	"context"
	"strings"

	"github.com/allsafeASM/api/internal/azure"
	"github.com/allsafeASM/api/internal/common"
	"github.com/allsafeASM/api/internal/models"
	"github.com/allsafeASM/api/internal/utils"
	"github.com/projectdiscovery/dnsx/libs/dnsx"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/retryabledns"
)

// DNSXScanner implements the Scanner interface for dnsx
type DNSXScanner struct {
	*BaseScanner
	blobClient *azure.BlobStorageClient
}

// NewDNSXScanner creates a new dnsx scanner
func NewDNSXScanner() *DNSXScanner {
	return &DNSXScanner{
		BaseScanner: NewBaseScanner(),
	}
}

// SetBlobClient sets the blob client for the DNSX scanner
func (s *DNSXScanner) SetBlobClient(blobClient *azure.BlobStorageClient) {
	s.blobClient = blobClient
}

// ValidateInput validates DNSX input specifically
func (s *DNSXScanner) ValidateInput(input models.ScannerInput) error {
	// Try to cast to DNSXInput for specific validation
	if dnsxInput, ok := input.(models.DNSXInput); ok {
		// Use the validator's DNSX-specific validation
		return s.validator.ValidateDNSXInput(dnsxInput)
	}

	// Fallback to generic validation
	return s.BaseScanner.ValidateInput(input)
}

func (s *DNSXScanner) Execute(ctx context.Context, input interface{}) (models.ScannerResult, error) {
	// Type assert and validate input
	dnsxInput, ok := input.(models.DNSXInput)
	if !ok {
		return nil, common.NewValidationError("input", "invalid input type, expected DNSXInput")
	}

	// Validate input using DNSX-specific validation
	if err := s.ValidateInput(dnsxInput); err != nil {
		return nil, err
	}

	gologger.Info().Msgf("DNSX starting with domain: %s, subdomains count: %d, hosts file: %s",
		dnsxInput.Domain, len(dnsxInput.Subdomains), dnsxInput.HostsFileLocation)

	// Create DNSX instance with optimized settings for bulk processing
	dnsClient, err := s.createDNSXClient()
	if err != nil {
		return nil, err
	}

	// Check if context is cancelled
	select {
	case <-ctx.Done():
		return nil, common.NewTimeoutError("DNSX execution cancelled", ctx.Err())
	default:
	}

	// Collect and process subdomains
	subdomainsToProcess, err := s.collectSubdomains(ctx, dnsxInput)
	if err != nil {
		return nil, err
	}

	// Process DNS resolution
	records := s.processDNSResolution(ctx, dnsClient, subdomainsToProcess)

	// Determine result domain
	resultDomain := s.determineResultDomain(dnsxInput, subdomainsToProcess)

	gologger.Info().Msgf("DNSX completed for domain %s, processed %d subdomains, found records for %d subdomains",
		resultDomain, len(subdomainsToProcess), len(records))

	return models.DNSXResult{
		Domain:  resultDomain,
		Records: records,
	}, nil
}

// createDNSXClient creates a new DNSX client with optimized settings
func (s *DNSXScanner) createDNSXClient() (*dnsx.DNSX, error) {
	dnsClient, err := dnsx.New(dnsx.Options{
		BaseResolvers: []string{
			"udp:8.8.8.8:53",
			"udp:8.8.4.4:53",
			"udp:1.1.1.1:53",
			"udp:1.0.0.1:53",
		},
		MaxRetries:    3,
		QuestionTypes: []uint16{1, 5}, // A, CNAME only
		Hostsfile:     true,
	})
	if err != nil {
		return nil, common.NewScannerError("failed to create DNSX client", err)
	}
	return dnsClient, nil
}

// collectSubdomains collects subdomains from different sources
func (s *DNSXScanner) collectSubdomains(ctx context.Context, dnsxInput models.DNSXInput) ([]string, error) {
	var allSubdomains []string

	// 1. Add subdomains from the input
	if len(dnsxInput.Subdomains) > 0 {
		allSubdomains = append(allSubdomains, dnsxInput.Subdomains...)
		gologger.Info().Msgf("Added %d subdomains from input", len(dnsxInput.Subdomains))
	}

	// 2. Read subdomains from blob storage if HostsFileLocation is provided
	if dnsxInput.HostsFileLocation != "" && s.blobClient != nil {
		blobSubdomains, err := s.readSubdomainsFromBlob(ctx, dnsxInput.HostsFileLocation)
		if err != nil {
			return nil, err
		}
		allSubdomains = append(allSubdomains, blobSubdomains...)
		gologger.Info().Msgf("Added %d subdomains from hosts file", len(blobSubdomains))
	} else if dnsxInput.HostsFileLocation != "" {
		gologger.Warning().Msgf("Hosts file location provided (%s) but blob client is nil", dnsxInput.HostsFileLocation)
	}

	// Determine what to process
	if len(allSubdomains) > 0 {
		// Process the collected subdomains list
		gologger.Info().Msgf("Processing %d subdomains from combined sources", len(allSubdomains))
		return allSubdomains, nil
	} else if dnsxInput.Domain != "" {
		// Fallback to single domain if no subdomains provided
		gologger.Info().Msgf("No subdomains found, processing single domain: %s", dnsxInput.Domain)
		return []string{dnsxInput.Domain}, nil
	} else {
		return nil, common.NewValidationError("domain", "no domain or subdomains provided for DNS resolution")
	}
}

// readSubdomainsFromBlob reads subdomains from blob storage
func (s *DNSXScanner) readSubdomainsFromBlob(ctx context.Context, hostsFileLocation string) ([]string, error) {
	gologger.Info().Msgf("Reading hosts file from blob storage: %s", hostsFileLocation)

	hostsFileContent, err := s.blobClient.ReadHostsFileFromBlob(ctx, hostsFileLocation)
	if err != nil {
		return nil, common.NewScannerError("failed to read hosts file from blob storage", err)
	}

	return utils.ReadSubdomainsFromString(hostsFileContent), nil
}

// processDNSResolution processes DNS resolution for all subdomains
func (s *DNSXScanner) processDNSResolution(ctx context.Context, dnsClient *dnsx.DNSX, subdomains []string) map[string]models.ResolutionInfo {
	records := make(map[string]models.ResolutionInfo)

	for i, subdomain := range subdomains {
		// Check context cancellation for each iteration
		select {
		case <-ctx.Done():
			gologger.Warning().Msg("DNSX processing cancelled due to context timeout")
			return records
		default:
		}

		// Clean the subdomain
		cleanSubdomain := strings.TrimSpace(subdomain)
		if cleanSubdomain == "" {
			continue
		}

		gologger.Debug().Msgf("Processing subdomain %d/%d: %s", i+1, len(subdomains), cleanSubdomain)

		// Perform DNS lookup
		resolutionInfo := s.performDNSLookup(dnsClient, cleanSubdomain)
		records[cleanSubdomain] = resolutionInfo
	}

	return records
}

// performDNSLookup performs DNS lookup for a single subdomain
func (s *DNSXScanner) performDNSLookup(dnsClient *dnsx.DNSX, subdomain string) models.ResolutionInfo {
	resolutionInfo := models.ResolutionInfo{
		Status: "resolved",
	}

	// Use QueryMultiple to get all record types at once
	dnsData, err := dnsClient.QueryMultiple(subdomain)
	if err != nil {
		gologger.Warning().Msgf("DNS lookup failed for %s: %v", subdomain, err)
		resolutionInfo.Status = "error"
		return resolutionInfo
	}

	// Extract different record types from the DNS data
	s.extractDNSRecords(&resolutionInfo, dnsData, subdomain)

	// If no records found at all, mark as not resolved
	if s.hasNoRecords(resolutionInfo) {
		resolutionInfo.Status = "not_resolved"
		gologger.Debug().Msgf("No DNS records found for %s", subdomain)
	}

	return resolutionInfo
}

// extractDNSRecords extracts DNS records from DNSX data
func (s *DNSXScanner) extractDNSRecords(resolutionInfo *models.ResolutionInfo, dnsData *retryabledns.DNSData, subdomain string) {
	if len(dnsData.A) > 0 {
		resolutionInfo.A = dnsData.A
		gologger.Debug().Msgf("A records for %s: %v", subdomain, dnsData.A)
	}

	if len(dnsData.CNAME) > 0 {
		resolutionInfo.CNAME = dnsData.CNAME
		gologger.Debug().Msgf("CNAME records for %s: %v", subdomain, dnsData.CNAME)
	}
}

// hasNoRecords checks if no DNS records were found
func (s *DNSXScanner) hasNoRecords(resolutionInfo models.ResolutionInfo) bool {
	return len(resolutionInfo.A) == 0 && len(resolutionInfo.CNAME) == 0
}

// determineResultDomain determines the domain to use for the result
func (s *DNSXScanner) determineResultDomain(dnsxInput models.DNSXInput, subdomainsToProcess []string) string {
	if dnsxInput.Domain != "" {
		return dnsxInput.Domain
	}
	if len(subdomainsToProcess) > 0 {
		return subdomainsToProcess[0]
	}
	return ""
}

func (s *DNSXScanner) GetName() string {
	return "dnsx"
}
