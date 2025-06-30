package scanners

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/allsafeASM/api/internal/azure"
	"github.com/allsafeASM/api/internal/common"
	"github.com/allsafeASM/api/internal/models"
	"github.com/allsafeASM/api/internal/utils"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/naabu/v2/pkg/result"
	"github.com/projectdiscovery/naabu/v2/pkg/runner"
)

// NaabuScanner implements the Scanner interface for naabu
type NaabuScanner struct {
	*BaseScanner
	blobClient *azure.BlobStorageClient
}

// NewNaabuScanner creates a new naabu scanner
func NewNaabuScanner() *NaabuScanner {
	return &NaabuScanner{
		BaseScanner: NewBaseScanner(),
	}
}

// SetBlobClient sets the blob client for the Naabu scanner
func (s *NaabuScanner) SetBlobClient(blobClient *azure.BlobStorageClient) {
	s.blobClient = blobClient
}

// ValidateInput validates Naabu input specifically
func (s *NaabuScanner) ValidateInput(input models.ScannerInput) error {
	// Try to cast to NaabuInput for specific validation
	if naabuInput, ok := input.(models.NaabuInput); ok {
		// Use the validator's Naabu-specific validation
		return s.validator.ValidateNaabuInput(naabuInput)
	}

	// Fallback to generic validation
	return s.BaseScanner.ValidateInput(input)
}

func (s *NaabuScanner) Execute(ctx context.Context, input interface{}) (models.ScannerResult, error) {
	// Type assert and validate input
	naabuInput, ok := input.(models.NaabuInput)
	if !ok {
		return nil, common.NewValidationError("input", "invalid input type, expected NaabuInput")
	}

	// Validate input using Naabu-specific validation
	if err := s.ValidateInput(naabuInput); err != nil {
		return nil, err
	}

	gologger.Info().Msgf("Naabu starting with domain: %s, IPs count: %d, hosts file: %s",
		naabuInput.Domain, len(naabuInput.IPs), naabuInput.HostsFileLocation)

	// Check if context is cancelled
	select {
	case <-ctx.Done():
		return nil, common.NewTimeoutError("Naabu execution cancelled", ctx.Err())
	default:
	}

	// Collect and process IPs
	ipsToProcess, err := s.collectIPs(ctx, naabuInput)
	if err != nil {
		return nil, err
	}

	if len(ipsToProcess) == 0 {
		return nil, common.NewValidationError("ips", "no IPs provided for port scanning")
	}

	// Execute naabu scan using the library
	ports, err := s.executeNaabuScan(ctx, naabuInput, ipsToProcess)
	if err != nil {
		return nil, err
	}

	// Determine result domain
	resultDomain := s.determineResultDomain(naabuInput, ipsToProcess)

	gologger.Info().Msgf("Naabu completed for domain %s, processed %d IPs, found open ports for %d IPs",
		resultDomain, len(ipsToProcess), len(ports))

	return models.NaabuResult{
		Domain: resultDomain,
		Ports:  ports,
	}, nil
}

// collectIPs collects IPs from different sources
func (s *NaabuScanner) collectIPs(ctx context.Context, naabuInput models.NaabuInput) ([]string, error) {
	var allIPs []string

	// 1. Add IPs from the input
	if len(naabuInput.IPs) > 0 {
		allIPs = append(allIPs, naabuInput.IPs...)
		gologger.Info().Msgf("Added %d IPs from input", len(naabuInput.IPs))
	}

	// 2. Read IPs from blob storage if HostsFileLocation is provided
	if naabuInput.HostsFileLocation != "" && s.blobClient != nil {
		blobIPs, err := s.readIPsFromBlob(ctx, naabuInput.HostsFileLocation)
		if err != nil {
			return nil, err
		}
		allIPs = append(allIPs, blobIPs...)
		gologger.Info().Msgf("Added %d IPs from hosts file", len(blobIPs))
	} else if naabuInput.HostsFileLocation != "" {
		gologger.Warning().Msgf("Hosts file location provided (%s) but blob client is nil", naabuInput.HostsFileLocation)
	}

	// Remove duplicates and validate IPs
	uniqueIPs := s.deduplicateAndValidateIPs(allIPs)

	return uniqueIPs, nil
}

// readIPsFromBlob reads IPs from blob storage
func (s *NaabuScanner) readIPsFromBlob(ctx context.Context, hostsFileLocation string) ([]string, error) {
	gologger.Info().Msgf("Reading hosts file from blob storage: %s", hostsFileLocation)

	hostsFileContent, err := s.blobClient.ReadHostsFileFromBlob(ctx, hostsFileLocation)
	if err != nil {
		return nil, common.NewScannerError("failed to read hosts file from blob storage", err)
	}

	return utils.ReadIPsFromString(hostsFileContent), nil
}

// deduplicateAndValidateIPs removes duplicates and validates IP addresses
func (s *NaabuScanner) deduplicateAndValidateIPs(ips []string) []string {
	seen := make(map[string]bool)
	var uniqueIPs []string

	for _, ip := range ips {
		cleanIP := strings.TrimSpace(ip)
		if cleanIP == "" {
			continue
		}

		// Use net.ParseIP for proper IP validation
		if parsedIP := net.ParseIP(cleanIP); parsedIP != nil && !seen[cleanIP] {
			seen[cleanIP] = true
			uniqueIPs = append(uniqueIPs, cleanIP)
		}
	}

	return uniqueIPs
}

// executeNaabuScan executes the naabu scan using the library
func (s *NaabuScanner) executeNaabuScan(ctx context.Context, naabuInput models.NaabuInput, ips []string) (map[string][]models.PortInfo, error) {
	// Create naabu options
	options := s.buildNaabuOptions(naabuInput, ips)

	gologger.Info().Msgf("Executing naabu with %d IPs", len(ips))

	// Create result storage
	ports := make(map[string][]models.PortInfo)
	var resultMutex sync.Mutex

	// Set up the OnResult callback
	options.OnResult = func(hr *result.HostResult) {
		// Check context cancellation
		select {
		case <-ctx.Done():
			return
		default:
		}

		resultMutex.Lock()
		defer resultMutex.Unlock()

		ip := hr.Host

		// Process all ports for this host
		for _, port := range hr.Ports {
			portInfo := models.PortInfo{
				Port:     port.Port,
				Protocol: "tcp", // naabu primarily scans TCP ports
			}

			if ports[ip] == nil {
				ports[ip] = []models.PortInfo{}
			}
			ports[ip] = append(ports[ip], portInfo)

			gologger.Debug().Msgf("Found open port: %s:%d", ip, port.Port)
		}
	}

	// Create naabu runner
	naabuRunner, err := runner.NewRunner(&options)
	if err != nil {
		return nil, common.NewScannerError("failed to create naabu runner", err)
	}
	defer naabuRunner.Close()

	// Execute the scan
	err = naabuRunner.RunEnumeration(ctx)
	if err != nil {
		return nil, common.NewScannerError("naabu scan failed", err)
	}

	return ports, nil
}

// buildNaabuOptions builds the naabu options from input
func (s *NaabuScanner) buildNaabuOptions(naabuInput models.NaabuInput, ips []string) runner.Options {
	options := runner.Options{
		Host: ips,
	}

	// Port configuration
	if len(naabuInput.Ports) > 0 {
		// Convert ports to string format
		portStrs := make([]string, len(naabuInput.Ports))
		for i, port := range naabuInput.Ports {
			portStrs[i] = strconv.Itoa(port)
		}
		options.Ports = strings.Join(portStrs, ",")
	} else if naabuInput.PortRange != "" {
		options.Ports = naabuInput.PortRange
	} else if naabuInput.TopPorts > 0 {
		options.TopPorts = strconv.Itoa(naabuInput.TopPorts)
	} else {
		// Default to top 1000 ports if no port specification
		options.TopPorts = "1000"
	}

	// Rate limiting and concurrency
	if naabuInput.RateLimit > 0 {
		options.Rate = naabuInput.RateLimit
	}

	if naabuInput.Concurrency > 0 {
		options.Threads = naabuInput.Concurrency
	}

	// Timeout
	if naabuInput.Timeout > 0 {
		options.Timeout = time.Duration(naabuInput.Timeout) * time.Second
	}

	// Additional options for better performance
	options.Silent = true // Suppress banner and progress

	return options
}

// determineResultDomain determines the domain for the result
func (s *NaabuScanner) determineResultDomain(naabuInput models.NaabuInput, ipsToProcess []string) string {
	if naabuInput.Domain != "" {
		return naabuInput.Domain
	}

	// If no domain provided, use a generic name based on the scan
	if len(ipsToProcess) > 0 {
		return fmt.Sprintf("port-scan-%d-ips", len(ipsToProcess))
	}

	return "port-scan"
}

func (s *NaabuScanner) GetName() string {
	return "naabu"
}
