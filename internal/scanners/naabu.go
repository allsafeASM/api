package scanners

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
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
func NewNaabuScanner(blobClient *azure.BlobStorageClient) *NaabuScanner {
	return &NaabuScanner{
		BaseScanner: NewBaseScanner(),
		blobClient:  blobClient,
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
		// Validate port range if provided
		if naabuInput.PortRange != "" {
			if err := s.validatePortRange(naabuInput.PortRange); err != nil {
				return common.NewValidationError("portRange", err.Error())
			}
		}

		// Use the validator's Naabu-specific validation
		return s.validator.ValidateNaabuInput(naabuInput)
	}

	// Fallback to generic validation
	return s.BaseScanner.ValidateInput(input)
}

// validatePortRange validates the port range format
func (s *NaabuScanner) validatePortRange(portRange string) error {
	// Check if it's a single port
	if strings.Contains(portRange, "-") {
		// Port range format: start-end
		parts := strings.Split(portRange, "-")
		if len(parts) != 2 {
			return fmt.Errorf("invalid port range format, expected 'start-end'")
		}

		startPort, err := strconv.Atoi(strings.TrimSpace(parts[0]))
		if err != nil {
			return fmt.Errorf("invalid start port: %s", parts[0])
		}

		endPort, err := strconv.Atoi(strings.TrimSpace(parts[1]))
		if err != nil {
			return fmt.Errorf("invalid end port: %s", parts[1])
		}

		if startPort < 1 || startPort > 65535 {
			return fmt.Errorf("start port must be between 1 and 65535")
		}

		if endPort < 1 || endPort > 65535 {
			return fmt.Errorf("end port must be between 1 and 65535")
		}

		if startPort >= endPort {
			return fmt.Errorf("start port must be less than end port")
		}
	} else {
		// Single port or comma-separated ports
		ports := strings.Split(portRange, ",")
		for _, portStr := range ports {
			port, err := strconv.Atoi(strings.TrimSpace(portStr))
			if err != nil {
				return fmt.Errorf("invalid port: %s", portStr)
			}
			if port < 1 || port > 65535 {
				return fmt.Errorf("port must be between 1 and 65535: %d", port)
			}
		}
	}

	return nil
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
	if naabuInput.HostsFileLocation != "" {
		if s.blobClient == nil {
			return nil, common.NewValidationError("blobClient", "blob client is required when HostsFileLocation is provided")
		}
		blobIPs, err := s.readIPsFromBlob(ctx, naabuInput.HostsFileLocation)
		if err != nil {
			return nil, err
		}
		allIPs = append(allIPs, blobIPs...)
		gologger.Info().Msgf("Added %d IPs from hosts file", len(blobIPs))
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
	startTime := time.Now()

	// Create naabu options
	options := s.buildNaabuOptions(naabuInput, ips)

	gologger.Info().Msgf("Executing naabu with %d IPs, ports: %s, threads: %d, rate: %d",
		len(ips), options.Ports, options.Threads, options.Rate)

	// Create result storage
	ports := make(map[string][]models.PortInfo)
	var resultMutex sync.Mutex
	var processedIPs int32

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
		atomic.AddInt32(&processedIPs, 1)

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

		gologger.Info().Msgf("Processed IP %d/%d: %s (found %d open ports)",
			atomic.LoadInt32(&processedIPs), len(ips), ip, len(hr.Ports))
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

	duration := time.Since(startTime)
	gologger.Info().Msgf("Naabu scan completed in %v, processed %d IPs, found open ports for %d IPs",
		duration, len(ips), len(ports))

	return ports, nil
}

// buildNaabuOptions builds the naabu options from input
func (s *NaabuScanner) buildNaabuOptions(naabuInput models.NaabuInput, ips []string) runner.Options {
	options := runner.Options{
		Host: ips,
	}

	// Port configuration with priority: specific ports > port range > top ports > default
	if len(naabuInput.Ports) > 0 {
		// Convert ports to string format
		portStrs := make([]string, len(naabuInput.Ports))
		for i, port := range naabuInput.Ports {
			portStrs[i] = strconv.Itoa(port)
		}
		options.Ports = strings.Join(portStrs, ",")
		gologger.Info().Msgf("Using specific ports: %s", options.Ports)
	} else if naabuInput.PortRange != "" {
		options.Ports = naabuInput.PortRange
		gologger.Info().Msgf("Using port range: %s", options.Ports)
	} else if naabuInput.TopPorts != "" {
		options.TopPorts = naabuInput.TopPorts
		gologger.Info().Msgf("Using top ports: %s", options.TopPorts)
	} else {
		// Default to top 100 ports (naabu only supports: full, 100, 1000)
		options.TopPorts = "100"
		gologger.Info().Msgf("Using default top ports: %s", options.TopPorts)
	}

	// Rate limiting and concurrency - set reasonable defaults
	if naabuInput.RateLimit > 0 {
		options.Rate = naabuInput.RateLimit
		gologger.Info().Msgf("Using custom rate limit: %d", options.Rate)
	} else {
		// Default rate limit of 1000 packets per second
		options.Rate = 1000
		gologger.Info().Msgf("Using default rate limit: %d", options.Rate)
	}

	if naabuInput.Concurrency > 0 {
		options.Threads = naabuInput.Concurrency
		gologger.Info().Msgf("Using custom concurrency: %d", options.Threads)
	} else {
		// Default to 25 concurrent threads for better performance
		options.Threads = 25
		gologger.Info().Msgf("Using default concurrency: %d", options.Threads)
	}

	// Timeout configuration
	if naabuInput.Timeout > 0 {
		options.Timeout = time.Duration(naabuInput.Timeout) * time.Second
		gologger.Info().Msgf("Using custom timeout: %v", options.Timeout)
	} else {
		// Default timeout of 30 seconds per host
		options.Timeout = 30 * time.Second
		gologger.Info().Msgf("Using default timeout: %v", options.Timeout)
	}

	// Performance optimizations
	options.Silent = true             // Suppress banner and progress
	options.Verbose = false           // Disable verbose output
	options.NoColor = true            // Disable color output
	options.Stream = true             // Enable streaming mode for faster processing
	options.Passive = false           // Ensure active scanning
	options.ScanAllIPS = false        // Don't scan all IPs if some are down
	options.WithHostDiscovery = false // Skip host discovery for faster scanning
	options.ScanType = "s"            // Use SYN scan for faster scanning

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
