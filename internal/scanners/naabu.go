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
	"github.com/projectdiscovery/gologger/levels"
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
		// Use the validator's Naabu-specific validation
		return s.validator.ValidateNaabuInput(naabuInput)
	}

	// Fallback to generic validation
	return s.BaseScanner.ValidateInput(input)
}

func (s *NaabuScanner) Execute(ctx context.Context, input interface{}) (models.ScannerResult, error) {
	// Type assert to the specific input type we expect
	naabuInput, ok := input.(models.NaabuInput)
	if !ok {
		return nil, common.NewValidationError("input", "invalid input type, expected NaabuInput")
	}

	// The validation function already handles the specific type, so we just call it directly
	if err := s.validator.ValidateNaabuInput(naabuInput); err != nil {
		return nil, err
	}

	gologger.Info().Msgf("Starting naabu scan for domain: %s", naabuInput.Domain)

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

	gologger.Debug().Msgf("Processing %d IPs for port scanning", len(ipsToProcess))
	gologger.Debug().Msgf("IPs to be scanned: %v", ipsToProcess)

	// Execute naabu scan using the library
	ports, err := s.executeNaabuScan(ctx, naabuInput, ipsToProcess)
	if err != nil {
		gologger.Error().Msgf("Naabu scan failed: %v", err)
		return nil, err
	}

	// Determine result domain
	resultDomain := s.determineResultDomain(naabuInput, ipsToProcess)

	// Create and return the result
	result := models.NaabuResult{
		Domain: resultDomain,
		Ports:  ports,
	}

	// Log summary
	totalPorts := 0
	for _, portList := range ports {
		totalPorts += len(portList)
	}

	if len(ports) == 0 {
		gologger.Info().Msgf("Naabu scan completed for %s: no open ports found", resultDomain)
	} else {
		gologger.Info().Msgf("Naabu scan completed for %s: %d open ports across %d IPs", resultDomain, totalPorts, len(ports))
	}

	return result, nil
}

// collectIPs collects IPs from different sources
func (s *NaabuScanner) collectIPs(ctx context.Context, naabuInput models.NaabuInput) ([]string, error) {
	var allIPs []string

	// 1. Add IPs from the input
	if len(naabuInput.IPs) > 0 {
		allIPs = append(allIPs, naabuInput.IPs...)
		gologger.Debug().Msgf("Added %d IPs from input", len(naabuInput.IPs))
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
		gologger.Debug().Msgf("Added %d IPs from hosts file", len(blobIPs))
	}

	// Remove duplicates and validate IPs
	uniqueIPs := s.deduplicateAndValidateIPs(allIPs)

	// Debug: Print the IPs that will be scanned
	gologger.Debug().Msgf("IPs to scan with naabu: %v", uniqueIPs)

	return uniqueIPs, nil
}

// readIPsFromBlob reads IPs from blob storage
func (s *NaabuScanner) readIPsFromBlob(ctx context.Context, hostsFileLocation string) ([]string, error) {
	gologger.Debug().Msgf("Reading hosts file from blob storage: %s", hostsFileLocation)

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

// executeNaabuScan executes the naabu scan using the library following the official documentation pattern
func (s *NaabuScanner) executeNaabuScan(ctx context.Context, naabuInput models.NaabuInput, ips []string) (map[string][]models.PortInfo, error) {
	startTime := time.Now()

	// Create result storage
	ports := make(map[string][]models.PortInfo)
	var resultMutex sync.Mutex
	var processedIPs int32
	var totalPortsFound int32

	// Build naabu options following the official documentation pattern
	options := runner.Options{
		Host: ips,
	}

	// Ensure we have valid hosts to scan
	if len(ips) == 0 {
		return nil, common.NewValidationError("hosts", "no valid hosts provided for scanning")
	}

	gologger.Debug().Msgf("Configuring naabu with %d hosts", len(ips))

	// Port configuration with priority: specific ports > port range > top ports > default
	if len(naabuInput.Ports) > 0 {
		// Convert ports to string format
		portStrs := make([]string, len(naabuInput.Ports))
		for i, port := range naabuInput.Ports {
			portStrs[i] = strconv.Itoa(port)
		}
		options.Ports = strings.Join(portStrs, ",")
		gologger.Debug().Msgf("Using specific ports: %s", options.Ports)
	} else if naabuInput.PortRange != "" {
		options.Ports = naabuInput.PortRange
		gologger.Debug().Msgf("Using port range: %s", options.Ports)
	} else if naabuInput.TopPorts != "" {
		options.TopPorts = naabuInput.TopPorts
		gologger.Debug().Msgf("Using top ports: %s", options.TopPorts)
	} else {
		// Default to top 100 ports (naabu only supports: full, 100, 1000)
		options.TopPorts = "100"
		gologger.Debug().Msgf("Using default top ports: %s", options.TopPorts)
	}

	// Dynamic configuration based on number of IPs
	numIPs := len(ips)

	// Rate limiting and concurrency - adjust based on IP count
	if naabuInput.RateLimit > 0 {
		options.Rate = naabuInput.RateLimit
	} else {
		// Adjust rate based on number of IPs
		switch {
		case numIPs <= 5:
			options.Rate = 100 // Conservative for small scans
		case numIPs <= 20:
			options.Rate = 1000 // Moderate for medium scans
		default:
			options.Rate = 2000 // High for very large scans
		}
	}

	if naabuInput.Concurrency > 0 {
		options.Threads = naabuInput.Concurrency
	} else {
		// Adjust threads based on number of IPs
		switch {
		case numIPs <= 5:
			options.Threads = 5 // Fewer threads for small scans
		case numIPs <= 20:
			options.Threads = 25 // Moderate threads for medium scans
		default:
			options.Threads = 50 // High thread count for very large scans
		}
	}

	// Set retries based on scan size
	switch {
	case numIPs <= 5:
		options.Retries = 2 // Fewer retries for small scans
	case numIPs <= 20:
		options.Retries = 3 // Standard retries for medium scans
	default:
		options.Retries = 1 // Fewer retries for large scans to avoid overwhelming
	}

	// Timeout configuration - adjust based on scan size
	if naabuInput.Timeout > 0 {
		options.Timeout = time.Duration(naabuInput.Timeout) * time.Second
	} else {
		// Adjust timeout based on number of IPs
		switch {
		case numIPs <= 5:
			options.Timeout = 10 * time.Second // Longer timeout for small scans
		case numIPs <= 20:
			options.Timeout = 5 * time.Second // Moderate timeout for medium scans
		default:
			options.Timeout = 3 * time.Second // Short timeout for very large scans
		}
	}

	// Performance optimizations
	options.Silent = true             // Suppress banner and progress
	options.Verbose = false           // Disable verbose output
	options.Stream = false            // Disable streaming mode to ensure proper result capture
	options.Passive = false           // Ensure active scanning
	options.WithHostDiscovery = false // Skip host discovery for faster scanning
	options.ScanType = "s"            // Use SYN scan for faster scanning (SynScan constant)
	options.ExcludeCDN = true         // Exclude CDN IPs from the scan

	// Set up the OnResult callback following the official documentation pattern
	options.OnResult = func(hr *result.HostResult) {
		gologger.Debug().Msgf("OnResult callback triggered for host: %s (IP: %s)", hr.Host, hr.IP)

		// Check context cancellation
		select {
		case <-ctx.Done():
			gologger.Debug().Msgf("Context cancelled in OnResult callback")
			return
		default:
		}

		resultMutex.Lock()
		defer resultMutex.Unlock()

		// Use IP address as the key, fallback to Host if IP is empty
		ip := hr.IP
		if ip == "" {
			ip = hr.Host
		}

		portsFound := len(hr.Ports)

		atomic.AddInt32(&processedIPs, 1)
		atomic.AddInt32(&totalPortsFound, int32(portsFound))

		gologger.Debug().Msgf("Found %d open ports on %s", portsFound, ip)

		// Process all ports for this host
		for _, port := range hr.Ports {
			portInfo := models.PortInfo{
				Port:     port.Port,
				Protocol: port.Protocol.String(), // Use actual protocol from result
			}

			if ports[ip] == nil {
				ports[ip] = []models.PortInfo{}
			}
			ports[ip] = append(ports[ip], portInfo)
		}
	}

	gologger.Debug().Msgf("Starting naabu scan with %d IPs, threads: %d, rate: %d, timeout: %v, retries: %d",
		len(ips), options.Threads, options.Rate, options.Timeout, options.Retries)

	// Create naabu runner following the official documentation pattern
	naabuRunner, err := runner.NewRunner(&options)

	if err != nil {
		gologger.Error().Msgf("Failed to create naabu runner: %v", err)
		return nil, common.NewScannerError("failed to create naabu runner", err)
	}
	defer func() {
		gologger.Debug().Msgf("Closing naabu runner...")
		naabuRunner.Close()
	}()

	// Execute the scan following the official documentation pattern
	gologger.Debug().Msgf("Starting naabu enumeration...")
	gologger.DefaultLogger.SetMaxLevel(levels.LevelFatal)

	err = naabuRunner.RunEnumeration(ctx)

	gologger.DefaultLogger.SetMaxLevel(levels.LevelInfo)

	if err != nil {
		gologger.Error().Msgf("Naabu enumeration failed: %v", err)
		return nil, common.NewScannerError("naabu scan failed", err)
	}
	gologger.Debug().Msgf("Naabu enumeration completed successfully")

	duration := time.Since(startTime)
	processedCount := atomic.LoadInt32(&processedIPs)
	totalPorts := atomic.LoadInt32(&totalPortsFound)

	gologger.Debug().Msgf("Naabu scan completed in %v, processed %d/%d IPs, found %d total open ports",
		duration, processedCount, len(ips), totalPorts)

	// Additional debugging information
	if processedCount == 0 {
		gologger.Warning().Msgf("No IPs were processed by OnResult callback - this might indicate an issue with result capture")
	}

	return ports, nil
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
