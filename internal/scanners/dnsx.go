package scanners

import (
	"context"
	"hash/fnv"
	"strings"
	"sync"
	"time"

	"github.com/allsafeASM/api/internal/azure"
	"github.com/allsafeASM/api/internal/common"
	"github.com/allsafeASM/api/internal/models"
	"github.com/allsafeASM/api/internal/utils"
	"github.com/projectdiscovery/dnsx/libs/dnsx"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/ratelimit"
	"github.com/projectdiscovery/retryabledns"
)

// ShardedResultMap provides thread-safe access to results with reduced contention
type ShardedResultMap struct {
	shards []*ResultShard
	count  int
}

// ResultShard represents a single shard of the result map
type ResultShard struct {
	mu      sync.RWMutex
	records map[string]models.ResolutionInfo
}

// NewShardedResultMap creates a new sharded result map
func NewShardedResultMap(shardCount int) *ShardedResultMap {
	shards := make([]*ResultShard, shardCount)
	for i := 0; i < shardCount; i++ {
		shards[i] = &ResultShard{
			records: make(map[string]models.ResolutionInfo),
		}
	}
	return &ShardedResultMap{
		shards: shards,
		count:  shardCount,
	}
}

// Set stores a result in the appropriate shard
func (s *ShardedResultMap) Set(domain string, result models.ResolutionInfo) {
	shard := s.shards[hashString(domain)%s.count]
	shard.mu.Lock()
	shard.records[domain] = result
	shard.mu.Unlock()
}

// GetAll returns all results from all shards
func (s *ShardedResultMap) GetAll() map[string]models.ResolutionInfo {
	result := make(map[string]models.ResolutionInfo)
	for _, shard := range s.shards {
		shard.mu.RLock()
		for domain, resolution := range shard.records {
			result[domain] = resolution
		}
		shard.mu.RUnlock()
	}
	return result
}

// hashString provides a simple hash function for domain distribution
func hashString(s string) int {
	h := fnv.New32a()
	h.Write([]byte(s))
	return int(h.Sum32())
}

// DNSXScanner implements the Scanner interface for dnsx
type DNSXScanner struct {
	*BaseScanner
	blobClient *azure.BlobStorageClient

	// Optimized components
	dnsClient   *dnsx.DNSX
	clientOnce  sync.Once
	clientMutex sync.RWMutex

	// Worker management
	workerChan chan string
	resultChan chan struct {
		domain string
		result models.ResolutionInfo
	}
	wgWorkers *sync.WaitGroup
	wgResults *sync.WaitGroup
	limiter   *ratelimit.Limiter

	// Configuration
	workerCount int
	rateLimit   int
	shardCount  int
}

// NewDNSXScanner creates a new dnsx scanner with optimized defaults
func NewDNSXScanner() *DNSXScanner {
	return &DNSXScanner{
		BaseScanner: NewBaseScanner(),
		wgWorkers:   &sync.WaitGroup{},
		wgResults:   &sync.WaitGroup{},
		workerCount: 50,   // Default worker count
		rateLimit:   1000, // Default rate limit per second
		shardCount:  16,   // Number of shards for result map
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
	// Type assert to the specific input type we expect
	dnsxInput, ok := input.(models.DNSXInput)
	if !ok {
		return nil, common.NewValidationError("input", "invalid input type, expected DNSXInput")
	}

	// Validate input
	if err := s.ValidateInput(dnsxInput); err != nil {
		return nil, err
	}

	gologger.Info().Msgf("Starting DNS resolution for domain: %s", dnsxInput.Domain)

	// Check if context is cancelled
	select {
	case <-ctx.Done():
		return nil, common.NewTimeoutError("DNSX execution cancelled", ctx.Err())
	default:
	}

	// Initialize components if needed
	if err := s.initializeComponents(); err != nil {
		return nil, err
	}

	// Collect and process subdomains
	subdomainsToProcess, err := s.collectSubdomains(ctx, dnsxInput)
	if err != nil {
		return nil, err
	}

	if len(subdomainsToProcess) == 0 {
		return nil, common.NewValidationError("subdomains", "no subdomains provided for DNS resolution")
	}

	gologger.Debug().Msgf("Processing %d subdomains for DNS resolution", len(subdomainsToProcess))

	// Execute DNS resolution
	records := s.processDNSResolutionOptimized(ctx, subdomainsToProcess)

	// Determine result domain
	resultDomain := s.determineResultDomain(dnsxInput, subdomainsToProcess)

	// Count subdomains with records
	subdomainsWithRecords := 0
	for _, record := range records {
		if !s.hasNoRecords(record) {
			subdomainsWithRecords++
		}
	}

	gologger.Info().Msgf("DNS resolution completed for %s: %d records found across %d subdomains",
		resultDomain, subdomainsWithRecords, len(records))

	// Create and return the result
	result := models.DNSXResult{
		Domain:  resultDomain,
		Records: records,
	}

	return result, nil
}

// initializeComponents initializes all optimized components
func (s *DNSXScanner) initializeComponents() error {
	// Get or create DNS client (connection pooling)
	if _, err := s.getDNSClient(); err != nil {
		return err
	}

	// Initialize rate limiter
	s.limiter = ratelimit.New(context.Background(), uint(s.rateLimit), time.Second)

	// Initialize channels with dynamic sizing (will be set in processDNSResolutionOptimized)
	s.workerChan = nil
	s.resultChan = nil

	return nil
}

// getDNSClient implements connection pooling for DNS client
func (s *DNSXScanner) getDNSClient() (*dnsx.DNSX, error) {
	s.clientMutex.RLock()
	if s.dnsClient != nil {
		defer s.clientMutex.RUnlock()
		return s.dnsClient, nil
	}
	s.clientMutex.RUnlock()

	s.clientMutex.Lock()
	defer s.clientMutex.Unlock()

	// Double-check after acquiring write lock
	if s.dnsClient != nil {
		return s.dnsClient, nil
	}

	// Create new DNS client
	dnsClient, err := s.createOptimizedDNSXClient()
	if err != nil {
		return nil, err
	}
	s.dnsClient = dnsClient
	return s.dnsClient, nil
}

// createOptimizedDNSXClient creates a new DNSX client with enhanced optimizations
func (s *DNSXScanner) createOptimizedDNSXClient() (*dnsx.DNSX, error) {
	// Use ProjectDiscovery's default options as base
	dnsxOptions := dnsx.DefaultOptions

	// Enhanced resolver configuration for better performance
	dnsxOptions.BaseResolvers = []string{
		"udp:1.1.1.1:53",         // Cloudflare
		"udp:1.0.0.1:53",         // Cloudflare
		"udp:8.8.8.8:53",         // Google
		"udp:8.8.4.4:53",         // Google
		"udp:9.9.9.9:53",         // Quad9
		"udp:149.112.112.112:53", // Quad9
		"udp:208.67.222.222:53",  // OpenDNS
		"udp:208.67.220.220:53",  // OpenDNS
		"udp:94.140.14.14:53",    // AdGuard
		"udp:94.140.15.15:53",    // AdGuard
	}

	// Optimized settings for bulk processing
	dnsxOptions.MaxRetries = 1                 // Reduced for speed
	dnsxOptions.QuestionTypes = []uint16{1, 5} // A, CNAME only
	dnsxOptions.Hostsfile = true
	dnsxOptions.QueryAll = false // Disable for speed

	dnsClient, err := dnsx.New(dnsxOptions)
	if err != nil {
		return nil, common.NewScannerError("failed to create DNSX client", err)
	}
	return dnsClient, nil
}

// calculateBufferSizes calculates optimal buffer sizes based on workload
func (s *DNSXScanner) calculateBufferSizes(subdomainCount int) (int, int) {
	workerBuffer := min(subdomainCount, s.workerCount*4)
	resultBuffer := min(subdomainCount, s.workerCount*2)
	return workerBuffer, resultBuffer
}

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// collectSubdomains collects subdomains from different sources
func (s *DNSXScanner) collectSubdomains(ctx context.Context, dnsxInput models.DNSXInput) ([]string, error) {
	var allSubdomains []string

	// 1. Add subdomains from the input
	if len(dnsxInput.Subdomains) > 0 {
		allSubdomains = append(allSubdomains, dnsxInput.Subdomains...)
		gologger.Debug().Msgf("Added %d subdomains from input", len(dnsxInput.Subdomains))
	}

	// 2. Read subdomains from blob storage if HostsFileLocation is provided
	if dnsxInput.HostsFileLocation != "" {
		if s.blobClient == nil {
			return nil, common.NewValidationError("blob_client", "hosts file location provided but blob client is not initialized")
		} else {
			blobSubdomains, err := s.readSubdomainsFromBlob(ctx, dnsxInput.HostsFileLocation)
			if err != nil {
				return nil, err
			}
			allSubdomains = append(allSubdomains, blobSubdomains...)
			gologger.Debug().Msgf("Added %d subdomains from hosts file", len(blobSubdomains))
		}
	}

	// 3. If no subdomains from other sources, use the domain itself
	if len(allSubdomains) == 0 {
		allSubdomains = []string{dnsxInput.Domain}
		gologger.Debug().Msgf("No subdomains found, processing single domain: %s", dnsxInput.Domain)
	} else {
		gologger.Debug().Msgf("Processing %d subdomains from combined sources", len(allSubdomains))
	}

	return allSubdomains, nil
}

// readSubdomainsFromBlob reads subdomains from blob storage
func (s *DNSXScanner) readSubdomainsFromBlob(ctx context.Context, hostsFileLocation string) ([]string, error) {
	gologger.Debug().Msgf("Reading hosts file from blob storage: %s", hostsFileLocation)

	hostsFileContent, err := s.blobClient.ReadHostsFileFromBlob(ctx, hostsFileLocation)
	if err != nil {
		return nil, common.NewScannerError("failed to read hosts file from blob storage", err)
	}

	return utils.ReadSubdomainsFromString(hostsFileContent), nil
}

// processDNSResolutionOptimized processes DNS resolution using enhanced optimizations
func (s *DNSXScanner) processDNSResolutionOptimized(ctx context.Context, subdomains []string) map[string]models.ResolutionInfo {
	// Calculate optimal buffer sizes
	workerBuffer, resultBuffer := s.calculateBufferSizes(len(subdomains))

	// Initialize channels with optimal buffer sizes
	s.workerChan = make(chan string, workerBuffer)
	s.resultChan = make(chan struct {
		domain string
		result models.ResolutionInfo
	}, resultBuffer)

	// Use sharded result map for better concurrency
	shardedResults := NewShardedResultMap(s.shardCount)

	// Start result collector
	s.wgResults.Add(1)
	go func() {
		defer s.wgResults.Done()
		for result := range s.resultChan {
			shardedResults.Set(result.domain, result.result)
		}
	}()

	// Start workers
	for i := 0; i < s.workerCount; i++ {
		s.wgWorkers.Add(1)
		go s.worker(ctx)
	}

	// Send work to workers
	go func() {
		defer close(s.workerChan)
		for _, subdomain := range subdomains {
			select {
			case s.workerChan <- subdomain:
			case <-ctx.Done():
				return
			}
		}
	}()

	// Wait for all workers to complete
	s.wgWorkers.Wait()
	close(s.resultChan)
	s.wgResults.Wait()

	return shardedResults.GetAll()
}

// worker is the optimized worker function
func (s *DNSXScanner) worker(ctx context.Context) {
	defer s.wgWorkers.Done()

	for subdomain := range s.workerChan {
		// Check context cancellation
		select {
		case <-ctx.Done():
			return
		default:
		}

		// Clean the subdomain
		cleanSubdomain := strings.TrimSpace(subdomain)
		if cleanSubdomain == "" {
			continue
		}

		// Apply rate limiting
		s.limiter.Take()

		// Perform DNS lookup using optimized pattern
		resolutionInfo := s.performOptimizedDNSLookup(cleanSubdomain)

		// Send result
		select {
		case s.resultChan <- struct {
			domain string
			result models.ResolutionInfo
		}{cleanSubdomain, resolutionInfo}:
		case <-ctx.Done():
			return
		}
	}
}

// performOptimizedDNSLookup performs DNS lookup using optimized pattern
func (s *DNSXScanner) performOptimizedDNSLookup(subdomain string) models.ResolutionInfo {
	resolutionInfo := models.ResolutionInfo{
		Status: "resolved",
	}

	// Get DNS client from pool
	dnsClient, err := s.getDNSClient()
	if err != nil {
		resolutionInfo.Status = "error"
		return resolutionInfo
	}

	// Use QueryMultiple like ProjectDiscovery does
	dnsData, err := dnsClient.QueryMultiple(subdomain)
	if err != nil {
		resolutionInfo.Status = "error"
		return resolutionInfo
	}

	// Skip nil responses (ProjectDiscovery pattern)
	if dnsData == nil {
		resolutionInfo.Status = "error"
		return resolutionInfo
	}

	// Extract DNS records
	s.extractDNSRecords(&resolutionInfo, dnsData)

	// If no records found, mark as not resolved
	if s.hasNoRecords(resolutionInfo) {
		resolutionInfo.Status = "not_resolved"
	}

	return resolutionInfo
}

// extractDNSRecords extracts DNS records from DNSX data
func (s *DNSXScanner) extractDNSRecords(resolutionInfo *models.ResolutionInfo, dnsData *retryabledns.DNSData) {
	if len(dnsData.A) > 0 {
		resolutionInfo.A = dnsData.A
	}

	if len(dnsData.CNAME) > 0 {
		resolutionInfo.CNAME = dnsData.CNAME
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
