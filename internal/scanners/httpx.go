package scanners

import (
	"context"
	"strings"

	"github.com/allsafeASM/api/internal/azure"
	"github.com/allsafeASM/api/internal/common"
	"github.com/allsafeASM/api/internal/models"
	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/projectdiscovery/httpx/runner"
)

// HttpxScanner implements the Scanner interface for httpx
type HttpxScanner struct {
	*BaseScanner
	blobClient *azure.BlobStorageClient
}

// NewHttpxScanner creates a new httpx scanner
func NewHttpxScanner() *HttpxScanner {
	return &HttpxScanner{
		BaseScanner: NewBaseScanner(),
	}
}

// SetBlobClient sets the blob client for the Httpx scanner
func (s *HttpxScanner) SetBlobClient(blobClient *azure.BlobStorageClient) {
	s.blobClient = blobClient
}

func (s *HttpxScanner) Execute(ctx context.Context, input interface{}) (models.ScannerResult, error) {

	// Type assert and validate input
	httpxInput, ok := input.(models.HttpxInput)
	if !ok {
		return nil, common.NewValidationError("input", "invalid input type, expected HttpxInput")
	}

	// Validate input using base scanner
	if err := s.ValidateInput(httpxInput); err != nil {
		return nil, err
	}

	// Check if context is cancelled
	select {
	case <-ctx.Done():
		return nil, common.NewTimeoutError("httpx execution cancelled", ctx.Err())
	default:
	}

	gologger.Info().Msgf("Starting httpx scan for domain: %s", httpxInput.Domain)

	var hosts []string
	if httpxInput.HostsFileLocation != "" {
		if s.blobClient == nil {
			return nil, common.NewValidationError("blob_client", "hosts file location provided but blob client is not initialized")
		}
		gologger.Debug().Msgf("Reading hosts file from blob storage: %s", httpxInput.HostsFileLocation)
		hostsFileContent, err := s.blobClient.ReadHostsFileFromBlob(ctx, httpxInput.HostsFileLocation)
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
		hosts = []string{httpxInput.Domain}
	}

	if len(hosts) == 0 {
		return models.HttpxResult{
			Domain:  httpxInput.Domain,
			Results: []models.HttpxHostResult{},
		}, nil
	}

	results := make([]models.HttpxHostResult, 0, len(hosts))
	resultCh := make(chan models.HttpxHostResult, len(hosts))
	doneCh := make(chan struct{})

	options := runner.Options{
		InputTargetHost: goflags.StringSlice{},
		TechDetect:      true,
		FollowRedirects: true,
		OnResult: func(r runner.Result) {
			if r.Err != nil {
				gologger.Debug().Msgf("httpx probe failed for %s: %v", r.Input, r.Err)
				return
			}
			resultCh <- models.HttpxHostResult{
				Host:          r.Input,
				StatusCode:    r.StatusCode,
				Technologies:  r.Technologies,
				ContentLength: r.ContentLength,
				ContentType:   r.ContentType,
				WebServer:     r.WebServer,
				Title:         r.Title,
			}
		},
	}
	for _, h := range hosts {
		options.InputTargetHost = append(options.InputTargetHost, h)
	}

	if err := options.ValidateOptions(); err != nil {
		return nil, common.NewScannerError("invalid httpx options", err)
	}

	httpxRunner, err := runner.New(&options)
	if err != nil {
		return nil, common.NewScannerError("failed to create httpx runner", err)
	}
	defer httpxRunner.Close()

	// Disable httpx runner logs
	gologger.DefaultLogger.SetMaxLevel(levels.LevelFatal)
	defer gologger.DefaultLogger.SetMaxLevel(levels.LevelInfo)

	// Run in a goroutine so we can respect context cancellation
	go func() {
		httpxRunner.RunEnumeration()
		close(doneCh)
	}()

	// Collect results or handle context cancellation
	collecting := true
	for collecting {
		select {
		case res := <-resultCh:
			results = append(results, res)
		case <-doneCh:
			collecting = false
		case <-ctx.Done():
			return nil, common.NewTimeoutError("httpx execution cancelled", ctx.Err())
		}
	}

	return models.HttpxResult{
		Domain:  httpxInput.Domain,
		Results: results,
	}, nil
}

func (s *HttpxScanner) GetName() string {
	return "httpx"
}
