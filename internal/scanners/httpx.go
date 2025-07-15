package scanners

import (
	"context"

	"github.com/allsafeASM/api/internal/azure"
	"github.com/allsafeASM/api/internal/common"
	"github.com/allsafeASM/api/internal/models"
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

	if httpxInput.InputPath == "" {
		return nil, common.NewValidationError("input_path", "InputPath is required and cannot be empty for httpx scanner")
	}

	results := make([]models.HttpxHostResult, 0)
	resultCh := make(chan models.HttpxHostResult, 1000)
	doneCh := make(chan struct{})

	options := runner.Options{
		TechDetect:          true,
		FollowRedirects:     true,
		FollowHostRedirects: false,
		MaxRedirects:        10, // Add explicit MaxRedirects setting
		Threads:             80,
		Timeout:             10,
		Version:             true,
		Asn:                 true,
		InputFile:           httpxInput.InputPath,
		OnResult: func(r runner.Result) {
			if r.Err != nil {
				gologger.Debug().Msgf("httpx probe failed for %s: %v", r.Input, r.Err)
				return
			}

			resultCh <- models.HttpxHostResult{
				Host:          r.Input,
				URL:           r.URL,
				StatusCode:    r.StatusCode,
				Technologies:  r.Technologies,
				ContentLength: r.ContentLength,
				ContentType:   r.ContentType,
				WebServer:     r.WebServer,
				Title:         r.Title,
				ASN:           r.ASN.AsNumber,
			}
		},
	}

	gologger.Info().Msgf("Using input file for httpx: %s", httpxInput.InputPath)

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
