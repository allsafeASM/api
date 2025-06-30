package scanners

import (
	"context"

	"github.com/allsafeASM/api/internal/common"
	"github.com/allsafeASM/api/internal/models"
	"github.com/projectdiscovery/gologger"
)

// HttpxScanner implements the Scanner interface for httpx
type HttpxScanner struct {
	*BaseScanner
}

// NewHttpxScanner creates a new httpx scanner
func NewHttpxScanner() *HttpxScanner {
	return &HttpxScanner{
		BaseScanner: NewBaseScanner(),
	}
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

	// TODO: Implement httpx scanning with context support
	// For now, return a placeholder message
	gologger.Warning().Msgf("HTTPX scanning not yet implemented for domain: %s", httpxInput.Domain)

	return models.HttpxResult{
		Domain: httpxInput.Domain,
		URLs:   []string{},
	}, common.NewScannerError("httpx scanning not yet implemented", nil)
}

func (s *HttpxScanner) GetName() string {
	return "httpx"
}
