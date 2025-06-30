package scanners

import (
	"github.com/allsafeASM/api/internal/common"
	"github.com/allsafeASM/api/internal/models"
	"github.com/allsafeASM/api/internal/validation"
)

// BaseScanner provides common functionality for all scanners
type BaseScanner struct {
	validator       *validation.Validator
	errorClassifier *common.ErrorClassifier
}

// NewBaseScanner creates a new base scanner
func NewBaseScanner() *BaseScanner {
	return &BaseScanner{
		validator:       validation.NewValidator(),
		errorClassifier: common.NewErrorClassifier(),
	}
}

// ValidateInput validates any scanner input using the validator
func (b *BaseScanner) ValidateInput(input models.ScannerInput) error {
	if input == nil {
		return common.NewValidationError("input", "scanner input cannot be nil")
	}

	if err := b.validator.ValidateScannerInput(input); err != nil {
		return common.NewValidationError("input", err.Error())
	}

	return nil
}

// GetBaseScanner returns the base scanner instance for interface compatibility
func (b *BaseScanner) GetBaseScanner() interface{} {
	return b
}

// ClassifyError classifies scanner-specific errors
func (b *BaseScanner) ClassifyError(err error) *common.AppError {
	if err == nil {
		return nil
	}

	// Check if it's already an AppError
	if appErr, ok := err.(*common.AppError); ok {
		return appErr
	}

	// Use the error classifier to determine the type
	return b.errorClassifier.ClassifyError(err)
}

// IsRetryableError determines if a scanner error should be retried
func (b *BaseScanner) IsRetryableError(err error) bool {
	return b.errorClassifier.IsRetryableError(err)
}
