package common

import (
	"fmt"
	"strings"
)

// Error types for better error classification
type ErrorType string

const (
	ErrorTypeValidation    ErrorType = "validation"
	ErrorTypeConfiguration ErrorType = "configuration"
	ErrorTypeNetwork       ErrorType = "network"
	ErrorTypeTimeout       ErrorType = "timeout"
	ErrorTypePermission    ErrorType = "permission"
	ErrorTypeNotFound      ErrorType = "not_found"
	ErrorTypeInternal      ErrorType = "internal"
	ErrorTypeScanner       ErrorType = "scanner"
)

// AppError represents a structured application error
type AppError struct {
	Type    ErrorType
	Message string
	Field   string
	Err     error
}

func (e *AppError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %s (%s)", e.Type, e.Message, e.Err.Error())
	}
	return fmt.Sprintf("%s: %s", e.Type, e.Message)
}

func (e *AppError) Unwrap() error {
	return e.Err
}

// IsRetryable determines if an error should be retried
func (e *AppError) IsRetryable() bool {
	switch e.Type {
	case ErrorTypeNetwork, ErrorTypeTimeout, ErrorTypeScanner:
		return true
	case ErrorTypeValidation, ErrorTypeConfiguration, ErrorTypePermission, ErrorTypeNotFound:
		return false
	default:
		return true // Default to retryable for unknown errors
	}
}

// Error constructors
func NewValidationError(field, message string) *AppError {
	return &AppError{
		Type:    ErrorTypeValidation,
		Field:   field,
		Message: message,
	}
}

func NewConfigurationError(field, message string) *AppError {
	return &AppError{
		Type:    ErrorTypeConfiguration,
		Field:   field,
		Message: message,
	}
}

func NewNetworkError(message string, err error) *AppError {
	return &AppError{
		Type:    ErrorTypeNetwork,
		Message: message,
		Err:     err,
	}
}

func NewTimeoutError(message string, err error) *AppError {
	return &AppError{
		Type:    ErrorTypeTimeout,
		Message: message,
		Err:     err,
	}
}

func NewPermissionError(message string, err error) *AppError {
	return &AppError{
		Type:    ErrorTypePermission,
		Message: message,
		Err:     err,
	}
}

func NewNotFoundError(message string, err error) *AppError {
	return &AppError{
		Type:    ErrorTypeNotFound,
		Message: message,
		Err:     err,
	}
}

func NewInternalError(message string, err error) *AppError {
	return &AppError{
		Type:    ErrorTypeInternal,
		Message: message,
		Err:     err,
	}
}

func NewScannerError(message string, err error) *AppError {
	return &AppError{
		Type:    ErrorTypeScanner,
		Message: message,
		Err:     err,
	}
}

// ErrorClassifier provides centralized error classification
type ErrorClassifier struct{}

func NewErrorClassifier() *ErrorClassifier {
	return &ErrorClassifier{}
}

// ClassifyError classifies an error and returns an AppError
func (c *ErrorClassifier) ClassifyError(err error) *AppError {
	if err == nil {
		return nil
	}

	// Check if it's already an AppError
	if appErr, ok := err.(*AppError); ok {
		return appErr
	}

	errStr := strings.ToLower(err.Error())

	// Permanent errors (non-retryable)
	permanentErrors := []string{
		"unknown task type",
		"domain is required",
		"invalid domain",
		"not yet implemented",
		"permission denied",
		"unauthorized",
		"forbidden",
		"not found",
		"invalid",
		"scan_id is required",
		"task type is required",
	}

	for _, permanentErr := range permanentErrors {
		if strings.Contains(errStr, permanentErr) {
			return NewValidationError("", err.Error())
		}
	}

	// Network/Timeout errors (retryable)
	retryableErrors := []string{
		"timeout",
		"connection",
		"network",
		"temporary",
		"rate limit",
		"throttle",
		"service unavailable",
		"internal server error",
		"bad gateway",
		"gateway timeout",
		"context deadline exceeded",
		"context canceled",
	}

	for _, retryableErr := range retryableErrors {
		if strings.Contains(errStr, retryableErr) {
			return NewNetworkError(err.Error(), err)
		}
	}

	// Default to internal error
	return NewInternalError(err.Error(), err)
}

// IsRetryableError determines if an error should be retried
func (c *ErrorClassifier) IsRetryableError(err error) bool {
	appErr := c.ClassifyError(err)
	return appErr.IsRetryable()
}
