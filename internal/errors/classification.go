package errors

import "strings"

// ErrorClassifier provides error classification functionality
type ErrorClassifier struct{}

// NewErrorClassifier creates a new error classifier
func NewErrorClassifier() *ErrorClassifier {
	return &ErrorClassifier{}
}

// IsRetryableError determines if an error should be retried
func (c *ErrorClassifier) IsRetryableError(err error) bool {
	if err == nil {
		return false
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
	}

	for _, permanentErr := range permanentErrors {
		if strings.Contains(errStr, permanentErr) {
			return false
		}
	}

	// Retryable errors
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
	}

	for _, retryableErr := range retryableErrors {
		if strings.Contains(errStr, retryableErr) {
			return true
		}
	}

	// Default to retryable for unknown errors
	return true
}
