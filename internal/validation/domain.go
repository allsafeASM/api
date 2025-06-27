package validation

import "strings"

// DomainValidator provides domain validation functionality
type DomainValidator struct{}

// NewDomainValidator creates a new domain validator
func NewDomainValidator() *DomainValidator {
	return &DomainValidator{}
}

// IsValidDomain performs basic domain format validation
func (v *DomainValidator) IsValidDomain(domain string) bool {
	if len(domain) == 0 || len(domain) > 253 {
		return false
	}

	// Check for valid characters and structure
	if strings.Contains(domain, "..") || strings.Contains(domain, ".-") || strings.Contains(domain, "-.") {
		return false
	}

	// Must start and end with alphanumeric
	if !isAlphanumeric(rune(domain[0])) || !isAlphanumeric(rune(domain[len(domain)-1])) {
		return false
	}

	return true
}

// isAlphanumeric checks if a character is alphanumeric
func isAlphanumeric(r rune) bool {
	return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')
}
