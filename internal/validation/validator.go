package validation

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/allsafeASM/api/internal/models"
)

// Validator provides all validation functionality
type Validator struct{}

// NewValidator creates a new validator instance
func NewValidator() *Validator {
	return &Validator{}
}

// ValidateDomain performs basic domain format validation
func (v *Validator) ValidateDomain(domain string) error {
	if domain == "" {
		return fmt.Errorf("domain is required")
	}

	// Basic length check
	if len(domain) > 253 {
		return fmt.Errorf("domain too long: %s", domain)
	}

	// Check for invalid patterns
	invalidPatterns := []string{"..", ".-", "-."}
	for _, pattern := range invalidPatterns {
		if strings.Contains(domain, pattern) {
			return fmt.Errorf("domain contains invalid pattern '%s': %s", pattern, domain)
		}
	}

	// Must start and end with alphanumeric
	if len(domain) == 0 || !isAlphanumeric(rune(domain[0])) || !isAlphanumeric(rune(domain[len(domain)-1])) {
		return fmt.Errorf("domain must start and end with alphanumeric character: %s", domain)
	}

	return nil
}

// ValidateTaskMessage validates a task message
func (v *Validator) ValidateTaskMessage(taskMsg *models.TaskMessage) error {
	if taskMsg.Domain == "" {
		return fmt.Errorf("domain is required for task processing")
	}

	if err := v.ValidateDomain(taskMsg.Domain); err != nil {
		return err
	}

	if taskMsg.ScanID == "" {
		return fmt.Errorf("scan_id is required")
	}

	if taskMsg.Task == "" {
		return fmt.Errorf("task type is required")
	}

	// Validate task type
	if !v.isValidTaskType(models.Task(taskMsg.Task)) {
		return fmt.Errorf("invalid task type: %s", taskMsg.Task)
	}

	return nil
}

// ValidateScannerInput validates any scanner input
func (v *Validator) ValidateScannerInput(input models.ScannerInput) error {
	if input.GetDomain() == "" {
		return fmt.Errorf("domain is required for %s scanner", input.GetScannerName())
	}

	if err := v.ValidateDomain(input.GetDomain()); err != nil {
		return fmt.Errorf("invalid domain format for %s: %w", input.GetScannerName(), err)
	}

	return nil
}

// ValidateSubfinderInput validates subfinder input
func (v *Validator) ValidateSubfinderInput(input models.SubfinderInput) error {
	return v.ValidateScannerInput(input)
}

// ValidateHttpxInput validates httpx input
func (v *Validator) ValidateHttpxInput(input models.HttpxInput) error {
	return v.ValidateScannerInput(input)
}

// ValidateDNSXInput validates dnsx input
func (v *Validator) ValidateDNSXInput(input models.DNSXInput) error {
	// For DNSX, we can have either a domain OR subdomains, or both
	if input.Domain == "" && len(input.Subdomains) == 0 {
		return fmt.Errorf("either domain or subdomains must be provided for DNSX scanner")
	}

	// If domain is provided, validate it
	if input.Domain != "" {
		if err := v.ValidateDomain(input.Domain); err != nil {
			return fmt.Errorf("invalid domain format for DNSX: %w", err)
		}
	}

	// If subdomains are provided, validate each one
	if len(input.Subdomains) > 0 {
		for i, subdomain := range input.Subdomains {
			if subdomain == "" {
				continue // Skip empty subdomains
			}
			if err := v.ValidateDomain(subdomain); err != nil {
				return fmt.Errorf("invalid subdomain at index %d: %w", i, err)
			}
		}
	}

	return nil
}

// ValidateNaabuInput validates naabu input
func (v *Validator) ValidateNaabuInput(input models.NaabuInput) error {
	// For Naabu, we can have either IPs OR a hosts file location, or both
	if len(input.IPs) == 0 && input.HostsFileLocation == "" {
		return fmt.Errorf("either IPs or hosts file location must be provided for Naabu scanner")
	}

	// If IPs are provided, validate each one
	if len(input.IPs) > 0 {
		for i, ip := range input.IPs {
			if ip == "" {
				continue // Skip empty IPs
			}
			if !v.isValidIP(ip) {
				return fmt.Errorf("invalid IP address at index %d: %s", i, ip)
			}
		}
	}

	// Validate port configuration
	if len(input.Ports) > 0 && input.PortRange != "" {
		return fmt.Errorf("cannot specify both specific ports and port range")
	}

	if len(input.Ports) > 0 && input.TopPorts > 0 {
		return fmt.Errorf("cannot specify both specific ports and top ports")
	}

	if input.PortRange != "" && input.TopPorts > 0 {
		return fmt.Errorf("cannot specify both port range and top ports")
	}

	// Validate port numbers
	for i, port := range input.Ports {
		if port < 1 || port > 65535 {
			return fmt.Errorf("invalid port number at index %d: %d (must be 1-65535)", i, port)
		}
	}

	// Validate top ports
	if input.TopPorts < 0 {
		return fmt.Errorf("top ports cannot be negative")
	}

	// Validate rate limit and concurrency
	if input.RateLimit < 0 {
		return fmt.Errorf("rate limit cannot be negative")
	}

	if input.Concurrency < 0 {
		return fmt.Errorf("concurrency cannot be negative")
	}

	// Validate timeout
	if input.Timeout < 0 {
		return fmt.Errorf("timeout cannot be negative")
	}

	return nil
}

// isValidIP performs basic IP validation
func (v *Validator) isValidIP(ip string) bool {
	// Basic validation - you might want to use net.ParseIP for more robust validation
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return false
	}

	for _, part := range parts {
		if num, err := strconv.Atoi(part); err != nil || num < 0 || num > 255 {
			return false
		}
	}

	return true
}

// isValidTaskType checks if the task type is supported
func (v *Validator) isValidTaskType(taskType models.Task) bool {
	validTasks := map[models.Task]bool{
		models.TaskSubfinder:  true,
		models.TaskHttpx:      true,
		models.TaskDNSResolve: true,
		models.TaskNaabu:      true,
	}
	return validTasks[taskType]
}

// isAlphanumeric checks if a character is alphanumeric
func isAlphanumeric(r rune) bool {
	return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')
}
