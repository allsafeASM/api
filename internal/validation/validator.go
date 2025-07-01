package validation

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/allsafeASM/api/internal/common"
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

	if taskMsg.ScanID == 0 {
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
	// Validate domain
	if err := v.ValidateDomain(input.Domain); err != nil {
		return err
	}

	// Validate IPs if provided
	if len(input.IPs) > 0 {
		for i, ip := range input.IPs {
			if !v.isValidIP(ip) {
				return common.NewValidationError(fmt.Sprintf("ips[%d]", i), fmt.Sprintf("invalid IP address: %s", ip))
			}
		}
	}

	// Validate hosts file location if provided
	if input.HostsFileLocation != "" {
		if strings.TrimSpace(input.HostsFileLocation) == "" {
			return common.NewValidationError("hosts_file_location", "hosts file location cannot be empty")
		}
	}

	// Validate ports if provided
	if len(input.Ports) > 0 {
		for i, port := range input.Ports {
			if port < 1 || port > 65535 {
				return common.NewValidationError(fmt.Sprintf("ports[%d]", i), fmt.Sprintf("port must be between 1 and 65535, got: %d", port))
			}
		}
	}

	// Validate port range if provided
	if input.PortRange != "" {
		if strings.TrimSpace(input.PortRange) == "" {
			return common.NewValidationError("port_range", "port range cannot be empty")
		}
		// Basic validation for port range format (e.g., "1-1000")
		if !strings.Contains(input.PortRange, "-") {
			return common.NewValidationError("port_range", "port range must be in format 'start-end' (e.g., '1-1000')")
		}
	}

	// Validate top ports if provided
	if input.TopPorts != "" {
		validTopPorts := map[string]bool{"full": true, "100": true, "1000": true}
		if !validTopPorts[input.TopPorts] {
			return common.NewValidationError("top_ports", "top_ports must be one of: 'full', '100', '1000'")
		}
	}

	// Validate rate limit if provided
	if input.RateLimit > 0 {
		if input.RateLimit > 10000 {
			return common.NewValidationError("rate_limit", "rate limit cannot exceed 10000 packets per second")
		}
	}

	// Validate concurrency if provided
	if input.Concurrency > 0 {
		if input.Concurrency > 100 {
			return common.NewValidationError("concurrency", "concurrency cannot exceed 100")
		}
	}

	// Validate timeout if provided
	if input.Timeout > 0 {
		if input.Timeout > 3600 {
			return common.NewValidationError("timeout", "timeout cannot exceed 3600 seconds")
		}
	}

	// Ensure at least one source of IPs is provided
	if len(input.IPs) == 0 && input.HostsFileLocation == "" {
		return common.NewValidationError("ips", "either IPs or hosts file location must be provided")
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
