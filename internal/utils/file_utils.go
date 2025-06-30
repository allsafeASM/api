package utils

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// ReadSubdomainsFromFile reads subdomains from a file, one per line
// This mimics the behavior of dnsx tool when processing subdomain files
func ReadSubdomainsFromFile(filepath string) ([]string, error) {
	file, err := os.Open(filepath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file %s: %w", filepath, err)
	}
	defer file.Close()

	var subdomains []string
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		subdomains = append(subdomains, line)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading file %s: %w", filepath, err)
	}

	return subdomains, nil
}

// ReadSubdomainsFromString reads subdomains from a string, splitting by newlines
// This is useful when the subdomains are passed as a string rather than a file
func ReadSubdomainsFromString(content string) []string {
	lines := strings.Split(content, "\n")
	var subdomains []string

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		// Skip empty lines and comments
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		subdomains = append(subdomains, trimmed)
	}

	return subdomains
}

// ValidateSubdomainFile checks if a file exists and is readable
func ValidateSubdomainFile(filepath string) error {
	file, err := os.Open(filepath)
	if err != nil {
		return fmt.Errorf("file %s does not exist or is not readable: %w", filepath, err)
	}
	defer file.Close()

	// Try to read at least one line to ensure it's a text file
	scanner := bufio.NewScanner(file)
	if !scanner.Scan() {
		return fmt.Errorf("file %s appears to be empty", filepath)
	}

	return nil
}
