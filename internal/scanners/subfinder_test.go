package scanners

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/allsafeASM/api/internal/models"
)

// TestSubdomainAPIEndpoint tests the subdomain API endpoint functionality
func TestSubdomainAPIEndpoint(t *testing.T) {
	// Test data
	testDomain := "example.com"
	apiKey := "test-api-key"

	// Create a mock server to simulate the subdomain API
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if the API key is present in headers
		if r.Header.Get("x-api-key") != apiKey {
			t.Errorf("Expected API key 'x-api-key' header, got: %s", r.Header.Get("x-api-key"))
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Check if the domain parameter is present
		domain := r.URL.Query().Get("z")
		if domain != testDomain {
			t.Errorf("Expected domain parameter 'z' to be '%s', got: %s", testDomain, domain)
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}

		// Return mock subdomain data
		subdomains := []string{
			"www.example.com",
			"api.example.com",
			"mail.example.com",
			"blog.example.com",
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(subdomains)
	}))
	defer mockServer.Close()

	// Test the API endpoint
	subdomains, err := fetchSubdomainsFromAPI(mockServer.URL, testDomain, apiKey)
	if err != nil {
		t.Fatalf("Failed to fetch subdomains: %v", err)
	}

	// Verify the results
	if len(subdomains) == 0 {
		t.Error("Expected subdomains to be returned, got empty slice")
	}

	expectedSubdomains := []string{
		"www.example.com",
		"api.example.com",
		"mail.example.com",
		"blog.example.com",
	}

	for i, expected := range expectedSubdomains {
		if i >= len(subdomains) {
			t.Errorf("Expected subdomain '%s' at index %d, but slice is too short", expected, i)
			continue
		}
		if subdomains[i] != expected {
			t.Errorf("Expected subdomain '%s' at index %d, got '%s'", expected, i, subdomains[i])
		}
	}

	t.Logf("Successfully fetched %d subdomains for domain: %s", len(subdomains), testDomain)
}

// TestSubdomainAPIEndpointWithRealAPI tests the actual subdomain API endpoint
func TestSubdomainAPIEndpointWithRealAPI(t *testing.T) {
	// Skip this test if no API key is provided
	apiKey := os.Getenv("SUBDOMAIN_API_KEY")
	if apiKey == "" {
		t.Skip("Skipping real API test: SUBDOMAIN_API_KEY environment variable not set")
	}

	testDomain := "example.com"

	// Test the real API endpoint
	subdomains, err := fetchSubdomainsFromAPI("https://api.subbdom.com/v1/search", testDomain, apiKey)
	if err != nil {
		t.Fatalf("Failed to fetch subdomains from real API: %v", err)
	}

	// Verify that we got some results
	if len(subdomains) == 0 {
		t.Error("Expected subdomains to be returned from real API, got empty slice")
	}

	// Verify that the subdomains are valid for the test domain
	for _, subdomain := range subdomains {
		if !isValidSubdomain(subdomain, testDomain) {
			t.Errorf("Invalid subdomain returned: %s for domain: %s", subdomain, testDomain)
		}
	}

	for _, subdomain := range subdomains {
		t.Logf("Found subdomain: %s", subdomain)
	}

	t.Logf("Successfully fetched %d subdomains from real API for domain: %s", len(subdomains), testDomain)
}

// TestSubfinderScannerWithAPI tests the subfinder scanner with API integration
func TestSubfinderScannerWithAPI(t *testing.T) {
	// Skip this test if no API key is provided
	apiKey := os.Getenv("SUBDOMAIN_API_KEY")
	if apiKey == "" {
		t.Skip("Skipping API integration test: SUBDOMAIN_API_KEY environment variable not set")
	}

	// Create a subfinder scanner
	scanner := NewSubfinderScanner()

	// Create test input
	input := models.SubfinderInput{
		Domain: "example.com",
	}

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Execute the scanner
	result, err := scanner.Execute(ctx, input)
	if err != nil {
		t.Fatalf("Failed to execute subfinder scanner: %v", err)
	}

	// Type assert the result
	subfinderResult, ok := result.(models.SubfinderResult)
	if !ok {
		t.Fatalf("Expected SubfinderResult, got %T", result)
	}

	// Verify the results
	if subfinderResult.Domain != input.Domain {
		t.Errorf("Expected domain '%s', got '%s'", input.Domain, subfinderResult.Domain)
	}

	if len(subfinderResult.Subdomains) == 0 {
		t.Error("Expected subdomains to be found, got empty slice")
	}

	// Verify that the domain itself is included in the results
	foundDomain := false
	for _, subdomain := range subfinderResult.Subdomains {
		if subdomain == input.Domain {
			foundDomain = true
			break
		}
	}

	if !foundDomain {
		t.Errorf("Expected domain '%s' to be included in subdomains list", input.Domain)
	}

	t.Logf("Subfinder scanner found %d subdomains for domain: %s", len(subfinderResult.Subdomains), input.Domain)
}

// TestSubfinderScannerWithoutAPI tests the subfinder scanner without API integration
func TestSubfinderScannerWithoutAPI(t *testing.T) {
	// Temporarily unset the API key
	originalAPIKey := os.Getenv("SUBDOMAIN_API_KEY")
	os.Unsetenv("SUBDOMAIN_API_KEY")
	defer func() {
		if originalAPIKey != "" {
			os.Setenv("SUBDOMAIN_API_KEY", originalAPIKey)
		}
	}()

	// Create a subfinder scanner
	scanner := NewSubfinderScanner()

	// Create test input
	input := models.SubfinderInput{
		Domain: "example.com",
	}

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Execute the scanner
	result, err := scanner.Execute(ctx, input)
	if err != nil {
		t.Fatalf("Failed to execute subfinder scanner: %v", err)
	}

	// Type assert the result
	subfinderResult, ok := result.(models.SubfinderResult)
	if !ok {
		t.Fatalf("Expected SubfinderResult, got %T", result)
	}

	// Verify the results
	if subfinderResult.Domain != input.Domain {
		t.Errorf("Expected domain '%s', got '%s'", input.Domain, subfinderResult.Domain)
	}

	if len(subfinderResult.Subdomains) == 0 {
		t.Error("Expected subdomains to be found, got empty slice")
	}

	// Verify that the domain itself is included in the results
	foundDomain := false
	for _, subdomain := range subfinderResult.Subdomains {
		if subdomain == input.Domain {
			foundDomain = true
			break
		}
	}

	if !foundDomain {
		t.Errorf("Expected domain '%s' to be included in subdomains list", input.Domain)
	}

	t.Logf("Subfinder scanner found %d subdomains for domain: %s", len(subfinderResult.Subdomains), input.Domain)
}

// fetchSubdomainsFromAPI makes an HTTP request to the subdomain API endpoint
func fetchSubdomainsFromAPI(baseURL, domain, apiKey string) ([]string, error) {
	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	// Create request
	url := fmt.Sprintf("%s?z=%s", baseURL, domain)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Add API key header
	req.Header.Set("x-api-key", apiKey)

	// Make the request
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()

	// Check response status
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API returned non-200 status: %d", resp.StatusCode)
	}

	// Parse JSON response
	var subdomains []string
	if err := json.NewDecoder(resp.Body).Decode(&subdomains); err != nil {
		return nil, fmt.Errorf("failed to decode JSON response: %w", err)
	}

	return subdomains, nil
}

// isValidSubdomain checks if a subdomain is valid for a given domain
func isValidSubdomain(subdomain, domain string) bool {
	// Simple validation: subdomain should end with the domain
	if len(subdomain) <= len(domain) {
		return subdomain == domain
	}

	// Check if subdomain ends with the domain
	return len(subdomain) > len(domain) && subdomain[len(subdomain)-len(domain):] == domain
}

// TestSubfinderScannerValidation tests input validation
func TestSubfinderScannerValidation(t *testing.T) {
	scanner := NewSubfinderScanner()

	// Test with invalid input type
	_, err := scanner.Execute(context.Background(), "invalid input")
	if err == nil {
		t.Error("Expected error for invalid input type")
	}

	// Test with empty domain
	input := models.SubfinderInput{Domain: ""}
	_, err = scanner.Execute(context.Background(), input)
	if err == nil {
		t.Error("Expected error for empty domain")
	}

	// Test with valid input
	input = models.SubfinderInput{Domain: "example.com"}
	// This might fail due to missing subfinder configuration, but should not panic
	_, err = scanner.Execute(context.Background(), input)
	// We don't check for specific errors here as the test environment might not have subfinder configured
}

// TestSubfinderScannerName tests the scanner name
func TestSubfinderScannerName(t *testing.T) {
	scanner := NewSubfinderScanner()
	expectedName := "subfinder"

	if scanner.GetName() != expectedName {
		t.Errorf("Expected scanner name '%s', got '%s'", expectedName, scanner.GetName())
	}
}

// TestRemoveDuplicates tests the duplicate removal functionality
func TestRemoveDuplicates(t *testing.T) {
	scanner := NewSubfinderScanner()

	input := []string{"a", "b", "a", "c", "b", "d"}
	expected := []string{"a", "b", "c", "d"}

	result := scanner.removeDuplicates(input)

	if len(result) != len(expected) {
		t.Errorf("Expected %d unique items, got %d", len(expected), len(result))
	}

	for i, item := range expected {
		if i >= len(result) || result[i] != item {
			t.Errorf("Expected item '%s' at index %d, got '%s'", item, i, result[i])
		}
	}
}

// TestContains tests the contains functionality
func TestContains(t *testing.T) {
	scanner := NewSubfinderScanner()

	slice := []string{"a", "b", "c"}

	if !scanner.contains(slice, "a") {
		t.Error("Expected slice to contain 'a'")
	}

	if !scanner.contains(slice, "b") {
		t.Error("Expected slice to contain 'b'")
	}

	if scanner.contains(slice, "d") {
		t.Error("Expected slice to not contain 'd'")
	}
}
