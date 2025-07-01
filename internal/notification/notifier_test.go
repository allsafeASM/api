package notification

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/allsafeASM/api/internal/models"
)

func TestNewNotifier(t *testing.T) {
	// Test with missing environment variables
	notifier, err := NewNotifier()
	if err == nil {
		t.Error("Expected error when DURABLE_API_ENDPOINT is missing")
	}

	// Test with valid environment variables
	os.Setenv("DURABLE_API_ENDPOINT", "https://test.azurewebsites.net/api/orchestrators")
	os.Setenv("DURABLE_API_KEY", "test-key")
	defer func() {
		os.Unsetenv("DURABLE_API_ENDPOINT")
		os.Unsetenv("DURABLE_API_KEY")
	}()

	notifier, err = NewNotifier()
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	if notifier.durableBaseURL != "https://test.azurewebsites.net/api/orchestrators" {
		t.Errorf("Expected durableBaseURL to be 'https://test.azurewebsites.net/api/orchestrators', got %s", notifier.durableBaseURL)
	}

	if notifier.durableKey != "test-key" {
		t.Errorf("Expected durableKey to be 'test-key', got %s", notifier.durableKey)
	}

	if notifier.httpClient.Timeout != 30*time.Second {
		t.Errorf("Expected HTTP client timeout to be 30 seconds, got %v", notifier.httpClient.Timeout)
	}
}

func TestNotificationPayload(t *testing.T) {
	subfinderResult := models.SubfinderResult{
		Domain:     "example.com",
		Subdomains: []string{"www.example.com", "api.example.com"},
	}

	result := &models.TaskResult{
		ScanID: 123,
		Task:   models.TaskSubfinder,
		Domain: "example.com",
		Status: models.TaskStatusCompleted,
		Data:   subfinderResult,
	}

	payload := NotificationPayload{
		ScanID: result.ScanID,
		Task:   string(result.Task),
		Domain: result.Domain,
		Status: string(result.Status),
	}

	// Convert the result to a map for the payload
	if scannerResult, ok := result.Data.(models.ScannerResult); ok {
		payload.Data = map[string]interface{}{
			"count": scannerResult.GetCount(),
		}
	}

	if payload.ScanID != 123 {
		t.Errorf("Expected ScanID to be 123, got %v", payload.ScanID)
	}

	if payload.Task != "subfinder" {
		t.Errorf("Expected Task to be 'subfinder', got %s", payload.Task)
	}

	if payload.Domain != "example.com" {
		t.Errorf("Expected Domain to be 'example.com', got %s", payload.Domain)
	}

	if payload.Status != "completed" {
		t.Errorf("Expected Status to be 'completed', got %s", payload.Status)
	}

	if payload.Data["count"] != 2 {
		t.Errorf("Expected count to be 2, got %v", payload.Data["count"])
	}
}

func TestNotifyCompletionWithRetry(t *testing.T) {
	// Set up test environment
	os.Setenv("DURABLE_API_ENDPOINT", "https://test.azurewebsites.net/api/orchestrators")
	os.Setenv("DURABLE_API_KEY", "test-key")
	defer func() {
		os.Unsetenv("DURABLE_API_ENDPOINT")
		os.Unsetenv("DURABLE_API_KEY")
	}()

	notifier, err := NewNotifier()
	if err != nil {
		t.Fatalf("Failed to create notifier: %v", err)
	}

	result := &models.TaskResult{
		ScanID:    123,
		Task:      models.TaskSubfinder,
		Domain:    "example.com",
		Status:    models.TaskStatusCompleted,
		Timestamp: time.Now().Format(time.RFC3339),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// This will fail because the endpoint doesn't exist, but it should retry
	err = notifier.NotifyCompletionWithRetry(ctx, "test-instance", "subfinder", result)
	if err == nil {
		t.Error("Expected error when calling non-existent endpoint")
	}
}
