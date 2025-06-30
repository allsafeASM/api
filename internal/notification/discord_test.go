package notification

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/allsafeASM/api/internal/models"
)

func TestNewDiscordNotifier(t *testing.T) {
	// Test with no webhook URL
	notifier, err := NewDiscordNotifier()
	if err != nil {
		t.Fatalf("Expected no error when no webhook URL is provided, got: %v", err)
	}
	if notifier.IsEnabled() {
		t.Error("Expected Discord notifier to be disabled when no webhook URL is provided")
	}

	// Test with webhook URL
	os.Setenv("DISCORD_WEBHOOK_URL", "https://discord.com/api/webhooks/test")
	defer os.Unsetenv("DISCORD_WEBHOOK_URL")

	notifier, err = NewDiscordNotifier()
	if err != nil {
		t.Fatalf("Expected no error when webhook URL is provided, got: %v", err)
	}
	if !notifier.IsEnabled() {
		t.Error("Expected Discord notifier to be enabled when webhook URL is provided")
	}
}

func TestDiscordNotifier_CreatePayload(t *testing.T) {
	notifier := &DiscordNotifier{
		enabled: true,
	}

	taskMsg := &models.TaskMessage{
		Task:       "subfinder",
		Domain:     "example.com",
		ScanID:     "test-scan-123",
		InstanceID: "test-instance-456",
	}

	subfinderResult := models.SubfinderResult{
		Domain:     "example.com",
		Subdomains: []string{"www.example.com", "api.example.com", "mail.example.com", "ftp.example.com", "admin.example.com"},
	}

	result := &models.TaskResult{
		ScanID:    "test-scan-123",
		Task:      "subfinder",
		Domain:    "example.com",
		Status:    "completed",
		Timestamp: time.Now().Format(time.RFC3339),
		Data:      subfinderResult,
	}

	// Test task received payload
	payload := notifier.createPayload(StepTaskReceived, taskMsg, nil, nil)
	if payload.Username != "AllSafe ASM Bot" {
		t.Errorf("Expected username 'AllSafe ASM Bot', got: %s", payload.Username)
	}
	if len(payload.Embeds) != 1 {
		t.Errorf("Expected 1 embed, got: %d", len(payload.Embeds))
	}
	if payload.Embeds[0].Title != "🔄 Task Received" {
		t.Errorf("Expected title '🔄 Task Received', got: %s", payload.Embeds[0].Title)
	}

	// Test task completed payload
	payload = notifier.createPayload(StepTaskCompleted, taskMsg, result, nil)
	if payload.Embeds[0].Title != "✅ Task Completed" {
		t.Errorf("Expected title '✅ Task Completed', got: %s", payload.Embeds[0].Title)
	}
	if payload.Embeds[0].Color != ColorSuccess {
		t.Errorf("Expected color %d, got: %d", ColorSuccess, payload.Embeds[0].Color)
	}

	// Test task failed payload
	err := fmt.Errorf("Test error")
	payload = notifier.createPayload(StepTaskFailed, taskMsg, nil, err)
	if payload.Embeds[0].Title != "❌ Task Failed" {
		t.Errorf("Expected title '❌ Task Failed', got: %s", payload.Embeds[0].Title)
	}
	if payload.Embeds[0].Color != ColorError {
		t.Errorf("Expected color %d, got: %d", ColorError, payload.Embeds[0].Color)
	}
}

func TestDiscordNotifier_NotifyMethods(t *testing.T) {
	notifier := &DiscordNotifier{
		enabled: false, // Disable to avoid actual webhook calls
	}

	taskMsg := &models.TaskMessage{
		Task:       "subfinder",
		Domain:     "example.com",
		ScanID:     "test-scan-123",
		InstanceID: "test-instance-456",
	}

	result := &models.TaskResult{
		ScanID:    "test-scan-123",
		Task:      "subfinder",
		Domain:    "example.com",
		Status:    "completed",
		Timestamp: time.Now().Format(time.RFC3339),
	}

	ctx := context.Background()

	// Test all notification steps (should not error when disabled)
	steps := []struct {
		name NotificationStep
		err  error
	}{
		{StepTaskReceived, nil},
		{StepTaskStarted, nil},
		{StepTaskCompleted, nil},
		{StepTaskFailed, fmt.Errorf("test")},
		{StepResultStored, nil},
		{StepNotificationSent, nil},
	}

	for _, step := range steps {
		t.Run(string(step.name), func(t *testing.T) {
			if err := notifier.NotifyStep(ctx, step.name, taskMsg, result, step.err); err != nil {
				t.Errorf("Expected no error for %s when disabled, got: %v", step.name, err)
			}
		})
	}
}
