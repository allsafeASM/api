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
	notifier, err := NewDiscordNotifier()
	if err != nil {
		t.Fatalf("Failed to create Discord notifier: %v", err)
	}

	taskMsg := &models.TaskMessage{
		Task:   models.TaskSubfinder,
		ScanID: 123,
		Domain: "example.com",
	}

	// Test Task Received
	payload := notifier.createPayload(StepTaskReceived, taskMsg, nil, nil)
	if len(payload.Embeds) == 0 {
		t.Fatal("Expected at least one embed")
	}
	if payload.Embeds[0].Title != "Task Received" {
		t.Errorf("Expected title 'Task Received', got: %s", payload.Embeds[0].Title)
	}

	// Test Task Completed
	result := &models.TaskResult{
		Task:   models.TaskSubfinder,
		ScanID: 123,
		Domain: "example.com",
		Status: models.TaskStatusCompleted,
		Data:   models.SubfinderResult{Domain: "example.com", Subdomains: []string{"www.example.com"}},
	}
	payload = notifier.createPayload(StepTaskCompleted, taskMsg, result, nil)
	if payload.Embeds[0].Title != "Task Completed" {
		t.Errorf("Expected title 'Task Completed', got: %s", payload.Embeds[0].Title)
	}

	// Test Task Failed
	payload = notifier.createPayload(StepTaskFailed, taskMsg, nil, fmt.Errorf("test error"))
	if payload.Embeds[0].Title != "Task Failed" {
		t.Errorf("Expected title 'Task Failed', got: %s", payload.Embeds[0].Title)
	}
}

func TestDiscordNotifier_NotifyMethods(t *testing.T) {
	notifier := &DiscordNotifier{
		enabled: false, // Disable to avoid actual webhook calls
	}

	taskMsg := &models.TaskMessage{
		Task:       "subfinder",
		Domain:     "example.com",
		ScanID:     123,
		InstanceID: "test-instance-456",
	}

	result := &models.TaskResult{
		ScanID:    123,
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
