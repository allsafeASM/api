package notification

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/allsafeASM/api/internal/models"
	"github.com/projectdiscovery/gologger"
)

// Notifier handles Azure Function notifications
type Notifier struct {
	durableBaseURL string
	durableKey     string
	httpClient     *http.Client
}

// NotificationPayload represents the payload sent to the Azure Function
type NotificationPayload struct {
	ScanID    int                    `json:"scan_id"`
	Task      string                 `json:"task"`
	Domain    string                 `json:"domain"`
	Status    string                 `json:"status"`
	Data      map[string]interface{} `json:"data,omitempty"`
	Error     string                 `json:"error,omitempty"`
	Timestamp string                 `json:"timestamp"`
	Duration  string                 `json:"duration,omitempty"`
}

// NewNotifier creates a new notifier instance
func NewNotifier() (*Notifier, error) {
	durableBaseURL := os.Getenv("DURABLE_API_ENDPOINT")
	durableKey := os.Getenv("DURABLE_API_KEY")

	if durableBaseURL == "" {
		return nil, fmt.Errorf("DURABLE_API_ENDPOINT environment variable is required")
	}
	if durableKey == "" {
		return nil, fmt.Errorf("DURABLE_API_KEY environment variable is required")
	}

	return &Notifier{
		durableBaseURL: durableBaseURL,
		durableKey:     durableKey,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}, nil
}

// NewConfiguredNotifier creates a notifier based on configuration
func NewConfiguredNotifier(enableNotifications bool) (*Notifier, error) {
	if !enableNotifications {
		return nil, nil // Not an error, just disabled
	}

	notifier, err := NewNotifier()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize notification service: %w", err)
	}

	return notifier, nil
}

// NotifyCompletion sends a completion notification to the Azure Function orchestrator
func (n *Notifier) NotifyCompletion(ctx context.Context, instanceID string, toolName string, result *models.TaskResult) error {
	if n == nil {
		return nil // Notifications disabled
	}

	eventName := fmt.Sprintf("%s_completed", toolName)

	// Construct the notification URL
	notificationURL := fmt.Sprintf("%s/instances/%s/raiseEvent/%s?code=%s",
		n.durableBaseURL, instanceID, eventName, n.durableKey)

	gologger.Info().Msgf("Notifying orchestrator at: %s", notificationURL)

	// Create HTTP request with empty JSON body
	req, err := http.NewRequestWithContext(ctx, "POST", notificationURL, strings.NewReader("{}"))
	if err != nil {
		return fmt.Errorf("failed to create HTTP request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	// Make the HTTP request
	resp, err := n.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send notification request: %w", err)
	}
	defer resp.Body.Close()

	// Check response status
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("notification request failed with status %d", resp.StatusCode)
	}

	gologger.Info().Msgf("Successfully sent event '%s' for instance '%s'. Status: %d", eventName, instanceID, resp.StatusCode)
	return nil
}

// NotifyCompletionWithRetry sends a completion notification with retry logic
func (n *Notifier) NotifyCompletionWithRetry(ctx context.Context, instanceID string, toolName string, result *models.TaskResult) error {
	if n == nil {
		return nil // Notifications disabled
	}

	maxRetries := 3
	baseDelay := 1 * time.Second

	for attempt := 0; attempt <= maxRetries; attempt++ {
		err := n.NotifyCompletion(ctx, instanceID, toolName, result)
		if err == nil {
			return nil
		}

		if attempt == maxRetries {
			return fmt.Errorf("failed to send notification after %d attempts: %w", maxRetries, err)
		}

		// Calculate exponential backoff delay
		delay := time.Duration(baseDelay.Nanoseconds() * int64(1<<attempt))
		gologger.Warning().Msgf("Notification failed (attempt %d/%d), retrying in %v: %v", attempt+1, maxRetries+1, delay, err)

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(delay):
			continue
		}
	}

	return fmt.Errorf("max retries exceeded")
}
