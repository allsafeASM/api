package notification

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/allsafeASM/api/internal/models"
	"github.com/projectdiscovery/gologger"
)

// DiscordNotifier handles sending notifications to Discord webhook
type DiscordNotifier struct {
	webhookURL string
	httpClient *http.Client
	enabled    bool
}

// DiscordEmbed represents a Discord embed object
type DiscordEmbed struct {
	Title       string                 `json:"title,omitempty"`
	Description string                 `json:"description,omitempty"`
	Color       int                    `json:"color,omitempty"`
	Fields      []DiscordEmbedField    `json:"fields,omitempty"`
	Timestamp   string                 `json:"timestamp,omitempty"`
	Footer      *DiscordEmbedFooter    `json:"footer,omitempty"`
	Thumbnail   *DiscordEmbedThumbnail `json:"thumbnail,omitempty"`
}

// DiscordEmbedField represents a field in a Discord embed
type DiscordEmbedField struct {
	Name   string `json:"name"`
	Value  string `json:"value"`
	Inline bool   `json:"inline,omitempty"`
}

// DiscordEmbedFooter represents the footer of a Discord embed
type DiscordEmbedFooter struct {
	Text string `json:"text"`
}

// DiscordEmbedThumbnail represents the thumbnail of a Discord embed
type DiscordEmbedThumbnail struct {
	URL string `json:"url"`
}

// DiscordWebhookPayload represents the payload sent to Discord webhook
type DiscordWebhookPayload struct {
	Username  string         `json:"username,omitempty"`
	AvatarURL string         `json:"avatar_url,omitempty"`
	Content   string         `json:"content,omitempty"`
	Embeds    []DiscordEmbed `json:"embeds,omitempty"`
}

// NotificationStep represents different steps in the task processing
type NotificationStep string

const (
	StepTaskReceived     NotificationStep = "task_received"
	StepTaskStarted      NotificationStep = "task_started"
	StepTaskCompleted    NotificationStep = "task_completed"
	StepTaskFailed       NotificationStep = "task_failed"
	StepResultStored     NotificationStep = "result_stored"
	StepNotificationSent NotificationStep = "notification_sent"
)

// Color constants for Discord embeds
const (
	ColorInfo    = 0x3498db // Blue
	ColorSuccess = 0x2ecc71 // Green
	ColorWarning = 0xf39c12 // Orange
	ColorError   = 0xe74c3c // Red
	ColorPurple  = 0x9b59b6 // Purple
)

// NewDiscordNotifier creates a new Discord notification service
func NewDiscordNotifier() (*DiscordNotifier, error) {
	webhookURL := os.Getenv("DISCORD_WEBHOOK_URL")

	if webhookURL == "" {
		return &DiscordNotifier{
			enabled: false,
		}, nil
	}

	// Create HTTP client with timeout
	httpClient := &http.Client{
		Timeout: 30 * time.Second,
	}

	return &DiscordNotifier{
		webhookURL: webhookURL,
		httpClient: httpClient,
		enabled:    true,
	}, nil
}

// IsEnabled returns whether Discord notifications are enabled
func (d *DiscordNotifier) IsEnabled() bool {
	return d.enabled
}

// NotifyStep sends a notification for a specific step in the task processing
func (d *DiscordNotifier) NotifyStep(ctx context.Context, step NotificationStep, taskMsg *models.TaskMessage, result *models.TaskResult, err error) error {
	if !d.enabled {
		return nil
	}

	payload := d.createPayload(step, taskMsg, result, err)
	return d.sendWebhook(ctx, payload)
}

// NotifyTaskReceived sends notification when a task is received
func (d *DiscordNotifier) NotifyTaskReceived(ctx context.Context, taskMsg *models.TaskMessage) error {
	return d.NotifyStep(ctx, StepTaskReceived, taskMsg, nil, nil)
}

// NotifyTaskStarted sends notification when a task starts processing
func (d *DiscordNotifier) NotifyTaskStarted(ctx context.Context, taskMsg *models.TaskMessage) error {
	return d.NotifyStep(ctx, StepTaskStarted, taskMsg, nil, nil)
}

// NotifyTaskCompleted sends notification when a task completes successfully
func (d *DiscordNotifier) NotifyTaskCompleted(ctx context.Context, taskMsg *models.TaskMessage, result *models.TaskResult) error {
	return d.NotifyStep(ctx, StepTaskCompleted, taskMsg, result, nil)
}

// NotifyTaskFailed sends notification when a task fails
func (d *DiscordNotifier) NotifyTaskFailed(ctx context.Context, taskMsg *models.TaskMessage, err error) error {
	return d.NotifyStep(ctx, StepTaskFailed, taskMsg, nil, err)
}

// NotifyResultStored sends notification when result is stored successfully
func (d *DiscordNotifier) NotifyResultStored(ctx context.Context, taskMsg *models.TaskMessage, result *models.TaskResult) error {
	return d.NotifyStep(ctx, StepResultStored, taskMsg, result, nil)
}

// NotifyNotificationSent sends notification when Azure notification is sent
func (d *DiscordNotifier) NotifyNotificationSent(ctx context.Context, taskMsg *models.TaskMessage, result *models.TaskResult) error {
	return d.NotifyStep(ctx, StepNotificationSent, taskMsg, result, nil)
}

// createPayload creates a Discord webhook payload based on the step and data
func (d *DiscordNotifier) createPayload(step NotificationStep, taskMsg *models.TaskMessage, result *models.TaskResult, err error) DiscordWebhookPayload {
	embed := DiscordEmbed{
		Timestamp: time.Now().Format(time.RFC3339),
	}

	switch step {
	case StepTaskReceived:
		embed.Title = "🔄 Task Received"
		embed.Description = "New task received for processing"
		embed.Color = ColorInfo
		embed.Fields = []DiscordEmbedField{
			{Name: "Task", Value: string(taskMsg.Task), Inline: true},
			{Name: "Domain", Value: taskMsg.Domain, Inline: true},
			{Name: "Scan ID", Value: taskMsg.ScanID, Inline: true},
		}

	case StepTaskStarted:
		embed.Title = "⚡ Task Started"
		embed.Description = "Task processing has begun"
		embed.Color = ColorPurple
		embed.Fields = []DiscordEmbedField{
			{Name: "Task", Value: string(taskMsg.Task), Inline: true},
			{Name: "Domain", Value: taskMsg.Domain, Inline: true},
			{Name: "Scan ID", Value: taskMsg.ScanID, Inline: true},
		}

	case StepTaskCompleted:
		embed.Title = "✅ Task Completed"
		embed.Description = "Task completed successfully"
		embed.Color = ColorSuccess
		embed.Fields = []DiscordEmbedField{
			{Name: "Task", Value: string(taskMsg.Task), Inline: true},
			{Name: "Domain", Value: taskMsg.Domain, Inline: true},
			{Name: "Scan ID", Value: taskMsg.ScanID, Inline: true},
		}

		if result != nil && result.Data != nil {
			if dataMap, ok := result.Data.(map[string]interface{}); ok {
				if count, ok := dataMap["count"].(int); ok {
					embed.Fields = append(embed.Fields, DiscordEmbedField{
						Name: "Results Count", Value: fmt.Sprintf("%d", count), Inline: true,
					})
				}
			}
		}

	case StepTaskFailed:
		embed.Title = "❌ Task Failed"
		embed.Description = "Task processing failed"
		embed.Color = ColorError
		embed.Fields = []DiscordEmbedField{
			{Name: "Task", Value: string(taskMsg.Task), Inline: true},
			{Name: "Domain", Value: taskMsg.Domain, Inline: true},
			{Name: "Scan ID", Value: taskMsg.ScanID, Inline: true},
		}
		if err != nil {
			embed.Fields = append(embed.Fields, DiscordEmbedField{
				Name: "Error", Value: err.Error(), Inline: false,
			})
		}

	case StepResultStored:
		embed.Title = "💾 Result Stored"
		embed.Description = "Task result stored successfully"
		embed.Color = ColorSuccess
		embed.Fields = []DiscordEmbedField{
			{Name: "Task", Value: string(taskMsg.Task), Inline: true},
			{Name: "Domain", Value: taskMsg.Domain, Inline: true},
			{Name: "Scan ID", Value: taskMsg.ScanID, Inline: true},
		}

	case StepNotificationSent:
		embed.Title = "📢 Notification Sent"
		embed.Description = "Azure notification sent successfully"
		embed.Color = ColorInfo
		embed.Fields = []DiscordEmbedField{
			{Name: "Task", Value: string(taskMsg.Task), Inline: true},
			{Name: "Domain", Value: taskMsg.Domain, Inline: true},
			{Name: "Scan ID", Value: taskMsg.ScanID, Inline: true},
		}
	}

	embed.Footer = &DiscordEmbedFooter{
		Text: "AllSafe ASM Worker",
	}

	return DiscordWebhookPayload{
		Username:  "AllSafe ASM Bot",
		AvatarURL: "https://i.imgur.com/oBPXx0D.png",
		Embeds:    []DiscordEmbed{embed},
	}
}

// sendWebhook sends the webhook payload to Discord
func (d *DiscordNotifier) sendWebhook(ctx context.Context, payload DiscordWebhookPayload) error {
	jsonData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal webhook payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", d.webhookURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create HTTP request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := d.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send Discord webhook: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("Discord webhook failed with status %d", resp.StatusCode)
	}

	gologger.Debug().Msgf("Discord webhook sent successfully. Status: %d", resp.StatusCode)
	return nil
}

// SendWebhookWithRetry sends a webhook with retry logic
func (d *DiscordNotifier) SendWebhookWithRetry(ctx context.Context, payload DiscordWebhookPayload) error {
	maxRetries := 3
	baseDelay := 1 * time.Second

	for attempt := 0; attempt <= maxRetries; attempt++ {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		err := d.sendWebhook(ctx, payload)
		if err == nil {
			return nil
		}

		if attempt == maxRetries {
			return fmt.Errorf("failed to send Discord webhook after %d attempts: %w", maxRetries+1, err)
		}

		delay := time.Duration(baseDelay.Nanoseconds() * int64(1<<attempt))
		gologger.Warning().Msgf("Discord webhook failed (attempt %d/%d), retrying in %v: %v", attempt+1, maxRetries+1, delay, err)

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(delay):
			continue
		}
	}

	return fmt.Errorf("max retries exceeded for Discord webhook")
}
