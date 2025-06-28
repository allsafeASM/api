package handlers

import (
	"context"
	"fmt"
	"time"

	"github.com/allsafeASM/api/internal/azure"
	"github.com/allsafeASM/api/internal/errors"
	"github.com/allsafeASM/api/internal/models"
	"github.com/allsafeASM/api/internal/notification"
	"github.com/allsafeASM/api/internal/validation"
	"github.com/allsafeASM/api/scanners"
	"github.com/projectdiscovery/gologger"
)

// TaskHandler handles task processing and result storage
type TaskHandler struct {
	blobClient                 *azure.BlobStorageClient
	scannerTimeout             time.Duration
	domainValidator            *validation.DomainValidator
	errorClassifier            *errors.ErrorClassifier
	notifier                   *notification.Notifier
	discordNotifier            *notification.DiscordNotifier
	enableNotifications        bool
	enableDiscordNotifications bool
}

// NewTaskHandler creates a new task handler
func NewTaskHandler(blobClient *azure.BlobStorageClient, scannerTimeout time.Duration, notifier *notification.Notifier, discordNotifier *notification.DiscordNotifier, enableNotifications bool, enableDiscordNotifications bool) *TaskHandler {
	return &TaskHandler{
		blobClient:                 blobClient,
		scannerTimeout:             scannerTimeout,
		domainValidator:            validation.NewDomainValidator(),
		errorClassifier:            errors.NewErrorClassifier(),
		notifier:                   notifier,
		discordNotifier:            discordNotifier,
		enableNotifications:        enableNotifications,
		enableDiscordNotifications: enableDiscordNotifications,
	}
}

// HandleTask processes a task and stores the result
func (h *TaskHandler) HandleTask(ctx context.Context, taskMsg *models.TaskMessage) *models.MessageProcessingResult {
	gologger.Info().Msgf("Processing task: %s for domain: %s", taskMsg.Task, taskMsg.Domain)

	// Send Discord notification for task received
	if h.enableDiscordNotifications && h.discordNotifier != nil {
		if err := h.discordNotifier.NotifyTaskReceived(ctx, taskMsg); err != nil {
			gologger.Warning().Msgf("Failed to send Discord notification for task received: %v", err)
		}
	}

	// Validate task message
	if taskMsg.Domain == "" {
		err := fmt.Errorf("domain is required for task processing")
		gologger.Error().Msgf("Task validation failed: %v", err)

		// Send Discord notification for task failed
		if h.enableDiscordNotifications && h.discordNotifier != nil {
			if notifyErr := h.discordNotifier.NotifyTaskFailed(ctx, taskMsg, err); notifyErr != nil {
				gologger.Warning().Msgf("Failed to send Discord notification for task failed: %v", notifyErr)
			}
		}

		return &models.MessageProcessingResult{
			Success:   false,
			Error:     err,
			Retryable: false,
		}
	}

	// Validate domain format (basic validation)
	if !h.domainValidator.IsValidDomain(taskMsg.Domain) {
		err := fmt.Errorf("invalid domain format: %s", taskMsg.Domain)
		gologger.Error().Msgf("Task validation failed: %v", err)

		// Send Discord notification for task failed
		if h.enableDiscordNotifications && h.discordNotifier != nil {
			if notifyErr := h.discordNotifier.NotifyTaskFailed(ctx, taskMsg, err); notifyErr != nil {
				gologger.Warning().Msgf("Failed to send Discord notification for task failed: %v", notifyErr)
			}
		}

		return &models.MessageProcessingResult{
			Success:   false,
			Error:     err,
			Retryable: false,
		}
	}

	// Create task result
	result := &models.TaskResult{
		ScanID:    taskMsg.ScanID,
		Task:      models.Task(taskMsg.Task),
		Domain:    taskMsg.Domain,
		Status:    models.TaskStatusRunning,
		Timestamp: time.Now().Format(time.RFC3339),
	}

	// Send Discord notification for task started
	if h.enableDiscordNotifications && h.discordNotifier != nil {
		if err := h.discordNotifier.NotifyTaskStarted(ctx, taskMsg); err != nil {
			gologger.Warning().Msgf("Failed to send Discord notification for task started: %v", err)
		}
	}

	// Create context with timeout for scanner operations
	scannerCtx, cancel := context.WithTimeout(ctx, h.scannerTimeout)
	defer cancel()

	// Process the task based on type
	var err error
	switch taskMsg.Task {
	case models.TaskSubfinder:
		err = h.handleSubfinderTask(scannerCtx, result)
	case models.TaskHttpx:
		err = h.handleHttpxTask(scannerCtx, result)
	case models.TaskDNSX:
		err = h.handleDNSXTask(scannerCtx, result)
	default: // Assume it's subfinder
		err = h.handleSubfinderTask(scannerCtx, result)
	}

	// Update result status
	if err != nil {
		result.Status = models.TaskStatusFailed
		result.Error = err.Error()
		gologger.Error().Msgf("Task failed for domain %s: %v", taskMsg.Domain, err)

		// Send Discord notification for task failed
		if h.enableDiscordNotifications && h.discordNotifier != nil {
			if notifyErr := h.discordNotifier.NotifyTaskFailed(ctx, taskMsg, err); notifyErr != nil {
				gologger.Warning().Msgf("Failed to send Discord notification for task failed: %v", notifyErr)
			}
		}

		// Determine if error is retryable
		retryable := h.errorClassifier.IsRetryableError(err)

		return &models.MessageProcessingResult{
			Success:   false,
			Error:     err,
			Retryable: retryable,
		}
	}

	result.Status = models.TaskStatusCompleted
	gologger.Info().Msgf("Task completed successfully for domain: %s", taskMsg.Domain)

	// Send Discord notification for task completed
	if h.enableDiscordNotifications && h.discordNotifier != nil {
		if notifyErr := h.discordNotifier.NotifyTaskCompleted(ctx, taskMsg, result); notifyErr != nil {
			gologger.Warning().Msgf("Failed to send Discord notification for task completed: %v", notifyErr)
		}
	}

	// Store result in blob storage
	if storeErr := h.blobClient.StoreTaskResult(ctx, result); storeErr != nil {
		gologger.Error().Msgf("Failed to store task result for domain %s: %v", taskMsg.Domain, storeErr)

		// Storage errors are usually retryable
		return &models.MessageProcessingResult{
			Success:   false,
			Error:     storeErr,
			Retryable: true,
		}
	}

	// Send Discord notification for result stored
	if h.enableDiscordNotifications && h.discordNotifier != nil {
		if notifyErr := h.discordNotifier.NotifyResultStored(ctx, taskMsg, result); notifyErr != nil {
			gologger.Warning().Msgf("Failed to send Discord notification for result stored: %v", notifyErr)
		}
	}

	// Send completion notification if enabled
	if h.enableNotifications && h.notifier != nil {
		if notifyErr := h.sendCompletionNotification(ctx, taskMsg, result); notifyErr != nil {
			gologger.Warning().Msgf("Failed to send completion notification for domain %s: %v", taskMsg.Domain, notifyErr)
			// Don't fail the task if notification fails, just log it
		} else {
			// Send Discord notification for Azure notification sent
			if h.enableDiscordNotifications && h.discordNotifier != nil {
				if discordErr := h.discordNotifier.NotifyNotificationSent(ctx, taskMsg, result); discordErr != nil {
					gologger.Warning().Msgf("Failed to send Discord notification for Azure notification sent: %v", discordErr)
				}
			}
		}
	}

	return &models.MessageProcessingResult{
		Success:   true,
		Error:     nil,
		Retryable: false,
	}
}

// handleSubfinderTask processes subfinder tasks
func (h *TaskHandler) handleSubfinderTask(ctx context.Context, result *models.TaskResult) error {
	if result.Domain == "" {
		return fmt.Errorf("domain is required for subfinder task")
	}

	subdomains, err := scanners.RunSubfinder(ctx, result.Domain)
	if err != nil {
		return fmt.Errorf("subfinder failed: %w", err)
	}

	result.Data = map[string]interface{}{
		"subdomains": subdomains,
		"count":      len(subdomains),
	}

	gologger.Info().Msgf("Subfinder completed. Found %d subdomains for %s", len(subdomains), result.Domain)
	return nil
}

// handleHttpxTask processes httpx tasks
func (h *TaskHandler) handleHttpxTask(ctx context.Context, result *models.TaskResult) error {
	if result.Domain == "" {
		return fmt.Errorf("domain is required for httpx task")
	}

	results, err := scanners.RunHttpx(ctx, result.Domain)
	if err != nil {
		return fmt.Errorf("httpx failed: %w", err)
	}

	result.Data = map[string]interface{}{
		"results": results,
		"count":   len(results),
	}

	gologger.Info().Msgf("HTTPX completed. Found %d results for %s", len(results), result.Domain)
	return nil
}

// handleDNSXTask processes DNSX tasks
func (h *TaskHandler) handleDNSXTask(ctx context.Context, result *models.TaskResult) error {
	if result.Domain == "" {
		return fmt.Errorf("domain is required for DNSX task")
	}

	results, err := scanners.RunDNSX(ctx, result.Domain)
	if err != nil {
		return fmt.Errorf("DNSX failed: %w", err)
	}

	result.Data = map[string]interface{}{
		"results": results,
		"count":   len(results),
	}

	gologger.Info().Msgf("DNSX completed. Found %d results for %s", len(results), result.Domain)
	return nil
}

// sendCompletionNotification sends a completion notification to the Azure Function orchestrator
func (h *TaskHandler) sendCompletionNotification(ctx context.Context, taskMsg *models.TaskMessage, result *models.TaskResult) error {
	// Use ScanID as the instance ID for the durable function
	instanceID := taskMsg.InstanceID
	if instanceID == "" {
		return fmt.Errorf("instance_id is required for notification")
	}

	// Map task names to tool names for the notification
	toolName := string(taskMsg.Task)

	gologger.Info().Msgf("Sending completion notification for task %s, domain %s, instance %s", toolName, taskMsg.Domain, instanceID)

	// Send notification with retry logic
	return h.notifier.NotifyCompletionWithRetry(ctx, instanceID, toolName, result)
}
