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
	blobClient          *azure.BlobStorageClient
	scannerTimeout      time.Duration
	domainValidator     *validation.DomainValidator
	errorClassifier     *errors.ErrorClassifier
	notifier            *notification.Notifier
	enableNotifications bool
}

// NewTaskHandler creates a new task handler
func NewTaskHandler(blobClient *azure.BlobStorageClient, scannerTimeout time.Duration, notifier *notification.Notifier, enableNotifications bool) *TaskHandler {
	return &TaskHandler{
		blobClient:          blobClient,
		scannerTimeout:      scannerTimeout,
		domainValidator:     validation.NewDomainValidator(),
		errorClassifier:     errors.NewErrorClassifier(),
		notifier:            notifier,
		enableNotifications: enableNotifications,
	}
}

// HandleTask processes a task and stores the result
func (h *TaskHandler) HandleTask(ctx context.Context, taskMsg *models.TaskMessage) *models.MessageProcessingResult {
	gologger.Info().Msgf("Processing task: %s for domain: %s", taskMsg.Task, taskMsg.Domain)

	// Validate task message
	if taskMsg.Domain == "" {
		err := fmt.Errorf("domain is required for task processing")
		gologger.Error().Msgf("Task validation failed: %v", err)
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

	// Create context with timeout for scanner operations
	scannerCtx, cancel := context.WithTimeout(ctx, h.scannerTimeout)
	defer cancel()

	// Process the task based on type
	var err error
	switch taskMsg.Task {
	case models.TaskSubfinder:
		err = h.handleSubfinderTask(scannerCtx, result)
	case models.TaskPortScan:
		err = h.handlePortScanTask(scannerCtx, result)
	case models.TaskHttpx:
		err = h.handleHttpxTask(scannerCtx, result)
	default: // Assume it's subfinder
		err = h.handleSubfinderTask(scannerCtx, result)
	}

	// Update result status
	if err != nil {
		result.Status = models.TaskStatusFailed
		result.Error = err.Error()
		gologger.Error().Msgf("Task failed for domain %s: %v", taskMsg.Domain, err)

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

	// Send completion notification if enabled
	if h.enableNotifications && h.notifier != nil {
		if notifyErr := h.sendCompletionNotification(ctx, taskMsg, result); notifyErr != nil {
			gologger.Warning().Msgf("Failed to send completion notification for domain %s: %v", taskMsg.Domain, notifyErr)
			// Don't fail the task if notification fails, just log it
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

// handlePortScanTask processes port scanning tasks
func (h *TaskHandler) handlePortScanTask(ctx context.Context, result *models.TaskResult) error {
	if result.Domain == "" {
		return fmt.Errorf("domain is required for portscan task")
	}

	ports, err := scanners.RunPortScanner(ctx, result.Domain)
	if err != nil {
		return fmt.Errorf("port scanner failed: %w", err)
	}

	result.Data = map[string]interface{}{
		"ports": ports,
		"count": len(ports),
	}

	gologger.Info().Msgf("Port scanning completed. Found %d open ports for %s", len(ports), result.Domain)
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
