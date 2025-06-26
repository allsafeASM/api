package handlers

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/allsafeASM/api/internal/azure"
	"github.com/allsafeASM/api/internal/models"
	"github.com/allsafeASM/api/scanners"
	"github.com/projectdiscovery/gologger"
)

// TaskHandler handles task processing and result storage
type TaskHandler struct {
	blobClient     *azure.BlobStorageClient
	scannerTimeout time.Duration
}

// NewTaskHandler creates a new task handler
func NewTaskHandler(blobClient *azure.BlobStorageClient, scannerTimeout time.Duration) *TaskHandler {
	return &TaskHandler{
		blobClient:     blobClient,
		scannerTimeout: scannerTimeout,
	}
}

// HandleTask processes a task and stores the result
func (h *TaskHandler) HandleTask(ctx context.Context, taskMsg *models.TaskMessage) *azure.MessageProcessingResult {
	gologger.Info().Msgf("Processing task: %s for domain: %s", taskMsg.Task, taskMsg.Domain)

	// Create task result
	result := &models.TaskResult{
		TaskID:    generateTaskID(),
		TaskType:  taskMsg.Task,
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
	case models.TaskTypeSubfinder:
		err = h.handleSubfinderTask(scannerCtx, result)
	case models.TaskTypePortScan:
		err = h.handlePortScanTask(scannerCtx, result)
	case models.TaskTypeHttpx:
		err = h.handleHttpxTask(scannerCtx, result)
	default:
		err = fmt.Errorf("unknown task type: %s", taskMsg.Task)
	}

	// Update result status
	if err != nil {
		result.Status = models.TaskStatusFailed
		result.Error = err.Error()
		gologger.Error().Msgf("Task failed: %v", err)

		// Determine if error is retryable
		retryable := h.isRetryableError(err)

		return &azure.MessageProcessingResult{
			Success:   false,
			Error:     err,
			Retryable: retryable,
		}
	}

	result.Status = models.TaskStatusCompleted
	gologger.Info().Msg("Task completed successfully")

	// Store result in blob storage
	if storeErr := h.blobClient.StoreTaskResult(ctx, result); storeErr != nil {
		gologger.Error().Msgf("Failed to store task result: %v", storeErr)

		// Storage errors are usually retryable
		return &azure.MessageProcessingResult{
			Success:   false,
			Error:     storeErr,
			Retryable: true,
		}
	}

	return &azure.MessageProcessingResult{
		Success:   true,
		Error:     nil,
		Retryable: false,
	}
}

// isRetryableError determines if an error should be retried
func (h *TaskHandler) isRetryableError(err error) bool {
	if err == nil {
		return false
	}

	errStr := strings.ToLower(err.Error())

	// Permanent errors (non-retryable)
	permanentErrors := []string{
		"unknown task type",
		"domain is required",
		"invalid domain",
		"not yet implemented",
		"permission denied",
		"unauthorized",
		"forbidden",
	}

	for _, permanentErr := range permanentErrors {
		if strings.Contains(errStr, permanentErr) {
			return false
		}
	}

	// Retryable errors
	retryableErrors := []string{
		"timeout",
		"connection",
		"network",
		"temporary",
		"rate limit",
		"throttle",
		"service unavailable",
		"internal server error",
		"bad gateway",
		"gateway timeout",
	}

	for _, retryableErr := range retryableErrors {
		if strings.Contains(errStr, retryableErr) {
			return true
		}
	}

	// Default to retryable for unknown errors
	return true
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

// generateTaskID generates a unique task ID
func generateTaskID() string {
	return fmt.Sprintf("task_%d", time.Now().UnixNano())
}
