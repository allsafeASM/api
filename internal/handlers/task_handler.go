package handlers

import (
	"context"
	"fmt"
	"time"

	"github.com/allsafeASM/api/internal/azure"
	"github.com/allsafeASM/api/internal/models"
	"github.com/allsafeASM/api/scanners"
	"github.com/projectdiscovery/gologger"
)

// TaskHandler handles task processing and result storage
type TaskHandler struct {
	blobClient *azure.BlobStorageClient
}

// NewTaskHandler creates a new task handler
func NewTaskHandler(blobClient *azure.BlobStorageClient) *TaskHandler {
	return &TaskHandler{
		blobClient: blobClient,
	}
}

// HandleTask processes a task and stores the result
func (h *TaskHandler) HandleTask(ctx context.Context, taskMsg *models.TaskMessage) error {
	gologger.Info().Msgf("Processing task: %s for domain: %s", taskMsg.Task, taskMsg.Domain)

	// Create task result
	result := &models.TaskResult{
		TaskID:    generateTaskID(),
		TaskType:  taskMsg.Task,
		Domain:    taskMsg.Domain,
		Status:    models.TaskStatusRunning,
		Timestamp: time.Now().Format(time.RFC3339),
	}

	// Process the task based on type
	var err error
	switch taskMsg.Task {
	case models.TaskTypeSubfinder:
		err = h.handleSubfinderTask(ctx, result)
	case models.TaskTypePortScan:
		err = h.handlePortScanTask(ctx, result)
	case models.TaskTypeHttpx:
		err = h.handleHttpxTask(ctx, result)
	default:
		err = fmt.Errorf("unknown task type: %s", taskMsg.Task)
	}

	// Update result status
	if err != nil {
		result.Status = models.TaskStatusFailed
		result.Error = err.Error()
		gologger.Error().Msgf("Task failed: %v", err)
	} else {
		result.Status = models.TaskStatusCompleted
		gologger.Info().Msg("Task completed successfully")
	}

	// Store result in blob storage
	if storeErr := h.blobClient.StoreTaskResult(ctx, result); storeErr != nil {
		gologger.Error().Msgf("Failed to store task result: %v", storeErr)
		return storeErr
	}

	return err
}

// handleSubfinderTask processes subfinder tasks
func (h *TaskHandler) handleSubfinderTask(ctx context.Context, result *models.TaskResult) error {
	if result.Domain == "" {
		return fmt.Errorf("domain is required for subfinder task")
	}

	subdomains := scanners.RunSubfinder(result.Domain)
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

	// TODO: Implement port scanning
	result.Data = map[string]interface{}{
		"message": "Port scanning not yet implemented",
	}

	gologger.Info().Msgf("Port scanning not yet implemented for domain: %s", result.Domain)
	return nil
}

// handleHttpxTask processes httpx tasks
func (h *TaskHandler) handleHttpxTask(ctx context.Context, result *models.TaskResult) error {
	if result.Domain == "" {
		return fmt.Errorf("domain is required for httpx task")
	}

	// TODO: Implement httpx scanning
	result.Data = map[string]interface{}{
		"message": "HTTPX not yet implemented",
	}

	gologger.Info().Msgf("HTTPX not yet implemented for domain: %s", result.Domain)
	return nil
}

// generateTaskID generates a unique task ID
func generateTaskID() string {
	return fmt.Sprintf("task_%d", time.Now().UnixNano())
}
