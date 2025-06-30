package handlers

import (
	"context"
	"fmt"
	"time"

	"github.com/allsafeASM/api/internal/azure"
	"github.com/allsafeASM/api/internal/common"
	"github.com/allsafeASM/api/internal/models"
	"github.com/allsafeASM/api/internal/notification"
	"github.com/allsafeASM/api/internal/scanners"
	"github.com/allsafeASM/api/internal/utils"
	"github.com/allsafeASM/api/internal/validation"
	"github.com/projectdiscovery/gologger"
)

// TaskHandler handles task processing and result storage
type TaskHandler struct {
	blobClient      *azure.BlobStorageClient
	scannerTimeout  time.Duration
	validator       *validation.Validator
	errorClassifier *common.ErrorClassifier
	scannerFactory  *scanners.ScannerFactory
	notifier        *notification.Notifier
	discordNotifier *notification.DiscordNotifier
}

// NewTaskHandler creates a new task handler
func NewTaskHandler(blobClient *azure.BlobStorageClient, scannerTimeout time.Duration, notifier *notification.Notifier, discordNotifier *notification.DiscordNotifier) *TaskHandler {
	return &TaskHandler{
		blobClient:      blobClient,
		scannerTimeout:  scannerTimeout,
		validator:       validation.NewValidator(),
		errorClassifier: common.NewErrorClassifier(),
		scannerFactory:  scanners.NewScannerFactoryWithBlobClient(blobClient),
		notifier:        notifier,
		discordNotifier: discordNotifier,
	}
}

// HandleTask processes a task and stores the result
func (h *TaskHandler) HandleTask(ctx context.Context, taskMsg *models.TaskMessage) *models.MessageProcessingResult {
	gologger.Info().Msgf("Processing task: %s for domain: %s", taskMsg.Task, taskMsg.Domain)

	// Track start time for duration calculation
	startTime := time.Now()

	// Send initial Discord notification
	h.sendDiscordNotification(ctx, taskMsg, nil, nil, notification.StepTaskReceived)

	// Validate task message
	if validationResult := h.validateTaskMessage(taskMsg); !validationResult.Success {
		h.sendDiscordNotification(ctx, taskMsg, nil, validationResult.Error, notification.StepTaskFailed)
		return validationResult
	}

	// Create and process task result
	result := h.createTaskResult(taskMsg)
	h.sendDiscordNotification(ctx, taskMsg, result, nil, notification.StepTaskStarted)

	// Process the task
	if processingResult := h.processTask(ctx, taskMsg, result); !processingResult.Success {
		// Set duration even for failed tasks
		result.Duration = time.Since(startTime).String()
		gologger.Error().Msgf("Task %s for domain %s failed after %s", taskMsg.Task, taskMsg.Domain, result.Duration)
		return processingResult
	}

	// Set duration for successful tasks
	result.Duration = time.Since(startTime).String()

	// Store result and send notifications
	return h.finalizeTask(ctx, taskMsg, result)
}

// validateTaskMessage validates the task message and returns appropriate result
func (h *TaskHandler) validateTaskMessage(taskMsg *models.TaskMessage) *models.MessageProcessingResult {
	if err := h.validator.ValidateTaskMessage(taskMsg); err != nil {
		return h.createFailureResult(err, false)
	}

	return &models.MessageProcessingResult{Success: true}
}

// createTaskResult creates a new task result with initial status
func (h *TaskHandler) createTaskResult(taskMsg *models.TaskMessage) *models.TaskResult {
	return &models.TaskResult{
		ScanID:    taskMsg.ScanID,
		Task:      models.Task(taskMsg.Task),
		Domain:    taskMsg.Domain,
		Status:    models.TaskStatusRunning,
		Timestamp: time.Now().Format(time.RFC3339),
	}
}

// processTask executes the task based on its type
func (h *TaskHandler) processTask(ctx context.Context, taskMsg *models.TaskMessage, result *models.TaskResult) *models.MessageProcessingResult {
	scannerCtx, cancel := context.WithTimeout(ctx, h.scannerTimeout)
	defer cancel()

	scanner, err := h.scannerFactory.GetScanner(models.Task(taskMsg.Task))
	if err != nil {
		// Fallback to subfinder if scanner not found
		gologger.Warning().Msgf("Scanner not found for task type %s, falling back to subfinder", taskMsg.Task)
		scanner, _ = h.scannerFactory.GetScanner(models.TaskSubfinder)
	}

	// Create appropriate input structure based on scanner type
	var scannerInput models.ScannerInput
	switch models.Task(taskMsg.Task) {
	case models.TaskSubfinder:
		scannerInput = models.SubfinderInput{Domain: result.Domain}
	case models.TaskHttpx:
		scannerInput = models.HttpxInput{Domain: result.Domain}
	case models.TaskDNSResolve:
		// For DNSX, we can process either a single domain or multiple subdomains
		// Use the utility function to properly parse subdomains from the input
		subdomains := utils.ReadSubdomainsFromString(result.Domain)

		dnsxInput := models.DNSXInput{
			Domain: result.Domain,
		}

		if len(subdomains) > 1 {
			// Multiple subdomains provided, use the first as the main domain
			dnsxInput.Domain = subdomains[0]
			dnsxInput.Subdomains = subdomains
		} else if len(subdomains) == 1 {
			// Single domain
			dnsxInput.Domain = subdomains[0]
		}

		gologger.Info().Msgf("DNSX input message: %+v", taskMsg)

		// Add hosts file location if provided in the task message
		if taskMsg.FilePath != "" {
			dnsxInput.HostsFileLocation = taskMsg.FilePath
			gologger.Info().Msgf("DNSX task with hosts file (file_path): %s", taskMsg.FilePath)
		} else {
			gologger.Info().Msgf("DNSX task without hosts file, domain: %s", result.Domain)
		}

		scannerInput = dnsxInput
	case models.TaskNaabu:
		// For Naabu port scanning
		naabuInput := models.NaabuInput{
			Domain: result.Domain,
		}

		// Add hosts file location if provided in the task message
		if taskMsg.FilePath != "" {
			naabuInput.HostsFileLocation = taskMsg.FilePath
			gologger.Info().Msgf("Naabu task with hosts file (file_path): %s", taskMsg.FilePath)
		} else {
			gologger.Info().Msgf("Naabu task without hosts file, domain: %s", result.Domain)
		}

		// Add naabu-specific parameters from config if provided
		if taskMsg.Config != nil {
			if topPorts, ok := taskMsg.Config["top_ports"]; ok && topPorts != "" {
				switch v := topPorts.(type) {
				case string:
					naabuInput.TopPorts = v
				case float64:
					// Convert numeric values to string format that naabu expects
					if v == 100 {
						naabuInput.TopPorts = "100"
					} else if v == 1000 {
						naabuInput.TopPorts = "1000"
					} else {
						gologger.Warning().Msgf("Invalid top_ports numeric value: %.0f (must be 100 or 1000), using default", v)
						naabuInput.TopPorts = "100" // Default fallback
					}
				case int:
					// Convert numeric values to string format that naabu expects
					if v == 100 {
						naabuInput.TopPorts = "100"
					} else if v == 1000 {
						naabuInput.TopPorts = "1000"
					} else {
						gologger.Warning().Msgf("Invalid top_ports numeric value: %d (must be 100 or 1000), using default", v)
						naabuInput.TopPorts = "100" // Default fallback
					}
				default:
					gologger.Warning().Msgf("Invalid top_ports type: %T, value: %v, using default", topPorts, topPorts)
					naabuInput.TopPorts = "100" // Default fallback
				}
				gologger.Info().Msgf("Naabu task with top ports: %s", naabuInput.TopPorts)
			}
			if ports, ok := taskMsg.Config["ports"].([]interface{}); ok && len(ports) > 0 {
				naabuInput.Ports = make([]int, len(ports))
				for i, port := range ports {
					if portNum, ok := port.(float64); ok {
						naabuInput.Ports[i] = int(portNum)
					}
				}
				gologger.Info().Msgf("Naabu task with specific ports: %v", naabuInput.Ports)
			}
			if portRange, ok := taskMsg.Config["port_range"].(string); ok && portRange != "" {
				naabuInput.PortRange = portRange
				gologger.Info().Msgf("Naabu task with port range: %s", portRange)
			}
			if rateLimit, ok := taskMsg.Config["rate_limit"].(float64); ok && rateLimit > 0 {
				naabuInput.RateLimit = int(rateLimit)
				gologger.Info().Msgf("Naabu task with rate limit: %d", naabuInput.RateLimit)
			}
			if concurrency, ok := taskMsg.Config["concurrency"].(float64); ok && concurrency > 0 {
				naabuInput.Concurrency = int(concurrency)
				gologger.Info().Msgf("Naabu task with concurrency: %d", naabuInput.Concurrency)
			}
			if timeout, ok := taskMsg.Config["timeout"].(float64); ok && timeout > 0 {
				naabuInput.Timeout = int(timeout)
				gologger.Info().Msgf("Naabu task with timeout: %d seconds", naabuInput.Timeout)
			}
		}

		scannerInput = naabuInput
	default:
		scannerInput = models.SubfinderInput{Domain: result.Domain}
	}

	// Validate input BEFORE executing
	if baseScanner := scanner.GetBaseScanner(); baseScanner != nil {
		if validator, ok := baseScanner.(interface {
			ValidateInput(models.ScannerInput) error
		}); ok {
			if err := validator.ValidateInput(scannerInput); err != nil {
				result.Status = models.TaskStatusFailed
				result.Error = fmt.Sprintf("invalid input: %v", err)
				gologger.Error().Msgf("Input validation failed for domain %s: %v", taskMsg.Domain, err)
				h.sendDiscordNotification(ctx, taskMsg, result, err, notification.StepTaskFailed)
				return h.createFailureResult(err, false)
			}
		}
	}

	scannerResult, err := scanner.Execute(scannerCtx, scannerInput)
	if err != nil {
		result.Status = models.TaskStatusFailed
		result.Error = err.Error()
		gologger.Error().Msgf("Task failed for domain %s: %v", taskMsg.Domain, err)

		h.sendDiscordNotification(ctx, taskMsg, result, err, notification.StepTaskFailed)

		retryable := h.errorClassifier.IsRetryableError(err)
		return h.createFailureResult(err, retryable)
	}

	result.Status = models.TaskStatusCompleted
	result.Data = scannerResult
	gologger.Info().Msgf("Task completed successfully for domain: %s using %s, found %d results",
		taskMsg.Domain, scanner.GetName(), scannerResult.GetCount())

	h.sendDiscordNotification(ctx, taskMsg, result, nil, notification.StepTaskCompleted)
	return &models.MessageProcessingResult{Success: true}
}

// finalizeTask stores the result and sends completion notifications
func (h *TaskHandler) finalizeTask(ctx context.Context, taskMsg *models.TaskMessage, result *models.TaskResult) *models.MessageProcessingResult {
	// Log the task duration
	gologger.Info().Msgf("Task %s for domain %s completed in %s", taskMsg.Task, taskMsg.Domain, result.Duration)

	// For subfinder, only store as text file, not JSON
	if result.Task == models.TaskSubfinder {
		if subfinderResult, ok := result.Data.(models.SubfinderResult); ok {
			err := h.blobClient.StoreSubfinderTextResult(ctx, &subfinderResult, result.ScanID, string(result.Task))
			if err != nil {
				gologger.Error().Msgf("Failed to store subfinder txt result for domain %s: %v", taskMsg.Domain, err)
				return h.createFailureResult(err, true) // Storage errors are usually retryable
			}
			gologger.Info().Msgf("Stored subfinder text result for domain %s", taskMsg.Domain)
		}
	} else {
		// For other tasks, store as JSON
		if storeErr := h.blobClient.StoreTaskResult(ctx, result); storeErr != nil {
			gologger.Error().Msgf("Failed to store task result for domain %s: %v", taskMsg.Domain, storeErr)
			return h.createFailureResult(storeErr, true) // Storage errors are usually retryable
		}
	}

	h.sendDiscordNotification(ctx, taskMsg, result, nil, notification.StepResultStored)

	// Send completion notification if enabled
	if h.notifier != nil {
		if notifyErr := h.sendCompletionNotification(ctx, taskMsg, result); notifyErr != nil {
			gologger.Warning().Msgf("Failed to send completion notification for domain %s: %v", taskMsg.Domain, notifyErr)
		} else {
			h.sendDiscordNotification(ctx, taskMsg, result, nil, notification.StepNotificationSent)
		}
	}

	return &models.MessageProcessingResult{Success: true}
}

// sendDiscordNotification sends a Discord notification for a specific step
func (h *TaskHandler) sendDiscordNotification(ctx context.Context, taskMsg *models.TaskMessage, result *models.TaskResult, err error, step notification.NotificationStep) {
	if h.discordNotifier == nil {
		return
	}

	if notifyErr := h.discordNotifier.NotifyStep(ctx, step, taskMsg, result, err); notifyErr != nil {
		gologger.Warning().Msgf("Failed to send Discord notification for step %s: %v", step, notifyErr)
	}
}

// createFailureResult creates a failure result with the given error and retryable flag
func (h *TaskHandler) createFailureResult(err error, retryable bool) *models.MessageProcessingResult {
	return &models.MessageProcessingResult{
		Success:   false,
		Error:     err,
		Retryable: retryable,
	}
}

// sendCompletionNotification sends a completion notification to the Azure Function orchestrator
func (h *TaskHandler) sendCompletionNotification(ctx context.Context, taskMsg *models.TaskMessage, result *models.TaskResult) error {
	if taskMsg.InstanceID == "" {
		return fmt.Errorf("instance_id is required for notification")
	}

	toolName := string(taskMsg.Task)
	gologger.Info().Msgf("Sending completion notification for task %s, domain %s, instance %s", toolName, taskMsg.Domain, taskMsg.InstanceID)

	return h.notifier.NotifyCompletionWithRetry(ctx, taskMsg.InstanceID, toolName, result)
}
