package azure

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/messaging/azservicebus"
	"github.com/allsafeASM/api/internal/models"
	"github.com/projectdiscovery/gologger"
)

// ServiceBusClient handles Azure Service Bus operations
type ServiceBusClient struct {
	client   *azservicebus.Client
	queue    string
	receiver *azservicebus.Receiver
}

// NewServiceBusClient creates a new Service Bus client
func NewServiceBusClient(connectionString, queueName string) (*ServiceBusClient, error) {
	// Create client with options for better resilience
	client, err := azservicebus.NewClientFromConnectionString(connectionString, &azservicebus.ClientOptions{
		RetryOptions: azservicebus.RetryOptions{
			MaxRetries:    3,
			RetryDelay:    1 * time.Second,
			MaxRetryDelay: 30 * time.Second,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create Service Bus client: %w", err)
	}

	// Create receiver with options for better performance
	receiver, err := client.NewReceiverForQueue(queueName, &azservicebus.ReceiverOptions{
		ReceiveMode: azservicebus.ReceiveModePeekLock,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create receiver: %w", err)
	}

	return &ServiceBusClient{
		client:   client,
		queue:    queueName,
		receiver: receiver,
	}, nil
}

// Close closes the Service Bus client
func (s *ServiceBusClient) Close(ctx context.Context) error {
	if s.receiver != nil {
		if err := s.receiver.Close(ctx); err != nil {
			return fmt.Errorf("failed to close receiver: %w", err)
		}
	}
	if s.client != nil {
		if err := s.client.Close(ctx); err != nil {
			return fmt.Errorf("failed to close client: %w", err)
		}
	}
	return nil
}

// HealthCheck verifies the Service Bus connection is working
func (s *ServiceBusClient) HealthCheck(ctx context.Context) error {
	// Try to get the receiver to test the connection
	receiver, err := s.client.NewReceiverForQueue(s.queue, nil)
	if err != nil {
		return fmt.Errorf("failed to create receiver for health check: %w", err)
	}
	defer receiver.Close(ctx)

	gologger.Debug().Msg("Service Bus health check passed - connection is working")
	return nil
}

// ProcessMessages continuously processes messages from the queue
func (s *ServiceBusClient) ProcessMessages(ctx context.Context, handler func(context.Context, *models.TaskMessage) *models.MessageProcessingResult, pollInterval time.Duration, lockRenewalInterval time.Duration, maxLockRenewalTime time.Duration, scannerTimeout time.Duration) error {
	gologger.Info().Msg("Starting message processing loop")

	for {
		select {
		case <-ctx.Done():
			gologger.Info().Msg("Message processing stopped due to context cancellation")
			return nil
		default:
		}

		// Process next message
		err := s.processNextMessage(ctx, s.receiver, handler, pollInterval, lockRenewalInterval, maxLockRenewalTime, scannerTimeout)
		if err != nil {
			gologger.Error().Msgf("Error processing message: %v", err)
			// Continue processing other messages
		}
	}
}

// isTimeoutError checks if an error is a timeout error
func (s *ServiceBusClient) isTimeoutError(err error) bool {
	return err != nil && (strings.Contains(err.Error(), "context deadline exceeded") ||
		strings.Contains(err.Error(), "timeout"))
}

// processNextMessage processes the next message from the queue
func (s *ServiceBusClient) processNextMessage(ctx context.Context, receiver *azservicebus.Receiver, handler func(context.Context, *models.TaskMessage) *models.MessageProcessingResult, pollInterval time.Duration, lockRenewalInterval time.Duration, maxLockRenewalTime time.Duration, scannerTimeout time.Duration) error {
	// Set receive timeout to poll interval
	receiveTimeout := pollInterval
	if receiveTimeout < time.Second {
		receiveTimeout = time.Second
	}

	// Receive message with timeout
	receiveCtx, cancel := context.WithTimeout(ctx, receiveTimeout)
	defer cancel()

	messages, err := receiver.ReceiveMessages(receiveCtx, 1, nil)
	if err != nil {
		if s.isTimeoutError(err) {
			gologger.Debug().Msgf("Receive timeout after %v - this is normal when no messages are available", receiveTimeout)
			return nil
		}
		return fmt.Errorf("failed to receive message: %w", err)
	}

	if len(messages) == 0 {
		return nil
	}

	message := messages[0]

	gologger.Debug().Msgf("Received message: %s", message.MessageID)

	// Create message processor and handle the message
	processor := s.newMessageProcessor(receiver)
	result := processor.ProcessMessage(ctx, message, handler, lockRenewalInterval, maxLockRenewalTime, scannerTimeout)

	// Handle the result
	return s.handleMessageResult(ctx, receiver, message, result)
}

// newMessageProcessor creates a new message processor
func (s *ServiceBusClient) newMessageProcessor(receiver *azservicebus.Receiver) *MessageProcessor {
	return &MessageProcessor{
		receiver: receiver,
	}
}

// handleMessageResult handles the result of message processing
func (s *ServiceBusClient) handleMessageResult(ctx context.Context, receiver *azservicebus.Receiver, message *azservicebus.ReceivedMessage, result *models.MessageProcessingResult) error {
	if result.Success {
		// Complete the message
		err := receiver.CompleteMessage(ctx, message, nil)
		if err != nil {
			return fmt.Errorf("failed to complete message: %w", err)
		}
		gologger.Debug().Msgf("Message completed successfully: %s", message.MessageID)
		return nil
	}

	// Handle failure
	if s.shouldRetryMessage(result) {
		// Abandon the message for retry
		err := receiver.AbandonMessage(ctx, message, nil)
		if err != nil {
			return fmt.Errorf("failed to abandon message: %w", err)
		}
		gologger.Warning().Msgf("Message abandoned for retry: %s, error: %v", message.MessageID, result.Error)
		return nil
	}

	// Dead letter the message
	err := receiver.DeadLetterMessage(ctx, message, nil)
	if err != nil {
		return fmt.Errorf("failed to dead letter message: %w", err)
	}
	gologger.Error().Msgf("Message dead lettered: %s, error: %v", message.MessageID, result.Error)
	return nil
}

// shouldRetryMessage determines if a message should be retried
func (s *ServiceBusClient) shouldRetryMessage(result *models.MessageProcessingResult) bool {
	return result.Retryable && result.RetryCount < 3
}

// MessageProcessor handles message processing logic
type MessageProcessor struct {
	receiver *azservicebus.Receiver
}

// ProcessMessage processes a single message with retry logic and auto-renewal
func (p *MessageProcessor) ProcessMessage(ctx context.Context, message *azservicebus.ReceivedMessage, handler func(context.Context, *models.TaskMessage) *models.MessageProcessingResult, lockRenewalInterval time.Duration, maxLockRenewalTime time.Duration, scannerTimeout time.Duration) *models.MessageProcessingResult {
	maxRetries := 3
	baseDelay := 1 * time.Second

	for attempt := 0; attempt <= maxRetries; attempt++ {
		// Check if context is cancelled
		select {
		case <-ctx.Done():
			return &models.MessageProcessingResult{
				Success:    false,
				Error:      ctx.Err(),
				Retryable:  false,
				RetryCount: attempt,
			}
		default:
		}

		// Create a context with timeout for the handler
		handlerCtx, cancel := context.WithTimeout(ctx, scannerTimeout)

		// Process the message with auto-renewal
		result := p.processMessageWithRenewal(handlerCtx, message, handler, lockRenewalInterval, maxLockRenewalTime)
		cancel()

		result.RetryCount = attempt

		if result.Success {
			return result
		}

		// If not retryable or max retries reached, return the result
		if !result.Retryable || attempt == maxRetries {
			return result
		}

		// Calculate exponential backoff delay
		delay := time.Duration(baseDelay.Nanoseconds() * int64(1<<attempt))
		gologger.Warning().Msgf("Processing failed (attempt %d/%d), retrying in %v: %v", attempt+1, maxRetries+1, delay, result.Error)

		// Wait before retry
		select {
		case <-ctx.Done():
			return &models.MessageProcessingResult{
				Success:    false,
				Error:      ctx.Err(),
				Retryable:  false,
				RetryCount: attempt,
			}
		case <-time.After(delay):
			continue
		}
	}

	return &models.MessageProcessingResult{
		Success:    false,
		Error:      fmt.Errorf("max retries exceeded"),
		Retryable:  false,
		RetryCount: maxRetries,
	}
}

// processMessageWithRenewal processes a message with automatic lock renewal
func (p *MessageProcessor) processMessageWithRenewal(ctx context.Context, message *azservicebus.ReceivedMessage, handler func(context.Context, *models.TaskMessage) *models.MessageProcessingResult, lockRenewalInterval time.Duration, maxLockRenewalTime time.Duration) *models.MessageProcessingResult {
	// Validate lock renewal interval (should be at least 1 second to avoid overwhelming the service)
	if lockRenewalInterval < time.Second {
		gologger.Warning().Msgf("Lock renewal interval too short (%v), using minimum of 1 second", lockRenewalInterval)
		lockRenewalInterval = time.Second
	}

	// Parse the message first
	var taskMsg models.TaskMessage
	if err := json.Unmarshal(message.Body, &taskMsg); err != nil {
		return &models.MessageProcessingResult{
			Success:   false,
			Error:     fmt.Errorf("failed to parse message as JSON: %w", err),
			Retryable: false,
		}
	}

	// Create a context with timeout for the entire operation
	operationCtx, cancelOperation := context.WithTimeout(ctx, maxLockRenewalTime)
	defer cancelOperation()

	// Create a channel to signal completion
	done := make(chan *models.MessageProcessingResult, 1)
	renewalError := make(chan error, 1)

	// Start the handler in a goroutine
	go func() {
		result := handler(operationCtx, &taskMsg)
		done <- result
	}()

	// Start lock renewal goroutine
	go func() {
		ticker := time.NewTicker(lockRenewalInterval)
		defer ticker.Stop()

		// Renew lock immediately after receiving the message
		if err := p.receiver.RenewMessageLock(operationCtx, message, nil); err != nil {
			gologger.Warning().Msgf("Failed to renew message lock initially: %v", err)
			renewalError <- err
			return
		}
		gologger.Debug().Msg("Initial message lock renewal successful")

		for {
			select {
			case <-operationCtx.Done():
				gologger.Debug().Msg("Lock renewal stopped due to operation completion or cancellation")
				return
			case <-ticker.C:
				// Renew the message lock
				if err := p.receiver.RenewMessageLock(operationCtx, message, nil); err != nil {
					gologger.Warning().Msgf("Failed to renew message lock: %v", err)
					renewalError <- err
					return
				}
				gologger.Debug().Msg("Message lock renewed successfully")
			}
		}
	}()

	// Wait for either completion, context cancellation, or renewal error
	select {
	case <-operationCtx.Done():
		return &models.MessageProcessingResult{
			Success:   false,
			Error:     operationCtx.Err(),
			Retryable: true, // Context cancellation is usually retryable
		}
	case err := <-renewalError:
		// Cancel the operation if lock renewal fails
		cancelOperation()
		return &models.MessageProcessingResult{
			Success:   false,
			Error:     fmt.Errorf("lock renewal failed: %w", err),
			Retryable: true, // Lock renewal failures are usually retryable
		}
	case result := <-done:
		return result
	}
}
