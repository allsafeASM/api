package azure

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/messaging/azservicebus"
	"github.com/allsafeASM/api/internal/models"
	"github.com/projectdiscovery/gologger"
)

// ServiceBusClient wraps Azure Service Bus operations
type ServiceBusClient struct {
	client    *azservicebus.Client
	queueName string
}

// NewServiceBusClient creates a new Service Bus client
func NewServiceBusClient(connectionString, queueName string) (*ServiceBusClient, error) {
	client, err := azservicebus.NewClientFromConnectionString(connectionString, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create service bus client: %w", err)
	}

	return &ServiceBusClient{
		client:    client,
		queueName: queueName,
	}, nil
}

// Close closes the Service Bus client
func (s *ServiceBusClient) Close(ctx context.Context) error {
	return s.client.Close(ctx)
}

// ReceiveMessages receives messages from the queue
func (s *ServiceBusClient) ReceiveMessages(ctx context.Context, maxMessages int) ([]*azservicebus.ReceivedMessage, error) {
	receiver, err := s.client.NewReceiverForQueue(s.queueName, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create receiver: %w", err)
	}
	defer receiver.Close(ctx)

	messages, err := receiver.ReceiveMessages(ctx, maxMessages, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to receive messages: %w", err)
	}

	return messages, nil
}

// CompleteMessage completes a message to remove it from the queue
func (s *ServiceBusClient) CompleteMessage(ctx context.Context, message *azservicebus.ReceivedMessage) error {
	receiver, err := s.client.NewReceiverForQueue(s.queueName, nil)
	if err != nil {
		return fmt.Errorf("failed to create receiver: %w", err)
	}
	defer receiver.Close(ctx)

	return receiver.CompleteMessage(ctx, message, nil)
}

// AbandonMessage abandons a message for retry
func (s *ServiceBusClient) AbandonMessage(ctx context.Context, message *azservicebus.ReceivedMessage, properties map[string]interface{}) error {
	receiver, err := s.client.NewReceiverForQueue(s.queueName, nil)
	if err != nil {
		return fmt.Errorf("failed to create receiver: %w", err)
	}
	defer receiver.Close(ctx)

	return receiver.AbandonMessage(ctx, message, &azservicebus.AbandonMessageOptions{
		PropertiesToModify: properties,
	})
}

// DeadLetterMessage moves a message to the dead letter queue
func (s *ServiceBusClient) DeadLetterMessage(ctx context.Context, message *azservicebus.ReceivedMessage, reason string, description string) error {
	receiver, err := s.client.NewReceiverForQueue(s.queueName, nil)
	if err != nil {
		return fmt.Errorf("failed to create receiver: %w", err)
	}
	defer receiver.Close(ctx)

	return receiver.DeadLetterMessage(ctx, message, &azservicebus.DeadLetterOptions{
		Reason:           &reason,
		ErrorDescription: &description,
	})
}

// SendMessage sends a message to the queue
func (s *ServiceBusClient) SendMessage(ctx context.Context, message interface{}) error {
	sender, err := s.client.NewSender(s.queueName, nil)
	if err != nil {
		return fmt.Errorf("failed to create sender: %w", err)
	}
	defer sender.Close(ctx)

	messageBytes, err := json.Marshal(message)
	if err != nil {
		return fmt.Errorf("failed to marshal message: %w", err)
	}

	sbMessage := &azservicebus.Message{
		Body: messageBytes,
	}

	return sender.SendMessage(ctx, sbMessage, nil)
}

// ProcessMessages processes messages from the queue with a handler function
func (s *ServiceBusClient) ProcessMessages(ctx context.Context, handler func(context.Context, *models.TaskMessage) *models.MessageProcessingResult, pollInterval time.Duration, lockRenewalInterval time.Duration, maxLockRenewalTime time.Duration, scannerTimeout time.Duration) error {
	// Create receiver with AutoRenewTimeout for automatic lock renewal
	receiver, err := s.client.NewReceiverForQueue(s.queueName, &azservicebus.ReceiverOptions{
		ReceiveMode: azservicebus.ReceiveModePeekLock,
	})
	if err != nil {
		return fmt.Errorf("failed to create receiver: %w", err)
	}
	defer receiver.Close(ctx)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			messages, err := receiver.ReceiveMessages(ctx, 1, nil)
			if err != nil {
				gologger.Error().Msgf("Failed to receive messages: %v", err)
				time.Sleep(pollInterval)
				continue
			}

			if len(messages) == 0 {
				time.Sleep(pollInterval)
				continue
			}

			message := messages[0]
			gologger.Info().Msgf("Received message: %s", string(message.Body))

			// Parse the message
			var taskMsg models.TaskMessage
			if err := json.Unmarshal(message.Body, &taskMsg); err != nil {
				gologger.Error().Msgf("Failed to parse message as JSON: %v", err)
				// This is a permanent error - move to dead letter queue
				if deadLetterErr := receiver.DeadLetterMessage(ctx, message, &azservicebus.DeadLetterOptions{
					Reason:           &[]string{"InvalidMessageFormat"}[0],
					ErrorDescription: &[]string{fmt.Sprintf("Failed to parse JSON: %v", err)}[0],
				}); deadLetterErr != nil {
					gologger.Error().Msgf("Failed to move message to dead letter queue: %v", deadLetterErr)
				}
				continue
			}

			// Process the message with retry logic and auto-renewal
			result := s.processMessageWithRetryAndRenewal(ctx, &taskMsg, handler, message, receiver, lockRenewalInterval, maxLockRenewalTime, scannerTimeout)

			// Handle the result
			if result.Success {
				// Message processed successfully - complete it
				if err := receiver.CompleteMessage(ctx, message, nil); err != nil {
					gologger.Error().Msgf("Failed to complete message: %v", err)
				} else {
					gologger.Info().Msg("Message completed successfully")
				}
			} else {
				// Message processing failed
				if result.Retryable && result.RetryCount < 3 {
					// Retryable error with retries remaining - abandon for retry
					retryCount := result.RetryCount + 1
					properties := map[string]interface{}{
						"RetryCount": retryCount,
						"LastError":  result.Error.Error(),
					}

					if abandonErr := receiver.AbandonMessage(ctx, message, &azservicebus.AbandonMessageOptions{
						PropertiesToModify: properties,
					}); abandonErr != nil {
						gologger.Error().Msgf("Failed to abandon message: %v", abandonErr)
					} else {
						gologger.Warning().Msgf("Message abandoned for retry (attempt %d/%d): %v", retryCount, 3, result.Error)
					}
				} else {
					// Non-retryable error or max retries exceeded - move to dead letter queue
					reason := "ProcessingFailed"
					description := fmt.Sprintf("Failed after %d attempts: %v", result.RetryCount+1, result.Error)

					if deadLetterErr := receiver.DeadLetterMessage(ctx, message, &azservicebus.DeadLetterOptions{
						Reason:           &reason,
						ErrorDescription: &description,
					}); deadLetterErr != nil {
						gologger.Error().Msgf("Failed to move message to dead letter queue: %v", deadLetterErr)
					} else {
						gologger.Error().Msgf("Message moved to dead letter queue: %v", result.Error)
					}
				}
			}
		}
	}
}

// processMessageWithRetryAndRenewal processes a message with retry logic and auto-renewal
func (s *ServiceBusClient) processMessageWithRetryAndRenewal(ctx context.Context, taskMsg *models.TaskMessage, handler func(context.Context, *models.TaskMessage) *models.MessageProcessingResult, message *azservicebus.ReceivedMessage, receiver *azservicebus.Receiver, lockRenewalInterval time.Duration, maxLockRenewalTime time.Duration, scannerTimeout time.Duration) *models.MessageProcessingResult {
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
		handlerCtx, cancel := context.WithTimeout(ctx, scannerTimeout) // Use configurable scanner timeout

		// Process the message with auto-renewal
		result := s.processMessageWithRenewal(handlerCtx, taskMsg, handler, message, receiver, lockRenewalInterval, maxLockRenewalTime)
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
func (s *ServiceBusClient) processMessageWithRenewal(ctx context.Context, taskMsg *models.TaskMessage, handler func(context.Context, *models.TaskMessage) *models.MessageProcessingResult, message *azservicebus.ReceivedMessage, receiver *azservicebus.Receiver, lockRenewalInterval time.Duration, maxLockRenewalTime time.Duration) *models.MessageProcessingResult {
	// Create a channel to signal completion
	done := make(chan *models.MessageProcessingResult, 1)

	// Start the handler in a goroutine
	go func() {
		result := handler(ctx, taskMsg)
		done <- result
	}()

	// Start lock renewal goroutine with maximum time limit
	renewalCtx, cancelRenewal := context.WithTimeout(context.Background(), maxLockRenewalTime)
	defer cancelRenewal()

	go func() {
		ticker := time.NewTicker(lockRenewalInterval)
		defer ticker.Stop()

		for {
			select {
			case <-renewalCtx.Done():
				gologger.Debug().Msg("Lock renewal stopped due to timeout or cancellation")
				return
			case <-ticker.C:
				// Renew the message lock
				if err := receiver.RenewMessageLock(ctx, message, nil); err != nil {
					gologger.Warning().Msgf("Failed to renew message lock: %v", err)
					// If renewal fails, we should stop processing
					cancelRenewal()
					return
				}
				gologger.Debug().Msg("Message lock renewed successfully")
			}
		}
	}()

	// Wait for either completion or context cancellation
	select {
	case <-ctx.Done():
		cancelRenewal()
		return &models.MessageProcessingResult{
			Success:   false,
			Error:     ctx.Err(),
			Retryable: true, // Context cancellation is usually retryable
		}
	case result := <-done:
		cancelRenewal()
		return result
	}
}
