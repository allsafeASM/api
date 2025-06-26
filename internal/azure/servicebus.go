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

// MessageProcessingResult represents the result of processing a message
type MessageProcessingResult struct {
	Success bool
	Error   error
	// Retryable indicates if the error is transient and should be retried
	Retryable bool
	// RetryCount is the number of times this message has been retried
	RetryCount int
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
func (s *ServiceBusClient) ProcessMessages(ctx context.Context, handler func(context.Context, *models.TaskMessage) *MessageProcessingResult, pollInterval time.Duration) error {
	receiver, err := s.client.NewReceiverForQueue(s.queueName, nil)
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
				if deadLetterErr := s.DeadLetterMessage(ctx, message, "InvalidMessageFormat", fmt.Sprintf("Failed to parse JSON: %v", err)); deadLetterErr != nil {
					gologger.Error().Msgf("Failed to move message to dead letter queue: %v", deadLetterErr)
				}
				continue
			}

			// Process the message with retry logic
			result := s.processMessageWithRetry(ctx, &taskMsg, handler, message)

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

// processMessageWithRetry processes a message with retry logic
func (s *ServiceBusClient) processMessageWithRetry(ctx context.Context, taskMsg *models.TaskMessage, handler func(context.Context, *models.TaskMessage) *MessageProcessingResult, message *azservicebus.ReceivedMessage) *MessageProcessingResult {
	maxRetries := 3
	baseDelay := 1 * time.Second

	for attempt := 0; attempt <= maxRetries; attempt++ {
		// Check if context is cancelled
		select {
		case <-ctx.Done():
			return &MessageProcessingResult{
				Success:    false,
				Error:      ctx.Err(),
				Retryable:  false,
				RetryCount: attempt,
			}
		default:
		}

		// Process the message
		result := handler(ctx, taskMsg)
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
			return &MessageProcessingResult{
				Success:    false,
				Error:      ctx.Err(),
				Retryable:  false,
				RetryCount: attempt,
			}
		case <-time.After(delay):
			continue
		}
	}

	return &MessageProcessingResult{
		Success:    false,
		Error:      fmt.Errorf("max retries exceeded"),
		Retryable:  false,
		RetryCount: maxRetries,
	}
}
