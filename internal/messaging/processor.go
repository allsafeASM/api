package messaging

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/messaging/azservicebus"
	"github.com/allsafeASM/api/internal/models"
	"github.com/projectdiscovery/gologger"
)

// MessageProcessor handles message processing logic
type MessageProcessor struct {
	receiver *azservicebus.Receiver
}

// NewMessageProcessor creates a new message processor
func NewMessageProcessor(receiver *azservicebus.Receiver) *MessageProcessor {
	return &MessageProcessor{
		receiver: receiver,
	}
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
	// Parse the message first
	var taskMsg models.TaskMessage
	if err := json.Unmarshal(message.Body, &taskMsg); err != nil {
		return &models.MessageProcessingResult{
			Success:   false,
			Error:     fmt.Errorf("failed to parse message as JSON: %w", err),
			Retryable: false,
		}
	}

	// Create a channel to signal completion
	done := make(chan *models.MessageProcessingResult, 1)

	// Start the handler in a goroutine
	go func() {
		result := handler(ctx, &taskMsg)
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
				if err := p.receiver.RenewMessageLock(ctx, message, nil); err != nil {
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
