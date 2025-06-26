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
func (s *ServiceBusClient) ProcessMessages(ctx context.Context, handler func(context.Context, *models.TaskMessage) error, pollInterval time.Duration) error {
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
				receiver.CompleteMessage(ctx, message, nil)
				continue
			}

			// Handle the message
			if err := handler(ctx, &taskMsg); err != nil {
				gologger.Error().Msgf("Failed to handle message: %v", err)
			}

			// Complete the message
			if err := receiver.CompleteMessage(ctx, message, nil); err != nil {
				gologger.Error().Msgf("Failed to complete message: %v", err)
			}
		}
	}
}
