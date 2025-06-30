package config

import (
	"fmt"
	"strings"
)

// AzureConfig holds Azure-specific configuration
type AzureConfig struct {
	ServiceBusConnectionString  string
	ServiceBusNamespace         string
	QueueName                   string
	BlobStorageConnectionString string
	BlobContainerName           string
}

// LoadAzureConfig loads Azure configuration from environment variables
func LoadAzureConfig() AzureConfig {
	return AzureConfig{
		ServiceBusConnectionString:  getEnv("SERVICEBUS_CONNECTION_STRING", ""),
		ServiceBusNamespace:         getEnv("SERVICEBUS_NAMESPACE", "asm-queue"),
		QueueName:                   getEnv("SERVICEBUS_QUEUE_NAME", "tasks"),
		BlobStorageConnectionString: getEnv("BLOB_STORAGE_CONNECTION_STRING", ""),
		BlobContainerName:           getEnv("BLOB_CONTAINER_NAME", "scans"),
	}
}

// ValidateAzureConfig validates Azure-specific configuration
func (c *AzureConfig) ValidateAzureConfig() error {
	validations := []struct {
		field   string
		value   string
		message string
	}{
		{"SERVICEBUS_CONNECTION_STRING", c.ServiceBusConnectionString, "Service Bus connection string is required"},
		{"BLOB_STORAGE_CONNECTION_STRING", c.BlobStorageConnectionString, "Blob Storage connection string is required"},
	}

	for _, v := range validations {
		if err := validateRequiredField(v.field, v.value, v.message); err != nil {
			return err
		}
	}

	if err := validateServiceBusNamespace(c.ServiceBusNamespace); err != nil {
		return err
	}

	if err := validateQueueName(c.QueueName); err != nil {
		return err
	}

	if err := validateContainerName(c.BlobContainerName); err != nil {
		return err
	}

	return nil
}

// validateRequiredField validates that a required field is not empty
func validateRequiredField(field, value, message string) error {
	if strings.TrimSpace(value) == "" {
		return &ConfigError{
			Field:   field,
			Message: message,
		}
	}
	return nil
}

// validateServiceBusNamespace validates the Service Bus namespace
func validateServiceBusNamespace(namespace string) error {
	if strings.TrimSpace(namespace) == "" {
		return &ConfigError{
			Field:   "SERVICEBUS_NAMESPACE",
			Message: "Service Bus namespace cannot be empty",
		}
	}

	// Basic validation for namespace format
	if len(namespace) < 6 || len(namespace) > 50 {
		return &ConfigError{
			Field:   "SERVICEBUS_NAMESPACE",
			Message: "Service Bus namespace must be between 6 and 50 characters",
		}
	}

	// Check for valid characters (alphanumeric and hyphens only)
	for _, char := range namespace {
		if !isValidNamespaceChar(char) {
			return &ConfigError{
				Field:   "SERVICEBUS_NAMESPACE",
				Message: fmt.Sprintf("Service Bus namespace contains invalid character '%c'. Only alphanumeric characters and hyphens are allowed", char),
			}
		}
	}

	return nil
}

// validateQueueName validates the queue name
func validateQueueName(queueName string) error {
	if strings.TrimSpace(queueName) == "" {
		return &ConfigError{
			Field:   "SERVICEBUS_QUEUE_NAME",
			Message: "Queue name cannot be empty",
		}
	}

	// Basic validation for queue name format
	if len(queueName) < 1 || len(queueName) > 260 {
		return &ConfigError{
			Field:   "SERVICEBUS_QUEUE_NAME",
			Message: "Queue name must be between 1 and 260 characters",
		}
	}

	return nil
}

// validateContainerName validates the blob container name
func validateContainerName(containerName string) error {
	if strings.TrimSpace(containerName) == "" {
		return &ConfigError{
			Field:   "BLOB_CONTAINER_NAME",
			Message: "Blob container name cannot be empty",
		}
	}

	// Basic validation for container name format
	if len(containerName) < 3 || len(containerName) > 63 {
		return &ConfigError{
			Field:   "BLOB_CONTAINER_NAME",
			Message: "Blob container name must be between 3 and 63 characters",
		}
	}

	// Check for valid characters (lowercase letters, numbers, and hyphens only)
	for _, char := range containerName {
		if !isValidContainerChar(char) {
			return &ConfigError{
				Field:   "BLOB_CONTAINER_NAME",
				Message: fmt.Sprintf("Blob container name contains invalid character '%c'. Only lowercase letters, numbers, and hyphens are allowed", char),
			}
		}
	}

	// Container name cannot start or end with hyphen
	if strings.HasPrefix(containerName, "-") || strings.HasSuffix(containerName, "-") {
		return &ConfigError{
			Field:   "BLOB_CONTAINER_NAME",
			Message: "Blob container name cannot start or end with a hyphen",
		}
	}

	return nil
}

// isValidNamespaceChar checks if a character is valid for a Service Bus namespace
func isValidNamespaceChar(char rune) bool {
	return (char >= 'a' && char <= 'z') ||
		(char >= 'A' && char <= 'Z') ||
		(char >= '0' && char <= '9') ||
		char == '-'
}

// isValidContainerChar checks if a character is valid for a blob container name
func isValidContainerChar(char rune) bool {
	return (char >= 'a' && char <= 'z') ||
		(char >= '0' && char <= '9') ||
		char == '-'
}
