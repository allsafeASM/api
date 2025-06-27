package config

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
	if c.ServiceBusConnectionString == "" {
		return &ConfigError{Field: "SERVICEBUS_CONNECTION_STRING", Message: "Service Bus connection string is required"}
	}
	if c.BlobStorageConnectionString == "" {
		return &ConfigError{Field: "BLOB_STORAGE_CONNECTION_STRING", Message: "Blob Storage connection string is required"}
	}
	return nil
}
