package config

import (
	"os"
	"strconv"
)

// Config holds all configuration for the application
type Config struct {
	Azure AzureConfig
	App   AppConfig
}

// AzureConfig holds Azure-specific configuration
type AzureConfig struct {
	ServiceBusConnectionString  string
	ServiceBusNamespace         string
	QueueName                   string
	BlobStorageConnectionString string
	BlobContainerName           string
}

// AppConfig holds application-specific configuration
type AppConfig struct {
	LogLevel       string
	PollInterval   int // seconds
	ScannerTimeout int // seconds
}

// Load loads configuration from environment variables
func Load() *Config {
	return &Config{
		Azure: AzureConfig{
			ServiceBusConnectionString:  getEnv("SERVICEBUS_CONNECTION_STRING", ""),
			ServiceBusNamespace:         getEnv("SERVICEBUS_NAMESPACE", "asm-queue"),
			QueueName:                   getEnv("SERVICEBUS_QUEUE_NAME", "tasks"),
			BlobStorageConnectionString: getEnv("BLOB_STORAGE_CONNECTION_STRING", ""),
			BlobContainerName:           getEnv("BLOB_CONTAINER_NAME", "scan-outputs"),
		},
		App: AppConfig{
			LogLevel:       getEnv("LOG_LEVEL", "info"),
			PollInterval:   getEnvAsInt("POLL_INTERVAL", 2),
			ScannerTimeout: getEnvAsInt("SCANNER_TIMEOUT", 60), // 1 hour
		},
	}
}

// Validate checks if required configuration is present
func (c *Config) Validate() error {
	if c.Azure.ServiceBusConnectionString == "" {
		return &ConfigError{Field: "SERVICEBUS_CONNECTION_STRING", Message: "Service Bus connection string is required"}
	}
	if c.Azure.BlobStorageConnectionString == "" {
		return &ConfigError{Field: "BLOB_STORAGE_CONNECTION_STRING", Message: "Blob Storage connection string is required"}
	}
	return nil
}

// ConfigError represents a configuration error
type ConfigError struct {
	Field   string
	Message string
}

func (e *ConfigError) Error() string {
	return e.Message
}

// Helper functions
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvAsInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intValue, err := strconv.Atoi(value); err == nil {
			return intValue
		}
	}
	return defaultValue
}
