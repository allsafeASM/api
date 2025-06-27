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

// AppConfig holds application-specific configuration
type AppConfig struct {
	LogLevel            string
	PollInterval        int // seconds
	ScannerTimeout      int // seconds
	LockRenewalInterval int // seconds - how often to renew message locks
	MaxLockRenewalTime  int // seconds - maximum time to keep renewing locks
	// Notification settings
	EnableNotifications bool
	NotificationTimeout int // seconds - timeout for notification requests
}

// Load loads configuration from environment variables
func Load() *Config {
	return &Config{
		Azure: LoadAzureConfig(),
		App: AppConfig{
			LogLevel:            getEnv("LOG_LEVEL", "info"),
			PollInterval:        getEnvAsInt("POLL_INTERVAL", 2),
			ScannerTimeout:      getEnvAsInt("SCANNER_TIMEOUT", 60*60),      // 1 hour
			LockRenewalInterval: getEnvAsInt("LOCK_RENEWAL_INTERVAL", 30),   // 30 seconds
			MaxLockRenewalTime:  getEnvAsInt("MAX_LOCK_RENEWAL_TIME", 3600), // 1 hour
			EnableNotifications: getEnvAsBool("ENABLE_NOTIFICATIONS", true),
			NotificationTimeout: getEnvAsInt("NOTIFICATION_TIMEOUT", 30), // 30 seconds
		},
	}
}

// Validate checks if required configuration is present
func (c *Config) Validate() error {
	if err := c.Azure.ValidateAzureConfig(); err != nil {
		return err
	}

	// Validate timeout values
	if c.App.ScannerTimeout < 30 || c.App.ScannerTimeout > 7200 {
		return &ConfigError{Field: "SCANNER_TIMEOUT", Message: "Scanner timeout must be between 30 and 7200 seconds"}
	}

	if c.App.PollInterval < 1 || c.App.PollInterval > 60 {
		return &ConfigError{Field: "POLL_INTERVAL", Message: "Poll interval must be between 1 and 60 seconds"}
	}

	// Validate lock renewal values
	if c.App.LockRenewalInterval < 10 || c.App.LockRenewalInterval > 300 {
		return &ConfigError{Field: "LOCK_RENEWAL_INTERVAL", Message: "Lock renewal interval must be between 10 and 300 seconds"}
	}

	if c.App.MaxLockRenewalTime < 60 || c.App.MaxLockRenewalTime > 7200 {
		return &ConfigError{Field: "MAX_LOCK_RENEWAL_TIME", Message: "Max lock renewal time must be between 60 and 7200 seconds"}
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

func getEnvAsBool(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		if boolValue, err := strconv.ParseBool(value); err == nil {
			return boolValue
		}
	}
	return defaultValue
}
