package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
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
	// Discord webhook settings
	EnableDiscordNotifications bool
	DiscordWebhookTimeout      int // seconds - timeout for Discord webhook requests
}

// Load loads configuration from environment variables
func Load() *Config {
	return &Config{
		Azure: LoadAzureConfig(),
		App:   LoadAppConfig(),
	}
}

// LoadAppConfig loads application-specific configuration
func LoadAppConfig() AppConfig {
	return AppConfig{
		LogLevel:                   getEnv("LOG_LEVEL", "info"),
		PollInterval:               getEnvAsInt("POLL_INTERVAL", 2),
		ScannerTimeout:             getEnvAsInt("SCANNER_TIMEOUT", 7200),       // 2 hours
		LockRenewalInterval:        getEnvAsInt("LOCK_RENEWAL_INTERVAL", 30),   // 30 seconds
		MaxLockRenewalTime:         getEnvAsInt("MAX_LOCK_RENEWAL_TIME", 3600), // 1 hour
		EnableNotifications:        getEnvAsBool("ENABLE_NOTIFICATIONS", true),
		NotificationTimeout:        getEnvAsInt("NOTIFICATION_TIMEOUT", 30), // 30 seconds
		EnableDiscordNotifications: getEnvAsBool("ENABLE_DISCORD_NOTIFICATIONS", true),
		DiscordWebhookTimeout:      getEnvAsInt("DISCORD_WEBHOOK_TIMEOUT", 30), // 30 seconds
	}
}

// Validate checks if required configuration is present
func (c *Config) Validate() error {
	if err := c.Azure.ValidateAzureConfig(); err != nil {
		return err
	}

	if err := c.App.ValidateAppConfig(); err != nil {
		return err
	}

	return nil
}

// ValidateAppConfig validates application-specific configuration
func (c *AppConfig) ValidateAppConfig() error {
	// Define validation rules
	validations := []struct {
		field     string
		value     int
		min, max  int
		fieldName string
	}{
		{"SCANNER_TIMEOUT", c.ScannerTimeout, 30, 7200, "Scanner timeout"},
		{"POLL_INTERVAL", c.PollInterval, 1, 60, "Poll interval"},
		{"LOCK_RENEWAL_INTERVAL", c.LockRenewalInterval, 10, 300, "Lock renewal interval"},
		{"MAX_LOCK_RENEWAL_TIME", c.MaxLockRenewalTime, 60, 7200, "Max lock renewal time"},
	}

	for _, v := range validations {
		if err := validateRange(v.field, v.value, v.min, v.max, v.fieldName); err != nil {
			return err
		}
	}

	if err := validateLogLevel(c.LogLevel); err != nil {
		return err
	}

	return nil
}

// validateRange validates that a value is within the specified range
func validateRange(field string, value, min, max int, fieldName string) error {
	if value < min || value > max {
		message := fmt.Sprintf("%s must be between %d and %d", fieldName, min, max)
		message += " seconds"

		return &ConfigError{
			Field:   field,
			Message: message,
		}
	}
	return nil
}

// validateLogLevel validates that the log level is valid
func validateLogLevel(logLevel string) error {
	validLevels := []string{"debug", "info", "warning", "warn", "error", "fatal"}
	logLevelLower := strings.ToLower(logLevel)

	for _, valid := range validLevels {
		if logLevelLower == valid {
			return nil
		}
	}

	return &ConfigError{
		Field:   "LOG_LEVEL",
		Message: fmt.Sprintf("Invalid log level '%s'. Valid levels are: %s", logLevel, strings.Join(validLevels, ", ")),
	}
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
