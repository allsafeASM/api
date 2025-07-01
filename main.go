package main

import (
	"github.com/allsafeASM/api/internal/app"
	"github.com/allsafeASM/api/internal/config"
	"github.com/projectdiscovery/gologger"
)

func main() {
	// Load and validate configuration
	cfg := config.Load()
	if err := cfg.Validate(); err != nil {
		gologger.Fatal().Msgf("Configuration validation failed: %v", err)
	}

	logConfiguration(cfg)
	gologger.Info().Msg("Starting AllSafe ASM Worker")

	// Create and initialize application
	application, err := app.NewApplication()
	if err != nil {
		gologger.Fatal().Msgf("Failed to initialize application: %v", err)
	}

	gologger.Info().Msg("Application ready. Press Ctrl+C to exit.")

	// Start the application
	if err := application.Start(); err != nil {
		gologger.Fatal().Msgf("Application error: %v", err)
	}

	gologger.Info().Msg("Application shutdown complete")
}

func logConfiguration(cfg *config.Config) {
	gologger.Info().Msg("Configuration:")
	gologger.Info().Msgf("  Service Bus: %s/%s", cfg.Azure.ServiceBusNamespace, cfg.Azure.QueueName)
	gologger.Info().Msgf("  Blob Storage: %s", cfg.Azure.BlobContainerName)
	gologger.Info().Msgf("  Scanner Timeout: %ds", cfg.App.ScannerTimeout)
	gologger.Info().Msgf("  Poll Interval: %ds", cfg.App.PollInterval)
	gologger.Info().Msgf("  Notifications: %t", cfg.App.EnableNotifications)
	gologger.Info().Msgf("  Discord: %t", cfg.App.EnableDiscordNotifications)
}
