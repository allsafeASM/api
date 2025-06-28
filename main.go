package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/allsafeASM/api/internal/azure"
	"github.com/allsafeASM/api/internal/config"
	"github.com/allsafeASM/api/internal/handlers"
	"github.com/allsafeASM/api/internal/logging"
	"github.com/allsafeASM/api/internal/notification"
	"github.com/projectdiscovery/gologger"
)

func main() {
	// Load configuration first
	cfg := config.Load()
	if err := cfg.Validate(); err != nil {
		gologger.Fatal().Msgf("Configuration error: %v", err)
	}

	// Set up logging based on configuration
	logger := logging.NewLogger()
	logger.SetupLogging(cfg.App.LogLevel)

	gologger.Info().Msg("Starting AllSafe ASM worker with configuration:")
	gologger.Info().Msgf("  Service Bus Namespace: %s", cfg.Azure.ServiceBusNamespace)
	gologger.Info().Msgf("  Queue Name: %s", cfg.Azure.QueueName)
	gologger.Info().Msgf("  Blob Container: %s", cfg.Azure.BlobContainerName)
	gologger.Info().Msgf("  Log Level: %s", cfg.App.LogLevel)
	gologger.Info().Msgf("  Notifications Enabled: %t", cfg.App.EnableNotifications)
	gologger.Info().Msgf("  Discord Notifications Enabled: %t", cfg.App.EnableDiscordNotifications)

	// Create Azure clients
	serviceBusClient, err := azure.NewServiceBusClient(
		cfg.Azure.ServiceBusConnectionString,
		cfg.Azure.QueueName,
	)
	if err != nil {
		gologger.Fatal().Msgf("Failed to create Service Bus client: %v", err)
	}
	defer serviceBusClient.Close(context.TODO())

	blobClient, err := azure.NewBlobStorageClient(
		cfg.Azure.BlobStorageConnectionString,
		cfg.Azure.BlobContainerName,
	)
	if err != nil {
		gologger.Fatal().Msgf("Failed to create Blob Storage client: %v", err)
	}

	// Create task handler
	scannerTimeout := time.Duration(cfg.App.ScannerTimeout) * time.Second

	// Initialize notification service if enabled
	var notifier *notification.Notifier
	if cfg.App.EnableNotifications {
		var err error
		notifier, err = notification.NewNotifier()
		if err != nil {
			gologger.Warning().Msgf("Failed to initialize notification service: %v. Notifications will be disabled.", err)
			cfg.App.EnableNotifications = false
		} else {
			gologger.Info().Msg("Notification service initialized successfully")
		}
	}

	// Initialize Discord notification service if enabled
	var discordNotifier *notification.DiscordNotifier
	if cfg.App.EnableDiscordNotifications {
		var err error
		discordNotifier, err = notification.NewDiscordNotifier()
		if err != nil {
			gologger.Warning().Msgf("Failed to initialize Discord notification service: %v. Discord notifications will be disabled.", err)
			cfg.App.EnableDiscordNotifications = false
		} else if discordNotifier.IsEnabled() {
			gologger.Info().Msg("Discord notification service initialized successfully")
		} else {
			gologger.Info().Msg("Discord webhook URL not provided, Discord notifications disabled")
			cfg.App.EnableDiscordNotifications = false
		}
	}

	taskHandler := handlers.NewTaskHandler(blobClient, scannerTimeout, notifier, discordNotifier, cfg.App.EnableNotifications, cfg.App.EnableDiscordNotifications)

	// Create context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start message processing with configured poll interval
	pollInterval := time.Duration(cfg.App.PollInterval) * time.Second
	lockRenewalInterval := time.Duration(cfg.App.LockRenewalInterval) * time.Second
	maxLockRenewalTime := time.Duration(cfg.App.MaxLockRenewalTime) * time.Second

	gologger.Info().Msgf("Starting message processing with poll interval: %v", pollInterval)
	gologger.Info().Msgf("Lock renewal interval: %v, Max lock renewal time: %v", lockRenewalInterval, maxLockRenewalTime)
	gologger.Info().Msgf("Scanner timeout per attempt: %v", scannerTimeout)

	go func() {
		if err := serviceBusClient.ProcessMessages(ctx, taskHandler.HandleTask, pollInterval, lockRenewalInterval, maxLockRenewalTime, scannerTimeout); err != nil {
			gologger.Error().Msgf("Message processing error: %v", err)
		}
	}()

	// Graceful shutdown: listen for interrupt or terminate signals
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	gologger.Info().Msg("Worker is running. Press Ctrl+C to exit.")
	<-sigs // Block until a signal is received

	gologger.Info().Msg("Shutdown signal received, stopping worker...")
	cancel() // Cancel context to stop message processing
	gologger.Info().Msg("Worker stopped.")
}
