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
	"github.com/projectdiscovery/gologger"
)

func main() {
	// Load configuration first
	cfg := config.Load()
	if err := cfg.Validate(); err != nil {
		gologger.Fatal().Msgf("Configuration error: %v", err)
	}

	// Set up logging based on configuration
	setupLogging(cfg.App.LogLevel)

	gologger.Info().Msg("Starting AllSafe ASM worker with configuration:")
	gologger.Info().Msgf("  Service Bus Namespace: %s", cfg.Azure.ServiceBusNamespace)
	gologger.Info().Msgf("  Queue Name: %s", cfg.Azure.QueueName)
	gologger.Info().Msgf("  Blob Container: %s", cfg.Azure.BlobContainerName)
	gologger.Info().Msgf("  Poll Interval: %d seconds", cfg.App.PollInterval)
	gologger.Info().Msgf("  Log Level: %s", cfg.App.LogLevel)

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
	taskHandler := handlers.NewTaskHandler(blobClient)

	// Create context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start message processing with configured poll interval
	pollInterval := time.Duration(cfg.App.PollInterval) * time.Second
	gologger.Info().Msgf("Starting message processing with poll interval: %v", pollInterval)
	go func() {
		if err := serviceBusClient.ProcessMessages(ctx, taskHandler.HandleTask, pollInterval); err != nil {
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

// setupLogging configures gologger based on the log level
func setupLogging(logLevel string) {
	// gologger automatically handles different log levels
	// The log level is mainly used for filtering output
	gologger.Info().Msgf("Log level set to: %s", logLevel)
}
