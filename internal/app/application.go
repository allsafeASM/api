package app

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/allsafeASM/api/internal/azure"
	"github.com/allsafeASM/api/internal/config"
	"github.com/allsafeASM/api/internal/handlers"
	"github.com/allsafeASM/api/internal/notification"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
)

// Application represents the main application structure
type Application struct {
	config           *config.Config
	serviceBusClient *azure.ServiceBusClient
	blobClient       *azure.BlobStorageClient
	taskHandler      *handlers.TaskHandler
	ctx              context.Context
	cancel           context.CancelFunc
}

// NewApplication creates and initializes a new application instance
func NewApplication() (*Application, error) {
	app := &Application{}

	if err := app.initialize(); err != nil {
		return nil, err
	}

	return app, nil
}

// initialize sets up all application components
func (app *Application) initialize() error {
	// Load and validate configuration
	app.config = config.Load()
	if err := app.config.Validate(); err != nil {
		return err
	}

	// Initialize logging
	app.setupLogging(app.config.App.LogLevel)

	// Initialize Azure clients
	if err := app.initializeAzureClients(); err != nil {
		return err
	}

	// Initialize task handler
	if err := app.initializeTaskHandler(); err != nil {
		return err
	}

	// Create context for graceful shutdown
	app.ctx, app.cancel = context.WithCancel(context.Background())

	// Log configuration
	app.logConfiguration()

	return nil
}

// setupLogging configures gologger based on the log level
func (app *Application) setupLogging(logLevel string) {
	gologger.Info().Msgf("Log level configured to: %s", logLevel)

	// Map log levels to gologger levels
	levelMap := map[string]levels.Level{
		"debug":   levels.LevelDebug,
		"info":    levels.LevelInfo,
		"warning": levels.LevelWarning,
		"warn":    levels.LevelWarning,
		"error":   levels.LevelError,
		"fatal":   levels.LevelFatal,
	}

	if level, exists := levelMap[strings.ToLower(logLevel)]; exists {
		gologger.DefaultLogger.SetMaxLevel(level)
	} else {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelInfo)
		gologger.Warning().Msgf("Unknown log level '%s', defaulting to 'info'", logLevel)
	}
}

// initializeAzureClients creates Azure Service Bus and Blob Storage clients
func (app *Application) initializeAzureClients() error {
	var err error

	// Initialize Service Bus client
	app.serviceBusClient, err = azure.NewServiceBusClient(
		app.config.Azure.ServiceBusConnectionString,
		app.config.Azure.QueueName,
	)
	if err != nil {
		return fmt.Errorf("failed to initialize Service Bus client: %w", err)
	}

	// Perform a health check on the Service Bus connection
	gologger.Info().Msg("Performing Service Bus health check...")
	if err := app.serviceBusClient.HealthCheck(context.Background()); err != nil {
		gologger.Warning().Msgf("Service Bus health check failed: %v", err)
	} else {
		gologger.Info().Msg("Service Bus health check passed")
	}

	// Initialize Blob Storage client
	app.blobClient, err = azure.NewBlobStorageClient(
		app.config.Azure.BlobStorageConnectionString,
		app.config.Azure.BlobContainerName,
	)
	if err != nil {
		return fmt.Errorf("failed to initialize Blob Storage client: %w", err)
	}

	return nil
}

// initializeTaskHandler creates the task handler with all dependencies
func (app *Application) initializeTaskHandler() error {
	scannerTimeout := time.Duration(app.config.App.ScannerTimeout) * time.Second

	// Initialize notifiers using factory functions
	notifier, err := notification.NewConfiguredNotifier(app.config.App.EnableNotifications)
	if err != nil {
		gologger.Warning().Msgf("Failed to initialize notification service: %v. Notifications will be disabled.", err)
	}

	discordNotifier, err := notification.NewConfiguredDiscordNotifier(app.config.App.EnableDiscordNotifications)
	if err != nil {
		gologger.Warning().Msgf("Failed to initialize Discord notification service: %v. Discord notifications will be disabled.", err)
	}

	app.taskHandler = handlers.NewTaskHandler(
		app.blobClient,
		scannerTimeout,
		notifier,
		discordNotifier,
	)

	return nil
}

// logConfiguration logs the current application configuration
func (app *Application) logConfiguration() {
	gologger.Info().Msg("Starting AllSafe ASM worker with configuration:")
	gologger.Info().Msgf("  Service Bus Namespace: %s", app.config.Azure.ServiceBusNamespace)
	gologger.Info().Msgf("  Queue Name: %s", app.config.Azure.QueueName)
	gologger.Info().Msgf("  Blob Container: %s", app.config.Azure.BlobContainerName)
	gologger.Info().Msgf("  Log Level: %s", app.config.App.LogLevel)
	gologger.Info().Msgf("  Scanner Timeout: %d seconds", app.config.App.ScannerTimeout)
	gologger.Info().Msgf("  Poll Interval: %d seconds", app.config.App.PollInterval)
	gologger.Info().Msgf("  Notifications Enabled: %t", app.config.App.EnableNotifications)
	gologger.Info().Msgf("  Discord Notifications Enabled: %t", app.config.App.EnableDiscordNotifications)
}

// Start begins the application's main processing loop
func (app *Application) Start() error {
	app.logProcessingConfiguration()

	processingErr := make(chan error, 1)
	go app.startMessageProcessing(processingErr)

	return app.waitForShutdown(processingErr)
}

// startMessageProcessing begins processing messages from the queue
func (app *Application) startMessageProcessing(processingErr chan<- error) {
	pollInterval := time.Duration(app.config.App.PollInterval) * time.Second
	lockRenewalInterval := time.Duration(app.config.App.LockRenewalInterval) * time.Second
	maxLockRenewalTime := time.Duration(app.config.App.MaxLockRenewalTime) * time.Second
	scannerTimeout := time.Duration(app.config.App.ScannerTimeout) * time.Second

	err := app.serviceBusClient.ProcessMessages(
		app.ctx,
		app.taskHandler.HandleTask,
		pollInterval,
		lockRenewalInterval,
		maxLockRenewalTime,
		scannerTimeout,
	)

	processingErr <- err
}

// logProcessingConfiguration logs the message processing configuration
func (app *Application) logProcessingConfiguration() {
	pollInterval := time.Duration(app.config.App.PollInterval) * time.Second
	lockRenewalInterval := time.Duration(app.config.App.LockRenewalInterval) * time.Second
	maxLockRenewalTime := time.Duration(app.config.App.MaxLockRenewalTime) * time.Second
	scannerTimeout := time.Duration(app.config.App.ScannerTimeout) * time.Second

	gologger.Info().Msgf("Starting message processing with poll interval: %v", pollInterval)
	gologger.Info().Msgf("Lock renewal interval: %v, Max lock renewal time: %v", lockRenewalInterval, maxLockRenewalTime)
	gologger.Info().Msgf("Scanner timeout per attempt: %v", scannerTimeout)
}

// waitForShutdown waits for shutdown signals and handles graceful shutdown
func (app *Application) waitForShutdown(processingErr <-chan error) error {
	signalChannel := make(chan os.Signal, 1)
	signal.Notify(signalChannel, syscall.SIGINT, syscall.SIGTERM)

	gologger.Info().Msg("Worker is running. Press Ctrl+C to exit.")

	select {
	case <-signalChannel:
		return app.handleGracefulShutdown()
	case err := <-processingErr:
		return err
	}
}

// handleGracefulShutdown performs graceful shutdown of the application
func (app *Application) handleGracefulShutdown() error {
	gologger.Info().Msg("Shutting down application gracefully...")

	// Cancel the main context to stop all goroutines
	app.cancel()

	// Close Azure clients
	if app.serviceBusClient != nil {
		app.serviceBusClient.Close(context.Background())
	}

	gologger.Info().Msg("Application shutdown complete")
	return nil
}
