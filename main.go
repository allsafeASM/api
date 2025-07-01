package main

import (
	"sync"

	"github.com/allsafeASM/api/internal/app"
	"github.com/allsafeASM/api/internal/config"
	"github.com/projectdiscovery/gologger"
)

func main() {
	// Load configuration to get worker count
	cfg := config.Load()
	if err := cfg.Validate(); err != nil {
		gologger.Fatal().Msgf("Configuration validation failed: %v", err)
	}

	// Log configuration once at startup
	logConfiguration(cfg)

	numWorkers := cfg.App.WorkerCount
	var wg sync.WaitGroup
	errorChan := make(chan error, numWorkers)
	readyChan := make(chan struct{}, numWorkers) // Channel to track when workers are ready
	shutdownChan := make(chan struct{}, 1)       // Channel to coordinate shutdown messages

	gologger.Info().Msgf("Starting AllSafe ASM with %d workers...", numWorkers)

	// Start worker goroutines
	for i := 1; i <= numWorkers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()

			application, err := app.NewApplication()
			if err != nil {
				gologger.Fatal().Msgf("Worker %d: Failed to initialize application: %v", workerID, err)
				errorChan <- err
				return
			}

			// Signal that this worker is ready
			readyChan <- struct{}{}

			if err := application.Start(shutdownChan); err != nil {
				gologger.Fatal().Msgf("Worker %d: Application error: %v", workerID, err)
				errorChan <- err
				return
			}
		}(i)
	}

	// Wait for all workers to be ready, then print the ready message once
	go func() {
		for i := 0; i < numWorkers; i++ {
			<-readyChan
		}
		gologger.Info().Msg("All workers ready. Press Ctrl+C to exit.")
	}()

	// Wait for all workers to complete or for an error
	go func() {
		wg.Wait()
		close(errorChan)
	}()

	// Check for any errors from workers
	for err := range errorChan {
		if err != nil {
			gologger.Fatal().Msgf("Worker error: %v", err)
		}
	}

	gologger.Info().Msg("All workers have completed")
}

// logConfiguration logs the current application configuration
func logConfiguration(cfg *config.Config) {
	gologger.Info().Msg("Configuration:")
	gologger.Info().Msgf("  Service Bus: %s/%s", cfg.Azure.ServiceBusNamespace, cfg.Azure.QueueName)
	gologger.Info().Msgf("  Blob Storage: %s", cfg.Azure.BlobContainerName)
	gologger.Info().Msgf("  Scanner Timeout: %ds", cfg.App.ScannerTimeout)
	gologger.Info().Msgf("  Poll Interval: %ds", cfg.App.PollInterval)
	gologger.Info().Msgf("  Worker Count: %d", cfg.App.WorkerCount)
	gologger.Info().Msgf("  Notifications: %t", cfg.App.EnableNotifications)
	gologger.Info().Msgf("  Discord: %t", cfg.App.EnableDiscordNotifications)
}
