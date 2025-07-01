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

	numWorkers := cfg.App.WorkerCount
	var wg sync.WaitGroup
	errorChan := make(chan error, numWorkers)

	gologger.Info().Msgf("Starting %d AllSafe ASM workers...", numWorkers)

	// Start worker goroutines
	for i := 1; i <= numWorkers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()

			gologger.Info().Msgf("Initializing worker %d...", workerID)

			application, err := app.NewApplication()
			if err != nil {
				gologger.Fatal().Msgf("Worker %d: Failed to initialize application: %v", workerID, err)
				errorChan <- err
				return
			}

			gologger.Info().Msgf("Worker %d: Starting application...", workerID)

			if err := application.Start(); err != nil {
				gologger.Fatal().Msgf("Worker %d: Application error: %v", workerID, err)
				errorChan <- err
				return
			}
		}(i)
	}

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
