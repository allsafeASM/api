package scanner

import (
	"fmt"
	"log"

  "github.com/projectdiscovery/goflags"
  "github.com/projectdiscovery/gologger"
  "github.com/projectdiscovery/gologger/levels"
	httpxrunner "github.com/projectdiscovery/httpx/runner"
)

// HttpxResult represents the HTTP scan result for a single subdomain.
type HttpxResult struct {
	Host         string   `json:"host"`
	Technologies []string `json:"technologies"`
	StatusCode   int      `json:"status_code"`
	Error        string   `json:"error,omitempty"`
}

// RunHttpx scans the provided subdomains for HTTP information and technology detection.
// It returns the results as a slice of HttpxResult.
func RunHttpx(subdomains []string) ([]HttpxResult, error) {
  // Set up logger
  gologger.DefaultLogger.SetMaxLevel(levels.LevelVerbose) // increase the verbosity (optional)

  // Declare results slice before running the enumeration
  var results []HttpxResult

	// Configure httpx options
	options := &httpxrunner.Options{
		Methods:        "GET",           // HTTP methods to use
    InputTargetHost: goflags.StringSlice(subdomains), // List of subdomains to scan
		TechDetect:     true,            // Enable technology detection
		JSONOutput:     false,           // We process the output programmatically
	}

	// Set up the OnResult callback to process results in memory
	options.OnResult = func(r httpxrunner.Result) {
		// Collect results in-memory
		result := HttpxResult{
			Host:         r.Input,
			StatusCode:   r.StatusCode,
			Technologies: r.Technologies,
		}

		// Handle errors if they occur
		if r.Err != nil {
			result.Error = r.Err.Error()
			log.Printf("[Error] %s: %s\n", r.Input, r.Err)
		} else {
			log.Printf("[Success] %s %d\n", r.Input, r.StatusCode)
		}

		results = append(results, result)
	}

	// Validate options before running the scan
	if err := options.ValidateOptions(); err != nil {
		return nil, fmt.Errorf("invalid httpx options: %w", err)
	}

	// Create a new HTTPX runner with the options
	runner, err := httpxrunner.New(options)
	if err != nil {
		return nil, fmt.Errorf("failed to create httpx runner: %w", err)
	}
	defer runner.Close()


	// Run the HTTPX enumeration
	runner.RunEnumeration()


	// Return the collected results
	return results, nil
}


