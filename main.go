package main

import (
	"github.com/allsafeASM/api/internal/app"
	"github.com/projectdiscovery/gologger"
)

func main() {
	application, err := app.NewApplication()
	if err != nil {
		gologger.Fatal().Msgf("Failed to initialize application: %v", err)
	}

	if err := application.Start(); err != nil {
		gologger.Fatal().Msgf("Application error: %v", err)
	}
}
