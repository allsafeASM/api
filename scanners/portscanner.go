package scanners

import (
	"context"
	"fmt"

	"github.com/projectdiscovery/gologger"
)

func RunPortScanner(ctx context.Context, domain string) ([]string, error) {
	// TODO: Implement port scanning with context support
	// For now, return a placeholder message
	gologger.Warning().Msgf("Port scanning not yet implemented for domain: %s", domain)
	return []string{}, fmt.Errorf("port scanning not yet implemented")
}
