package scanner

import (
  "fmt"
  "time"
  "sync"

  "api/internal/models"
)


// In your main scanner or task handler
func Scan(req models.ScanRequest) (*models.ScanResponse, error) {
    // Create initial scan response
    response := &models.ScanResponse{
        ScanID:    req.ScanID,
        Domain:    req.Domain,
        ScanStats: models.ScanStats{
            StartTime: time.Now(),
            Status:    "in-progress",
          },
    }

    // Run subdomain enumeration
    subdomains := RunSubfinder(req.Domain)
    response.Subdomains = subdomains

    // Run DNS resolution
    dnsScanner, err := NewDNSScanner()
    if err != nil {
      response.ScanStats.Status = "failed"
      response.ScanStats.ErrorMessage = fmt.Sprintf("DNS scanner initialization failed: %v", err)
      return response, err
    }

    // Resolve IP addresses for each subdomain
    var wg sync.WaitGroup
    for i := range response.Subdomains {
      wg.Add(1)
      go func(i int) {
        defer wg.Done()
        subdomain := response.Subdomains[i].Name
        resolution, err := dnsScanner.ResolveSubdomain(subdomain)
        if err != nil {
          response.Subdomains[i].Status = "inactive"
          return
        }
        response.Subdomains[i].Resolution = resolution
        response.Subdomains[i].Status = "active"
      }(i)
    }
    wg.Wait()

    // Run port scanning
    RunNaabu(&response.Subdomains, "100")

    
    // Update scan stats
    response.ScanStats.EndTime = time.Now()
    response.ScanStats.Duration = response.ScanStats.EndTime.Sub(response.ScanStats.StartTime).Seconds()
    response.ScanStats.Status = "completed"
    response.ScanStats.SubdomainCount = len(response.Subdomains)
    response.ScanStats.ResolvedCount = 0
    for _, sub := range response.Subdomains {
      if sub.Status == "active" {
        response.ScanStats.ResolvedCount++
        for _, port := range sub.OpenPorts {
          response.ScanStats.TotalPorts++
          if port.Service != "" {
            response.ScanStats.OpenPortCount++
          }
        }
      }
    }

    return response, nil
}
