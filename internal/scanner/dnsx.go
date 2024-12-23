package scanner

import (
    "github.com/projectdiscovery/dnsx/libs/dnsx"
    "api/internal/models"
)


// DNSScanner is a client for DNS resolution
type DNSScanner struct {
  client *dnsx.DNSX
}

// NewDNSScanner creates a new DNS scanner
func NewDNSScanner() (*DNSScanner, error) {
  options := dnsx.DefaultOptions
  client, err := dnsx.New(options)
  if err != nil {
    return nil, err
  }
  return &DNSScanner{client: client}, nil
}


// ResolveSubdomain resolves the IP address of a subdomain
func (s *DNSScanner) ResolveSubdomain(subdomain string) (models.ResolutionInfo, error) {
  var resolution models.ResolutionInfo

  // Query for A and CNAME records 
  dnsData, err := s.client.QueryOne(subdomain)
  if err != nil {
    return resolution, err
  }

  // Extract A and CNAME records 
  resolution.A = dnsData.A
  resolution.CNAME = dnsData.CNAME

  return resolution, nil
}
