package scanner

import (
	"log"
  "context"

  "api/internal/models"
	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/naabu/v2/pkg/result"
	"github.com/projectdiscovery/naabu/v2/pkg/runner"
)


// RunNaabu is a function that runs the naabu scanner
func RunNaabu(subdomains *[]models.SubdomainInfo, topPorts string) {
  // Extract the subdomain name
  var subdomainsName []string

  // Map the subdomain name to the subdomains slice
  MapSubdomain := make(map[string]*models.SubdomainInfo)

  
  for i := range *subdomains {
    if (*subdomains)[i].Status != "active" {
      continue
    }
    MapSubdomain[(*subdomains)[i].Name] = &(*subdomains)[i]
    subdomainsName = append(subdomainsName, (*subdomains)[i].Name)
  }


  options := runner.Options{
    Host:      goflags.StringSlice(subdomainsName),
    TopPorts: topPorts,
    ScanType: "s",
    Timeout: 1000,
    Rate: 1000,
  }

  options.OnResult = func(hr *result.HostResult) {
    var openPorts []models.PortInfo
    for _, port := range hr.Ports {
      openPorts = append(openPorts, models.PortInfo{
        Port: port.Port,
        Protocol: port.Protocol.String(),
      })
    }
    MapSubdomain[hr.Host].OpenPorts = openPorts
  }

  naabuRunner, err := runner.NewRunner(&options)
  if err != nil {
    log.Fatal(err)
  }
  defer naabuRunner.Close()

  naabuRunner.RunEnumeration(context.TODO())
}
