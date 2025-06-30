package scanners

import (
	"fmt"

	"github.com/allsafeASM/api/internal/azure"
	"github.com/allsafeASM/api/internal/models"
)

// ScannerFactory creates and manages scanner instances
type ScannerFactory struct {
	scanners   map[models.Task]models.Scanner
	blobClient *azure.BlobStorageClient
}

// NewScannerFactory creates a new scanner factory with all available scanners
func NewScannerFactory() *ScannerFactory {
	return &ScannerFactory{
		scanners: map[models.Task]models.Scanner{
			models.TaskSubfinder:  NewSubfinderScanner(),
			models.TaskHttpx:      NewHttpxScanner(),
			models.TaskDNSResolve: NewDNSXScanner(),
			models.TaskNaabu:      NewNaabuScanner(nil), // Naabu scanner without blob client
		},
	}
}

// NewScannerFactoryWithBlobClient creates a new scanner factory with blob storage access
func NewScannerFactoryWithBlobClient(blobClient *azure.BlobStorageClient) *ScannerFactory {
	// Create DNSX scanner and set blob client
	dnsxScanner := NewDNSXScanner()
	dnsxScanner.SetBlobClient(blobClient)

	// Create Naabu scanner with blob client
	naabuScanner := NewNaabuScanner(blobClient)

	return &ScannerFactory{
		scanners: map[models.Task]models.Scanner{
			models.TaskSubfinder:  NewSubfinderScanner(),
			models.TaskHttpx:      NewHttpxScanner(),
			models.TaskDNSResolve: dnsxScanner,
			models.TaskNaabu:      naabuScanner,
		},
		blobClient: blobClient,
	}
}

// GetScanner returns a scanner for the given task type
func (factory *ScannerFactory) GetScanner(taskType models.Task) (models.Scanner, error) {
	scanner, exists := factory.scanners[taskType]
	if !exists {
		return nil, fmt.Errorf("no scanner found for task type: %s", taskType)
	}
	return scanner, nil
}

// GetAvailableScanners returns a list of available scanner names
func (factory *ScannerFactory) GetAvailableScanners() []string {
	var names []string
	for taskType := range factory.scanners {
		names = append(names, string(taskType))
	}
	return names
}
