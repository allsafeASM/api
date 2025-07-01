package models

import (
	"context"
)

// Scanner defines the interface for all security scanners
type Scanner interface {
	Execute(ctx context.Context, input interface{}) (ScannerResult, error)
	GetName() string
	GetBaseScanner() interface{} // Return interface{} to avoid import cycle
}

// ScannerResult represents the common interface for all scanner results
type ScannerResult interface {
	GetCount() int
	GetDomain() string
}

// ScannerInput represents the base interface for all scanner inputs
type ScannerInput interface {
	GetDomain() string
	GetScannerName() string
}

// SubfinderInput represents input for the subfinder scanner
type SubfinderInput struct {
	Domain string `json:"domain"`
}

func (s SubfinderInput) GetDomain() string {
	return s.Domain
}

func (s SubfinderInput) GetScannerName() string {
	return "subfinder"
}

// SubfinderResult represents the result of a subfinder scan
type SubfinderResult struct {
	Domain     string   `json:"domain"`
	Subdomains []string `json:"subdomains"`
}

func (r SubfinderResult) GetCount() int {
	return len(r.Subdomains)
}

func (r SubfinderResult) GetDomain() string {
	return r.Domain
}

// HttpxInput represents input for the httpx scanner
type HttpxInput struct {
	Domain            string `json:"domain"`
	HostsFileLocation string `json:"input_blob_path,omitempty"` // The location of where the hosts file is located from blob storage
	// Future fields could include:
	// Ports []int `json:"ports,omitempty"`
	// Threads int `json:"threads,omitempty"`
	// Timeout time.Duration `json:"timeout,omitempty"`
}

func (h HttpxInput) GetDomain() string {
	return h.Domain
}

func (h HttpxInput) GetScannerName() string {
	return "httpx"
}

// HttpxHostResult represents the result for a single host in httpx
type HttpxHostResult struct {
	Host         string   `json:"host"`
	StatusCode   int      `json:"status_code"`
	Technologies []string `json:"technologies,omitempty"`
}

// HttpxResult represents the result of an httpx scan
type HttpxResult struct {
	Domain  string            `json:"domain"`
	Results []HttpxHostResult `json:"output"`
}

func (r HttpxResult) GetCount() int {
	return len(r.Results)
}

func (r HttpxResult) GetDomain() string {
	return r.Domain
}

// DNSXInput represents input for the dnsx scanner
type DNSXInput struct {
	Domain            string   `json:"domain"`
	Subdomains        []string `json:"subdomains,omitempty"`      // List of subdomains to resolve
	HostsFileLocation string   `json:"input_blob_path,omitempty"` // The location of where the hosts file is located from blob storage
	// Future fields could include:
	// RecordTypes []string `json:"record_types,omitempty"`
	// Resolvers []string `json:"resolvers,omitempty"`
}

func (d DNSXInput) GetDomain() string {
	return d.Domain
}

func (d DNSXInput) GetScannerName() string {
	return "dnsx"
}

// DNSXResult represents the result of a dnsx scan
type DNSXResult struct {
	Domain  string                    `json:"domain"`
	Records map[string]ResolutionInfo `json:"output"`
}

// ResolutionInfo represents DNS resolution information for a record type
type ResolutionInfo struct {
	Status string   `json:"status"`
	A      []string `json:"A,omitempty"`
	CNAME  []string `json:"CNAME,omitempty"`
}

func (r DNSXResult) GetCount() int {
	return len(r.Records)
}

func (r DNSXResult) GetDomain() string {
	return r.Domain
}

// NaabuInput represents input for the naabu scanner
type NaabuInput struct {
	Domain            string   `json:"domain"`
	IPs               []string `json:"ips,omitempty"`             // List of IPs to scan
	HostsFileLocation string   `json:"input_blob_path,omitempty"` // The location of where the hosts file is located from blob storage
	Ports             []int    `json:"ports,omitempty"`           // Specific ports to scan
	PortRange         string   `json:"port_range,omitempty"`      // Port range (e.g., "1-1000")
	TopPorts          string   `json:"top_ports,omitempty"`       // Number of top ports to scan (valid values: "full", "100", "1000")
	RateLimit         int      `json:"rate_limit,omitempty"`      // Rate limit for scanning
	Concurrency       int      `json:"concurrency,omitempty"`     // Number of concurrent scans
	Timeout           int      `json:"timeout,omitempty"`         // Timeout in seconds
}

func (n NaabuInput) GetDomain() string {
	return n.Domain
}

func (n NaabuInput) GetScannerName() string {
	return "naabu"
}

// NaabuResult represents the result of a naabu scan
type NaabuResult struct {
	Domain string                `json:"domain"`
	Ports  map[string][]PortInfo `json:"output"` // IP -> []PortInfo
}

// PortInfo represents information about an open port
type PortInfo struct {
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	Service  string `json:"service,omitempty"`
}

func (r NaabuResult) GetCount() int {
	total := 0
	for _, ports := range r.Ports {
		total += len(ports)
	}
	return total
}

func (r NaabuResult) GetDomain() string {
	return r.Domain
}
