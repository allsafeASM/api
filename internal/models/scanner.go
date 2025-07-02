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
	Domain    string `json:"domain"`
	InputPath string `json:"input_path,omitempty"` // Local path to the input file for httpx
}

func (h HttpxInput) GetDomain() string {
	return h.Domain
}

func (h HttpxInput) GetScannerName() string {
	return "httpx"
}

// HttpxHostResult represents the result for a single host in httpx
type HttpxHostResult struct {
	Host          string       `json:"host"`
	URL           string       `json:"url"`
	StatusCode    int          `json:"status_code"`
	Technologies  []string     `json:"technologies,omitempty"`
	ContentLength int          `json:"content_length,omitempty"`
	ContentType   string       `json:"content_type,omitempty"`
	WebServer     string       `json:"web_server,omitempty"`
	Title         string       `json:"title,omitempty"`
	ASN           *AsnResponse `json:"asn,omitempty"`
}

type AsnResponse struct {
	AsNumber  string   `json:"as_number" csv:"as_number"`
	AsName    string   `json:"as_name" csv:"as_name"`
	AsCountry string   `json:"as_country" csv:"as_country"`
	AsRange   []string `json:"as_range" csv:"as_range"`
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

// NucleiInput represents input for the nuclei scanner
type NucleiInput struct {
	Domain            string `json:"domain"`
	HostsFileLocation string `json:"input_blob_path,omitempty"` // The location of where the hosts file is located from blob storage
	Type              string `json:"type,omitempty"`            // Type of nuclei scan (e.g., "http")
}

func (n NucleiInput) GetDomain() string {
	return n.Domain
}

func (n NucleiInput) GetScannerName() string {
	return "nuclei"
}

// NucleiVulnerability represents a single vulnerability found by nuclei
type NucleiVulnerability struct {
	TemplateID       string     `json:"template_id"`
	Info             NucleiInfo `json:"info"`
	Type             string     `json:"type"`
	Host             string     `json:"host"`
	MatchedAt        string     `json:"matched_at"`
	ExtractedResults []string   `json:"extracted_results,omitempty"`
}

// NucleiInfo represents template information
type NucleiInfo struct {
	Name        string   `json:"name"`
	Tags        []string `json:"tags,omitempty"`
	Description string   `json:"description,omitempty"`
	Reference   []string `json:"reference,omitempty"`
	Severity    string   `json:"severity,omitempty"`
}

// NucleiResult represents the result of a nuclei scan
type NucleiResult struct {
	Domain          string                `json:"domain"`
	Vulnerabilities []NucleiVulnerability `json:"output"`
}

func (r NucleiResult) GetCount() int {
	return len(r.Vulnerabilities)
}

func (r NucleiResult) GetDomain() string {
	return r.Domain
}
