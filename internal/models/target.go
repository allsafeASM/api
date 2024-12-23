package models

import "time"

// ScanRequest represents the input for a scan operation.
type ScanRequest struct {
  ScanID int64  `json:"scan_id"`
  Domain string `json:"domain"`
}

// ScanResponse represents the results of a scan operation.
type ScanResponse struct {
  ScanID        int64           `json:"scan_id"`
  Domain        string          `json:"domain"`
  ScanStats     ScanStats       `json:"scan_stats"`
  Subdomains    []SubdomainInfo `json:"subdomains"`
}

// ScanStats represents statistics of a scan operation.
type ScanStats struct {
    StartTime         time.Time `json:"start_time"`
    EndTime          time.Time `json:"end_time"`
    Duration         float64   `json:"duration_seconds"`
    Status        string          `json:"status"`          // "completed", "in-progress", "failed"
    ErrorMessage  string          `json:"error_message"`   // Optional: error details if any
    SubdomainCount int             `json:"subdomain_count"` // Count of subdomains discovered
    ResolvedCount int             `json:"resolved_count"`  // Count of successfully resolved subdomains
    OpenPortCount int             `json:"open_port_count"` // Count of subdomains with open ports
    TotalPorts       int       `json:"total_ports_scanned"`
}

// SubdomainInfo represents detailed information about a discovered subdomain.
type SubdomainInfo struct {
  Name         string           `json:"name"`
  Status       string           `json:"status"`       // "active", "inactive", "error"
  HTTPStatus   int             `json:"http_status,omitempty"`
  Technologies []string        `json:"technologies,omitempty"`
  OpenPorts    []PortInfo      `json:"open_ports,omitempty"`
  Resolution   ResolutionInfo `json:"resolution,omitempty"`
}

// ResolutionInfo represents DNS resolution details for a subdomain.
type ResolutionInfo struct {
	A     []string `json:"A"`
	CNAME []string `json:"CNAME"`
}

// PortInfo represents details of an open port.
type PortInfo struct {
  Port     int    `json:"port"`
  Service  string `json:"service"`  // Optional: Service running on the port (e.g., "HTTP", "SSH")
  Protocol string `json:"protocol"` // "TCP" or "UDP"
}
