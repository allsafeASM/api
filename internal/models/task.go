package models

// TaskMessage represents the structure of messages in the queue
type TaskMessage struct {
	Task       Task   `json:"task"`
	ScanID     string `json:"scan_id"`
	Domain     string `json:"domain"`
	InstanceID string `json:"instance_id"`
	FilePath   string `json:"input_blob_path,omitempty"` // Optional file path for tools that need file input

	Config map[string]interface{} `json:"config,omitempty"` // Tool-specific configuration
}

// TaskResult represents the result of a completed task
type TaskResult struct {
	Task      Task       `json:"task"`
	ScanID    string     `json:"scan_id"`
	Domain    string     `json:"domain"`
	Status    TaskStatus `json:"status"`
	Data      any        `json:"data,omitempty"`
	Error     string     `json:"error,omitempty"`
	Timestamp string     `json:"timestamp"`
	Duration  string     `json:"duration,omitempty"` // Duration of the task execution
}

// Task types
type Task string

const (
	TaskSubfinder  Task = "subfinder"
	TaskHttpx      Task = "httpx"
	TaskDNSResolve Task = "dns_resolve"
	TaskNaabu      Task = "port_scan"
)

// Task status
type TaskStatus string

const (
	TaskStatusCompleted TaskStatus = "completed"
	TaskStatusFailed    TaskStatus = "failed"
	TaskStatusRunning   TaskStatus = "running"
)

// MessageProcessingResult represents the result of processing a message
type MessageProcessingResult struct {
	Success bool
	Error   error
	// Retryable indicates if the error is transient and should be retried
	Retryable bool
	// RetryCount is the number of times this message has been retried
	RetryCount int
}
