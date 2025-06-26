package models

// TaskMessage represents the structure of messages in the queue
type TaskMessage struct {
	Task   string `json:"task"`
	Domain string `json:"domain"`
}

// TaskResult represents the result of a completed task
type TaskResult struct {
	TaskID    string      `json:"task_id"`
	TaskType  string      `json:"task_type"`
	Domain    string      `json:"domain"`
	Status    string      `json:"status"`
	Data      interface{} `json:"data,omitempty"`
	Error     string      `json:"error,omitempty"`
	Timestamp string      `json:"timestamp"`
}

// Task types
const (
	TaskTypeSubfinder = "subfinder"
	TaskTypePortScan  = "portscan"
	TaskTypeHttpx     = "httpx"
)

// Task status
const (
	TaskStatusCompleted = "completed"
	TaskStatusFailed    = "failed"
	TaskStatusRunning   = "running"
)
