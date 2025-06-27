# AllSafe ASM Worker

A scalable Azure-based application security monitoring (ASM) worker that processes security scanning tasks using Azure Service Bus and stores results in Azure Blob Storage.

## Architecture

The application follows a clean architecture pattern with clear separation of concerns:

```
api/
├── internal/
│   ├── azure/           # Azure service clients
│   │   ├── servicebus.go # Service Bus operations
│   │   └── blobstorage.go # Blob Storage operations
│   ├── config/          # Configuration management
│   │   └── config.go
│   ├── handlers/        # Business logic handlers
│   │   └── task_handler.go
│   └── models/          # Data models
│       └── task.go
├── scanners/            # Security scanning tools
│   ├── subfinder.go
│   ├── portscanner.go
│   └── httpx.go
├── main.go              # Main application (processes tasks from queue)
├── Makefile             # Build and run commands
└── go.mod
```

## Components

### 1. Main Application (`main.go`)
- Processes tasks from Azure Service Bus queue
- Executes security scans using various tools
- Stores results in Azure Blob Storage
- Handles graceful shutdown

### 2. Azure Services
- **Service Bus**: Message queue for task distribution
- **Blob Storage**: Persistent storage for scan results

### 3. Security Scanners
- **Subfinder**: Subdomain enumeration
- **Port Scanner**: Port scanning (TODO)
- **HTTPX**: HTTP probing (TODO)

## Configuration

Set the following environment variables:

```bash
# Required
SERVICEBUS_CONNECTION_STRING=your_service_bus_connection_string
BLOB_STORAGE_CONNECTION_STRING=your_blob_storage_connection_string

# Optional (with defaults)
SERVICEBUS_NAMESPACE=asm-queue
SERVICEBUS_QUEUE_NAME=tasks
BLOB_CONTAINER_NAME=scans
LOG_LEVEL=info
MAX_WORKERS=5
POLL_INTERVAL=2
SCANNER_TIMEOUT=3600
LOCK_RENEWAL_INTERVAL=30
MAX_LOCK_RENEWAL_TIME=3600

# Notification settings (optional)
ENABLE_NOTIFICATIONS=true
DURABLE_API_ENDPOINT=https://your-function-app.azurewebsites.net/api/orchestrators
DURABLE_API_KEY=your_function_key
NOTIFICATION_TIMEOUT=30
```

**Configuration Validation:**
- Scanner timeout must be between 30 and 7200 seconds
- Poll interval must be between 1 and 60 seconds
- Lock renewal interval must be between 10 and 300 seconds
- Max lock renewal time must be between 60 and 7200 seconds
- All required connection strings must be provided

## Message Lock Auto-Renewal

The worker automatically renews message locks during long-running operations to prevent message expiration. This is especially important for security scanning tasks that may take several minutes to complete.

**Configuration:**
- `LOCK_RENEWAL_INTERVAL`: How often to renew the message lock (default: 30 seconds)
- `MAX_LOCK_RENEWAL_TIME`: Maximum time to keep renewing locks (default: 1 hour)

**How it works:**
1. When a message is received, a background goroutine starts renewing the lock every `LOCK_RENEWAL_INTERVAL` seconds
2. Lock renewal continues until either:
   - The task completes successfully
   - The task fails (retryable or non-retryable)
   - `MAX_LOCK_RENEWAL_TIME` is reached
   - The worker is shut down
3. If lock renewal fails, the task is abandoned for retry

## Usage

### Running the Application

```bash
# Run directly
go run main.go

# Or use make
make run

# Build and run
make build
./bin/allsafe-asm
```

### Sending Tasks to Queue

You can send tasks to the Azure Service Bus queue using Azure CLI, Azure Portal, or any Service Bus client:

```bash
# Using Azure CLI (example)
az servicebus queue message send \
  --namespace-name asm-queue \
  --queue-name tasks \
  --connection-string "your_connection_string" \
  --body '{"task": "subfinder", "domain": "example.com"}'
```

Supported task types:
- `subfinder` - Subdomain enumeration
- `portscan` - Port scanning (common ports)
- `httpx` - HTTP probing (common endpoints)

## Task Processing Flow

1. **Queue**: Task is received from Azure Service Bus queue in PeekLock mode
2. **Processing**: Worker picks up task from queue with retry logic
3. **Execution**: Appropriate scanner is executed with timeout
4. **Storage**: Results are stored in Azure Blob Storage
5. **Completion**: Task is marked as completed or moved to DLQ

## Task Completion Notifications

The worker can send completion notifications to Azure Durable Functions when tasks finish processing. This enables integration with orchestrator workflows.

### Configuration

Enable notifications by setting the following environment variables:

```bash
ENABLE_NOTIFICATIONS=true
DURABLE_API_ENDPOINT=https://your-function-app.azurewebsites.net/api/orchestrators
DURABLE_API_KEY=your_function_key
NOTIFICATION_TIMEOUT=30
```

### Notification Flow

1. **Task Completion**: When a task completes (success or failure), the worker prepares a notification payload
2. **HTTP Request**: Sends a POST request to the Azure Function endpoint with the task result
3. **Event Name**: Uses the format `{toolName}_completed` (e.g., `subfinderCompleted`, `portscanCompleted`)
4. **Instance ID**: Uses the `scan_id` from the task message as the durable function instance ID
5. **Retry Logic**: Implements exponential backoff retry (3 attempts) for failed notifications

### Notification Payload

```json
{
  "scan_id": "task_1234567890",
  "task": "subfinder",
  "domain": "example.com",
  "status": "completed",
  "data": {
    "subdomains": ["www.example.com", "api.example.com"],
    "count": 2
  },
  "timestamp": "2024-01-15T10:30:45Z"
}
```

### Error Handling

- **Notification Failures**: If notification fails, the task is still marked as successful (notification errors don't fail the task)
- **Missing Configuration**: If notification settings are missing, notifications are disabled gracefully
- **Network Issues**: Implements retry logic with exponential backoff for transient failures

### Message Processing Strategy

The worker implements a robust message processing system:

#### **Success Path**
- ✅ **CompleteMessage()** - Message processed successfully

#### **Retryable Errors** (e.g., network timeouts, rate limits)
- 🔄 **In-process retries** - Up to 3 attempts with exponential backoff
- 🔄 **AbandonMessage()** - If still failing after retries, let Service Bus handle re-delivery

#### **Permanent Errors** (e.g., invalid task type, missing domain)
- 🚫 **DeadLetterMessage()** - Move to Dead Letter Queue immediately
- 🚫 **No retries** - Prevents unnecessary processing attempts

#### **Error Classification**
- **Retryable**: Network issues, timeouts, rate limits, temporary service unavailability
- **Non-retryable**: Invalid message format, unknown task types, permission errors

#### **Configuration**
- **Scanner Timeout**: `SCANNER_TIMEOUT=3600` (1 hour default)
- **Poll Interval**: `POLL_INTERVAL=2` (seconds between queue checks)
- **Max Retries**: 3 attempts with exponential backoff (1s, 2s, 4s)

## Task Results

Results are stored in Azure Blob Storage with the following structure:

```
scans/
├── domain-scan_id/
│   ├── subfinder/
│   │   ├── in/
│   │   │   └── uuid.json
│   │   └── out/
│   │   │   └── uuid.json
│   ├── portscan/
│   └── httpx/
```

Each result file contains:
```json
{
  "scan_id": "task_1234567890",
  "task": "subfinder",
  "domain": "example.com",
  "status": "completed",
  "data": {
    "subdomains": ["www.example.com", "api.example.com"],
    "count": 2
  },
  "timestamp": "2024-01-15T10:30:45Z"
}
```

## Development

### Adding New Scanners

1. Implement the scanner in the `scanners/` directory
2. Add the task type constant in `internal/models/task.go`
3. Add the handler in `internal/handlers/task_handler.go`

### Adding New Azure Services

1. Create a new client in `internal/azure/`
2. Add configuration in `internal/config/config.go`
3. Update the main application to use the new service

## Building

```bash
# Build application
make build

# Or manually
go build -o bin/allsafe-asm main.go
```

## Docker

```bash
# Build Docker image
make docker-build

# Or manually
docker build -t allsafe-asm .
```

## Monitoring

- Monitor Azure Service Bus queue metrics
- Check Azure Blob Storage for task results
- Review application logs for errors and performance
- Use Azure Application Insights for detailed monitoring

## Security Considerations

- Use Azure Managed Identity when possible
- Store connection strings securely
- Validate all input data
- Monitor for suspicious activity
- Implement proper logging and error handling 