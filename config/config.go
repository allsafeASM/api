package config

// Constants for RabbitMQ configuration.
const (
  RabbitMQURL       = "amqp://guest:guest@localhost:5672/"
  TaskQueueName     = "scan_tasks"
  ResultsQueueName  = "scan_results"
  ResultsStorageDir = "./results/"
  NumOfWorkers      = 4
)

