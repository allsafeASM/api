package main

import (
  "log"
  "api/config"
  "api/internal/rabbitmq"
  "api/utils"
  "api/internal/task"
)


func main() {

  // Create a new RabbitMQ connection
  conn, err := rabbitmq.NewConnectionManager()
	utils.FailOnError(err, "Failed to create RabbitMQ connection")
  defer conn.Close()

  // Enable QoS with prefetch count = 1
  err = conn.Channel.Qos(1, 0, false)
  utils.FailOnError(err, "Failed to set QoS")

  // Declare the task queue
  err = rabbitmq.DeclareQueue(conn.Channel, config.TaskQueueName)
  utils.FailOnError(err, "Failed to declare task queue")

  // Consume tasks from the task queue
  log.Printf("Spawning %d workers", config.NumOfWorkers)
  log.Printf("Waiting for tasks...")
  rabbitmq.ConsumeTasks(conn.Channel, config.TaskQueueName, task.TaskHandler)

  // Wait indefinitely
  select {}
}

