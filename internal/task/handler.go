package task

import (
  "encoding/json"
  "log"
  "api/internal/rabbitmq"
  "api/internal/models"
  "api/internal/scanner"
  "api/config"
  "api/utils"

	amqp "github.com/rabbitmq/amqp091-go"
)


func TaskHandler(channel *amqp.Channel, message []byte) error {
  var req models.ScanRequest
  if err := json.Unmarshal(message, &req); err != nil {
    log.Printf("Failed to unmarshal message: %v", err)
    return err
  }

  // Run subfinder
  log.Printf("Received scan request for domain %s, with ID %v", req.Domain, req.ScanID)
  result, err := scanner.Scan(req)
  if err != nil {
    log.Printf("Failed to scan domain %s: %v", req.Domain, err)
    return err
  }

  // Publish result to RabbitMQ
  message, err = json.Marshal(result)
  utils.FailOnError(err, "Failed to marshal result")

  err = rabbitmq.PublishTask(channel, config.ResultsQueueName, message)
  utils.FailOnError(err, "Failed to publish result")

  return nil
}


func ResultsHandler(channel *amqp.Channel, message []byte) error {
  var result models.ScanResponse
  if err := json.Unmarshal(message, &result); err != nil {
    log.Printf("Failed to unmarshal message: %v", err)
    return err
  }

  // Save result to file
  err := utils.SaveToFile(result)
  utils.FailOnError(err, "Failed to save result to file")

  return nil
}

