package main

import (
	"api/config"
	"api/internal/models"
	"api/internal/rabbitmq"
	"api/internal/task"
	"api/utils"
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
)

func main() {
	// Connect to RabbitMQ
	connManager, err := rabbitmq.NewConnectionManager()
	utils.FailOnError(err, "Failed to connect to RabbitMQ")
	defer connManager.Close()

	// Declare queues for tasks and results
	err = rabbitmq.DeclareQueue(connManager.Channel, config.TaskQueueName)
	utils.FailOnError(err, "Failed to declare task queue")

	err = rabbitmq.DeclareQueue(connManager.Channel, config.ResultsQueueName)
	utils.FailOnError(err, "Failed to declare results queue")

	// Consume Results
	go rabbitmq.ConsumeTasks(connManager.Channel, config.ResultsQueueName, task.ResultsHandler)

	// Setup HTTP server
	r := gin.Default()

	// API to receive scan requests
	r.POST("/scan", func(c *gin.Context) {
		var req models.ScanRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
			return
		}

		// Publish task to RabbitMQ
		message, err := json.Marshal(req)

		err = rabbitmq.PublishTask(connManager.Channel, config.TaskQueueName, message)

		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to queue task"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"message": "Scan queued", "scan_id": req.ScanID})
	})

	// API to retrieve scan results
	r.GET("/results/:scan_id", func(c *gin.Context) {
		scanID := c.Param("scan_id")
		filePath := fmt.Sprintf("%s%s.json", config.ResultsStorageDir, scanID)

		if _, err := os.Stat(filePath); os.IsNotExist(err) {
			c.JSON(http.StatusNotFound, gin.H{"message": "Results not available"})
			return
		}

		// Read and return the file content
		content, err := os.ReadFile(filePath)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to read results"})
			return
		}

		c.Data(http.StatusOK, "application/json", content)
	})

	// Start the server
	r.Run(":8080")
}
