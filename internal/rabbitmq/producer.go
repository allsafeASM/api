package rabbitmq

import (
	"log"
  
	"github.com/projectdiscovery/gologger"
	amqp "github.com/rabbitmq/amqp091-go"
)

// PublishTask sends a task message to the specified queue.
func PublishTask(channel *amqp.Channel, queueName string, message []byte) error {
	err := channel.Publish(
		"",        // exchange
		queueName, // routing key (queue name)
		false,     // mandatory
		false,     // immediate
		amqp.Publishing{
			ContentType: "application/json",
			Body:        message,
		},
	)
	if err != nil {
		log.Printf("Failed to publish message to queue %s: %v", queueName, err)
		return err
	}
  gologger.Info().Msgf("Message published to queue %s", queueName)

	return nil
}

