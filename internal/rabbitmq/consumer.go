package rabbitmq

import (
	"log"

	amqp "github.com/rabbitmq/amqp091-go"
)

// ConsumeTasks starts consuming messages from the specified queue.
func ConsumeTasks(channel *amqp.Channel, queueName string, handler func(*amqp.Channel, []byte) error) error {
	msgs, err := channel.Consume(
		queueName, // queue name
		"",        // consumer tag
		false,      // auto-ack
		false,     // exclusive
		false,     // no-local
		false,     // no-wait
		nil,       // arguments
	)
	if err != nil {
		log.Printf("Failed to register consumer for queue %s: %v", queueName, err)
		return err
	}


	// Consume messages
	for msg := range msgs {
		if err := handler(channel, msg.Body); err != nil {
			log.Printf("Error handling message: %v", err)
      msg.Nack(false, true)
		} else {
      msg.Ack(false)
    }
	}

	return nil
}

