package rabbitmq

import (
	amqp "github.com/rabbitmq/amqp091-go"
	"log"
)

// DeclareQueue ensures a queue exists with the given name.
func DeclareQueue(channel *amqp.Channel, name string) error {
	_, err := channel.QueueDeclare(
		name,  // queue name
		true,  // durable
		false, // auto-delete
		false, // exclusive
		false, // no-wait
		nil,   // arguments
	)
	if err != nil {
		log.Printf("Failed to declare queue %s: %v", name, err)
		return err
	}
	return nil
}

