package rabbitmq

import (

  "api/config"
	amqp "github.com/rabbitmq/amqp091-go"
)


// ConnectionManager manages the RabbitMQ connection.
type ConnectionManager struct {
	Connection *amqp.Connection
	Channel    *amqp.Channel
  ConnPool   *amqp.Connection
}

// NewConnectionManager creates and initializes a new RabbitMQ connection.
func NewConnectionManager() (*ConnectionManager, error) {
	conn, err := amqp.Dial(config.RabbitMQURL)
	if err != nil {
		return nil, err
	}

	ch, err := conn.Channel()
	if err != nil {
		conn.Close()
		return nil, err
	}

	return &ConnectionManager{
		Connection: conn,
		Channel:    ch,
	}, nil
}

// Close closes the RabbitMQ connection and channel.
func (cm *ConnectionManager) Close() {
	if cm.Channel != nil {
		cm.Channel.Close()
	}
	if cm.Connection != nil {
		cm.Connection.Close()
	}
}

