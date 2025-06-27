package logging

import (
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
)

// Logger provides logging functionality
type Logger struct{}

// NewLogger creates a new logger
func NewLogger() *Logger {
	return &Logger{}
}

// SetupLogging configures gologger based on the log level
func (l *Logger) SetupLogging(logLevel string) {
	gologger.Info().Msgf("Log level configured to: %s", logLevel)

	switch logLevel {
	case "debug":
		gologger.DefaultLogger.SetMaxLevel(levels.LevelDebug)
	case "info":
		gologger.DefaultLogger.SetMaxLevel(levels.LevelInfo)
	case "warning", "warn":
		gologger.DefaultLogger.SetMaxLevel(levels.LevelWarning)
	case "error":
		gologger.DefaultLogger.SetMaxLevel(levels.LevelError)
	case "fatal":
		gologger.DefaultLogger.SetMaxLevel(levels.LevelFatal)
	default:
		gologger.DefaultLogger.SetMaxLevel(levels.LevelInfo)
	}
}
