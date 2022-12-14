package log

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/rs/zerolog"
)

var _ Logger = (*defaultLogger)(nil)

type defaultLogger struct {
	zerolog.Logger

	trace bool
}

// NewDefaultLogger returns a default logger that can be used within Tendermint
// and that fulfills the Logger interface. The underlying logging provider is a
// zerolog logger that supports typical log levels along with JSON and plain/text
// log formats.
//
// Since zerolog supports typed structured logging and it is difficult to reflect
// that in a generic interface, all logging methods accept a series of key/value
// pair tuples, where the key must be a string.
func NewDefaultLogger(format, level string, trace bool) (Logger, error) {
	var logWriter io.Writer
	switch strings.ToLower(format) {
	case LogFormatPlain, LogFormatText:
		logWriter = zerolog.ConsoleWriter{
			Out:        os.Stderr,
			NoColor:    true,
			TimeFormat: time.RFC3339,
			FormatLevel: func(i interface{}) string {
				if ll, ok := i.(string); ok {
					return strings.ToUpper(ll)
				}
				return "????"
			},
		}

	case LogFormatJSON:
		logWriter = os.Stderr

	default:
		return nil, fmt.Errorf("unsupported log format: %s", format)
	}

	logLevel, err := zerolog.ParseLevel(level)
	if err != nil {
		return nil, fmt.Errorf("failed to parse log level (%s): %w", level, err)
	}

	// make the writer thread-safe
	logWriter = newSyncWriter(logWriter)

	return defaultLogger{
		Logger: zerolog.New(logWriter).Level(logLevel).With().Timestamp().Logger(),
		trace:  trace,
	}, nil
}

// MustNewDefaultLogger delegates a call NewDefaultLogger where it panics on
// error.
func MustNewDefaultLogger(format, level string, trace bool) Logger {
	logger, err := NewDefaultLogger(format, level, trace)
	if err != nil {
		panic(err)
	}

	return logger
}

func (l defaultLogger) Info(msg string, keyVals ...interface{}) {
	l.Logger.Info().Fields(keyVals).Msg(msg)
}

func (l defaultLogger) Error(msg string, keyVals ...interface{}) {
	e := l.Logger.Error()
	if l.trace {
		e = e.Stack()
	}

	e.Fields(keyVals).Msg(msg)
}

func (l defaultLogger) Debug(msg string, keyVals ...interface{}) {
	l.Logger.Debug().Fields(keyVals).Msg(msg)
}

func (l defaultLogger) With(keyVals ...interface{}) Logger {
	return defaultLogger{
		Logger: l.Logger.With().Fields(keyVals).Logger(),
		trace:  l.trace,
	}
}
