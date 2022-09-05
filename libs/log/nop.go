package log

import (
	"github.com/rs/zerolog/log"
	// "github.com/rs/zerolog"
)

func NewNopLogger() Logger {

	return &defaultLogger{
		Logger: log.Logger,
		// Logger: zerolog.Nop(),
	}
}
