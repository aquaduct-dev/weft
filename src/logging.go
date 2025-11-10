package server

import (
	"os"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func Init(level zerolog.Level) {
	// Pretty logging is enabled by default. Disable it if WEFT_ENV is set to "prod".
	if os.Getenv("WEFT_ENV") != "prod" {
		log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339})
	}

	zerolog.SetGlobalLevel(level)
}
