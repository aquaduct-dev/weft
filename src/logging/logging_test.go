// logging_test.go checks both branches of Init: outside WEFT_ENV=prod the
// global zerolog logger is switched to human-readable console output on
// stderr, and with WEFT_ENV=prod the existing (JSON) logger is left alone.
// Both cases also check that Init applies the requested global level.
package logging

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// saveGlobals snapshots the globals Init mutates and restores them when the
// test ends, so tests do not leak logger state into each other.
func saveGlobals(t *testing.T) {
	t.Helper()
	oldLogger := log.Logger
	oldLevel := zerolog.GlobalLevel()
	oldStderr := os.Stderr
	t.Cleanup(func() {
		log.Logger = oldLogger
		zerolog.SetGlobalLevel(oldLevel)
		os.Stderr = oldStderr
	})
}

func TestInitConsoleOutsideProd(t *testing.T) {
	for _, env := range []string{"", "dev"} {
		t.Run("WEFT_ENV="+env, func(t *testing.T) {
			saveGlobals(t)
			t.Setenv("WEFT_ENV", env)

			// Init captures os.Stderr when it builds the ConsoleWriter, so
			// point it at a pipe first and read back what gets logged.
			r, w, err := os.Pipe()
			if err != nil {
				t.Fatalf("os.Pipe: %v", err)
			}
			os.Stderr = w

			Init(zerolog.InfoLevel)
			log.Debug().Msg("hidden-debug")
			log.Info().Msg("hello-console")
			w.Close()
			out, _ := io.ReadAll(r)
			t.Logf("console output: %q", out)

			if zerolog.GlobalLevel() != zerolog.InfoLevel {
				t.Fatalf("global level = %v, want info", zerolog.GlobalLevel())
			}
			s := string(out)
			if !strings.Contains(s, "INF") || !strings.Contains(s, "hello-console") {
				t.Fatalf("expected console-formatted info line, got %q", s)
			}
			if strings.HasPrefix(strings.TrimSpace(s), "{") {
				t.Fatalf("expected console output, got JSON %q", s)
			}
			if strings.Contains(s, "hidden-debug") {
				t.Fatalf("debug line logged below the info level: %q", s)
			}
		})
	}
}

func TestInitKeepsJSONInProd(t *testing.T) {
	saveGlobals(t)
	t.Setenv("WEFT_ENV", "prod")

	var buf bytes.Buffer
	log.Logger = zerolog.New(&buf)

	Init(zerolog.WarnLevel)
	log.Info().Msg("hidden-info")
	log.Warn().Msg("hello-json")
	t.Logf("prod output: %q", buf.String())

	if zerolog.GlobalLevel() != zerolog.WarnLevel {
		t.Fatalf("global level = %v, want warn", zerolog.GlobalLevel())
	}
	s := buf.String()
	if !strings.Contains(s, `"level":"warn"`) || !strings.Contains(s, `"message":"hello-json"`) {
		t.Fatalf("expected the JSON logger to be kept, got %q", s)
	}
	if strings.Contains(s, "hidden-info") {
		t.Fatalf("info line logged below the warn level: %q", s)
	}
}
